//! A circuit: one hop (Rápido) or two (Privado), and everything that goes with
//! bringing it up and taking it down in the right order.
//!
//! Two hops are two ordinary WireGuard tunnels, one inside the other, joined
//! by routing and nothing new: the outer tunnel on the first interface goes to
//! the *entry* node over the physical link; the inner tunnel on the second
//! interface goes to the *exit* node, and its UDP packets are routed into the
//! outer interface, so the outer tunnel encrypts them a second time. The
//! default route goes into the inner interface; DNS is the exit's resolver.
//! The entry sees who the client is but not where the traffic goes; the exit
//! sees the traffic but gets it from the entry's address.
//!
//! Each hop is shown its own key, derived from the client's master key for
//! that node (see `keys`): the entry and the exit have no key in common.
//!
//! With no entry the circuit is exactly the single tunnel of phases 1 and 2.
//!
//! Nothing here logs an address, a name looked up or a byte of traffic.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hidravpn_tun::TunConfig;
use tokio::task::JoinHandle;

use crate::config::{ClientConfig, Invite};
use crate::keys::ClientKey;
use crate::killswitch::{self, KillConfig};
use crate::netcfg::{self, RevertPlan, ViaRoute, Wanted};
use crate::tunnel::{Tunnel, TunnelStatus};

/// The smallest MTU IPv6 allows, and the floor for the inner tunnel.
const MIN_MTU: u16 = 1280;

/// What the outer tunnel adds around each inner packet: WireGuard's 32 bytes
/// plus the UDP and IP headers, with margin.
const OUTER_OVERHEAD: u16 = 80;

/// How the circuit is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// One hop: fastest, the node sees both who and where.
    Rapido,
    /// Two hops: the entry sees who, the exit sees where, neither sees both.
    Privado,
}

impl Mode {
    /// The wire form, ASCII, as the control channel and `status` carry it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Rapido => "rapido",
            Mode::Privado => "privado",
        }
    }

    /// The name shown to a person.
    pub fn label(&self) -> &'static str {
        match self {
            Mode::Rapido => "Rápido",
            Mode::Privado => "Privado",
        }
    }
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which nodes the circuit goes through.
#[derive(Debug, Clone)]
pub struct CircuitSpec {
    /// The node that reaches the internet.
    pub exit: Invite,
    /// The node the client talks to first, when there are two hops.
    pub entry: Option<Invite>,
}

impl CircuitSpec {
    pub fn hops(&self) -> u8 {
        if self.entry.is_some() {
            2
        } else {
            1
        }
    }

    pub fn mode(&self) -> Mode {
        if self.entry.is_some() {
            Mode::Privado
        } else {
            Mode::Rapido
        }
    }

    /// The MTU of the tunnel that carries the machine's traffic: the exit's
    /// own MTU for one hop; for two, also small enough that an inner packet
    /// plus the outer tunnel's overhead fits the entry's MTU. Never below the
    /// 1280 that IPv6 requires.
    pub fn inner_mtu(&self) -> u16 {
        let mut mtu = self.exit.mtu;
        if let Some(entry) = &self.entry {
            mtu = mtu.min(entry.mtu.saturating_sub(OUTER_OVERHEAD));
        }
        mtu.max(MIN_MTU)
    }

    /// Both invites must be valid, and with two hops they must be two
    /// different nodes: going through the same node twice costs the latency
    /// of a second hop and buys none of its privacy.
    pub fn validate(&self) -> Result<()> {
        self.exit.validate().context("the exit invite")?;
        if let Some(entry) = &self.entry {
            entry.validate().context("the entry invite")?;
            if entry.node_public_key.trim() == self.exit.node_public_key.trim() {
                return Err(anyhow!(
                    "the entry and the exit are the same node (same key); two hops need two different nodes"
                ));
            }
            if entry.endpoint_addr()? == self.exit.endpoint_addr()? {
                return Err(anyhow!(
                    "the entry and the exit have the same endpoint; two hops need two different nodes"
                ));
            }
        }
        Ok(())
    }
}

/// How the circuit should treat the rest of the machine.
#[derive(Debug, Clone)]
pub struct CircuitOptions {
    /// Route IPv6 into the tunnel too (where it is dropped), so it cannot go
    /// around the VPN.
    pub route_ipv6: bool,
    /// Let the kill switch pass the local subnet.
    pub allow_lan: bool,
    /// Arm the kill switch; refusing the connection if it will not arm.
    pub kill_switch: bool,
    /// Interface names are this plus a number: `hvpn0` for the outer (or
    /// only) tunnel, `hvpn1` for the inner one.
    pub interface_base: String,
}

impl Default for CircuitOptions {
    fn default() -> Self {
        Self {
            route_ipv6: true,
            allow_lan: false,
            kill_switch: true,
            interface_base: "hvpn".into(),
        }
    }
}

/// Which node a hop goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Entry,
    Exit,
}

/// One tunnel's state.
#[derive(Debug, Clone)]
pub struct HopStatus {
    pub role: Role,
    pub node_name: String,
    pub endpoint: String,
    pub interface: String,
    pub tunnel: TunnelStatus,
}

/// The circuit's state: `connected` only when every hop has a live session.
#[derive(Debug, Clone)]
pub struct CircuitStatus {
    pub connected: bool,
    pub mode: Mode,
    /// Entry first (if any), exit last.
    pub hops: Vec<HopStatus>,
}

impl CircuitStatus {
    pub fn exit(&self) -> &HopStatus {
        self.hops.last().expect("a circuit always has an exit")
    }

    pub fn entry(&self) -> Option<&HopStatus> {
        if self.hops.len() == 2 {
            self.hops.first()
        } else {
            None
        }
    }
}

struct Hop {
    role: Role,
    invite: Invite,
    interface: String,
    tunnel: Arc<Tunnel>,
    runner: JoinHandle<()>,
}

impl Hop {
    fn status(&self) -> HopStatus {
        HopStatus {
            role: self.role,
            node_name: self.invite.node_name.clone(),
            endpoint: self.invite.endpoint.clone(),
            interface: self.interface.clone(),
            tunnel: self.tunnel.status(),
        }
    }

    /// Asks the tunnel to stop and waits until its tasks have let go of the
    /// interface, so that dropping the hop really removes it.
    async fn stop(self) {
        self.tunnel.stop();
        let _ = self.runner.await;
        drop(self.tunnel);
    }
}

/// What has been done so far, so a failure half-way can be undone in reverse.
#[derive(Default)]
struct Steps {
    outer: Option<Hop>,
    inner: Option<Hop>,
    plan: Option<RevertPlan>,
    kill_switch: bool,
}

impl Steps {
    async fn undo(self) {
        if self.kill_switch {
            let _ = killswitch::remove();
        }
        if let Some(p) = &self.plan {
            let _ = netcfg::revert(p);
        }
        if let Some(h) = self.inner {
            h.stop().await;
        }
        if let Some(h) = self.outer {
            h.stop().await;
        }
    }
}

/// A running circuit. Drop it only through `down`, which puts the machine back.
pub struct Circuit {
    spec: CircuitSpec,
    outer: Option<Hop>,
    inner: Hop,
    plan: RevertPlan,
    kill_switch: bool,
}

impl Circuit {
    /// Brings the circuit up, in the one order that works, and undoes
    /// everything on any failure.
    ///
    /// 1. the outer interface and tunnel to the entry (two hops only);
    /// 2. the inner interface, with the inner MTU;
    /// 3. the network plan, once: the entry's endpoint over the physical
    ///    gateway, the exit's endpoint through the outer interface, the
    ///    default route into the inner one, DNS at the exit's resolver;
    /// 4. only then the inner tunnel's socket, so its first packet already
    ///    goes into the outer interface (a connected UDP socket caches its
    ///    route);
    /// 5. the kill switch, allowing both interfaces and the entry's endpoint.
    pub async fn up(spec: CircuitSpec, key: ClientKey, opts: CircuitOptions) -> Result<Self> {
        spec.validate()?;
        let mut steps = Steps::default();
        match Self::bring_up(&spec, key, &opts, &mut steps).await {
            Ok(()) => Ok(Self {
                spec,
                outer: steps.outer.take(),
                inner: steps.inner.take().expect("the inner hop is up"),
                plan: steps.plan.take().expect("the plan is applied"),
                kill_switch: steps.kill_switch,
            }),
            Err(e) => {
                steps.undo().await;
                Err(e)
            }
        }
    }

    async fn bring_up(
        spec: &CircuitSpec,
        key: ClientKey,
        opts: &CircuitOptions,
        steps: &mut Steps,
    ) -> Result<()> {
        // A plan from a connection that died is undone first; otherwise the
        // new routes would stack on the old ones.
        if let Ok(Some(old)) = netcfg::load_plan() {
            let _ = netcfg::revert(&old);
        }

        let outer_name = format!("{}0", opts.interface_base);

        // 1. The outer tunnel, to the entry. Its interface carries a /32:
        // the client needs nothing on the entry's subnet, and a wider prefix
        // would shadow the exit's resolver when both nodes use the same
        // default subnet.
        if let Some(entry) = &spec.entry {
            let (ip, _) = entry.client_ip()?;
            let tun = hidravpn_tun::open(&TunConfig {
                name: outer_name.clone(),
                ipv4: (ip, 32),
                ipv6: None,
                mtu: entry.mtu,
            })
            .context("the outer tunnel interface")?;
            let ifname = hidravpn_tun::name(&tun).unwrap_or(outer_name.clone());
            let cfg = ClientConfig {
                invite: entry.clone(),
                key: key.clone(),
            };
            let tunnel = Arc::new(
                Tunnel::new(&cfg, tun)
                    .await
                    .context("the outer tunnel to the entry")?,
            );
            let runner = spawn_runner(&tunnel);
            steps.outer = Some(Hop {
                role: Role::Entry,
                invite: entry.clone(),
                interface: ifname,
                tunnel,
                runner,
            });
        }

        // 2. The inner (or only) interface.
        let inner_name = match &steps.outer {
            Some(_) => format!("{}1", opts.interface_base),
            None => outer_name,
        };
        let (ip, prefix) = spec.exit.client_ip()?;
        let tun = hidravpn_tun::open(&TunConfig {
            name: inner_name.clone(),
            ipv4: (ip, prefix),
            ipv6: None,
            mtu: spec.inner_mtu(),
        })
        .context("the tunnel interface")?;
        let inner_ifname = hidravpn_tun::name(&tun).unwrap_or(inner_name);

        // 3. The network plan.
        let (node_ip, via_tunnel) = match (&spec.entry, &steps.outer) {
            (Some(entry), Some(outer)) => (
                entry.endpoint_ip()?,
                vec![ViaRoute {
                    host: spec.exit.endpoint_ip()?,
                    interface: outer.interface.clone(),
                }],
            ),
            _ => (spec.exit.endpoint_ip()?, Vec::new()),
        };
        let plan = netcfg::apply(&Wanted {
            interface: inner_ifname.clone(),
            node_ip,
            dns: spec.exit.dns,
            route_ipv6: opts.route_ipv6,
            via_tunnel,
        })
        .context("could not route the machine through the tunnel")?;
        steps.plan = Some(plan);

        // 4. The inner tunnel's socket, now that its route exists.
        let cfg = ClientConfig {
            invite: spec.exit.clone(),
            key,
        };
        let tunnel = Arc::new(
            Tunnel::new(&cfg, tun)
                .await
                .context("the tunnel to the exit")?,
        );
        let runner = spawn_runner(&tunnel);
        steps.inner = Some(Hop {
            role: Role::Exit,
            invite: spec.exit.clone(),
            interface: inner_ifname.clone(),
            tunnel,
            runner,
        });

        // 5. The kill switch. If it will not arm, the whole circuit is undone
        // by the caller: an unprotected tunnel is worse than no tunnel.
        if opts.kill_switch {
            let (interface, extra_interface, node_endpoint) = match (&spec.entry, &steps.outer) {
                (Some(entry), Some(outer)) => (
                    outer.interface.clone(),
                    Some(inner_ifname.clone()),
                    entry.endpoint_addr()?,
                ),
                _ => (inner_ifname.clone(), None, spec.exit.endpoint_addr()?),
            };
            killswitch::apply(&KillConfig {
                interface,
                node_endpoint,
                dns: spec.exit.dns,
                allow_lan: opts.allow_lan,
                extra_interface,
            })
            .context("could not arm the kill switch; connection refused")?;
            steps.kill_switch = true;
        }
        Ok(())
    }

    pub fn spec(&self) -> &CircuitSpec {
        &self.spec
    }

    pub fn mode(&self) -> Mode {
        self.spec.mode()
    }

    pub fn hops(&self) -> u8 {
        self.spec.hops()
    }

    /// Whether the kill switch was armed by this circuit.
    pub fn kill_switch_armed(&self) -> bool {
        self.kill_switch
    }

    /// The interface the machine's traffic goes into.
    pub fn interface(&self) -> &str {
        &self.inner.interface
    }

    pub fn status(&self) -> CircuitStatus {
        let mut hops = Vec::with_capacity(2);
        if let Some(o) = &self.outer {
            hops.push(o.status());
        }
        hops.push(self.inner.status());
        CircuitStatus {
            connected: hops.iter().all(|h| h.tunnel.connected),
            mode: self.spec.mode(),
            hops,
        }
    }

    /// Whether some tunnel task has died, so the caller can give up.
    pub fn is_finished(&self) -> bool {
        self.inner.runner.is_finished()
            || self
                .outer
                .as_ref()
                .map(|o| o.runner.is_finished())
                .unwrap_or(false)
    }

    /// Takes the circuit down in reverse: the kill switch, the routes and
    /// DNS, the inner tunnel, the outer one. Every step is attempted; the
    /// first error is reported once all are done.
    pub async fn down(self) -> Result<()> {
        let ks = if self.kill_switch {
            killswitch::remove()
        } else {
            Ok(())
        };
        let nc = netcfg::revert(&self.plan);
        self.inner.stop().await;
        if let Some(o) = self.outer {
            o.stop().await;
        }
        ks.and(nc)
    }
}

fn spawn_runner(tunnel: &Arc<Tunnel>) -> JoinHandle<()> {
    let t = tunnel.clone();
    tokio::spawn(async move {
        let _ = t.run().await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn invite(name: &str, endpoint: &str, mtu: u16) -> Invite {
        Invite {
            node_name: name.into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: endpoint.into(),
            client_address: "10.77.0.2/16".into(),
            dns: Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu,
            keepalive: 25,
        }
    }

    #[test]
    fn one_hop_is_rapido_and_keeps_the_exit_mtu() {
        let spec = CircuitSpec {
            exit: invite("exit", "95.216.142.72:51820", 1420),
            entry: None,
        };
        assert_eq!(spec.hops(), 1);
        assert_eq!(spec.mode(), Mode::Rapido);
        assert_eq!(spec.inner_mtu(), 1420);
        spec.validate().unwrap();
    }

    #[test]
    fn two_hops_is_privado_and_the_inner_mtu_fits_inside_the_outer() {
        let spec = CircuitSpec {
            exit: invite("exit", "95.216.142.72:51820", 1420),
            entry: Some(invite("entry", "5.6.7.8:51820", 1420)),
        };
        assert_eq!(spec.hops(), 2);
        assert_eq!(spec.mode(), Mode::Privado);
        assert_eq!(spec.inner_mtu(), 1340);
        spec.validate().unwrap();
    }

    #[test]
    fn the_inner_mtu_is_the_smaller_of_the_two_and_never_below_1280() {
        let small_exit = CircuitSpec {
            exit: invite("exit", "95.216.142.72:51820", 1300),
            entry: Some(invite("entry", "5.6.7.8:51820", 1500)),
        };
        assert_eq!(small_exit.inner_mtu(), 1300);
        let small_entry = CircuitSpec {
            exit: invite("exit", "95.216.142.72:51820", 1500),
            entry: Some(invite("entry", "5.6.7.8:51820", 1280)),
        };
        assert_eq!(small_entry.inner_mtu(), 1280);
    }

    #[test]
    fn the_entry_and_the_exit_must_be_different_nodes() {
        let exit = invite("exit", "95.216.142.72:51820", 1420);
        let same_key = CircuitSpec {
            entry: Some(exit.clone()),
            exit: exit.clone(),
        };
        let err = same_key.validate().unwrap_err().to_string();
        assert!(err.contains("same node"), "{err}");

        let mut other_key = exit.clone();
        other_key.node_public_key = ClientKey::generate().unwrap().public_base64();
        let same_endpoint = CircuitSpec {
            entry: Some(other_key),
            exit: exit.clone(),
        };
        let err = same_endpoint.validate().unwrap_err().to_string();
        assert!(err.contains("same endpoint"), "{err}");
    }

    #[test]
    fn a_bad_invite_on_either_hop_is_refused() {
        let mut bad = invite("entry", "5.6.7.8:51820", 1420);
        bad.node_public_key = "short".into();
        let spec = CircuitSpec {
            exit: invite("exit", "95.216.142.72:51820", 1420),
            entry: Some(bad),
        };
        assert!(spec.validate().unwrap_err().to_string().contains("entry"));
    }

    #[test]
    fn modes_have_a_wire_form_and_a_label() {
        assert_eq!(Mode::Rapido.as_str(), "rapido");
        assert_eq!(Mode::Privado.to_string(), "privado");
        assert_eq!(Mode::Privado.label(), "Privado");
    }
}
