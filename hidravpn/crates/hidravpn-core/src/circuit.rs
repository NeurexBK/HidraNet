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
//! Each hop is shown its own key (see `keys`): the entry, reached from the
//! client's address, the key derived for it; the exit, reached through the
//! entry, a fresh key admitted through the entry for this one connection
//! (`admit_behind`), or for an exit admitted by hand the key derived for it
//! behind an entry — never a key it could have seen from the client's own
//! address.
//!
//! With no entry the circuit is exactly the single tunnel of phases 1 and 2.
//!
//! Nothing here logs an address, a name looked up or a byte of traffic.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hidravpn_tun::TunConfig;
use tokio::task::JoinHandle;

use crate::config::{ClientConfig, Invite, ShownKey};
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
    /// The key the exit is shown when it was made for this connection
    /// (`prepare`). None: the key derived for it — for one hop, the per-node
    /// key; for two, the key behind an entry (an exit admitted by hand).
    pub exit_key: Option<ClientKey>,
    /// The key the entry is shown when it was made for this connection.
    /// None: the per-node key derived for it.
    pub entry_key: Option<ClientKey>,
}

impl CircuitSpec {
    /// One hop, or two with the exit shown the key derived for it behind an
    /// entry.
    pub fn new(exit: Invite, entry: Option<Invite>) -> Self {
        Self {
            exit,
            entry,
            exit_key: None,
            entry_key: None,
        }
    }

    /// Which key the exit is shown.
    fn exit_shown(&self) -> ShownKey {
        match (&self.exit_key, &self.entry) {
            (Some(k), _) => ShownKey::Exact(k.clone()),
            (None, None) => ShownKey::Direct,
            (None, Some(_)) => ShownKey::Behind,
        }
    }

    /// Which key the entry is shown.
    fn entry_shown(&self) -> ShownKey {
        match &self.entry_key {
            Some(k) => ShownKey::Exact(k.clone()),
            None => ShownKey::Direct,
        }
    }

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
    /// 1280 that IPv6 requires: with an entry MTU under 1360 an inner packet
    /// does not fit one outer packet, and the system splits it in two (slower,
    /// still delivered) rather than lose IPv6 on the inner interface.
    pub fn inner_mtu(&self) -> u16 {
        let mut mtu = self.exit.mtu;
        if let Some(entry) = &self.entry {
            mtu = mtu.min(entry.mtu.saturating_sub(OUTER_OVERHEAD));
        }
        mtu.max(MIN_MTU)
    }

    /// The node reached over the physical link: the entry when there are two
    /// hops, the exit when there is one. The one address the kill switch lets
    /// packets go to off-tunnel.
    pub fn first_hop_endpoint(&self) -> Result<SocketAddr> {
        match &self.entry {
            Some(entry) => entry.endpoint_addr(),
            None => self.exit.endpoint_addr(),
        }
    }

    /// Both invites must be valid, and with two hops they must be two
    /// different nodes: going through the same node twice costs the latency
    /// of a second hop and buys none of its privacy.
    pub fn validate(&self) -> Result<()> {
        self.check(Invite::validate)
    }

    /// `validate` for a circuit not yet prepared: a node that admits openly
    /// or with a pass is still the stand-in made from its record, whose
    /// tunnel addresses come with the invite `prepare` wins (checked in full
    /// then, and again when the circuit comes up), so only its shape is
    /// checked here.
    pub fn validate_plan(&self) -> Result<()> {
        self.check(|i: &Invite| {
            if i.admits_openly() || i.takes_passes() {
                i.validate_shape()
            } else {
                i.validate()
            }
        })
    }

    fn check(&self, valid: impl Fn(&Invite) -> Result<()>) -> Result<()> {
        valid(&self.exit).context("the exit invite")?;
        if let Some(entry) = &self.entry {
            valid(entry).context("the entry invite")?;
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
    /// 5. the kill switch, allowing both interfaces and the entry's endpoint,
    ///    in place of whatever was armed before, in one step;
    /// 6. the inner tunnel's first packet.
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
        netcfg::recover_dns();

        if let Some(entry) = &spec.entry {
            if ONE_ADDRESS_PER_INTERFACE && same_address(entry, &spec.exit) {
                return Err(anyhow!(
                    "{} and {} gave this machine the same tunnel address, which one machine cannot hold on two interfaces; connect again, or ask an operator to give one of them another tunnel subnet",
                    entry.node_name,
                    spec.exit.node_name
                ));
            }
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
            netcfg::check_address(&ifname, ip)?;
            let cfg = ClientConfig {
                invite: entry.clone(),
                key: key.clone(),
                shown: spec.entry_shown(),
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
        netcfg::check_address(&inner_ifname, ip)?;

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

        // 4. The inner tunnel's socket, now that its route exists. It is not
        // run yet: its first packet waits for the kill switch below, because
        // during a rotation the hold in force lets nothing out on a tunnel
        // interface, and a handshake dropped there would cost a retry.
        let cfg = ClientConfig {
            invite: spec.exit.clone(),
            key,
            shown: spec.exit_shown(),
        };
        let tunnel = Arc::new(
            Tunnel::new(&cfg, tun)
                .await
                .context("the tunnel to the exit")?,
        );

        // 5. The kill switch, replacing in one step whatever is armed (a
        // rotation's hold, a crashed run's rules). If it will not arm, the
        // whole circuit is undone by the caller: an unprotected tunnel is
        // worse than no tunnel. (`tunnel` is dropped on the way out, which
        // closes its socket and removes the interface.)
        if opts.kill_switch {
            let (interface, extra_interface, node_endpoint, outer_peer) =
                match (&spec.entry, &steps.outer) {
                    (Some(entry), Some(outer)) => (
                        outer.interface.clone(),
                        Some(inner_ifname.clone()),
                        entry.endpoint_addr()?,
                        Some(spec.exit.endpoint_addr()?),
                    ),
                    _ => (inner_ifname.clone(), None, spec.exit.endpoint_addr()?, None),
                };
            killswitch::apply(&KillConfig {
                interface,
                node_endpoint,
                dns: spec.exit.dns,
                allow_lan: opts.allow_lan,
                extra_interface,
                outer_peer,
            })
            .context("could not arm the kill switch; connection refused")?;
            steps.kill_switch = true;
        }

        // 6. Only now the inner tunnel runs and shakes hands.
        let runner = spawn_runner(&tunnel);
        steps.inner = Some(Hop {
            role: Role::Exit,
            invite: spec.exit.clone(),
            interface: inner_ifname,
            tunnel,
            runner,
        });
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
        self.down_with(true).await
    }

    /// `down`, with the choice of leaving the kill switch as it stands: for a
    /// rotation, where `killswitch::hold` is already in place and the next
    /// circuit's own rules will replace it, so the machine is never on the
    /// open network in between.
    pub async fn down_with(self, lift_kill_switch: bool) -> Result<()> {
        let ks = if self.kill_switch && lift_kill_switch {
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

/// What `prepare` made ready: the circuit, the invites it won with a pass
/// (for the pocket to keep), and notes for the person.
pub struct Prepared {
    pub spec: CircuitSpec,
    pub redeemed: Vec<Invite>,
    pub notes: Vec<String>,
}

/// Gets everything a circuit through `exit` (and `entry`) needs before it
/// can come up: a key made for this one connection from every node that
/// admits openly or with a pass, so no such node sees the same key twice.
///
/// - The first hop (the entry, or the only node) is asked directly: it sees
///   this machine's address in any case. A node that admits openly is asked
///   for a session key, paid for with a proof of work; a node that admits
///   with a pass is given the next pass from `wallet` (one redeemed and not
///   yet used is used as it is; with none left, the last pass's key, and a
///   note says so).
/// - The exit of two hops is asked *through the entry* (`admit_behind`), so
///   it never hears from this address, with a session key or a pass. It
///   never falls back to a key it was shown before: with no pass left for
///   it, the connection is refused and says so.
///
/// A node admitted by hand is used with the key its operator admitted.
///
/// `held` is empty for a first connection, when nothing is armed yet. When a
/// circuit is being replaced it names the first hops the kill switch holds
/// open, and the hold is widened to exactly the requests this needs. The
/// hold stays in place when this returns, successfully or not: the circuit
/// that follows replaces it, or the caller lifts it. A pass that never
/// reached its node goes back into `wallet`; one a node refused is spent.
pub async fn prepare(
    exit: &Invite,
    entry: Option<&Invite>,
    key: &ClientKey,
    opts: &CircuitOptions,
    held: &[SocketAddr],
    wallet: &mut crate::pass::Wallet,
) -> Result<Prepared> {
    let mut spec = CircuitSpec::new(exit.clone(), entry.cloned());
    let mut redeemed = Vec::new();
    let mut notes = Vec::new();
    let first = entry.unwrap_or(exit);
    if first.admits_openly() && !first.admits_sessions() {
        return Err(not_updated(first));
    }
    if (first.admits_sessions() || first.takes_passes()) && !held.is_empty() {
        let mut nodes = held.to_vec();
        nodes.push(first.endpoint_addr()?);
        killswitch::hold_admitting(&nodes, &[first.admission_addr()?], None)
            .context("could not hold the kill switch to ask the first node for admission")?;
    }
    let mut won = None;
    if first.admits_sessions() {
        let fresh = ClientKey::generate()?;
        let invite = crate::admission::request_admission(
            &first.record(),
            &fresh.public_base64(),
            "client",
            true,
        )
        .await
        .with_context(|| format!("asking {} for admission", first.node_name))?;
        won = Some((invite, Some(fresh)));
    } else if first.takes_passes() {
        if let Some(invite) = first_hop_pass(first, wallet, &mut notes).await? {
            redeemed.push(invite.clone());
            won = Some((invite, None));
        }
    }
    if let Some((invite, fresh)) = won {
        match entry {
            Some(_) => {
                spec.entry = Some(invite);
                spec.entry_key = fresh;
            }
            None => {
                spec.exit = invite;
                spec.exit_key = fresh;
            }
        }
    }
    if let Some(entry) = spec.entry.clone() {
        let ask = if exit.admits_openly() {
            if !exit.admits_sessions() {
                return Err(not_updated(exit));
            }
            Some(Ask::Session)
        } else if exit.takes_passes() {
            let pass = wallet.take_for(&exit.node_public_key).ok_or_else(|| {
                anyhow!(
                    "no pass left for {}: as the exit of two hops it is only ever shown a key admitted through the entry, never one it saw before; `hidravpn passes get` asks the issuer for more",
                    exit.node_name
                )
            })?;
            Some(Ask::Pass(pass))
        } else {
            None
        };
        if let Some(ask) = ask {
            if !crate::pocket::entry_can_reach(&entry, exit) {
                if let Ask::Pass(p) = ask {
                    wallet.passes.push(p);
                }
                return Err(anyhow!(
                    "{} cannot ask {} for admission on this machine's behalf: its software is older than that (no `admission-relay` in the node list)",
                    entry.node_name,
                    exit.node_name
                ));
            }
            let session = matches!(ask, Ask::Session);
            let (mut invite, mut fresh) = admit_behind(
                &entry,
                spec.entry_shown(),
                exit,
                key,
                opts,
                held,
                ask,
                wallet,
            )
            .await?;
            // Nodes on the same default subnet can hand this machine the
            // same address, which Windows cannot hold on two interfaces. A
            // session is simply asked for again: the exit leases the next
            // address while the first lease lapses unused.
            let mut tries = 0;
            while ONE_ADDRESS_PER_INTERFACE && session && same_address(&entry, &invite) && tries < 3
            {
                tries += 1;
                (invite, fresh) = admit_behind(
                    &entry,
                    spec.entry_shown(),
                    exit,
                    key,
                    opts,
                    held,
                    Ask::Session,
                    wallet,
                )
                .await?;
            }
            if invite.pass.is_some() {
                redeemed.push(invite.clone());
            }
            spec.exit = invite;
            spec.exit_key = fresh;
        }
    }
    Ok(Prepared {
        spec,
        redeemed,
        notes,
    })
}

/// A first hop that admits with a pass: the next pass, redeemed directly.
/// None means the invite is used as it is — a pass redeemed and not yet
/// used, or, with no pass left or none taken, the last pass's key (and a
/// note says so).
async fn first_hop_pass(
    node: &Invite,
    wallet: &mut crate::pass::Wallet,
    notes: &mut Vec<String>,
) -> Result<Option<Invite>> {
    let now = crate::timefmt::now_unix().max(0) as u64;
    if node.pass.as_ref().is_some_and(|p| p.fresh(now)) {
        return Ok(None);
    }
    let Some(pass) = wallet.take_for(&node.node_public_key) else {
        if node.pass.is_some() {
            notes.push(format!(
                "no pass left for {}: connecting with the last one's key; `hidravpn passes get` for more",
                node.node_name
            ));
            return Ok(None);
        }
        return Err(anyhow!(
            "no pass left for {}: `hidravpn passes get` asks the issuer for more",
            node.node_name
        ));
    };
    match crate::admission::redeem_pass(&node.record(), &pass).await {
        Ok(invite) => Ok(Some(invite)),
        Err(e) => {
            if e.downcast_ref::<crate::admission::PassRefused>().is_none() {
                wallet.passes.push(pass);
            }
            if node.pass.is_some() {
                notes.push(format!("{e:#}; connecting with the last pass's key"));
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}

/// Windows will not hold one address on two interfaces (it gives the second
/// a link-local one, silently); Linux does, and two hops with the same
/// address on both interfaces work there.
const ONE_ADDRESS_PER_INTERFACE: bool = cfg!(windows);

/// Whether two invites give this machine the same tunnel address.
fn same_address(a: &Invite, b: &Invite) -> bool {
    matches!((a.client_ip(), b.client_ip()), (Ok((x, _)), Ok((y, _))) if x == y)
}

/// What an exit is asked for through the entry.
enum Ask {
    /// A key made for this connection, with a proof of work.
    Session,
    /// The key this pass names.
    Pass(crate::pass::Pass),
}

fn not_updated(node: &Invite) -> anyhow::Error {
    anyhow!(
        "{} admits openly but its software is older than per-connection keys (no `sessions` in the node list); it is not used until its operator updates it",
        node.node_name
    )
}

/// Asks an exit that admits openly to admit a fresh key, through the entry,
/// so the exit never hears from this machine's own address and never sees a
/// key it could tie to it. Returns the exit's invite for that key, and the
/// key, for one connection.
///
/// While it runs, the kill switch holds the machine to exactly this: the
/// encrypted packets to the entry (and to `held`, the first hop of a circuit
/// being replaced), and inside the entry's tunnel one TCP connection to the
/// exit's admission port. No DNS, nothing else, and no default route into
/// the entry, which forwards nothing but WireGuard and this request in any
/// case.
#[allow(clippy::too_many_arguments)]
async fn admit_behind(
    entry: &Invite,
    entry_shown: ShownKey,
    exit: &Invite,
    key: &ClientKey,
    opts: &CircuitOptions,
    held: &[SocketAddr],
    ask: Ask,
    wallet: &mut crate::pass::Wallet,
) -> Result<(Invite, Option<ClientKey>)> {
    entry.validate().context("the entry invite")?;
    let entry_ep = entry.endpoint_addr()?;
    let admission = exit.admission_addr()?;
    let outer_name = format!("{}0", opts.interface_base);
    let mut nodes = vec![entry_ep];
    nodes.extend(held.iter().copied().filter(|a| *a != entry_ep));

    // The interface first, then the hold that names it: Windows filters an
    // interface by its LUID, which exists only once the interface does. An
    // interface with no route to it carries nothing meanwhile, and whatever
    // hold or kill switch is already in place still blocks the rest.
    let (ip, _) = entry.client_ip()?;
    let tun = hidravpn_tun::open(&TunConfig {
        name: outer_name.clone(),
        ipv4: (ip, 32),
        ipv6: None,
        mtu: entry.mtu,
    })
    .context("the outer tunnel interface")?;
    let ifname = hidravpn_tun::name(&tun).unwrap_or(outer_name);
    killswitch::hold_admitting(
        &nodes,
        &[],
        Some(&killswitch::Bridge {
            interface: ifname.clone(),
            to: admission,
        }),
    )
    .context("could not hold the kill switch to ask the exit through the entry")?;
    let cfg = ClientConfig {
        invite: entry.clone(),
        key: key.clone(),
        shown: entry_shown,
    };
    let tunnel = Arc::new(
        Tunnel::new(&cfg, tun)
            .await
            .context("the tunnel to the entry")?,
    );
    let runner = spawn_runner(&tunnel);
    let hop = Hop {
        role: Role::Entry,
        invite: entry.clone(),
        interface: ifname.clone(),
        tunnel,
        runner,
    };
    let asked: Result<(Invite, Option<ClientKey>)> = async {
        netcfg::route_host_via(admission.ip(), &ifname)?;
        let how = format!(
            "asking {} for admission through {}",
            exit.node_name, entry.node_name
        );
        match &ask {
            Ask::Session => {
                let fresh = ClientKey::generate()?;
                let invite = crate::admission::request_admission(
                    &exit.record(),
                    &fresh.public_base64(),
                    "client",
                    true,
                )
                .await
                .context(how)?;
                Ok((invite, Some(fresh)))
            }
            Ask::Pass(pass) => {
                let invite = crate::admission::redeem_pass(&exit.record(), pass)
                    .await
                    .context(how)?;
                Ok((invite, None))
            }
        }
    }
    .await;
    // The interface goes, and its route with it, whatever the answer.
    hop.stop().await;
    if let (Err(e), Ask::Pass(pass)) = (&asked, ask) {
        // A pass that never reached the node is kept; one it refused is spent.
        if e.downcast_ref::<crate::admission::PassRefused>().is_none() {
            wallet.passes.push(pass);
        }
    }
    asked
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
            operator: None,
            role: None,
            pass: None,
            country: None,
            admission: None,
            admission_port: None,
            behind: false,
            features: Vec::new(),
        }
    }

    #[test]
    fn two_invites_with_one_address_are_seen_as_the_same_address() {
        let mut a = invite("a", "203.0.113.10:51820", 1420);
        let mut b = invite("b", "203.0.113.11:51820", 1420);
        a.client_address = "10.77.0.3/32".into();
        b.client_address = "10.77.0.3/16".into();
        assert!(same_address(&a, &b));
        b.client_address = "10.77.0.4/16".into();
        assert!(!same_address(&a, &b));
    }

    #[test]
    fn one_hop_is_rapido_and_keeps_the_exit_mtu() {
        let spec = CircuitSpec {
            exit: invite("exit", "203.0.113.10:51820", 1420),
            entry: None,
            exit_key: None,
            entry_key: None,
        };
        assert_eq!(spec.hops(), 1);
        assert_eq!(spec.mode(), Mode::Rapido);
        assert_eq!(spec.inner_mtu(), 1420);
        spec.validate().unwrap();
        assert_eq!(
            spec.first_hop_endpoint().unwrap(),
            SocketAddr::from(([203, 0, 113, 10], 51820)),
            "one hop: the exit is reached over the physical link"
        );
    }

    #[test]
    fn two_hops_is_privado_and_the_inner_mtu_fits_inside_the_outer() {
        let spec = CircuitSpec {
            exit: invite("exit", "203.0.113.10:51820", 1420),
            entry: Some(invite("entry", "203.0.113.20:51820", 1420)),
            exit_key: None,
            entry_key: None,
        };
        assert_eq!(spec.hops(), 2);
        assert_eq!(spec.mode(), Mode::Privado);
        assert_eq!(spec.inner_mtu(), 1340);
        spec.validate().unwrap();
        assert_eq!(
            spec.first_hop_endpoint().unwrap(),
            SocketAddr::from(([203, 0, 113, 20], 51820)),
            "two hops: the entry is the node on the physical link"
        );
    }

    #[test]
    fn the_inner_mtu_is_the_smaller_of_the_two_and_never_below_1280() {
        let small_exit = CircuitSpec {
            exit: invite("exit", "203.0.113.10:51820", 1300),
            entry: Some(invite("entry", "203.0.113.20:51820", 1500)),
            exit_key: None,
            entry_key: None,
        };
        assert_eq!(small_exit.inner_mtu(), 1300);
        let small_entry = CircuitSpec {
            exit: invite("exit", "203.0.113.10:51820", 1500),
            entry: Some(invite("entry", "203.0.113.20:51820", 1280)),
            exit_key: None,
            entry_key: None,
        };
        assert_eq!(small_entry.inner_mtu(), 1280);
    }

    #[test]
    fn the_entry_and_the_exit_must_be_different_nodes() {
        let exit = invite("exit", "203.0.113.10:51820", 1420);
        let same_key = CircuitSpec {
            entry: Some(exit.clone()),
            exit: exit.clone(),
            exit_key: None,
            entry_key: None,
        };
        let err = same_key.validate().unwrap_err().to_string();
        assert!(err.contains("same node"), "{err}");

        let mut other_key = exit.clone();
        other_key.node_public_key = ClientKey::generate().unwrap().public_base64();
        let same_endpoint = CircuitSpec {
            entry: Some(other_key),
            exit: exit.clone(),
            exit_key: None,
            entry_key: None,
        };
        let err = same_endpoint.validate().unwrap_err().to_string();
        assert!(err.contains("same endpoint"), "{err}");
    }

    #[test]
    fn a_bad_invite_on_either_hop_is_refused() {
        let mut bad = invite("entry", "203.0.113.20:51820", 1420);
        bad.node_public_key = "short".into();
        let spec = CircuitSpec {
            exit: invite("exit", "203.0.113.10:51820", 1420),
            entry: Some(bad),
            exit_key: None,
            entry_key: None,
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
