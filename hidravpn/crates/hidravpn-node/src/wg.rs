//! The WireGuard interface. The kernel's, where the kernel has one (every
//! current Linux does); otherwise our own, in userspace (userspace.rs). Both
//! are configured the same way, through wireguard-control, so the rest of
//! the node does not care which it got — and neither do `admit` and
//! `status`, which run as separate processes.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use tracing::info;
use wireguard_control::{Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

use crate::config::{NodeConfig, TunnelNet, TunnelNet6};
use crate::userspace::{socket_path, UserspaceDevice};

pub struct WgDevice {
    iface: InterfaceName,
    backend: Backend,
    userspace: Option<UserspaceDevice>,
    /// The IPv6 subnet this node carries for its clients, when it does: the
    /// interface holds the node's address in it, and every peer is allowed
    /// its own address there besides its IPv4 one.
    v6: Option<TunnelNet6>,
}

#[derive(Debug, Default, Clone)]
pub struct PeerStats {
    pub last_handshake: Option<Duration>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

impl WgDevice {
    /// Creates and configures the interface for this node, with IPv6 when
    /// `net6` is given and the kernel's WireGuard runs it (the userspace one
    /// carries IPv4 only).
    pub async fn bring_up(
        cfg: &NodeConfig,
        net: &TunnelNet,
        net6: Option<TunnelNet6>,
    ) -> Result<Self> {
        let iface = InterfaceName::from_str(&cfg.interface)
            .map_err(|e| anyhow!("bad interface name: {e}"))?;
        let key = Key::from_base64(&cfg.private_key).map_err(|_| anyhow!("invalid private key"))?;
        let update = || {
            DeviceUpdate::new()
                .set_private_key(key.clone())
                .set_listen_port(cfg.listen_port)
                .replace_peers()
        };

        match update().apply(&iface, Backend::Kernel) {
            Ok(()) => {
                let addr = format!("{}/{}", net.node_ip, net.prefix);
                run("ip", &["address", "replace", &addr, "dev", &cfg.interface])?;
                run(
                    "ip",
                    &["link", "set", "dev", &cfg.interface, "mtu", "1420", "up"],
                )?;
                let v6 = match net6 {
                    Some(n) => {
                        let addr6 = format!("{}/{}", n.node_ip, n.prefix);
                        match run(
                            "ip",
                            &[
                                "-6",
                                "address",
                                "replace",
                                &addr6,
                                "dev",
                                &cfg.interface,
                                "nodad",
                            ],
                        ) {
                            Ok(()) => Some(n),
                            Err(_) => {
                                info!("the tunnel interface took no IPv6 address; clients get IPv4 only");
                                None
                            }
                        }
                    }
                    None => None,
                };
                Ok(Self {
                    iface,
                    backend: Backend::Kernel,
                    userspace: None,
                    v6,
                })
            }
            Err(e) => {
                info!("kernel WireGuard not available ({e}); running WireGuard in userspace");
                let dev =
                    UserspaceDevice::start(&cfg.interface, &cfg.private_key, cfg.listen_port, net)
                        .await?;
                // The control socket is served by this process; configure
                // it from a blocking thread so the server can answer.
                let iface2 = iface;
                let upd = update();
                tokio::task::spawn_blocking(move || upd.apply(&iface2, Backend::Userspace))
                    .await
                    .context("configuring userspace WireGuard")??;
                if net6.is_some() {
                    info!("WireGuard in userspace carries IPv4 only; clients get IPv4 only");
                }
                Ok(Self {
                    iface,
                    backend: Backend::Userspace,
                    userspace: Some(dev),
                    v6: None,
                })
            }
        }
    }

    /// Talks to the interface a running node created, from another process.
    /// It carries IPv6 when the running node gave it its address in `net6`.
    pub fn open_existing(name: &str, net6: Option<TunnelNet6>) -> Result<Self> {
        let iface =
            InterfaceName::from_str(name).map_err(|e| anyhow!("bad interface name: {e}"))?;
        let backend = if socket_path(name).exists() {
            Backend::Userspace
        } else {
            Backend::Kernel
        };
        Device::get(&iface, backend).map_err(|e| anyhow!("no running node on {name}: {e}"))?;
        let v6 = net6.filter(|n| interface_has(name, n.node_ip));
        Ok(Self {
            iface,
            backend,
            userspace: None,
            v6,
        })
    }

    /// The IPv6 subnet this node carries for clients, when it does.
    pub fn ipv6(&self) -> Option<TunnelNet6> {
        self.v6
    }

    /// Stops carrying IPv6: the node's address goes from the interface, and
    /// peers admitted from now on are allowed their IPv4 address only.
    pub fn drop_ipv6(&mut self) {
        if let Some(n) = self.v6.take() {
            let addr6 = format!("{}/{}", n.node_ip, n.prefix);
            let _ = run(
                "ip",
                &[
                    "-6",
                    "address",
                    "del",
                    &addr6,
                    "dev",
                    &self.iface.to_string(),
                ],
            );
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self.backend {
            Backend::Kernel => "kernel",
            _ => "userspace",
        }
    }

    fn apply(&self, update: DeviceUpdate) -> Result<()> {
        if self.userspace.is_some() {
            // Same process as the control socket's server: do not block a
            // runtime thread on it.
            let iface = self.iface;
            let backend = self.backend;
            tokio::task::block_in_place(move || update.apply(&iface, backend))?;
            Ok(())
        } else {
            update.apply(&self.iface, self.backend)?;
            Ok(())
        }
    }

    /// Admits a key with its IPv4 tunnel address, and the IPv6 one that goes
    /// with it when this node carries IPv6: a client can send from those and
    /// nothing else.
    pub fn add_peer(&self, public_key: &str, ip: Ipv4Addr) -> Result<()> {
        let key = Key::from_base64(public_key.trim()).map_err(|_| anyhow!("invalid public key"))?;
        let mut peer = PeerConfigBuilder::new(&key)
            .replace_allowed_ips()
            .add_allowed_ip(IpAddr::V4(ip), 32);
        if let Some(n) = self.v6 {
            peer = peer.add_allowed_ip(IpAddr::V6(n.address_for(ip)), 128);
        }
        self.apply(DeviceUpdate::new().add_peer(peer))
            .context("adding the peer")
    }

    pub fn remove_peer(&self, public_key: &str) -> Result<()> {
        let key = Key::from_base64(public_key.trim()).map_err(|_| anyhow!("invalid public key"))?;
        self.apply(DeviceUpdate::new().remove_peer_by_key(&key))
            .context("removing the peer")
    }

    /// Per-peer handshake age and byte counts, by public key. Endpoints are
    /// deliberately not returned: a client's address is nobody's business.
    pub fn peer_stats(&self) -> Result<HashMap<String, PeerStats>> {
        let dev = Device::get(&self.iface, self.backend)?;
        let now = SystemTime::now();
        Ok(dev
            .peers
            .into_iter()
            .map(|p| {
                let last = p
                    .stats
                    .last_handshake_time
                    .and_then(|t| now.duration_since(t).ok());
                (
                    p.config.public_key.to_base64(),
                    PeerStats {
                        last_handshake: last,
                        rx_bytes: p.stats.rx_bytes,
                        tx_bytes: p.stats.tx_bytes,
                    },
                )
            })
            .collect())
    }

    pub fn tear_down(mut self) {
        match self.backend {
            Backend::Kernel => {
                if let Ok(d) = Device::get(&self.iface, Backend::Kernel) {
                    let _ = d.delete();
                }
            }
            _ => {
                if let Some(dev) = self.userspace.take() {
                    dev.stop();
                }
            }
        }
    }
}

pub async fn bring_up(
    cfg: &NodeConfig,
    net: &TunnelNet,
    net6: Option<TunnelNet6>,
) -> Result<WgDevice> {
    WgDevice::bring_up(cfg, net, net6).await
}

pub fn open_existing(name: &str, net6: Option<TunnelNet6>) -> Result<WgDevice> {
    WgDevice::open_existing(name, net6)
}

/// Whether the interface holds this IPv6 address.
fn interface_has(name: &str, addr: std::net::Ipv6Addr) -> bool {
    std::process::Command::new("ip")
        .args(["-6", "-o", "address", "show", "dev", name])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split_whitespace()
                .any(|w| w.split('/').next() == Some(&addr.to_string()))
        })
        .unwrap_or(false)
}
