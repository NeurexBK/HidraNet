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

use crate::config::{NodeConfig, TunnelNet};
use crate::userspace::{socket_path, UserspaceDevice};

pub struct WgDevice {
    iface: InterfaceName,
    backend: Backend,
    userspace: Option<UserspaceDevice>,
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
    /// Creates and configures the interface for this node.
    pub async fn bring_up(cfg: &NodeConfig, net: &TunnelNet) -> Result<Self> {
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
                Ok(Self {
                    iface,
                    backend: Backend::Kernel,
                    userspace: None,
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
                Ok(Self {
                    iface,
                    backend: Backend::Userspace,
                    userspace: Some(dev),
                })
            }
        }
    }

    /// Talks to the interface a running node created, from another process.
    pub fn open_existing(name: &str) -> Result<Self> {
        let iface =
            InterfaceName::from_str(name).map_err(|e| anyhow!("bad interface name: {e}"))?;
        let backend = if socket_path(name).exists() {
            Backend::Userspace
        } else {
            Backend::Kernel
        };
        Device::get(&iface, backend).map_err(|e| anyhow!("no running node on {name}: {e}"))?;
        Ok(Self {
            iface,
            backend,
            userspace: None,
        })
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

    pub fn add_peer(
        &self,
        public_key: &str,
        ip: Ipv4Addr,
        preshared_key: Option<&str>,
    ) -> Result<()> {
        let key = Key::from_base64(public_key.trim()).map_err(|_| anyhow!("invalid public key"))?;
        let mut peer = PeerConfigBuilder::new(&key)
            .replace_allowed_ips()
            .add_allowed_ip(IpAddr::V4(ip), 32);
        if let Some(psk) = preshared_key {
            let psk =
                Key::from_base64(psk.trim()).map_err(|_| anyhow!("invalid pre-shared key"))?;
            peer = peer.set_preshared_key(psk);
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

pub async fn bring_up(cfg: &NodeConfig, net: &TunnelNet) -> Result<WgDevice> {
    WgDevice::bring_up(cfg, net).await
}

pub fn open_existing(name: &str) -> Result<WgDevice> {
    WgDevice::open_existing(name)
}
