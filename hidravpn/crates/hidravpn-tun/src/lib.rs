//! The TUN interface, one per operating system.
//!
//! Everything above this crate reads and writes IP packets; this is the only
//! place that knows how the operating system hands them over. Linux uses
//! `/dev/net/tun`, macOS a `utun`, Windows the Wintun driver — the driver
//! itself is Microsoft-signed and is loaded from `wintun.dll` beside the
//! executable at run time, so no driver is installed by us.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use anyhow::{Context, Result};
pub use tun_rs::AsyncDevice;

/// What the interface should look like once it is up.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Interface name. On Windows this is also the adapter's display name.
    pub name: String,
    /// The tunnel's address and prefix length, inside the node's subnet.
    pub ipv4: (Ipv4Addr, u8),
    /// Optional IPv6 address inside the tunnel.
    pub ipv6: Option<(Ipv6Addr, u8)>,
    /// 1420 leaves room for the WireGuard and UDP/IP headers on a 1500 link.
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "hvpn0".into(),
            ipv4: (Ipv4Addr::new(10, 77, 0, 2), 16),
            ipv6: None,
            mtu: 1420,
        }
    }
}

/// Opens the interface, assigns its address and brings it up. Needs
/// administrator rights on every platform; the error says so when they are
/// missing rather than failing somewhere less obvious later.
pub fn open(cfg: &TunConfig) -> Result<Arc<AsyncDevice>> {
    let mut b = tun_rs::DeviceBuilder::new()
        .name(cfg.name.clone())
        .mtu(cfg.mtu)
        .ipv4(cfg.ipv4.0, cfg.ipv4.1, None);
    if let Some((addr, prefix)) = cfg.ipv6 {
        b = b.ipv6(addr, prefix);
    }
    #[cfg(windows)]
    {
        // The lowest metric, so the system prefers this adapter's routes and
        // DNS over the physical adapter's while the tunnel is up.
        b = b.metric(1).description("HidraVPN tunnel".to_string());
    }
    let dev = b.enable(true).build_async().with_context(|| {
        format!(
            "could not create the tunnel interface \"{}\" (this needs administrator rights{})",
            cfg.name,
            if cfg!(windows) {
                "; on Windows wintun.dll must sit beside hidravpn.exe"
            } else {
                ""
            }
        )
    })?;
    Ok(Arc::new(dev))
}

/// The name the system gave the interface; on Linux it may differ from the
/// one asked for if that was taken.
pub fn name(dev: &AsyncDevice) -> Result<String> {
    dev.name()
        .context("could not read the tunnel interface's name")
}
