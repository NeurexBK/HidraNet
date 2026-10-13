//! The kill switch: while it is on, the only packets that may leave the machine
//! are the encrypted WireGuard packets to the node and the traffic that goes
//! inside the tunnel. Everything else is dropped — so if the tunnel falls, the
//! connection does not quietly fail back to the open internet; it simply stops
//! until the tunnel is back or `down` is run.
//!
//! Two leaks the ordinary routing of phase 1 could still allow are closed here:
//! IPv6 (blocked outright, since the tunnel carries only IPv4 in this phase)
//! and DNS (allowed only to the node's own resolver, never to any other server
//! the system might still be configured to ask).
//!
//! Like the rest of the client's network changes, this touches only a table of
//! our own, so removing it removes everything and nothing else on the machine
//! is disturbed. Nothing here is logged.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Result;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// What the kill switch must let through while it is on.
#[derive(Debug, Clone)]
pub struct KillConfig {
    /// The tunnel interface; all traffic on it is allowed (that is the point).
    pub interface: String,
    /// The node's WireGuard endpoint: the one address reachable off-tunnel.
    pub node_endpoint: SocketAddr,
    /// The node's resolver, the only DNS server any query may go to.
    pub dns: Ipv4Addr,
    /// Let the local subnet through as well (a printer, a NAS). Off by default:
    /// strict is safer, and phase 1 users asked for the whole machine covered.
    pub allow_lan: bool,
    /// A second tunnel interface to allow: the inner tunnel of a two-hop
    /// circuit. The only address reachable off-tunnel is still `node_endpoint`,
    /// the entry node. None for a single hop.
    pub extra_interface: Option<String>,
}

/// Turns the kill switch on. Replaces any rules a previous run left behind, so
/// it is safe to call again; returns an error, and changes nothing lasting, on
/// an operating system where it is not built yet.
pub fn apply(cfg: &KillConfig) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::apply(cfg)
    }
    #[cfg(windows)]
    {
        windows::apply(cfg)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = cfg;
        anyhow::bail!(
            "the kill switch is not built for this operating system yet (macOS comes after Linux and Windows); refusing to connect without it"
        )
    }
}

/// Holds the line while a circuit is replaced: the encrypted WireGuard
/// packets to `node_endpoints` — the first hop of the circuit coming down and
/// of the one going up — may leave, and nothing else; no tunnel interface is
/// allowed, because none is trusted yet. `apply` replaces it once the new
/// circuit is up, in one step; `remove` lifts it. So a new identity, or a
/// reconnect over a running circuit, never has a moment on the open network.
pub fn hold(node_endpoints: &[SocketAddr]) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::hold(node_endpoints)
    }
    #[cfg(windows)]
    {
        windows::hold(node_endpoints)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = node_endpoints;
        anyhow::bail!("the kill switch is not built for this operating system yet")
    }
}

/// Turns the kill switch off. Succeeds even if it was already off, so `down`
/// and cleanup can always call it.
pub fn remove() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::remove()
    }
    #[cfg(windows)]
    {
        windows::remove()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Ok(())
    }
}

/// Whether the kill switch is on right now.
pub fn is_active() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::is_active()
    }
    #[cfg(windows)]
    {
        windows::is_active()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        false
    }
}
