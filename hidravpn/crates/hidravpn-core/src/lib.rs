//! The tunnel: WireGuard keys and configuration, the data plane that moves
//! packets between the TUN interface and the node, and the client-side network
//! configuration (routes and DNS) that sends the whole machine through it.
//!
//! Nothing here logs an address, a name looked up, or a byte of traffic.

pub mod config;
pub mod killswitch;
pub mod keys;
pub mod netcfg;
pub mod tunnel;

pub use config::{ClientConfig, Invite};
pub use keys::ClientKey;
pub use tunnel::{Tunnel, TunnelStatus};
