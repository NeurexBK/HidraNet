//! The tunnel: WireGuard keys and configuration, the data plane that moves
//! packets between the TUN interface and the node, and the client-side network
//! configuration (routes and DNS) that sends the whole machine through it.
//! A circuit puts one or two tunnels together: one hop (Rápido) or two
//! (Privado), nested by routing. Each node is shown a key derived for it
//! from the client's one master key, so no two nodes see the same key. A
//! pocket holds the nodes a client may pick from.
//!
//! Nothing here logs an address, a name looked up, or a byte of traffic.

pub mod circuit;
pub mod config;
pub mod keys;
pub mod killswitch;
pub mod netcfg;
pub mod pocket;
pub mod random;
pub mod tunnel;

pub use circuit::{Circuit, CircuitOptions, CircuitSpec, CircuitStatus, HopStatus, Mode, Role};
pub use config::{ClientConfig, Invite};
pub use keys::ClientKey;
pub use pocket::{Pick, Pocket, Slot};
pub use tunnel::{Tunnel, TunnelStatus};
