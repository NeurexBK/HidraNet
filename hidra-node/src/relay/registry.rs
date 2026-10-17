use std::net::SocketAddr;

use crate::config::RelayInfo;
use crate::error::{HidraError, Result};

#[derive(Debug, Clone)]
pub struct RelayEntry {
    pub name: String,
    pub addr: SocketAddr,
    /// Base64 of the relay's `noise_static.public`. When set, the client
    /// refuses a handshake that lands on any other key; when empty, the hop
    /// is unverified and the client says so once. Relays found through the
    /// DHT arrive empty until the descriptor carries the key.
    pub noise_pubkey_b64: String,
    /// Base64 of the relay's hybrid identity, Ed25519 ‖ ML-DSA-87. When set,
    /// the relay has to prove it in message B of the handshake, which is
    /// what keeps a quantum computer from impersonating it; when empty the
    /// hop is authenticated by X25519 alone, as before.
    pub identity_pubkey_b64: String,
}

pub fn load_relay_list(relays: &[RelayInfo]) -> Result<Vec<RelayEntry>> {
    let mut entries = Vec::with_capacity(relays.len());

    for r in relays {
        let addr: SocketAddr = r
            .addr
            .parse()
            .map_err(|e| HidraError::Relay(format!("invalid relay addr '{}': {e}", r.addr)))?;

        entries.push(RelayEntry {
            name: r.name.clone(),
            addr,
            noise_pubkey_b64: r.noise_pubkey.clone(),
            identity_pubkey_b64: r.identity_pubkey.clone(),
        });
    }

    Ok(entries)
}
