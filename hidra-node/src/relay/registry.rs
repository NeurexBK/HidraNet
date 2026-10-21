use std::net::SocketAddr;

use crate::config::RelayInfo;
use crate::error::{HidraError, Result};

#[derive(Debug, Clone)]
pub struct RelayEntry {
    pub name: String,
    pub addr: SocketAddr,
    /// The relay's Noise static identity key (base64), from the trusted relay
    /// list. The client pins each hop against it so no relay carrying another
    /// hop's handshake can impersonate it.
    pub noise_pubkey_b64: String,
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
        });
    }

    Ok(entries)
}
