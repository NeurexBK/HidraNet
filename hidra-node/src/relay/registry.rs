use std::net::SocketAddr;

use base64::Engine as _;

use crate::config::RelayInfo;
use crate::error::{HidraError, Result};

#[derive(Debug, Clone)]
pub struct RelayEntry {
    pub name: String,
    pub addr: SocketAddr,
    // Optional base64-encoded X25519 static key, checked by both client paths.
    // An empty key preserves the existing unpinned discovery mode.
    pub noise_pubkey_b64: String,
}

impl RelayEntry {
    /// Decode the configured X25519 key, or return None for an unpinned relay.
    pub fn expected_noise_key(&self) -> Result<Option<[u8; 32]>> {
        if self.noise_pubkey_b64.is_empty() {
            return Ok(None);
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.noise_pubkey_b64)
            .map_err(|_| HidraError::Relay("invalid relay public key encoding".into()))?;
        let key = bytes.try_into().map_err(|_| {
            HidraError::Relay("relay public key must contain exactly 32 bytes".into())
        })?;
        Ok(Some(key))
    }
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
