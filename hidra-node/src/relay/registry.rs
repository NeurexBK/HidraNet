use std::net::SocketAddr;

use crate::config::RelayInfo;
use crate::error::{HidraError, Result};

#[derive(Debug, Clone)]
pub struct RelayEntry {
    pub name: String,
    pub addr: SocketAddr,
    // Read by the library's consumers, not by the binary, which resolves a
    // relay's static key from the DHT descriptor instead of the config file.
    #[allow(dead_code)]
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
