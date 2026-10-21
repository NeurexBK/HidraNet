use std::net::SocketAddr;

use base64::Engine as _;
use tracing::warn;

use crate::config::RelayInfo;
use crate::error::{HidraError, Result};
use crate::p2p::dht::descriptor::VerifiedRelay;

/// The relays the operator listed in the configuration, each pinned to the
/// X25519 key written next to it.
///
/// An entry without a key is skipped, with a warning: a circuit through it
/// could not tell the relay from anyone else answering at that address. An
/// entry whose address or key does not parse is an error, since that is a
/// typo the operator needs to see.
pub fn load_relay_list(relays: &[RelayInfo]) -> Result<Vec<VerifiedRelay>> {
    let mut entries = Vec::with_capacity(relays.len());

    for r in relays {
        if r.noise_pubkey.trim().is_empty() {
            warn!(name = %r.name, "configured relay has no noise_pubkey; skipped");
            continue;
        }
        let addr: SocketAddr = r
            .addr
            .parse()
            .map_err(|e| HidraError::Relay(format!("invalid relay addr for '{}': {e}", r.name)))?;
        let key: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(r.noise_pubkey.trim())
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| {
                HidraError::Relay(format!(
                    "noise_pubkey for '{}' is not a base64 32-byte key",
                    r.name
                ))
            })?;
        entries.push(VerifiedRelay::pinned(addr, key));
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(addr: &str, key: &str) -> RelayInfo {
        RelayInfo {
            name: "r".into(),
            addr: addr.into(),
            noise_pubkey: key.into(),
        }
    }

    #[test]
    fn a_relay_without_a_key_is_never_used() {
        let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let list = load_relay_list(&[
            info("198.51.100.1:9001", ""),
            info("198.51.100.2:9001", &key),
        ])
        .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].transport_key(), &[9u8; 32]);
        assert!(load_relay_list(&[info("198.51.100.2:9001", "c2hvcnQ=")]).is_err());
    }
}
