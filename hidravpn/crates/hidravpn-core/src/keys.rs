//! The client's WireGuard key pair.
//!
//! In this phase the key is static: the node admits a public key and the
//! client keeps the matching secret. Once passes exist (phase 5) the client
//! will use a fresh key for every connection, registered when it presents a
//! pass, so that no node ever sees the same key twice.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};

pub struct ClientKey {
    secret: StaticSecret,
}

impl ClientKey {
    /// A new random key, from the operating system's randomness.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness available: {e}"))?;
        Ok(Self {
            secret: StaticSecret::from(bytes),
        })
    }

    pub fn from_base64(s: &str) -> Result<Self> {
        let bytes = decode32(s.trim()).context("the client key is not a valid WireGuard key")?;
        Ok(Self {
            secret: StaticSecret::from(bytes),
        })
    }

    pub fn secret_base64(&self) -> String {
        B64.encode(self.secret.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn public_base64(&self) -> String {
        B64.encode(self.public().as_bytes())
    }

    pub(crate) fn secret(&self) -> StaticSecret {
        self.secret.clone()
    }

    /// The secret itself, for a WireGuard device that is not the client's.
    pub fn into_secret(self) -> StaticSecret {
        self.secret
    }
}

/// A peer's public key from its base64 form, as WireGuard tools print it.
pub fn public_key_from_base64(s: &str) -> Result<PublicKey> {
    Ok(PublicKey::from(
        decode32(s.trim()).context("not a valid WireGuard public key")?,
    ))
}

fn decode32(s: &str) -> Result<[u8; 32]> {
    let v = B64.decode(s)?;
    let arr: [u8; 32] = v
        .try_into()
        .map_err(|_| anyhow!("a WireGuard key is 32 bytes"))?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_base64() {
        let k = ClientKey::generate().unwrap();
        let again = ClientKey::from_base64(&k.secret_base64()).unwrap();
        assert_eq!(k.public_base64(), again.public_base64());
        assert_eq!(
            public_key_from_base64(&k.public_base64()).unwrap(),
            k.public()
        );
    }

    #[test]
    fn two_keys_differ() {
        assert_ne!(
            ClientKey::generate().unwrap().public_base64(),
            ClientKey::generate().unwrap().public_base64()
        );
    }

    #[test]
    fn a_bad_key_is_refused() {
        assert!(ClientKey::from_base64("not a key").is_err());
        assert!(public_key_from_base64("AAAA").is_err());
    }
}
