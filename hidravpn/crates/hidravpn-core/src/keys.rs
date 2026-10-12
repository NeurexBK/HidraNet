//! The client's WireGuard keys: one master key, and one key per node derived
//! from it.
//!
//! The master key is the one secret the client keeps (`client.key`). No node
//! ever sees its public half. What a node admits is the key derived for that
//! node:
//!
//! ```text
//! node_key = HKDF-SHA256(ikm  = the 32 bytes of the master key,
//!                        salt = "HidraVPN per-node key v1",
//!                        info = the 32 raw bytes of the node's public key)
//! ```
//!
//! The derivation is deterministic, so there is nothing new to store, and
//! two nodes get two unrelated keys: an entry and an exit that compared the
//! keys they were shown would find nothing in common. Once passes exist
//! (phase 5) the client will use a fresh key for every connection instead.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use boringtun::x25519::{PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;

/// The salt of the per-node derivation. It is versioned: changing it would
/// change every derived key, and every client would need admitting again.
const PER_NODE_SALT: &[u8] = b"HidraVPN per-node key v1";

/// Clone so the two hops of a circuit can each derive their own key from it.
#[derive(Clone)]
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

    /// The key this client presents to one node, derived from this key and
    /// the node's public key. Deterministic: the same master key and the same
    /// node always give the same key, so the node admits it once. Different
    /// nodes get keys with nothing in common, and none of them is the master
    /// key itself.
    pub fn for_node(&self, node_public: &PublicKey) -> ClientKey {
        let hk = Hkdf::<Sha256>::new(Some(PER_NODE_SALT), &self.secret.to_bytes());
        let mut okm = [0u8; 32];
        hk.expand(node_public.as_bytes(), &mut okm)
            .expect("32 bytes is well within what HKDF-SHA256 can expand");
        // `StaticSecret::from` clamps the bytes as X25519 requires.
        ClientKey {
            secret: StaticSecret::from(okm),
        }
    }

    /// `for_node` from the node's public key in base64, as an invite or the
    /// node's own `pubkey` command prints it.
    pub fn for_node_base64(&self, node_public: &str) -> Result<ClientKey> {
        Ok(self.for_node(&public_key_from_base64(node_public)?))
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
        assert!(ClientKey::generate()
            .unwrap()
            .for_node_base64("not a key")
            .is_err());
    }

    #[test]
    fn the_per_node_key_is_deterministic() {
        let master = ClientKey::generate().unwrap();
        let node = ClientKey::generate().unwrap().public();
        let a = master.for_node(&node);
        let b = ClientKey::from_base64(&master.secret_base64())
            .unwrap()
            .for_node(&node);
        assert_eq!(a.public_base64(), b.public_base64());
        assert_eq!(a.secret_base64(), b.secret_base64());
        // The base64 form of the node's key gives the same derived key.
        let c = master
            .for_node_base64(&B64.encode(node.as_bytes()))
            .unwrap();
        assert_eq!(a.public_base64(), c.public_base64());
    }

    #[test]
    fn different_nodes_get_different_keys() {
        let master = ClientKey::generate().unwrap();
        let entry = ClientKey::generate().unwrap().public();
        let exit = ClientKey::generate().unwrap().public();
        assert_ne!(
            master.for_node(&entry).public_base64(),
            master.for_node(&exit).public_base64()
        );
    }

    #[test]
    fn the_derived_key_is_never_the_master_key() {
        for _ in 0..16 {
            let master = ClientKey::generate().unwrap();
            let node = ClientKey::generate().unwrap().public();
            let derived = master.for_node(&node);
            assert_ne!(derived.public_base64(), master.public_base64());
            assert_ne!(derived.secret_base64(), master.secret_base64());
            // Nor is it the key a node would derive for itself.
            assert_ne!(derived.public_base64(), B64.encode(node.as_bytes()));
        }
    }

    /// A fixed vector, so a change to the salt, the hash, the info or the
    /// clamping is caught: every admitted client would otherwise need
    /// admitting again without anyone noticing why.
    #[test]
    fn the_derivation_matches_its_fixed_vector() {
        // master = 0x01 repeated; node public = the X25519 base point (9, 0, ...).
        let master = ClientKey::from_base64(&B64.encode([0x01u8; 32])).unwrap();
        let mut node = [0u8; 32];
        node[0] = 9;
        let derived = master.for_node(&PublicKey::from(node));
        // Computed once with an independent HKDF-SHA256 implementation
        // (Python's cryptography package) and X25519 clamping, then pinned.
        assert_eq!(
            derived.secret_base64(),
            "JwEGmDsDyvshlNDOKa2uPZMhRsweGLw/nZvHUP0g3hU="
        );
        assert_eq!(
            derived.public_base64(),
            "KnZcpNZwWbvyqdErhX2Jid2OUtC5KAgA6e2ofITszi0="
        );
    }
}
