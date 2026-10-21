//! Descriptors: what a service or a relay says about itself, signed with its
//! own key.
//!
//! # Service descriptors
//!
//! A `.hidra` address is the BLAKE3 of the service's Ed25519 public key, and
//! the descriptor says where the service can be reached (its introduction
//! points). Before, whoever answered a lookup could put any introduction
//! points next to the right public key; now the descriptor carries the
//! service's signature over its address, key, revision and introduction
//! points, so a node in the lookup path can withhold a descriptor or replay
//! an older one, and nothing else. Lookups ask several disjoint paths and keep
//! the highest revision they can verify.
//!
//! # Relay descriptors
//!
//! A relay signs, with its DHT identity key, the address it serves circuits on
//! and the X25519 key it answers circuit handshakes with. A client builds a
//! hop only to a relay whose descriptor verifies, and the handshake for that
//! hop completes only with the holder of the key the descriptor names: a node
//! that answers a lookup can hide a relay, but cannot put its own key in that
//! relay's place.

use std::net::SocketAddr;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{HidraError, Result};

/// More would only be a way to make a descriptor large.
pub const MAX_INTRO_POINTS: usize = 8;

const DOMAIN: &[u8] = b"hidra/service-descriptor/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDescriptor {
    pub service_pubkey: [u8; 32],
    pub intro_points: Vec<SocketAddr>,
    /// Larger is newer: the signer's clock in seconds when it signed.
    pub revision: u64,
    pub signature: Vec<u8>,
}

/// Where in the key space a service's descriptor lives: the nodes closest to
/// this ID store it.
pub fn service_target(service_hash: &[u8; 20]) -> crate::p2p::dht::node::NodeId {
    let mut padded = [0u8; 32];
    padded[..20].copy_from_slice(service_hash);
    crate::p2p::dht::node::NodeId::from_public_key(&padded)
}

/// The address a key is published under: BLAKE3 of the key, first 20 bytes.
pub fn service_hash_of(service_pubkey: &[u8; 32]) -> [u8; 20] {
    let h = blake3::hash(service_pubkey);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.as_bytes()[..20]);
    out
}

fn signed_bytes(
    service_hash: &[u8; 20],
    service_pubkey: &[u8; 32],
    revision: u64,
    intro_points: &[SocketAddr],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(DOMAIN.len() + 64 + intro_points.len() * 24);
    b.extend_from_slice(DOMAIN);
    b.extend_from_slice(service_hash);
    b.extend_from_slice(service_pubkey);
    b.extend_from_slice(&revision.to_le_bytes());
    b.push(intro_points.len() as u8);
    for p in intro_points {
        let s = p.to_string();
        b.push(s.len() as u8);
        b.extend_from_slice(s.as_bytes());
    }
    b
}

impl ServiceDescriptor {
    /// Signs a descriptor for the service whose key this is.
    pub fn sign(service_key: &SigningKey, intro_points: Vec<SocketAddr>, revision: u64) -> Self {
        let service_pubkey = service_key.verifying_key().to_bytes();
        let hash = service_hash_of(&service_pubkey);
        let signature = service_key
            .sign(&signed_bytes(
                &hash,
                &service_pubkey,
                revision,
                &intro_points,
            ))
            .to_bytes()
            .to_vec();
        Self {
            service_pubkey,
            intro_points,
            revision,
            signature,
        }
    }

    /// Signs with the current time as the revision.
    pub fn sign_now(service_key: &SigningKey, intro_points: Vec<SocketAddr>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::sign(service_key, intro_points, now)
    }

    pub fn service_hash(&self) -> [u8; 20] {
        service_hash_of(&self.service_pubkey)
    }

    /// The descriptor is the service's: published under `expected_hash`,
    /// which is the hash of the key that signed it, with between one and
    /// MAX_INTRO_POINTS introduction points.
    pub fn verify(&self, expected_hash: &[u8; 20]) -> Result<()> {
        if &self.service_hash() != expected_hash {
            return Err(HidraError::Protocol(
                "service descriptor: the key is not the one this address names".into(),
            ));
        }
        if self.intro_points.is_empty() || self.intro_points.len() > MAX_INTRO_POINTS {
            return Err(HidraError::Protocol(
                "service descriptor: between 1 and 8 introduction points".into(),
            ));
        }
        let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            HidraError::Protocol("service descriptor: a signature is 64 bytes".into())
        })?;
        let key = VerifyingKey::from_bytes(&self.service_pubkey)
            .map_err(|_| HidraError::Protocol("service descriptor: not an Ed25519 key".into()))?;
        key.verify_strict(
            &signed_bytes(
                expected_hash,
                &self.service_pubkey,
                self.revision,
                &self.intro_points,
            ),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| {
            HidraError::Protocol("service descriptor: the service did not sign this".into())
        })
    }
}

const RELAY_DOMAIN: &[u8] = b"hidra/relay-descriptor/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDescriptor {
    /// The relay's Ed25519 identity: the key its DHT node ID is bound to.
    pub identity_key: [u8; 32],
    /// Where it accepts links.
    pub addr: SocketAddr,
    /// The X25519 static key it answers link and circuit handshakes with.
    pub transport_key: [u8; 32],
    /// The signer's clock in seconds when it signed.
    pub published: u64,
    pub signature: Vec<u8>,
}

fn relay_signed_bytes(
    identity_key: &[u8; 32],
    addr: &SocketAddr,
    transport_key: &[u8; 32],
    published: u64,
) -> Vec<u8> {
    let a = addr.to_string();
    let mut b = Vec::with_capacity(RELAY_DOMAIN.len() + 80 + a.len());
    b.extend_from_slice(RELAY_DOMAIN);
    b.extend_from_slice(identity_key);
    b.push(a.len() as u8);
    b.extend_from_slice(a.as_bytes());
    b.extend_from_slice(transport_key);
    b.extend_from_slice(&published.to_le_bytes());
    b
}

impl RelayDescriptor {
    pub fn sign(
        identity: &SigningKey,
        addr: SocketAddr,
        transport_key: [u8; 32],
        published: u64,
    ) -> Self {
        let identity_key = identity.verifying_key().to_bytes();
        let signature = identity
            .sign(&relay_signed_bytes(&identity_key, &addr, &transport_key, published))
            .to_bytes()
            .to_vec();
        Self {
            identity_key,
            addr,
            transport_key,
            published,
            signature,
        }
    }

    pub fn sign_now(identity: &SigningKey, addr: SocketAddr, transport_key: [u8; 32]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::sign(identity, addr, transport_key, now)
    }

    /// The relay signed exactly this address and this key.
    pub fn verify(&self) -> Result<VerifiedRelay> {
        let sig: [u8; 64] = self.signature.as_slice().try_into().map_err(|_| {
            HidraError::Protocol("relay descriptor: a signature is 64 bytes".into())
        })?;
        let key = VerifyingKey::from_bytes(&self.identity_key)
            .map_err(|_| HidraError::Protocol("relay descriptor: not an Ed25519 key".into()))?;
        key.verify_strict(
            &relay_signed_bytes(&self.identity_key, &self.addr, &self.transport_key, self.published),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| HidraError::Protocol("relay descriptor: the relay did not sign this".into()))?;
        Ok(VerifiedRelay {
            addr: self.addr,
            transport_key: self.transport_key,
        })
    }
}

/// A relay a circuit may use: an address and the key that must answer there.
///
/// There are two ways to get one, and no other: a relay descriptor that
/// verifies, or a key the operator of this node wrote into its configuration.
/// The circuit code takes nothing else, so a relay whose key nobody vouched
/// for cannot become a hop.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedRelay {
    addr: SocketAddr,
    transport_key: [u8; 32],
}

impl VerifiedRelay {
    /// A key pinned by whoever configured this node, not learned from the
    /// network.
    pub fn pinned(addr: SocketAddr, transport_key: [u8; 32]) -> Self {
        Self { addr, transport_key }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn transport_key(&self) -> &[u8; 32] {
        &self.transport_key
    }
}

/// Neither the address nor the key: a relay list in a log is a list of the
/// hops a user picked.
impl std::fmt::Debug for VerifiedRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedRelay(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn a_relay_descriptor_verifies_only_as_the_relay_signed_it() {
        let key = SigningKey::generate(&mut OsRng);
        let addr: SocketAddr = "198.51.100.2:9001".parse().unwrap();
        let d = RelayDescriptor::sign(&key, addr, [5; 32], 100);
        let v = d.verify().unwrap();
        assert_eq!(v.addr(), addr);
        assert_eq!(v.transport_key(), &[5; 32]);

        // Another transport key: the point of the whole thing.
        let mut swapped = d.clone();
        swapped.transport_key = [6; 32];
        assert!(swapped.verify().is_err());

        let mut moved = d.clone();
        moved.addr = "203.0.113.9:9001".parse().unwrap();
        assert!(moved.verify().is_err());

        let mut older = d.clone();
        older.published = 99;
        assert!(older.verify().is_err());

        // Re-signed by someone else but presented under the relay's identity.
        let other = SigningKey::generate(&mut OsRng);
        let mut forged = RelayDescriptor::sign(&other, addr, [6; 32], 100);
        forged.identity_key = d.identity_key;
        assert!(forged.verify().is_err());

        assert_eq!(format!("{v:?}"), "VerifiedRelay(..)");
    }

    fn intro() -> Vec<SocketAddr> {
        vec!["198.51.100.7:9001".parse().unwrap()]
    }

    #[test]
    fn a_descriptor_verifies_only_as_the_service_signed_it() {
        let key = SigningKey::generate(&mut OsRng);
        let d = ServiceDescriptor::sign(&key, intro(), 10);
        let hash = d.service_hash();
        assert!(d.verify(&hash).is_ok());

        // Other introduction points: the signature no longer covers them.
        let mut moved = d.clone();
        moved.intro_points = vec!["203.0.113.66:9001".parse().unwrap()];
        assert!(moved.verify(&hash).is_err());

        // Another revision: refused too, so a replay cannot pose as newer.
        let mut bumped = d.clone();
        bumped.revision = 11;
        assert!(bumped.verify(&hash).is_err());

        // Signed by another key but presented under this address: refused,
        // whether the other key is shown or the real one.
        let other = SigningKey::generate(&mut OsRng);
        let forged = ServiceDescriptor::sign(&other, intro(), 99);
        assert!(forged.verify(&hash).is_err());
        let mut forged_with_real_key = forged;
        forged_with_real_key.service_pubkey = d.service_pubkey;
        assert!(forged_with_real_key.verify(&hash).is_err());

        // No introduction point, or too many: refused.
        let empty = ServiceDescriptor::sign(&key, vec![], 10);
        assert!(empty.verify(&hash).is_err());
        let many = ServiceDescriptor::sign(&key, vec!["198.51.100.7:1".parse().unwrap(); 9], 10);
        assert!(many.verify(&hash).is_err());
    }
}
