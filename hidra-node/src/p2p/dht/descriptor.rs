//! A hidden service's descriptor, signed by the service's own key.
//!
//! A `.hidra` address is the BLAKE3 of the service's Ed25519 public key, and
//! the descriptor says where the service can be reached (its introduction
//! points). Before, whoever answered a lookup could put any introduction
//! points next to the right public key; now the descriptor carries the
//! service's signature over its address, key, revision and introduction
//! points, so a node in the lookup path can withhold a descriptor or replay
//! an older one, and nothing else. Lookups ask several disjoint paths and keep
//! the highest revision they can verify.

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

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

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
