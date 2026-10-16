//! Hybrid signatures: Ed25519 and ML-DSA-87 over the same bytes, both
//! required to verify.
//!
//! Ed25519 is what every identity in HidraNet is made of today, and it falls
//! to Shor's algorithm the day a large enough quantum computer exists. A
//! signature does not have the "record now, break later" problem that key
//! exchange has — an old signature is not worth forging — but an identity is:
//! whoever can forge a node's signature on that day can be that node, publish
//! its descriptor and take over its `.hidra` names. So the identity grows a
//! post-quantum half now, while the day is far off, rather than after.
//!
//! Hybrid rather than ML-DSA alone, for the same reason the handshake is: a
//! break of either scheme leaves the other standing. A verifier accepts only
//! when both halves verify, so an attacker needs both private keys.
//!
//! Sizes, for the record: a hybrid public key is 32 + 2592 bytes and a hybrid
//! signature 64 + 4627. That is the cost of the lattice half, and it is why
//! this is used where a few kilobytes do not matter — an identity, a mail
//! envelope, a descriptor — and not on every cell.

// The library is the surface; the binary reaches only what HidraMail uses,
// and it denies warnings. The rest is here for the DHT descriptor and the
// service identity once those move to hybrid signatures.
#![allow(dead_code)]

use ed25519_dalek::{Signer as _, Verifier as _};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{HidraError, Result};

/// Context string for the ML-DSA half. ML-DSA takes one natively; it keeps a
/// signature made here from meaning anything to another protocol that
/// happens to sign the same bytes with the same key.
const DOMAIN: &[u8] = b"HidraNet-hybrid-sig-v1";

pub const ED25519_PUBLIC_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-87 encoded verifying key.
pub const MLDSA_PUBLIC_LEN: usize = 2592;
/// ML-DSA-87 encoded signature.
pub const MLDSA_SIGNATURE_LEN: usize = 4627;
pub const PUBLIC_LEN: usize = ED25519_PUBLIC_LEN + MLDSA_PUBLIC_LEN;
pub const SIGNATURE_LEN: usize = ED25519_SIGNATURE_LEN + MLDSA_SIGNATURE_LEN;

/// The ML-DSA seed. 32 bytes regenerate the whole key, so that is what goes
/// to disk rather than the expanded 4896-byte private key.
pub type PqSeed = [u8; 32];

pub struct HybridSigningKey {
    ed: ed25519_dalek::SigningKey,
    pq: ml_dsa::SigningKey<MlDsa87>,
}

#[derive(Clone)]
pub struct HybridVerifyingKey {
    ed: ed25519_dalek::VerifyingKey,
    pq: ml_dsa::VerifyingKey<MlDsa87>,
}

/// Both halves, kept apart so a protocol that already carries an Ed25519
/// signature can keep that field as it is and add the other beside it.
pub struct HybridSignature {
    pub ed25519: Vec<u8>,
    pub mldsa: Vec<u8>,
}

impl HybridSigningKey {
    pub fn generate() -> Self {
        let ed = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let mut seed: PqSeed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let key = Self::from_parts(ed, &seed);
        seed.zeroize();
        key
    }

    /// Assemble from the two secrets as they are stored: the Ed25519 key the
    /// node already had, and the ML-DSA seed beside it.
    pub fn from_parts(ed: ed25519_dalek::SigningKey, pq_seed: &PqSeed) -> Self {
        let pq = ml_dsa::SigningKey::<MlDsa87>::from_seed(&ml_dsa::Seed::from(*pq_seed));
        Self { ed, pq }
    }

    pub fn pq_seed(&self) -> PqSeed {
        let seed = self.pq.to_seed();
        let mut out = [0u8; 32];
        out.copy_from_slice(seed.as_slice());
        out
    }

    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            ed: self.ed.verifying_key(),
            pq: self.pq.expanded_key().verifying_key(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let ed25519 = self.ed.sign(message).to_bytes().to_vec();
        let pq = self
            .pq
            .expanded_key()
            .sign_deterministic(message, DOMAIN)
            .map_err(|_| HidraError::Crypto("ML-DSA signing failed".into()))?;
        Ok(HybridSignature {
            ed25519,
            mldsa: pq.encode().to_vec(),
        })
    }
}

impl HybridVerifyingKey {
    pub fn ed25519(&self) -> &ed25519_dalek::VerifyingKey {
        &self.ed
    }

    /// Ed25519 half, then the ML-DSA half.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_LEN);
        out.extend_from_slice(self.ed.as_bytes());
        out.extend_from_slice(&self.pq.encode());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_LEN {
            return Err(HidraError::Crypto(format!(
                "hybrid public key has {} bytes, not {PUBLIC_LEN}",
                bytes.len()
            )));
        }
        let (ed, pq) = bytes.split_at(ED25519_PUBLIC_LEN);
        Ok(Self {
            ed: ed25519_verifying_key(ed)?,
            pq: mldsa_verifying_key(pq)?,
        })
    }

    pub fn from_parts(ed: &[u8], pq: &[u8]) -> Result<Self> {
        Ok(Self {
            ed: ed25519_verifying_key(ed)?,
            pq: mldsa_verifying_key(pq)?,
        })
    }

    /// Accept only when both halves verify. The failures are not told apart:
    /// a caller does not need to know which scheme refused, and saying so
    /// would only help someone probing one half at a time.
    pub fn verify(&self, message: &[u8], signature: &HybridSignature) -> Result<()> {
        let ed_ok = ed25519_dalek::Signature::from_slice(&signature.ed25519)
            .map(|sig| self.ed.verify(message, &sig).is_ok())
            .unwrap_or(false);
        let pq_ok = EncodedSignature::<MlDsa87>::try_from(signature.mldsa.as_slice())
            .ok()
            .and_then(|enc| Signature::<MlDsa87>::decode(&enc))
            .map(|sig| self.pq.verify_with_context(message, DOMAIN, &sig))
            .unwrap_or(false);
        if ed_ok && pq_ok {
            Ok(())
        } else {
            Err(HidraError::Crypto("hybrid signature did not verify".into()))
        }
    }
}

impl HybridSignature {
    /// Ed25519 half, then the ML-DSA half.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.mldsa);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(HidraError::Crypto(format!(
                "hybrid signature has {} bytes, not {SIGNATURE_LEN}",
                bytes.len()
            )));
        }
        let (ed, pq) = bytes.split_at(ED25519_SIGNATURE_LEN);
        Ok(Self {
            ed25519: ed.to_vec(),
            mldsa: pq.to_vec(),
        })
    }
}

fn ed25519_verifying_key(bytes: &[u8]) -> Result<ed25519_dalek::VerifyingKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| HidraError::Crypto("Ed25519 public key must be 32 bytes".into()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|_| HidraError::Crypto("Ed25519 public key is not a valid point".into()))
}

fn mldsa_verifying_key(bytes: &[u8]) -> Result<ml_dsa::VerifyingKey<MlDsa87>> {
    let enc = EncodedVerifyingKey::<MlDsa87>::try_from(bytes).map_err(|_| {
        HidraError::Crypto(format!(
            "ML-DSA public key must be {MLDSA_PUBLIC_LEN} bytes"
        ))
    })?;
    Ok(ml_dsa::VerifyingKey::<MlDsa87>::decode(&enc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_sizes_are_the_real_ones() {
        let key = HybridSigningKey::generate();
        let sig = key.sign(b"x").unwrap();
        assert_eq!(key.verifying_key().to_bytes().len(), PUBLIC_LEN);
        assert_eq!(sig.ed25519.len(), ED25519_SIGNATURE_LEN);
        assert_eq!(sig.mldsa.len(), MLDSA_SIGNATURE_LEN);
        assert_eq!(sig.to_bytes().len(), SIGNATURE_LEN);
    }

    #[test]
    fn a_signature_verifies_and_round_trips_through_bytes() {
        let key = HybridSigningKey::generate();
        let msg = b"a descriptor, say";
        let sig = key.sign(msg).unwrap();
        let vk = HybridVerifyingKey::from_bytes(&key.verifying_key().to_bytes()).unwrap();
        vk.verify(msg, &sig).unwrap();
        vk.verify(msg, &HybridSignature::from_bytes(&sig.to_bytes()).unwrap())
            .unwrap();
    }

    /// Neither half alone is enough. This is the property that makes the
    /// construction hybrid rather than two signatures stapled together: an
    /// attacker holding one private key, by a quantum computer or a bug in
    /// one scheme, still cannot produce an acceptable signature.
    #[test]
    fn breaking_one_half_is_not_enough() {
        let key = HybridSigningKey::generate();
        let vk = key.verifying_key();
        let msg = b"message";
        let good = key.sign(msg).unwrap();

        let mut ed_broken = HybridSignature {
            ed25519: good.ed25519.clone(),
            mldsa: good.mldsa.clone(),
        };
        ed_broken.ed25519[10] ^= 1;
        assert!(vk.verify(msg, &ed_broken).is_err());

        let mut pq_broken = HybridSignature {
            ed25519: good.ed25519.clone(),
            mldsa: good.mldsa.clone(),
        };
        pq_broken.mldsa[100] ^= 1;
        assert!(vk.verify(msg, &pq_broken).is_err());

        // The right Ed25519 signature with another key's ML-DSA signature.
        let other = HybridSigningKey::generate();
        let mixed = HybridSignature {
            ed25519: good.ed25519.clone(),
            mldsa: other.sign(msg).unwrap().mldsa,
        };
        assert!(vk.verify(msg, &mixed).is_err());
    }

    #[test]
    fn a_different_message_is_refused() {
        let key = HybridSigningKey::generate();
        let sig = key.sign(b"one").unwrap();
        assert!(key.verifying_key().verify(b"two", &sig).is_err());
    }

    #[test]
    fn the_seed_regenerates_the_same_key() {
        let key = HybridSigningKey::generate();
        let seed = key.pq_seed();
        let ed = ed25519_dalek::SigningKey::from_bytes(&key.ed.to_bytes());
        let again = HybridSigningKey::from_parts(ed, &seed);
        assert_eq!(
            key.verifying_key().to_bytes(),
            again.verifying_key().to_bytes()
        );
        let sig = key.sign(b"m").unwrap();
        again.verifying_key().verify(b"m", &sig).unwrap();
    }

    #[test]
    fn malformed_keys_and_signatures_are_refused_not_panicked_on() {
        assert!(HybridVerifyingKey::from_bytes(&[0u8; 10]).is_err());
        assert!(HybridVerifyingKey::from_bytes(&[0u8; PUBLIC_LEN + 1]).is_err());
        assert!(HybridSignature::from_bytes(&[0u8; 5]).is_err());
        let key = HybridSigningKey::generate();
        let short = HybridSignature {
            ed25519: vec![0u8; 3],
            mldsa: vec![0u8; 3],
        };
        assert!(key.verifying_key().verify(b"m", &short).is_err());
    }
}
