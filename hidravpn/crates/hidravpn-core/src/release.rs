//! The release key: the one Ed25519 public key that says "this came from
//! HidraVPN's maintainers". `hidravpn-sign` signs release files and signed
//! node lists with its secret half, on a machine that is offline; this is the
//! public half, embedded here and in the browser so that what verifies a file
//! never comes from the same place as the file.
//!
//! Both keys exist and their public halves are embedded below. A build whose
//! constant is empty verifies nothing and refuses everything: a client that
//! accepted unsigned node lists "for now" would be a client that accepts
//! unsigned node lists.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Base64 of the 32-byte public key, exactly as `hidravpn-sign keygen` printed
/// it. Keep it identical to RELEASE_PUBLIC_KEY in
/// hidravpn/browser/src/main/release-verify.js; a test checks the two match.
pub const RELEASE_PUBLIC_KEY_B64: &str = "denZsjS2YtKOo4LRIGGTaKuHIWDFigChoLa71o0jBq8=";

/// The key that signs node lists: a different one, so the release key can
/// stay in a drawer while lists are made every few weeks, and so losing the
/// list key costs a release, not every installed client. Base64, exactly as
/// `hidravpn-sign keygen` printed it. `scripts/embed-release-key.sh` writes
/// both constants.
pub const LIST_PUBLIC_KEY_B64: &str = "0HfVyf5QtcUjBQSvRYQNeirD/I0432RnmlKQ+/gmNkk=";

/// A key that can check a signature; never one that can make one.
#[derive(Debug, Clone)]
pub struct ReleaseKey(VerifyingKey);

impl ReleaseKey {
    /// The release key this build carries, if it carries one.
    pub fn embedded() -> Option<ReleaseKey> {
        Self::from_constant(RELEASE_PUBLIC_KEY_B64)
    }

    /// The list-signing key this build carries, if it carries one.
    pub fn embedded_list_key() -> Option<ReleaseKey> {
        Self::from_constant(LIST_PUBLIC_KEY_B64)
    }

    fn from_constant(b64: &str) -> Option<ReleaseKey> {
        if b64.trim().is_empty() {
            None
        } else {
            ReleaseKey::from_base64(b64).ok()
        }
    }

    pub fn from_base64(b64: &str) -> Result<ReleaseKey> {
        let bytes: [u8; 32] = B64
            .decode(b64.trim())
            .context("the public key is not base64")?
            .try_into()
            .map_err(|_| anyhow!("a public key is 32 bytes"))?;
        Ok(ReleaseKey(
            VerifyingKey::from_bytes(&bytes).context("not a valid Ed25519 public key")?,
        ))
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0.to_bytes())
    }

    /// Checks `signature_b64` (what `hidravpn-sign sign` writes to FILE.sig)
    /// against `data` (the bytes of FILE, exactly as signed).
    pub fn verify(&self, data: &[u8], signature_b64: &str) -> Result<()> {
        let bytes: [u8; 64] = B64
            .decode(signature_b64.trim())
            .context("the signature is not base64")?
            .try_into()
            .map_err(|_| anyhow!("a signature is 64 bytes"))?;
        let sig = Signature::from_bytes(&bytes);
        self.0
            .verify(data, &sig)
            .map_err(|_| anyhow!("the signature does not match: the file was changed, or was not signed with the release key"))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    //! A signing key for tests only; the real one never comes near this code.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub struct TestSigner(SigningKey);

    impl TestSigner {
        pub fn new() -> Self {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).unwrap();
            TestSigner(SigningKey::from_bytes(&seed))
        }
        pub fn public(&self) -> ReleaseKey {
            ReleaseKey(self.0.verifying_key())
        }
        /// What `hidravpn-sign sign` would write beside the file.
        pub fn sign(&self, data: &[u8]) -> String {
            B64.encode(self.0.sign(data).to_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::TestSigner;
    use super::*;

    #[test]
    fn a_signature_verifies_and_a_changed_byte_or_another_key_does_not() {
        let signer = TestSigner::new();
        let key = signer.public();
        let data = b"{\"version\":1}";
        let sig = signer.sign(data);
        key.verify(data, &sig).unwrap();
        key.verify(b"{\"version\":2}", &sig).unwrap_err();
        TestSigner::new().public().verify(data, &sig).unwrap_err();
        // The key survives the round trip the browser and the docs use.
        let again = ReleaseKey::from_base64(&key.to_base64()).unwrap();
        again.verify(data, &sig).unwrap();
    }

    #[test]
    fn garbage_is_refused_with_a_reason_never_a_panic() {
        let key = TestSigner::new().public();
        assert!(key.verify(b"x", "not base64!!").is_err());
        assert!(key.verify(b"x", &B64.encode([0u8; 63])).is_err());
        assert!(key.verify(b"x", "").is_err());
        assert!(ReleaseKey::from_base64("short").is_err());
        assert!(ReleaseKey::from_base64(&B64.encode([0u8; 31])).is_err());
    }

    #[test]
    fn an_embedded_key_is_either_absent_or_a_real_key() {
        // Set by scripts/embed-release-key.sh; a constant that is set must
        // parse, or every verification would fail
        // for a reason nobody would spot.
        for (name, c, k) in [
            ("release", RELEASE_PUBLIC_KEY_B64, ReleaseKey::embedded()),
            ("list", LIST_PUBLIC_KEY_B64, ReleaseKey::embedded_list_key()),
        ] {
            if c.trim().is_empty() {
                assert!(k.is_none(), "{name}");
            } else {
                assert!(k.is_some(), "the embedded {name} key does not parse");
                assert_eq!(k.unwrap().to_base64(), c.trim(), "{name}");
            }
        }
    }
}
