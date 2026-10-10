//! Encryption at rest for the secrets in the keys directory.
//!
//! File permissions keep other accounts out of a running machine. They do
//! nothing for the machine itself: a stolen laptop, a disk pulled from a
//! seized server, a backup copied to object storage, a snapshot of a VM. In
//! all of those the keys directory is just bytes, and for a relay those bytes
//! are the node's identity — whoever holds them can be that relay, publish
//! its descriptor and accept its traffic. For a hidden service they *are* the
//! service, because the address is the public key.
//!
//! So a secret can be stored under a passphrase. Set `HIDRA_KEY_PASSPHRASE`
//! and the file on disk becomes
//!
//! ```text
//! hidrakey1:<base64(salt ‖ nonce ‖ ciphertext ‖ tag)>
//! ```
//!
//! with the key from Argon2id and the sealing from XChaCha20-Poly1305. The
//! passphrase itself is never written anywhere.
//!
//! Without the variable, secrets stay in the clear as they were. That is a
//! deliberate choice rather than an oversight: a relay is a daemon that has
//! to come back up after a reboot without a human present, and a passphrase
//! baked into a unit file or a Docker environment is theatre. What matters is
//! that the choice is visible, so the node says which mode it is in at
//! startup, and it migrates in either direction on its own: a plaintext key
//! is sealed the first time it loads with a passphrase set, and a sealed key
//! refuses to load without one instead of silently regenerating an identity.
//!
//! Argon2id is at 64 MiB and 3 passes — the same cost as a chat room key.
//! Node startup happens once, so there is no reason to be cheap about it, and
//! anyone holding the file can otherwise try passphrases as fast as their
//! hardware allows.

use std::path::Path;

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{HidraError, Result};

/// Marks a sealed file, and pins the parameters it was sealed with. A second
/// format would get its own prefix rather than a flag inside the ciphertext.
const MAGIC: &str = "hidrakey1:";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24; // XChaCha20
const KEY_LEN: usize = 32;

const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 1;

/// The environment variable holding the passphrase, or `None`.
///
/// Read fresh each time rather than cached, so a process that clears it after
/// startup actually stops being able to unseal.
pub fn passphrase() -> Option<String> {
    match std::env::var("HIDRA_KEY_PASSPHRASE") {
        Ok(p) if !p.is_empty() => Some(p),
        _ => None,
    }
}

/// True when this file is sealed, whatever we hold.
pub fn is_sealed(contents: &str) -> bool {
    contents.trim_start().starts_with(MAGIC)
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_PASSES, ARGON_LANES, Some(KEY_LEN))
        .map_err(|e| HidraError::KeyManagement(format!("argon2 parameters: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| HidraError::KeyManagement(format!("argon2: {e}")))?;
    Ok(key)
}

/// Seal `plaintext` under `passphrase`, returning the file's contents.
///
/// The magic prefix is authenticated as associated data, so a sealed file
/// cannot be passed off as a different format by editing the prefix.
pub fn seal(passphrase: &str, plaintext: &[u8]) -> Result<String> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| HidraError::KeyManagement(format!("cipher: {e}")))?;
    key.zeroize();

    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext, aad: MAGIC.as_bytes() },
        )
        .map_err(|_| HidraError::KeyManagement("sealing the key failed".into()))?;

    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(format!("{MAGIC}{}", BASE64.encode(&blob)))
}

/// Unseal a file written by [`seal`].
pub fn unseal(passphrase: &str, contents: &str) -> Result<Vec<u8>> {
    let body = contents
        .trim()
        .strip_prefix(MAGIC)
        .ok_or_else(|| HidraError::KeyManagement("not a sealed key file".into()))?;

    let blob = BASE64
        .decode(body.trim())
        .map_err(|e| HidraError::KeyManagement(format!("sealed key is not base64: {e}")))?;

    if blob.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(HidraError::KeyManagement("sealed key is truncated".into()));
    }

    let (salt, rest) = blob.split_at(SALT_LEN);
    let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);

    let mut key = derive(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| HidraError::KeyManagement(format!("cipher: {e}")))?;
    key.zeroize();

    cipher
        .decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload { msg: ciphertext, aad: MAGIC.as_bytes() },
        )
        // Wrong passphrase and tampered file are the same failure here, and
        // saying which would tell someone holding the file whether a guess
        // was close.
        .map_err(|_| {
            HidraError::KeyManagement(
                "could not unseal the key: wrong HIDRA_KEY_PASSPHRASE, or the file \
                 has been altered"
                    .into(),
            )
        })
}

/// Write a secret, sealed when a passphrase is set and in the clear when not.
pub fn write_secret(path: &Path, plaintext: &[u8]) -> Result<()> {
    match passphrase() {
        Some(p) => {
            let sealed = seal(&p, plaintext)?;
            super::keys::write_private_file(path, sealed.as_bytes())
        }
        None => super::keys::write_private_file(path, plaintext),
    }
}

/// Read a secret, unsealing it when it is sealed.
///
/// Also carries the two mismatches between what is on disk and what is held,
/// because both are worth being loud about:
///
/// - sealed file, no passphrase: fail. Falling through to "generate a new
///   identity" would strand a relay's reputation and lose a hidden service's
///   address, which is the kind of data loss that looks like a bug for weeks.
/// - plaintext file, passphrase set: unseal nothing, and report that it wants
///   migrating. The caller does the rewriting, since only it knows whether
///   the file is one it is allowed to rewrite.
pub fn read_secret(path: &Path) -> Result<SecretRead> {
    let contents = std::fs::read_to_string(path)?;
    let sealed = is_sealed(&contents);

    match (sealed, passphrase()) {
        (true, Some(p)) => Ok(SecretRead {
            plaintext: unseal(&p, &contents)?,
            needs_sealing: false,
        }),
        (true, None) => Err(HidraError::KeyManagement(format!(
            "{} is sealed but HIDRA_KEY_PASSPHRASE is not set. Set it to the \
             passphrase this node was started with; deleting the file would \
             give this node a new identity and, for a hidden service, a new \
             address.",
            path.display()
        ))),
        (false, Some(_)) => Ok(SecretRead {
            plaintext: contents.trim().as_bytes().to_vec(),
            needs_sealing: true,
        }),
        (false, None) => Ok(SecretRead {
            plaintext: contents.trim().as_bytes().to_vec(),
            needs_sealing: false,
        }),
    }
}

pub struct SecretRead {
    /// The file's contents as they were before sealing — still base64 of the
    /// raw key, which is what the callers already parse.
    pub plaintext: Vec<u8>,
    /// A passphrase is set and this file was not sealed yet.
    pub needs_sealing: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_key_comes_back_unchanged() {
        let plaintext = b"c29tZSBrZXkgbWF0ZXJpYWw=";
        let sealed = seal("correct horse", plaintext).unwrap();
        assert!(is_sealed(&sealed));
        assert_eq!(unseal("correct horse", &sealed).unwrap(), plaintext);
    }

    #[test]
    fn the_plaintext_is_not_in_the_file() {
        let plaintext = b"c29tZSBrZXkgbWF0ZXJpYWw=";
        let sealed = seal("pw", plaintext).unwrap();
        assert!(!sealed.contains("c29tZSBrZXkgbWF0ZXJpYWw"));
    }

    #[test]
    fn the_wrong_passphrase_is_refused() {
        let sealed = seal("right", b"secret").unwrap();
        assert!(unseal("wrong", &sealed).is_err());
    }

    #[test]
    fn a_flipped_bit_is_refused() {
        let sealed = seal("pw", b"secret").unwrap();
        let body = sealed.strip_prefix(MAGIC).unwrap();
        let mut blob = BASE64.decode(body).unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        let tampered = format!("{MAGIC}{}", BASE64.encode(&blob));
        assert!(unseal("pw", &tampered).is_err());
    }

    #[test]
    fn two_seals_of_the_same_key_differ() {
        // Fresh salt and nonce each time, so a file does not reveal that the
        // key is unchanged across two writes.
        let a = seal("pw", b"secret").unwrap();
        let b = seal("pw", b"secret").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn the_prefix_is_authenticated() {
        let sealed = seal("pw", b"secret").unwrap();
        // Re-labelling a sealed file must not unseal under the new label.
        let relabelled = sealed.replace(MAGIC, "hidrakey9:");
        assert!(unseal("pw", &relabelled).is_err());
    }

    #[test]
    fn a_truncated_file_is_refused_rather_than_panicking() {
        assert!(unseal("pw", &format!("{MAGIC}AAAA")).is_err());
        assert!(unseal("pw", MAGIC).is_err());
        assert!(unseal("pw", "not sealed at all").is_err());
    }

    #[test]
    fn plaintext_is_not_mistaken_for_sealed() {
        assert!(!is_sealed("c29tZSBrZXkgbWF0ZXJpYWw="));
        assert!(is_sealed("hidrakey1:AAAA"));
        assert!(is_sealed("  hidrakey1:AAAA"));
    }
}
