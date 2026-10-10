use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

use crate::error::{HidraError, Result};

pub struct NodeKeys {
    pub identity_signing: SigningKey,
    pub identity_verifying: ed25519_dalek::VerifyingKey,
    pub noise_static_secret: StaticSecret,
    pub noise_static_public: X25519Public,
    pub node_id: String,
}

/// Create a file only this user can read, and never widen it even for an
/// instant.
///
/// `fs::write` creates with the process umask — 0644 on a normal system — and
/// a `set_permissions` afterwards closes the window only after it has been
/// open. Anything that reads the file in between, from another account on a
/// shared machine to a backup agent that happens to run right then, gets the
/// key. The mode goes on at `open(2)` instead, so the file is never readable
/// by anyone else at any point in its life.
pub fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        restrict_dir(parent)?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    // The bytes are on disk before we say they are. A key half-written by a
    // process that then died is a node that will not start.
    file.sync_all()?;

    // An existing file keeps the mode it already had, so set it as well.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Keep the keys directory itself to its owner. Without this the directory is
/// 0755: the files inside cannot be read, but their names, sizes and
/// modification times can, which tells a local attacker exactly which node
/// this is and when it last rotated anything.
pub fn restrict_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

impl NodeKeys {
    pub fn generate() -> Self {
        let identity_signing = SigningKey::generate(&mut OsRng);
        let identity_verifying = identity_signing.verifying_key();
        let noise_static_secret = StaticSecret::random_from_rng(OsRng);
        let noise_static_public = X25519Public::from(&noise_static_secret);
        let node_id = derive_node_id(&identity_verifying);

        Self {
            identity_signing,
            identity_verifying,
            noise_static_secret,
            noise_static_public,
            node_id,
        }
    }

    pub fn load_or_generate(keys_dir: &Path) -> Result<Self> {
        if keys_dir.join("identity.secret").exists() {
            Self::load(keys_dir)
        } else {
            let keys = Self::generate();
            keys.save(keys_dir)?;
            Ok(keys)
        }
    }

    pub fn save(&self, keys_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(keys_dir)?;
        restrict_dir(keys_dir)?;

        // The two secrets are created 0600 at open(2). They used to be
        // written with fs::write and chmodded afterwards, which left them
        // world-readable for as long as that took.
        write_private_file(
            &keys_dir.join("identity.secret"),
            BASE64.encode(self.identity_signing.to_bytes()).as_bytes(),
        )?;
        write_private_file(
            &keys_dir.join("noise_static.secret"),
            BASE64.encode(self.noise_static_secret.to_bytes()).as_bytes(),
        )?;

        // The public halves are published to the network anyway.
        std::fs::write(
            keys_dir.join("identity.public"),
            BASE64.encode(self.identity_verifying.to_bytes()),
        )?;
        std::fs::write(
            keys_dir.join("noise_static.public"),
            BASE64.encode(self.noise_static_public.to_bytes()),
        )?;

        Ok(())
    }

    pub fn load(keys_dir: &Path) -> Result<Self> {
        let identity_secret_b64 =
            std::fs::read_to_string(keys_dir.join("identity.secret"))?;
        let mut identity_bytes = BASE64.decode(identity_secret_b64.trim()).map_err(|e| {
            HidraError::KeyManagement(format!("invalid identity key encoding: {e}"))
        })?;

        if identity_bytes.len() != 32 {
            return Err(HidraError::KeyManagement(
                "identity key must be exactly 32 bytes".into(),
            ));
        }

        let mut id_array = [0u8; 32];
        id_array.copy_from_slice(&identity_bytes);
        identity_bytes.zeroize();

        let identity_signing = SigningKey::from_bytes(&id_array);
        id_array.zeroize();
        let identity_verifying = identity_signing.verifying_key();

        let noise_secret_b64 =
            std::fs::read_to_string(keys_dir.join("noise_static.secret"))?;
        let mut noise_bytes = BASE64.decode(noise_secret_b64.trim()).map_err(|e| {
            HidraError::KeyManagement(format!("invalid noise key encoding: {e}"))
        })?;

        if noise_bytes.len() != 32 {
            return Err(HidraError::KeyManagement(
                "noise static key must be exactly 32 bytes".into(),
            ));
        }

        let mut noise_array = [0u8; 32];
        noise_array.copy_from_slice(&noise_bytes);
        noise_bytes.zeroize();

        let noise_static_secret = StaticSecret::from(noise_array);
        noise_array.zeroize();
        let noise_static_public = X25519Public::from(&noise_static_secret);

        let node_id = derive_node_id(&identity_verifying);

        Ok(Self {
            identity_signing,
            identity_verifying,
            noise_static_secret,
            noise_static_public,
            node_id,
        })
    }
}

/// The identity of a `.hidra` hidden service.
///
/// The address *is* the public key, so whoever holds `service.secret` is the
/// service, to everyone, with nothing to revoke. It used to be written with
/// `fs::write` and no mode at all — 0644, readable by every account on the
/// machine — which is a worse exposure than the node keys had, since those at
/// least got a `chmod` a moment later.
pub struct ServiceKeys {
    pub signing_key: SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub address: String,
    pub address_hash: [u8; 20],
}

impl ServiceKeys {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let (address, address_hash) = derive_hidra_address(&verifying_key);
        Self { signing_key, verifying_key, address, address_hash }
    }

    pub fn load_or_generate(keys_dir: &Path) -> Result<Self> {
        let svc_dir = keys_dir.join("service");
        if svc_dir.join("service.secret").exists() {
            Self::load(&svc_dir)
        } else {
            let keys = Self::generate();
            keys.save(&svc_dir)?;
            Ok(keys)
        }
    }

    fn save(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        restrict_dir(dir)?;

        write_private_file(
            &dir.join("service.secret"),
            BASE64.encode(self.signing_key.to_bytes()).as_bytes(),
        )?;

        // The public key and the address are what the service advertises.
        std::fs::write(
            dir.join("service.public"),
            BASE64.encode(self.verifying_key.to_bytes()),
        )?;
        std::fs::write(dir.join("service.address"), &self.address)?;
        Ok(())
    }

    fn load(dir: &Path) -> Result<Self> {
        let secret_b64 = std::fs::read_to_string(dir.join("service.secret"))?;
        let mut secret_bytes = BASE64.decode(secret_b64.trim()).map_err(|e| {
            HidraError::KeyManagement(format!("invalid service key encoding: {e}"))
        })?;
        if secret_bytes.len() != 32 {
            return Err(HidraError::KeyManagement(
                "service key must be exactly 32 bytes".into(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&secret_bytes);
        secret_bytes.zeroize();
        let signing_key = SigningKey::from_bytes(&arr);
        arr.zeroize();
        let verifying_key = signing_key.verifying_key();
        let (address, address_hash) = derive_hidra_address(&verifying_key);

        // A key found world-readable has already been exposed for however
        // long it sat there, so say so rather than fixing it quietly.
        warn_if_group_or_world_readable(&dir.join("service.secret"));
        Ok(Self { signing_key, verifying_key, address, address_hash })
    }
}

fn derive_hidra_address(
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> (String, [u8; 20]) {
    let hash = blake3::hash(verifying_key.as_bytes());
    let mut addr_hash = [0u8; 20];
    addr_hash.copy_from_slice(&hash.as_bytes()[..20]);
    let hex: String = addr_hash.iter().map(|b| format!("{b:02x}")).collect();
    (format!("{hex}.hidra"), addr_hash)
}

/// Tell the operator when a secret on disk is readable by anyone else.
///
/// Tightening it silently would hide the fact that it was loose, and the key
/// has to be treated as compromised either way — the point is that someone
/// finds out.
pub fn warn_if_group_or_world_readable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o077;
            if mode != 0 {
                tracing::warn!(
                    file = %path.display(),
                    mode = format!("{:o}", meta.permissions().mode() & 0o777),
                    "a secret key on disk is readable by other accounts on this \
                     machine. Treat it as compromised: generate a new one rather \
                     than only fixing the permissions."
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn derive_node_id(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    let hash = blake3::hash(verifying_key.as_bytes());
    let id_bytes = &hash.as_bytes()[..16];
    id_bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_generation_produces_valid_node_id() {
        let keys = NodeKeys::generate();
        assert_eq!(keys.node_id.len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn key_roundtrip_through_filesystem() {
        let dir = std::env::temp_dir().join(format!("hidra_test_{}", uuid::Uuid::new_v4()));
        let keys = NodeKeys::generate();
        keys.save(&dir).unwrap();

        let loaded = NodeKeys::load(&dir).unwrap();
        assert_eq!(keys.node_id, loaded.node_id);
        assert_eq!(
            keys.noise_static_public.as_bytes(),
            loaded.noise_static_public.as_bytes()
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
