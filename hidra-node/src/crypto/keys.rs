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

        std::fs::write(
            keys_dir.join("identity.secret"),
            BASE64.encode(self.identity_signing.to_bytes()),
        )?;
        std::fs::write(
            keys_dir.join("identity.public"),
            BASE64.encode(self.identity_verifying.to_bytes()),
        )?;
        std::fs::write(
            keys_dir.join("noise_static.secret"),
            BASE64.encode(self.noise_static_secret.to_bytes()),
        )?;
        std::fs::write(
            keys_dir.join("noise_static.public"),
            BASE64.encode(self.noise_static_public.to_bytes()),
        )?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let secret_perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(
                keys_dir.join("identity.secret"),
                secret_perms.clone(),
            )?;
            std::fs::set_permissions(
                keys_dir.join("noise_static.secret"),
                secret_perms,
            )?;
        }

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
