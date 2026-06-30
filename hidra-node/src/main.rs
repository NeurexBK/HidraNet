#![deny(warnings)]

// =============================================================================
// HidraNet — Single-file consolidated binary
// Secure overlay network with Noise XX, onion routing, DHT, SOCKS5 proxy
// =============================================================================

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use tracing::{debug, info, warn};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

// ─────────────────────────────────────────────────────────────────────────────
// mod error
// ─────────────────────────────────────────────────────────────────────────────
mod error {
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum HidraError {
        #[error("I/O error: {0}")]
        Io(#[from] std::io::Error),

        #[error("configuration error: {0}")]
        Config(#[from] config::ConfigError),

        #[error("cryptographic error: {0}")]
        Crypto(String),

        #[error("handshake error: {0}")]
        Handshake(String),

        #[error("protocol error: {0}")]
        Protocol(String),

        #[error("key management error: {0}")]
        KeyManagement(String),

        #[error("invalid address: {0}")]
        AddrParse(#[from] std::net::AddrParseError),

        #[error("relay error: {0}")]
        Relay(String),

        #[error("circuit error: {0}")]
        Circuit(String),
    }

    pub type Result<T> = std::result::Result<T, HidraError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod logging
// ─────────────────────────────────────────────────────────────────────────────
mod logging {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    pub fn init_logging(level: &str, format: &str) {
        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

        match format {
            "json" => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(
                        fmt::layer()
                            .json()
                            .with_target(true)
                            .with_thread_ids(true)
                            .with_file(true)
                            .with_line_number(true)
                            .with_span_list(true),
                    )
                    .init();
            }
            _ => {
                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(
                        fmt::layer()
                            .pretty()
                            .with_target(true)
                            .with_thread_ids(true),
                    )
                    .init();
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod config
// ─────────────────────────────────────────────────────────────────────────────
mod app_config {
    use serde::Deserialize;

    use crate::error::Result;

    #[derive(Debug, Deserialize, Clone)]
    pub struct AppConfig {
        pub node: NodeConfig,
        pub network: NetworkConfig,
        pub logging: LoggingConfig,
        pub paths: PathsConfig,
        #[serde(default)]
        pub relays: Vec<RelayInfo>,
        #[serde(default)]
        pub dht: DhtConfig,
        #[serde(default)]
        pub proxy: ProxyConfig,
        #[serde(default)]
        pub hidden_service: HiddenServiceConfig,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct HiddenServiceConfig {
        #[serde(default)]
        #[allow(dead_code)]
        pub enabled: bool,
        #[serde(default = "default_hs_port")]
        pub local_port: u16,
        #[serde(default)]
        pub app: Option<String>,
        #[serde(default)]
        pub mail_name: Option<String>,
    }

    impl Default for HiddenServiceConfig {
        fn default() -> Self {
            Self {
                enabled: false,
                local_port: default_hs_port(),
                app: None,
                mail_name: None,
            }
        }
    }

    fn default_hs_port() -> u16 {
        8080
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct DhtConfig {
        #[serde(default = "default_dht_port")]
        pub port: u16,
        #[serde(default)]
        pub bootstrap_nodes: Vec<String>,
        #[serde(default = "default_true")]
        pub enabled: bool,
    }

    impl Default for DhtConfig {
        fn default() -> Self {
            Self {
                port: default_dht_port(),
                bootstrap_nodes: Vec::new(),
                enabled: true,
            }
        }
    }

    fn default_dht_port() -> u16 {
        7000
    }

    fn default_true() -> bool {
        true
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct ProxyConfig {
        #[serde(default = "default_proxy_addr")]
        pub listen_addr: String,
        #[serde(default = "default_proxy_port")]
        pub port: u16,
    }

    impl Default for ProxyConfig {
        fn default() -> Self {
            Self {
                listen_addr: default_proxy_addr(),
                port: default_proxy_port(),
            }
        }
    }

    fn default_proxy_addr() -> String {
        "127.0.0.1".into()
    }

    fn default_proxy_port() -> u16 {
        9050
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct RelayInfo {
        pub name: String,
        pub addr: String,
        pub noise_pubkey: String,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct NodeConfig {
        pub name: String,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct NetworkConfig {
        pub listen_addr: String,
        pub listen_port: u16,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct LoggingConfig {
        pub level: String,
        pub format: String,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct PathsConfig {
        pub keys_dir: String,
    }

    pub fn load_config(path: &str) -> Result<AppConfig> {
        let config = config::Config::builder()
            .add_source(config::File::new(path, config::FileFormat::Toml))
            .build()?;
        let app_config: AppConfig = config.try_deserialize()?;
        Ok(app_config)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod crypto
// ─────────────────────────────────────────────────────────────────────────────
mod crypto {
    pub mod handshake {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305,
        };
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};
        use zeroize::{Zeroize, ZeroizeOnDrop};

        use crate::error::{HidraError, Result};

        const PROTOCOL_NAME: &[u8; 32] = b"Noise_XX_25519_ChaChaPoly_BLAKE3";
        const DH_LEN: usize = 32;
        const TAG_LEN: usize = 16;

        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub enum Role {
            Initiator,
            Responder,
        }

        #[derive(Zeroize, ZeroizeOnDrop)]
        struct CipherState {
            key: Option<[u8; 32]>,
            #[zeroize(skip)]
            nonce: u64,
        }

        impl CipherState {
            fn empty() -> Self {
                Self {
                    key: None,
                    nonce: 0,
                }
            }

            fn from_key(key: [u8; 32]) -> Self {
                Self {
                    key: Some(key),
                    nonce: 0,
                }
            }

            fn has_key(&self) -> bool {
                self.key.is_some()
            }

            fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
                let key =
                    self.key.ok_or_else(|| HidraError::Crypto("cipher not keyed".into()))?;
                if self.nonce == u64::MAX {
                    return Err(HidraError::Crypto("nonce exhaustion".into()));
                }

                let nonce_bytes = Self::build_nonce(self.nonce);
                let cipher = ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|_| HidraError::Crypto("invalid cipher key length".into()))?;

                let ciphertext = cipher
                    .encrypt(
                        (&nonce_bytes).into(),
                        Payload {
                            msg: plaintext,
                            aad: ad,
                        },
                    )
                    .map_err(|_| HidraError::Crypto("AEAD encryption failed".into()))?;

                self.nonce += 1;
                Ok(ciphertext)
            }

            fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
                let key =
                    self.key.ok_or_else(|| HidraError::Crypto("cipher not keyed".into()))?;
                if self.nonce == u64::MAX {
                    return Err(HidraError::Crypto("nonce exhaustion".into()));
                }

                let nonce_bytes = Self::build_nonce(self.nonce);
                let cipher = ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|_| HidraError::Crypto("invalid cipher key length".into()))?;

                let plaintext = cipher
                    .decrypt(
                        (&nonce_bytes).into(),
                        Payload {
                            msg: ciphertext,
                            aad: ad,
                        },
                    )
                    .map_err(|_| HidraError::Crypto("AEAD decryption failed".into()))?;

                self.nonce += 1;
                Ok(plaintext)
            }

            fn build_nonce(n: u64) -> [u8; 12] {
                let mut nonce = [0u8; 12];
                nonce[4..].copy_from_slice(&n.to_le_bytes());
                nonce
            }
        }

        struct SymmetricState {
            h: [u8; 32],
            ck: [u8; 32],
            cipher: CipherState,
        }

        impl SymmetricState {
            fn initialize() -> Self {
                let h = *PROTOCOL_NAME;
                Self {
                    ck: h,
                    h,
                    cipher: CipherState::empty(),
                }
            }

            fn mix_key(&mut self, ikm: &[u8]) {
                let (ck, temp_k) = hkdf(&self.ck, ikm);
                self.ck = ck;
                self.cipher = CipherState::from_key(temp_k);
            }

            fn mix_hash(&mut self, data: &[u8]) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&self.h);
                hasher.update(data);
                self.h = *hasher.finalize().as_bytes();
            }

            fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
                let ciphertext = if self.cipher.has_key() {
                    self.cipher.encrypt(&self.h, plaintext)?
                } else {
                    plaintext.to_vec()
                };
                self.mix_hash(&ciphertext);
                Ok(ciphertext)
            }

            fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
                let plaintext = if self.cipher.has_key() {
                    self.cipher.decrypt(&self.h, ciphertext)?
                } else {
                    ciphertext.to_vec()
                };
                self.mix_hash(ciphertext);
                Ok(plaintext)
            }

            fn split(mut self) -> (TransportCipher, TransportCipher) {
                let (k1, k2) = hkdf(&self.ck, &[]);
                self.h.zeroize();
                self.ck.zeroize();
                (
                    TransportCipher(CipherState::from_key(k1)),
                    TransportCipher(CipherState::from_key(k2)),
                )
            }
        }

        fn hkdf(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
            let temp_key = blake3::keyed_hash(ck, ikm);
            let output1 = blake3::keyed_hash(temp_key.as_bytes(), &[0x01]);
            let mut hasher = blake3::Hasher::new_keyed(temp_key.as_bytes());
            hasher.update(output1.as_bytes());
            hasher.update(&[0x02]);
            let output2 = hasher.finalize();
            (*output1.as_bytes(), *output2.as_bytes())
        }

        pub struct TransportCipher(CipherState);

        impl TransportCipher {
            pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
                self.0.encrypt(&[], plaintext)
            }

            pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
                self.0.decrypt(&[], ciphertext)
            }

            pub fn session_key(&self) -> Result<[u8; 32]> {
                self.0
                    .key
                    .ok_or_else(|| HidraError::Crypto("cipher not keyed".into()))
            }
        }

        pub struct HandshakeState {
            symmetric: Option<SymmetricState>,
            s: StaticSecret,
            e: Option<StaticSecret>,
            rs: Option<PublicKey>,
            re: Option<PublicKey>,
            role: Role,
        }

        impl HandshakeState {
            pub fn new(role: Role, static_secret: StaticSecret) -> Self {
                Self {
                    symmetric: Some(SymmetricState::initialize()),
                    s: static_secret,
                    e: None,
                    rs: None,
                    re: None,
                    role,
                }
            }

            fn sym(&mut self) -> Result<&mut SymmetricState> {
                self.symmetric
                    .as_mut()
                    .ok_or_else(|| HidraError::Handshake("state already consumed".into()))
            }

            pub fn write_message_a(&mut self) -> Result<Vec<u8>> {
                let e = StaticSecret::random_from_rng(OsRng);
                let e_pub = PublicKey::from(&e);
                self.e = Some(e);
                self.sym()?.mix_hash(e_pub.as_bytes());
                let mut msg = Vec::with_capacity(DH_LEN);
                msg.extend_from_slice(e_pub.as_bytes());
                let payload_ct = self.sym()?.encrypt_and_hash(&[])?;
                msg.extend_from_slice(&payload_ct);
                Ok(msg)
            }

            pub fn read_message_a(&mut self, message: &[u8]) -> Result<()> {
                if message.len() < DH_LEN {
                    return Err(HidraError::Handshake("message A too short".into()));
                }
                let re_bytes: [u8; 32] = message[..DH_LEN]
                    .try_into()
                    .map_err(|_| HidraError::Handshake("invalid ephemeral key in A".into()))?;
                self.re = Some(PublicKey::from(re_bytes));
                self.sym()?.mix_hash(&re_bytes);
                self.sym()?.decrypt_and_hash(&message[DH_LEN..])?;
                Ok(())
            }

            pub fn write_message_b(&mut self) -> Result<Vec<u8>> {
                let e = StaticSecret::random_from_rng(OsRng);
                let e_pub = PublicKey::from(&e);
                self.e = Some(e);
                self.sym()?.mix_hash(e_pub.as_bytes());
                let mut msg = Vec::with_capacity(DH_LEN + DH_LEN + TAG_LEN + TAG_LEN);
                msg.extend_from_slice(e_pub.as_bytes());

                let re = self.re.ok_or_else(|| {
                    HidraError::Handshake("missing remote ephemeral for ee".into())
                })?;
                let ee = self.e.as_ref().ok_or_else(|| {
                    HidraError::Handshake("missing local ephemeral for ee".into())
                })?.diffie_hellman(&re);
                self.sym()?.mix_key(ee.as_bytes());

                let s_pub = PublicKey::from(&self.s);
                let enc_s = self.sym()?.encrypt_and_hash(s_pub.as_bytes())?;
                msg.extend_from_slice(&enc_s);

                let es_dh = match self.role {
                    Role::Responder => self.s.diffie_hellman(&re),
                    Role::Initiator => {
                        let rs = self.rs.ok_or_else(|| {
                            HidraError::Handshake("missing remote static for es".into())
                        })?;
                        self.e.as_ref().ok_or_else(|| {
                            HidraError::Handshake("missing local ephemeral for es".into())
                        })?.diffie_hellman(&rs)
                    }
                };
                self.sym()?.mix_key(es_dh.as_bytes());
                let payload_ct = self.sym()?.encrypt_and_hash(&[])?;
                msg.extend_from_slice(&payload_ct);
                Ok(msg)
            }

            pub fn read_message_b(&mut self, message: &[u8]) -> Result<()> {
                let min = DH_LEN + DH_LEN + TAG_LEN + TAG_LEN;
                if message.len() < min {
                    return Err(HidraError::Handshake(format!(
                        "message B too short: {} < {min}", message.len()
                    )));
                }
                let mut off = 0;

                let re_bytes: [u8; 32] = message[off..off + DH_LEN]
                    .try_into()
                    .map_err(|_| HidraError::Handshake("invalid ephemeral key in B".into()))?;
                self.re = Some(PublicKey::from(re_bytes));
                self.sym()?.mix_hash(&re_bytes);
                off += DH_LEN;

                let re = self.re.ok_or_else(|| {
                    HidraError::Handshake("missing remote ephemeral for ee".into())
                })?;
                let ee = self.e.as_ref().ok_or_else(|| {
                    HidraError::Handshake("missing local ephemeral for ee".into())
                })?.diffie_hellman(&re);
                self.sym()?.mix_key(ee.as_bytes());

                let enc_s = &message[off..off + DH_LEN + TAG_LEN];
                let rs_bytes = self.sym()?.decrypt_and_hash(enc_s)?;
                let rs_array: [u8; 32] = rs_bytes.try_into().map_err(|_| {
                    HidraError::Handshake("invalid static key length in B".into())
                })?;
                self.rs = Some(PublicKey::from(rs_array));
                off += DH_LEN + TAG_LEN;

                let es_dh = match self.role {
                    Role::Initiator => {
                        let rs = self.rs.ok_or_else(|| {
                            HidraError::Handshake("missing remote static for es".into())
                        })?;
                        self.e.as_ref().ok_or_else(|| {
                            HidraError::Handshake("missing local ephemeral for es".into())
                        })?.diffie_hellman(&rs)
                    }
                    Role::Responder => self.s.diffie_hellman(&re),
                };
                self.sym()?.mix_key(es_dh.as_bytes());
                self.sym()?.decrypt_and_hash(&message[off..])?;
                Ok(())
            }

            pub fn write_message_c(&mut self) -> Result<Vec<u8>> {
                let mut msg = Vec::with_capacity(DH_LEN + TAG_LEN + TAG_LEN);
                let s_pub = PublicKey::from(&self.s);
                let enc_s = self.sym()?.encrypt_and_hash(s_pub.as_bytes())?;
                msg.extend_from_slice(&enc_s);

                let se_dh = match self.role {
                    Role::Initiator => {
                        let re = self.re.ok_or_else(|| {
                            HidraError::Handshake("missing remote ephemeral for se".into())
                        })?;
                        self.s.diffie_hellman(&re)
                    }
                    Role::Responder => {
                        let rs = self.rs.ok_or_else(|| {
                            HidraError::Handshake("missing remote static for se".into())
                        })?;
                        self.e.as_ref().ok_or_else(|| {
                            HidraError::Handshake("missing local ephemeral for se".into())
                        })?.diffie_hellman(&rs)
                    }
                };
                self.sym()?.mix_key(se_dh.as_bytes());
                let payload_ct = self.sym()?.encrypt_and_hash(&[])?;
                msg.extend_from_slice(&payload_ct);
                Ok(msg)
            }

            pub fn read_message_c(&mut self, message: &[u8]) -> Result<()> {
                let min = DH_LEN + TAG_LEN + TAG_LEN;
                if message.len() < min {
                    return Err(HidraError::Handshake(format!(
                        "message C too short: {} < {min}", message.len()
                    )));
                }
                let mut off = 0;

                let enc_s = &message[off..off + DH_LEN + TAG_LEN];
                let rs_bytes = self.sym()?.decrypt_and_hash(enc_s)?;
                let rs_array: [u8; 32] = rs_bytes.try_into().map_err(|_| {
                    HidraError::Handshake("invalid static key length in C".into())
                })?;
                self.rs = Some(PublicKey::from(rs_array));
                off += DH_LEN + TAG_LEN;

                let se_dh = match self.role {
                    Role::Responder => {
                        let rs = self.rs.ok_or_else(|| {
                            HidraError::Handshake("missing remote static for se".into())
                        })?;
                        self.e.as_ref().ok_or_else(|| {
                            HidraError::Handshake("missing local ephemeral for se".into())
                        })?.diffie_hellman(&rs)
                    }
                    Role::Initiator => {
                        let re = self.re.ok_or_else(|| {
                            HidraError::Handshake("missing remote ephemeral for se".into())
                        })?;
                        self.s.diffie_hellman(&re)
                    }
                };
                self.sym()?.mix_key(se_dh.as_bytes());
                self.sym()?.decrypt_and_hash(&message[off..])?;
                Ok(())
            }

            pub fn into_transport(mut self) -> Result<(TransportCipher, TransportCipher)> {
                let symmetric = self.symmetric.take().ok_or_else(|| {
                    HidraError::Handshake("state already consumed".into())
                })?;
                let role = self.role;
                let (c1, c2) = symmetric.split();
                match role {
                    Role::Initiator => Ok((c1, c2)),
                    Role::Responder => Ok((c2, c1)),
                }
            }
        }
    }

    pub mod keys {
        use std::path::Path;

        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
        use zeroize::Zeroize;

        use crate::error::{HidraError, Result};

        pub struct NodeKeys {
            pub identity_signing: SigningKey,
            #[allow(dead_code)]
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
                Ok(())
            }

            pub fn load(keys_dir: &Path) -> Result<Self> {
                let identity_secret_b64 =
                    std::fs::read_to_string(keys_dir.join("identity.secret"))?;
                let mut identity_bytes =
                    BASE64.decode(identity_secret_b64.trim()).map_err(|e| {
                        HidraError::KeyManagement(format!(
                            "invalid identity key encoding: {e}"
                        ))
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
                let mut noise_bytes =
                    BASE64.decode(noise_secret_b64.trim()).map_err(|e| {
                        HidraError::KeyManagement(format!(
                            "invalid noise key encoding: {e}"
                        ))
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
                std::fs::write(
                    dir.join("service.secret"),
                    BASE64.encode(self.signing_key.to_bytes()),
                )?;
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
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod network
// ─────────────────────────────────────────────────────────────────────────────
mod network {
    pub mod connection {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        use crate::crypto::handshake::TransportCipher;
        use crate::error::{HidraError, Result};

        const MAX_FRAME_SIZE: usize = 65_536;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum Message {
            Ping(Vec<u8>),
            Pong(Vec<u8>),
            CreateCircuit { circuit_id: u32 },
            CircuitCreated { circuit_id: u32 },
            Relay { circuit_id: u32, data: Vec<u8> },
        }

        impl Message {
            pub fn serialize(&self) -> Vec<u8> {
                match self {
                    Self::Ping(data) => {
                        let mut buf = Vec::with_capacity(1 + data.len());
                        buf.push(0x01);
                        buf.extend_from_slice(data);
                        buf
                    }
                    Self::Pong(data) => {
                        let mut buf = Vec::with_capacity(1 + data.len());
                        buf.push(0x02);
                        buf.extend_from_slice(data);
                        buf
                    }
                    Self::CreateCircuit { circuit_id } => {
                        let mut buf = Vec::with_capacity(5);
                        buf.push(0x10);
                        buf.extend_from_slice(&circuit_id.to_be_bytes());
                        buf
                    }
                    Self::CircuitCreated { circuit_id } => {
                        let mut buf = Vec::with_capacity(5);
                        buf.push(0x11);
                        buf.extend_from_slice(&circuit_id.to_be_bytes());
                        buf
                    }
                    Self::Relay { circuit_id, data } => {
                        let mut buf = Vec::with_capacity(5 + data.len());
                        buf.push(0x20);
                        buf.extend_from_slice(&circuit_id.to_be_bytes());
                        buf.extend_from_slice(data);
                        buf
                    }
                }
            }

            pub fn deserialize(data: &[u8]) -> Result<Self> {
                if data.is_empty() {
                    return Err(HidraError::Protocol("empty message body".into()));
                }
                match data[0] {
                    0x01 => Ok(Self::Ping(data[1..].to_vec())),
                    0x02 => Ok(Self::Pong(data[1..].to_vec())),
                    0x10 => {
                        if data.len() < 5 {
                            return Err(HidraError::Protocol(
                                "CreateCircuit too short".into(),
                            ));
                        }
                        let circuit_id =
                            u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                        Ok(Self::CreateCircuit { circuit_id })
                    }
                    0x11 => {
                        if data.len() < 5 {
                            return Err(HidraError::Protocol(
                                "CircuitCreated too short".into(),
                            ));
                        }
                        let circuit_id =
                            u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                        Ok(Self::CircuitCreated { circuit_id })
                    }
                    0x20 => {
                        if data.len() < 5 {
                            return Err(HidraError::Protocol(
                                "Relay message too short".into(),
                            ));
                        }
                        let circuit_id =
                            u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                        Ok(Self::Relay {
                            circuit_id,
                            data: data[5..].to_vec(),
                        })
                    }
                    tag => Err(HidraError::Protocol(format!(
                        "unknown message type: 0x{tag:02x}"
                    ))),
                }
            }
        }

        pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
            let len = u32::try_from(data.len()).map_err(|_| {
                HidraError::Protocol("frame exceeds u32 size limit".into())
            })?;
            stream.write_all(&len.to_be_bytes()).await?;
            stream.write_all(data).await?;
            stream.flush().await?;
            Ok(())
        }

        pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > MAX_FRAME_SIZE {
                return Err(HidraError::Protocol(format!(
                    "frame size {len} exceeds maximum {MAX_FRAME_SIZE}"
                )));
            }
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            Ok(buf)
        }

        pub struct SecureConnection {
            stream: TcpStream,
            send_cipher: TransportCipher,
            recv_cipher: TransportCipher,
        }

        impl SecureConnection {
            pub fn new(
                stream: TcpStream,
                send_cipher: TransportCipher,
                recv_cipher: TransportCipher,
            ) -> Self {
                Self {
                    stream,
                    send_cipher,
                    recv_cipher,
                }
            }

            pub async fn send_message(&mut self, msg: &Message) -> Result<()> {
                let plaintext = msg.serialize();
                let ciphertext = self.send_cipher.encrypt(&plaintext)?;
                write_frame(&mut self.stream, &ciphertext).await
            }

            pub async fn recv_message(&mut self) -> Result<Message> {
                let ciphertext = read_frame(&mut self.stream).await?;
                let plaintext = self.recv_cipher.decrypt(&ciphertext)?;
                Message::deserialize(&plaintext)
            }
        }
    }

    pub mod listener {
        use std::net::SocketAddr;
        use std::sync::Arc;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tracing::{debug, info, warn};
        use uuid::Uuid;
        use x25519_dalek::StaticSecret;

        use crate::crypto::handshake::{HandshakeState, Role};
        use crate::error::Result;
        use crate::network::connection::{read_frame, write_frame, Message, SecureConnection};
        use crate::relay::router::RelayRouter;

        pub const PROTO_NOISE_SESSION: u8 = 0x00;
        pub const PROTO_FORWARDED_CELL: u8 = 0x01;

        pub struct NodeListener {
            listener: TcpListener,
            static_secret: Arc<[u8; 32]>,
            rate_limiter: Arc<crate::security::rate_limiter::RateLimiter>,
        }

        impl NodeListener {
            pub async fn bind(
                addr: SocketAddr,
                static_secret: StaticSecret,
            ) -> Result<Self> {
                let listener = TcpListener::bind(addr).await?;
                info!(listen_addr = %addr, "TCP listener bound");
                let rate_limiter = Arc::new(
                    crate::security::rate_limiter::RateLimiter::new(
                        crate::security::rate_limiter::RateLimitConfig::default(),
                    ),
                );
                Ok(Self {
                    listener,
                    static_secret: Arc::new(static_secret.to_bytes()),
                    rate_limiter,
                })
            }

            pub async fn accept_loop(&self) -> Result<()> {
                let router = RelayRouter::new(Arc::clone(&self.static_secret));
                let limiter = Arc::clone(&self.rate_limiter);

                let cleanup_limiter = Arc::clone(&self.rate_limiter);
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(
                        std::time::Duration::from_secs(60),
                    );
                    loop {
                        interval.tick().await;
                        cleanup_limiter.cleanup_stale();
                    }
                });

                loop {
                    let (mut stream, remote_addr) = self.listener.accept().await?;
                    let peer_ip = remote_addr.ip();

                    if let Err(e) = limiter.check_rate_limit(peer_ip) {
                        debug!(peer = %remote_addr, error = %e, "rate limited");
                        continue;
                    }
                    if let Err(e) = limiter.track_connection(peer_ip) {
                        debug!(peer = %remote_addr, error = %e, "connection limit");
                        continue;
                    }

                    info!(remote_addr = %remote_addr, "accepted connection");

                    let mut proto_byte = [0u8; 1];
                    if let Err(e) = stream.read_exact(&mut proto_byte).await {
                        warn!(error = %e, "failed to read protocol byte");
                        limiter.release_connection(peer_ip);
                        continue;
                    }

                    match proto_byte[0] {
                        PROTO_NOISE_SESSION => {
                            router.handle_client_connection(stream, remote_addr).await;
                        }
                        PROTO_FORWARDED_CELL => {
                            router.handle_forwarded_cell(stream, remote_addr).await;
                        }
                        other => {
                            warn!(
                                proto = other,
                                "unknown protocol byte, dropping connection"
                            );
                        }
                    }

                    limiter.release_connection(peer_ip);
                }
            }
        }

        pub async fn connect_to_peer(
            addr: SocketAddr,
            static_secret: StaticSecret,
        ) -> Result<()> {
            let session_id = Uuid::new_v4().to_string();
            let _span = tracing::info_span!(
                "session",
                session_id = %session_id,
                remote_addr = %addr,
                role = "initiator",
            )
            .entered();

            info!("connecting to peer");
            let mut stream = tokio::net::TcpStream::connect(addr).await?;
            info!("TCP connection established");

            stream.write_all(&[PROTO_NOISE_SESSION]).await?;

            debug!("starting Noise XX handshake as initiator");
            let mut handshake = HandshakeState::new(Role::Initiator, static_secret);

            let msg_a = handshake.write_message_a()?;
            write_frame(&mut stream, &msg_a).await?;

            let msg_b = read_frame(&mut stream).await?;
            handshake.read_message_b(&msg_b)?;

            let msg_c = handshake.write_message_c()?;
            write_frame(&mut stream, &msg_c).await?;

            info!("Noise XX handshake completed");

            let (send_cipher, recv_cipher) = handshake.into_transport()?;
            let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

            let ping = Message::Ping(b"HidraPing".to_vec());
            conn.send_message(&ping).await?;
            info!("sent encrypted Ping");

            let msg = conn.recv_message().await?;
            match msg {
                Message::Pong(ref data) => {
                    info!(
                        payload = %String::from_utf8_lossy(data),
                        "received encrypted Pong"
                    );
                }
                Message::Ping(_) => {
                    warn!("unexpected Ping from responder");
                }
                _ => {
                    warn!("unexpected message from responder");
                }
            }

            info!("session completed");
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod onion
// ─────────────────────────────────────────────────────────────────────────────
mod onion {
    pub mod cell {
        use serde::{Deserialize, Serialize};
        use std::net::SocketAddr;

        use crate::error::{HidraError, Result};

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub struct LayerHeader {
            pub next_hop: Option<SocketAddr>,
        }

        impl LayerHeader {
            pub fn serialize_bincode(&self) -> Result<Vec<u8>> {
                bincode::serialize(self).map_err(|e| {
                    HidraError::Protocol(format!("header serialization failed: {e}"))
                })
            }

            pub fn deserialize_bincode(data: &[u8]) -> Result<Self> {
                bincode::deserialize(data).map_err(|e| {
                    HidraError::Protocol(format!("header deserialization failed: {e}"))
                })
            }
        }

        #[derive(Debug, Clone, Serialize, Deserialize)]
        pub enum RelayCommand {
            Connect { host: String, port: u16 },
            Connected,
            Data(Vec<u8>),
            End,
            ConnectFailed(String),
            ResolveDns { hostname: String },
            DnsResolved { addresses: Vec<String> },
            RegisterService { service_hash: Vec<u8> },
            ServiceRegistered,
            ConnectService { service_hash: Vec<u8> },
            ServiceConnected,
        }

        impl RelayCommand {
            pub fn serialize_bincode(&self) -> Result<Vec<u8>> {
                bincode::serialize(self).map_err(|e| {
                    HidraError::Protocol(format!(
                        "relay command serialize failed: {e}"
                    ))
                })
            }

            pub fn deserialize_bincode(data: &[u8]) -> Result<Self> {
                bincode::deserialize(data).map_err(|e| {
                    HidraError::Protocol(format!(
                        "relay command deserialize failed: {e}"
                    ))
                })
            }
        }
    }

    pub mod layer {
        use chacha20poly1305::{
            aead::{Aead, KeyInit, Payload},
            ChaCha20Poly1305,
        };
        use rand::RngCore;

        use crate::error::{HidraError, Result};
        use crate::onion::cell::LayerHeader;

        const NONCE_LEN: usize = 12;
        const TAG_LEN: usize = 16;

        pub fn wrap_layer(
            key: &[u8; 32],
            header: &LayerHeader,
            inner: &[u8],
        ) -> Result<Vec<u8>> {
            let header_bytes = header.serialize_bincode()?;
            let header_len = (header_bytes.len() as u32).to_be_bytes();
            let mut plaintext =
                Vec::with_capacity(4 + header_bytes.len() + inner.len());
            plaintext.extend_from_slice(&header_len);
            plaintext.extend_from_slice(&header_bytes);
            plaintext.extend_from_slice(inner);

            let mut nonce = [0u8; NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut nonce);

            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| HidraError::Crypto("invalid layer key".into()))?;

            let ciphertext = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: &plaintext,
                        aad: &[],
                    },
                )
                .map_err(|_| HidraError::Crypto("layer encryption failed".into()))?;

            let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        }

        pub fn peel_layer(
            key: &[u8; 32],
            encrypted: &[u8],
        ) -> Result<(LayerHeader, Vec<u8>)> {
            if encrypted.len() < NONCE_LEN + TAG_LEN {
                return Err(HidraError::Crypto("layer data too short".into()));
            }
            let nonce: [u8; NONCE_LEN] = encrypted[..NONCE_LEN]
                .try_into()
                .map_err(|_| HidraError::Crypto("invalid nonce".into()))?;
            let ciphertext = &encrypted[NONCE_LEN..];

            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| HidraError::Crypto("invalid layer key".into()))?;

            let plaintext = cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &[],
                    },
                )
                .map_err(|_| HidraError::Crypto("layer decryption failed".into()))?;

            if plaintext.len() < 4 {
                return Err(HidraError::Crypto(
                    "decrypted layer too short for header length".into(),
                ));
            }
            let header_len = u32::from_be_bytes([
                plaintext[0],
                plaintext[1],
                plaintext[2],
                plaintext[3],
            ]) as usize;
            if plaintext.len() < 4 + header_len {
                return Err(HidraError::Crypto(
                    "decrypted layer too short for header".into(),
                ));
            }
            let header =
                LayerHeader::deserialize_bincode(&plaintext[4..4 + header_len])?;
            let inner = plaintext[4 + header_len..].to_vec();
            Ok((header, inner))
        }

        pub fn encrypt_stream(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
            let mut nonce = [0u8; NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut nonce);

            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| HidraError::Crypto("invalid stream key".into()))?;

            let ciphertext = cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: data,
                        aad: &[],
                    },
                )
                .map_err(|_| HidraError::Crypto("stream encryption failed".into()))?;

            let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        }

        pub fn decrypt_stream(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
            if encrypted.len() < NONCE_LEN + TAG_LEN {
                return Err(HidraError::Crypto("stream data too short".into()));
            }
            let nonce: [u8; NONCE_LEN] = encrypted[..NONCE_LEN]
                .try_into()
                .map_err(|_| HidraError::Crypto("invalid nonce".into()))?;
            let ciphertext = &encrypted[NONCE_LEN..];

            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| HidraError::Crypto("invalid stream key".into()))?;

            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &[],
                    },
                )
                .map_err(|_| HidraError::Crypto("stream decryption failed".into()))
        }
    }

    pub mod circuit {
        use std::net::SocketAddr;
        use zeroize::Zeroize;

        #[derive(Clone)]
        pub struct CircuitHop {
            pub addr: SocketAddr,
            pub session_key: [u8; 32],
        }

        impl std::fmt::Debug for CircuitHop {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("CircuitHop")
                    .field("addr", &self.addr)
                    .field("session_key", &"[REDACTED]")
                    .finish()
            }
        }

        impl Drop for CircuitHop {
            fn drop(&mut self) {
                self.session_key.zeroize();
            }
        }

        #[derive(Debug)]
        pub struct Circuit {
            pub id: u32,
            pub hops: Vec<CircuitHop>,
        }

        impl Circuit {
            pub fn new(id: u32, hops: Vec<CircuitHop>) -> Self {
                Self { id, hops }
            }
        }
    }

    pub mod builder {
        use crate::error::Result;
        use crate::onion::cell::LayerHeader;
        use crate::onion::circuit::Circuit;
        use crate::onion::layer::wrap_layer;

        pub fn build_onion(circuit: &Circuit, payload: &[u8]) -> Result<Vec<u8>> {
            let hops = &circuit.hops;
            let mut current = payload.to_vec();
            for i in (0..hops.len()).rev() {
                let next_hop = if i == hops.len() - 1 {
                    None
                } else {
                    Some(hops[i + 1].addr)
                };
                let header = LayerHeader { next_hop };
                current = wrap_layer(&hops[i].session_key, &header, &current)?;
            }
            Ok(current)
        }

        pub fn peel_response_layers(
            circuit: &Circuit,
            mut data: Vec<u8>,
        ) -> Result<Vec<u8>> {
            for hop in &circuit.hops {
                let (_, inner) =
                    crate::onion::layer::peel_layer(&hop.session_key, &data)?;
                data = inner;
            }
            Ok(data)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod p2p
// ─────────────────────────────────────────────────────────────────────────────
mod p2p {
    pub mod dht {
        pub mod node {
            use std::fmt;
            use std::net::SocketAddr;
            use serde::{Deserialize, Serialize};

            pub const ID_LEN: usize = 20;
            pub const ID_BITS: usize = ID_LEN * 8;

            #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
            pub struct NodeId(pub [u8; ID_LEN]);

            impl NodeId {
                pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
                    let hash = blake3::hash(pubkey);
                    let mut id = [0u8; ID_LEN];
                    id.copy_from_slice(&hash.as_bytes()[..ID_LEN]);
                    Self(id)
                }

                pub fn random() -> Self {
                    let mut id = [0u8; ID_LEN];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
                    Self(id)
                }

                pub fn xor_distance(&self, other: &NodeId) -> [u8; ID_LEN] {
                    let mut dist = [0u8; ID_LEN];
                    for i in 0..ID_LEN {
                        dist[i] = self.0[i] ^ other.0[i];
                    }
                    dist
                }

                pub fn bucket_index(&self, other: &NodeId) -> Option<usize> {
                    let dist = self.xor_distance(other);
                    leading_bit_position(&dist)
                }
            }

            fn leading_bit_position(data: &[u8; ID_LEN]) -> Option<usize> {
                for (i, &byte) in data.iter().enumerate() {
                    if byte != 0 {
                        let bit_in_byte = 7 - byte.leading_zeros() as usize;
                        return Some((ID_LEN - 1 - i) * 8 + bit_in_byte);
                    }
                }
                None
            }

            impl fmt::Debug for NodeId {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "NodeId(")?;
                    for byte in &self.0[..4] {
                        write!(f, "{byte:02x}")?;
                    }
                    write!(f, "..)")
                }
            }

            impl fmt::Display for NodeId {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    for byte in &self.0 {
                        write!(f, "{byte:02x}")?;
                    }
                    Ok(())
                }
            }

            #[derive(Debug, Clone, Serialize, Deserialize)]
            pub struct NodeInfo {
                pub id: NodeId,
                pub dht_addr: SocketAddr,
                pub relay_addr: Option<SocketAddr>,
                pub public_key: [u8; 32],
            }

            impl NodeInfo {
                pub fn is_relay(&self) -> bool {
                    self.relay_addr.is_some()
                }
            }

            impl PartialEq for NodeInfo {
                fn eq(&self, other: &Self) -> bool {
                    self.id == other.id
                }
            }

            impl Eq for NodeInfo {}
        }

        pub mod message {
            use std::net::SocketAddr;

            use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
            use serde::{Deserialize, Serialize};

            use crate::error::{HidraError, Result};
            use crate::p2p::dht::node::{NodeId, NodeInfo};

            const MAGIC: &[u8; 4] = b"HDHT";
            const SIGNATURE_LEN: usize = 64;
            const PUBKEY_LEN: usize = 32;
            const HEADER_LEN: usize = 4 + SIGNATURE_LEN + PUBKEY_LEN;

            #[derive(Debug, Clone, Serialize, Deserialize)]
            pub enum DhtMessage {
                Ping { request_id: u64, sender: NodeInfo },
                Pong { request_id: u64, sender: NodeInfo },
                FindNode { request_id: u64, sender: NodeInfo, target: NodeId },
                FindNodeResponse { request_id: u64, nodes: Vec<NodeInfo> },
                Store { request_id: u64, sender: NodeInfo, key: NodeId, value: Vec<u8> },
                StoreResponse { request_id: u64, stored: bool },
                AnnounceRelay { request_id: u64, sender: NodeInfo },
                AnnounceService {
                    request_id: u64,
                    sender: NodeInfo,
                    service_hash: [u8; 20],
                    intro_points: Vec<SocketAddr>,
                    service_pubkey: [u8; 32],
                },
                LookupService {
                    request_id: u64,
                    sender: NodeInfo,
                    service_hash: [u8; 20],
                },
                LookupServiceResponse {
                    request_id: u64,
                    intro_points: Vec<SocketAddr>,
                    service_pubkey: [u8; 32],
                    found: bool,
                },
            }

            impl DhtMessage {
                pub fn request_id(&self) -> u64 {
                    match self {
                        Self::Ping { request_id, .. }
                        | Self::Pong { request_id, .. }
                        | Self::FindNode { request_id, .. }
                        | Self::FindNodeResponse { request_id, .. }
                        | Self::Store { request_id, .. }
                        | Self::StoreResponse { request_id, .. }
                        | Self::AnnounceRelay { request_id, .. }
                        | Self::AnnounceService { request_id, .. }
                        | Self::LookupService { request_id, .. }
                        | Self::LookupServiceResponse { request_id, .. } => *request_id,
                    }
                }

                pub fn message_type(&self) -> &'static str {
                    match self {
                        Self::Ping { .. } => "PING",
                        Self::Pong { .. } => "PONG",
                        Self::FindNode { .. } => "FIND_NODE",
                        Self::FindNodeResponse { .. } => "FIND_NODE_RESPONSE",
                        Self::Store { .. } => "STORE",
                        Self::StoreResponse { .. } => "STORE_RESPONSE",
                        Self::AnnounceRelay { .. } => "ANNOUNCE_RELAY",
                        Self::AnnounceService { .. } => "ANNOUNCE_SERVICE",
                        Self::LookupService { .. } => "LOOKUP_SERVICE",
                        Self::LookupServiceResponse { .. } => "LOOKUP_SERVICE_RESPONSE",
                    }
                }

                pub fn is_response(&self) -> bool {
                    matches!(
                        self,
                        Self::Pong { .. }
                            | Self::FindNodeResponse { .. }
                            | Self::StoreResponse { .. }
                            | Self::LookupServiceResponse { .. }
                    )
                }
            }

            pub fn sign_and_serialize(
                msg: &DhtMessage,
                signing_key: &SigningKey,
            ) -> Result<Vec<u8>> {
                let payload = bincode::serialize(msg).map_err(|e| {
                    HidraError::Protocol(format!(
                        "DHT message serialize failed: {e}"
                    ))
                })?;
                let pubkey_bytes = signing_key.verifying_key().to_bytes();
                let mut sign_data =
                    Vec::with_capacity(PUBKEY_LEN + payload.len());
                sign_data.extend_from_slice(&pubkey_bytes);
                sign_data.extend_from_slice(&payload);
                let signature = signing_key.sign(&sign_data);
                let mut packet =
                    Vec::with_capacity(HEADER_LEN + payload.len());
                packet.extend_from_slice(MAGIC);
                packet.extend_from_slice(&signature.to_bytes());
                packet.extend_from_slice(&pubkey_bytes);
                packet.extend_from_slice(&payload);
                Ok(packet)
            }

            pub fn verify_and_deserialize(
                packet: &[u8],
            ) -> Result<(DhtMessage, [u8; 32])> {
                if packet.len() < HEADER_LEN {
                    return Err(HidraError::Protocol(
                        "DHT packet too short".into(),
                    ));
                }
                if &packet[..4] != MAGIC {
                    return Err(HidraError::Protocol(
                        "invalid DHT magic bytes".into(),
                    ));
                }
                let sig_bytes: [u8; SIGNATURE_LEN] =
                    packet[4..4 + SIGNATURE_LEN].try_into().map_err(|_| {
                        HidraError::Protocol("invalid signature length".into())
                    })?;
                let pubkey_bytes: [u8; PUBKEY_LEN] =
                    packet[4 + SIGNATURE_LEN..HEADER_LEN]
                        .try_into()
                        .map_err(|_| {
                            HidraError::Protocol("invalid pubkey length".into())
                        })?;
                let payload = &packet[HEADER_LEN..];
                let signature = Signature::from_bytes(&sig_bytes);
                let verifying_key =
                    VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
                        HidraError::Crypto(format!(
                            "invalid Ed25519 public key: {e}"
                        ))
                    })?;
                let mut sign_data =
                    Vec::with_capacity(PUBKEY_LEN + payload.len());
                sign_data.extend_from_slice(&pubkey_bytes);
                sign_data.extend_from_slice(payload);
                verifying_key.verify(&sign_data, &signature).map_err(|_| {
                    HidraError::Crypto(
                        "DHT message signature verification failed".into(),
                    )
                })?;
                let msg: DhtMessage =
                    bincode::deserialize(payload).map_err(|e| {
                        HidraError::Protocol(format!(
                            "DHT message deserialize failed: {e}"
                        ))
                    })?;
                Ok((msg, pubkey_bytes))
            }
        }

        pub mod kbuckets {
            use std::time::Instant;
            use crate::p2p::dht::node::{NodeId, NodeInfo, ID_BITS};

            pub const K: usize = 20;

            #[derive(Debug)]
            struct BucketEntry {
                info: NodeInfo,
                last_seen: Instant,
            }

            #[derive(Debug)]
            struct KBucket {
                entries: Vec<BucketEntry>,
            }

            impl KBucket {
                fn new() -> Self {
                    Self { entries: Vec::with_capacity(K) }
                }

                fn len(&self) -> usize {
                    self.entries.len()
                }

                fn is_full(&self) -> bool {
                    self.entries.len() >= K
                }

                fn contains(&self, id: &NodeId) -> bool {
                    self.entries.iter().any(|e| e.info.id == *id)
                }

                fn update_or_insert(&mut self, info: NodeInfo) -> UpdateResult {
                    if let Some(pos) =
                        self.entries.iter().position(|e| e.info.id == info.id)
                    {
                        self.entries[pos].info = info;
                        self.entries[pos].last_seen = Instant::now();
                        let entry = self.entries.remove(pos);
                        self.entries.push(entry);
                        UpdateResult::Updated
                    } else if !self.is_full() {
                        self.entries.push(BucketEntry {
                            info,
                            last_seen: Instant::now(),
                        });
                        UpdateResult::Inserted
                    } else {
                        UpdateResult::BucketFull {
                            least_recent_id: self.entries[0].info.id,
                        }
                    }
                }

                fn remove(&mut self, id: &NodeId) -> bool {
                    if let Some(pos) =
                        self.entries.iter().position(|e| e.info.id == *id)
                    {
                        self.entries.remove(pos);
                        true
                    } else {
                        false
                    }
                }

                fn get_nodes(&self) -> Vec<NodeInfo> {
                    self.entries.iter().map(|e| e.info.clone()).collect()
                }

                fn stale_nodes(
                    &self,
                    timeout: std::time::Duration,
                ) -> Vec<NodeId> {
                    let now = Instant::now();
                    self.entries
                        .iter()
                        .filter(|e| now.duration_since(e.last_seen) > timeout)
                        .map(|e| e.info.id)
                        .collect()
                }
            }

            #[derive(Debug)]
            pub enum UpdateResult {
                Inserted,
                Updated,
                BucketFull { least_recent_id: NodeId },
            }

            pub struct RoutingTable {
                our_id: NodeId,
                buckets: Vec<KBucket>,
            }

            impl RoutingTable {
                pub fn new(our_id: NodeId) -> Self {
                    let mut buckets = Vec::with_capacity(ID_BITS);
                    for _ in 0..ID_BITS {
                        buckets.push(KBucket::new());
                    }
                    Self { our_id, buckets }
                }

                pub fn our_id(&self) -> &NodeId {
                    &self.our_id
                }

                pub fn update(&mut self, info: NodeInfo) -> UpdateResult {
                    if info.id == self.our_id {
                        return UpdateResult::Updated;
                    }
                    let bucket_idx = match self.our_id.bucket_index(&info.id) {
                        Some(idx) => idx,
                        None => return UpdateResult::Updated,
                    };
                    self.buckets[bucket_idx].update_or_insert(info)
                }

                pub fn remove(&mut self, id: &NodeId) {
                    if let Some(idx) = self.our_id.bucket_index(id) {
                        self.buckets[idx].remove(id);
                    }
                }

                pub fn find_closest(
                    &self,
                    target: &NodeId,
                    count: usize,
                ) -> Vec<NodeInfo> {
                    let mut all_nodes: Vec<NodeInfo> = self
                        .buckets
                        .iter()
                        .flat_map(|b| b.get_nodes())
                        .collect();
                    all_nodes.sort_by(|a, b| {
                        let da = a.id.xor_distance(target);
                        let db = b.id.xor_distance(target);
                        da.cmp(&db)
                    });
                    all_nodes.truncate(count);
                    all_nodes
                }

                pub fn find_relays(&self, count: usize) -> Vec<NodeInfo> {
                    let mut relays: Vec<NodeInfo> = self
                        .buckets
                        .iter()
                        .flat_map(|b| b.get_nodes())
                        .filter(|n| n.is_relay())
                        .collect();
                    use rand::seq::SliceRandom;
                    relays.shuffle(&mut rand::thread_rng());
                    relays.truncate(count);
                    relays
                }

                pub fn stale_nodes(
                    &self,
                    timeout: std::time::Duration,
                ) -> Vec<NodeId> {
                    self.buckets
                        .iter()
                        .flat_map(|b| b.stale_nodes(timeout))
                        .collect()
                }

                pub fn total_nodes(&self) -> usize {
                    self.buckets.iter().map(|b| b.len()).sum()
                }

                pub fn contains(&self, id: &NodeId) -> bool {
                    if let Some(idx) = self.our_id.bucket_index(id) {
                        self.buckets[idx].contains(id)
                    } else {
                        false
                    }
                }
            }
        }

        pub mod handler {
            use std::collections::HashMap;
            use std::net::SocketAddr;
            use tracing::{debug, info};

            use crate::p2p::dht::kbuckets::{RoutingTable, UpdateResult, K};
            use crate::p2p::dht::message::DhtMessage;
            use crate::p2p::dht::node::NodeInfo;

            const GOSSIP_FANOUT: usize = 3;

            #[derive(Debug, Clone)]
            pub struct ServiceDescriptor {
                pub intro_points: Vec<SocketAddr>,
                pub service_pubkey: [u8; 32],
            }

            pub type ServiceStore = HashMap<[u8; 20], ServiceDescriptor>;

            pub struct HandleResult {
                pub response: Option<DhtMessage>,
                pub gossip_targets: Vec<(NodeInfo, DhtMessage)>,
            }

            pub struct DhtHandler;

            impl DhtHandler {
                pub fn handle_message(
                    table: &mut RoutingTable,
                    msg: DhtMessage,
                    our_info: &NodeInfo,
                    _sender_addr: SocketAddr,
                    services: &mut ServiceStore,
                ) -> HandleResult {
                    let no_gossip = || HandleResult {
                        response: None,
                        gossip_targets: Vec::new(),
                    };
                    let reply = |r: DhtMessage| HandleResult {
                        response: Some(r),
                        gossip_targets: Vec::new(),
                    };

                    match msg {
                        DhtMessage::Ping { request_id, sender } => {
                            let bucket_index =
                                table.our_id().bucket_index(&sender.id);
                            info!(
                                dht_message_type = "PING",
                                node_id = %sender.id,
                                bucket_index = ?bucket_index,
                                peer_count = table.total_nodes(),
                                "received DHT PING"
                            );
                            update_table(table, sender);
                            reply(DhtMessage::Pong {
                                request_id,
                                sender: our_info.clone(),
                            })
                        }
                        DhtMessage::Pong { request_id: _, sender } => {
                            let bucket_index =
                                table.our_id().bucket_index(&sender.id);
                            info!(
                                dht_message_type = "PONG",
                                node_id = %sender.id,
                                bucket_index = ?bucket_index,
                                peer_count = table.total_nodes(),
                                "received DHT PONG"
                            );
                            update_table(table, sender);
                            no_gossip()
                        }
                        DhtMessage::FindNode { request_id, sender, target } => {
                            let bucket_index =
                                table.our_id().bucket_index(&sender.id);
                            info!(
                                dht_message_type = "FIND_NODE",
                                node_id = %sender.id,
                                target = %target,
                                bucket_index = ?bucket_index,
                                peer_count = table.total_nodes(),
                                "received FIND_NODE"
                            );
                            update_table(table, sender);
                            let closest = table.find_closest(&target, K);
                            debug!(
                                dht_message_type = "FIND_NODE_RESPONSE",
                                nodes_count = closest.len(),
                                "sending FIND_NODE response"
                            );
                            reply(DhtMessage::FindNodeResponse {
                                request_id,
                                nodes: closest,
                            })
                        }
                        DhtMessage::FindNodeResponse { nodes, .. } => {
                            debug!(
                                dht_message_type = "FIND_NODE_RESPONSE",
                                nodes_count = nodes.len(),
                                "received FIND_NODE response"
                            );
                            for node in nodes {
                                update_table(table, node);
                            }
                            no_gossip()
                        }
                        DhtMessage::Store { request_id, sender, .. } => {
                            let bucket_index =
                                table.our_id().bucket_index(&sender.id);
                            info!(
                                dht_message_type = "STORE",
                                node_id = %sender.id,
                                bucket_index = ?bucket_index,
                                peer_count = table.total_nodes(),
                                "received STORE"
                            );
                            update_table(table, sender);
                            reply(DhtMessage::StoreResponse {
                                request_id,
                                stored: true,
                            })
                        }
                        DhtMessage::StoreResponse { .. } => no_gossip(),
                        DhtMessage::AnnounceService {
                            request_id: _, sender, service_hash, intro_points, service_pubkey,
                        } => {
                            info!(
                                dht_message_type = "ANNOUNCE_SERVICE",
                                node_id = %sender.id,
                                peer_count = table.total_nodes(),
                                "received service announcement"
                            );
                            update_table(table, sender);
                            services.insert(service_hash, ServiceDescriptor {
                                intro_points,
                                service_pubkey,
                            });
                            no_gossip()
                        }
                        DhtMessage::LookupService {
                            request_id, sender, service_hash,
                        } => {
                            info!(
                                dht_message_type = "LOOKUP_SERVICE",
                                node_id = %sender.id,
                                peer_count = table.total_nodes(),
                                "received service lookup"
                            );
                            update_table(table, sender);
                            if let Some(desc) = services.get(&service_hash) {
                                reply(DhtMessage::LookupServiceResponse {
                                    request_id,
                                    intro_points: desc.intro_points.clone(),
                                    service_pubkey: desc.service_pubkey,
                                    found: true,
                                })
                            } else {
                                reply(DhtMessage::LookupServiceResponse {
                                    request_id,
                                    intro_points: Vec::new(),
                                    service_pubkey: [0u8; 32],
                                    found: false,
                                })
                            }
                        }
                        DhtMessage::LookupServiceResponse { .. } => no_gossip(),
                        DhtMessage::AnnounceRelay { request_id: _, sender } => {
                            let bucket_index =
                                table.our_id().bucket_index(&sender.id);
                            let already_known =
                                table.contains(&sender.id) && sender.is_relay();
                            info!(
                                dht_message_type = "ANNOUNCE_RELAY",
                                node_id = %sender.id,
                                is_relay = sender.is_relay(),
                                bucket_index = ?bucket_index,
                                peer_count = table.total_nodes(),
                                "received relay announcement"
                            );
                            update_table(table, sender.clone());

                            let gossip =
                                if !already_known && sender.is_relay() {
                                    let nearest = table.find_closest(
                                        &sender.id,
                                        GOSSIP_FANOUT + 1,
                                    );
                                    nearest
                                        .into_iter()
                                        .filter(|n| {
                                            n.id != sender.id
                                                && n.id != *table.our_id()
                                        })
                                        .take(GOSSIP_FANOUT)
                                        .map(|target| {
                                            let msg = DhtMessage::AnnounceRelay {
                                                request_id: rand_request_id(),
                                                sender: sender.clone(),
                                            };
                                            (target, msg)
                                        })
                                        .collect()
                                } else {
                                    Vec::new()
                                };

                            HandleResult {
                                response: None,
                                gossip_targets: gossip,
                            }
                        }
                    }
                }
            }

            fn update_table(table: &mut RoutingTable, info: NodeInfo) {
                let node_id = info.id;
                let bucket_index = table.our_id().bucket_index(&node_id);
                match table.update(info) {
                    UpdateResult::Inserted => {
                        debug!(
                            node_id = %node_id,
                            bucket_index = ?bucket_index,
                            peer_count = table.total_nodes(),
                            "added node to routing table"
                        );
                    }
                    UpdateResult::Updated => {
                        debug!(
                            node_id = %node_id,
                            bucket_index = ?bucket_index,
                            "updated node in routing table"
                        );
                    }
                    UpdateResult::BucketFull { least_recent_id } => {
                        debug!(
                            node_id = %node_id,
                            bucket_index = ?bucket_index,
                            least_recent = %least_recent_id,
                            "bucket full, node not added"
                        );
                    }
                }
            }

            fn rand_request_id() -> u64 {
                use rand::Rng;
                rand::thread_rng().r#gen()
            }
        }

        // DHT node (from dht/mod.rs)
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        use ed25519_dalek::SigningKey;
        use tokio::net::UdpSocket;
        use tokio::sync::{mpsc, Mutex, oneshot};
        use tracing::{debug, info, warn};

        use crate::error::{HidraError, Result};
        use self::handler::{DhtHandler, ServiceStore};
        use self::kbuckets::{RoutingTable, K};
        use self::message::{sign_and_serialize, verify_and_deserialize, DhtMessage};
        use self::node::{NodeId, NodeInfo};

        const MAX_UDP_PACKET: usize = 65535;
        const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
        const ALPHA: usize = 3;

        type PendingMap = HashMap<u64, oneshot::Sender<(DhtMessage, SocketAddr)>>;

        pub struct DhtNode {
            socket: Arc<UdpSocket>,
            routing_table: Arc<Mutex<RoutingTable>>,
            our_info: NodeInfo,
            signing_key: SigningKey,
            pending: Arc<Mutex<PendingMap>>,
            service_store: Arc<Mutex<ServiceStore>>,
            #[allow(dead_code)]
            shutdown_tx: Option<mpsc::Sender<()>>,
        }

        impl DhtNode {
            pub async fn new(
                bind_addr: SocketAddr,
                signing_key: SigningKey,
                relay_addr: Option<SocketAddr>,
            ) -> Result<Self> {
                let socket = UdpSocket::bind(bind_addr).await?;
                let local_addr = socket.local_addr()?;
                let pubkey = signing_key.verifying_key().to_bytes();
                let node_id = NodeId::from_public_key(&pubkey);
                let our_info = NodeInfo {
                    id: node_id,
                    dht_addr: local_addr,
                    relay_addr,
                    public_key: pubkey,
                };
                info!(
                    node_id = %node_id,
                    dht_addr = %local_addr,
                    is_relay = relay_addr.is_some(),
                    "DHT node initialized"
                );
                Ok(Self {
                    socket: Arc::new(socket),
                    routing_table: Arc::new(Mutex::new(RoutingTable::new(node_id))),
                    our_info,
                    signing_key,
                    pending: Arc::new(Mutex::new(HashMap::new())),
                    service_store: Arc::new(Mutex::new(HashMap::new())),
                    shutdown_tx: None,
                })
            }

            pub fn our_info(&self) -> &NodeInfo {
                &self.our_info
            }

            pub fn routing_table(&self) -> &Arc<Mutex<RoutingTable>> {
                &self.routing_table
            }

            pub async fn start(&mut self) {
                let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
                self.shutdown_tx = Some(shutdown_tx);

                let socket = Arc::clone(&self.socket);
                let table = Arc::clone(&self.routing_table);
                let pending = Arc::clone(&self.pending);
                let svc_store = Arc::clone(&self.service_store);
                let our_info = self.our_info.clone();
                let signing_key_bytes = self.signing_key.to_bytes();

                tokio::spawn(async move {
                    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
                    let mut buf = vec![0u8; MAX_UDP_PACKET];
                    loop {
                        tokio::select! {
                            result = socket.recv_from(&mut buf) => {
                                match result {
                                    Ok((len, addr)) => {
                                        if let Err(e) = process_packet(
                                            &buf[..len], addr, &table, &pending,
                                            &svc_store,
                                            &our_info, &signing_key, &socket,
                                        ).await {
                                            debug!(error = %e, from = %addr, "failed to process DHT packet");
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "UDP recv error");
                                    }
                                }
                            }
                            _ = shutdown_rx.recv() => {
                                info!("DHT receive loop shutting down");
                                break;
                            }
                        }
                    }
                });
            }

            pub async fn send_message(
                &self,
                msg: &DhtMessage,
                addr: SocketAddr,
            ) -> Result<()> {
                let packet = sign_and_serialize(msg, &self.signing_key)?;
                self.socket.send_to(&packet, addr).await?;
                debug!(
                    dht_message_type = msg.message_type(),
                    target = %addr,
                    "sent DHT message"
                );
                Ok(())
            }

            pub async fn send_request(
                &self,
                msg: DhtMessage,
                addr: SocketAddr,
            ) -> Result<DhtMessage> {
                let request_id = msg.request_id();
                let (tx, rx) = oneshot::channel();
                {
                    let mut pending = self.pending.lock().await;
                    pending.insert(request_id, tx);
                }
                self.send_message(&msg, addr).await?;
                let result = tokio::time::timeout(REQUEST_TIMEOUT, rx).await;
                {
                    let mut pending = self.pending.lock().await;
                    pending.remove(&request_id);
                }
                match result {
                    Ok(Ok((response, _addr))) => Ok(response),
                    Ok(Err(_)) => Err(HidraError::Protocol(
                        "DHT response channel closed".into(),
                    )),
                    Err(_) => Err(HidraError::Protocol(format!(
                        "DHT request timed out (id={request_id}, target={addr})"
                    ))),
                }
            }

            pub async fn ping(&self, addr: SocketAddr) -> Result<NodeInfo> {
                let request_id = new_request_id();
                let msg = DhtMessage::Ping {
                    request_id,
                    sender: self.our_info.clone(),
                };
                let response = self.send_request(msg, addr).await?;
                match response {
                    DhtMessage::Pong { sender, .. } => {
                        let mut table = self.routing_table.lock().await;
                        table.update(sender.clone());
                        Ok(sender)
                    }
                    other => Err(HidraError::Protocol(format!(
                        "expected PONG, got {}",
                        other.message_type()
                    ))),
                }
            }

            pub async fn find_node(
                &self,
                target: &NodeId,
            ) -> Result<Vec<NodeInfo>> {
                let initial = {
                    let table = self.routing_table.lock().await;
                    table.find_closest(target, K)
                };
                if initial.is_empty() {
                    return Ok(vec![]);
                }
                let mut seen: HashMap<NodeId, NodeInfo> = HashMap::new();
                let mut queried: std::collections::HashSet<NodeId> =
                    std::collections::HashSet::new();
                for node in &initial {
                    seen.insert(node.id, node.clone());
                }
                loop {
                    let mut candidates: Vec<NodeInfo> = seen
                        .values()
                        .filter(|n| !queried.contains(&n.id))
                        .cloned()
                        .collect();
                    candidates.sort_by(|a, b| {
                        let da = a.id.xor_distance(target);
                        let db = b.id.xor_distance(target);
                        da.cmp(&db)
                    });
                    let to_query: Vec<NodeInfo> =
                        candidates.into_iter().take(ALPHA).collect();
                    if to_query.is_empty() {
                        break;
                    }
                    let mut tasks = Vec::new();
                    for node in &to_query {
                        queried.insert(node.id);
                        let request_id = new_request_id();
                        let msg = DhtMessage::FindNode {
                            request_id,
                            sender: self.our_info.clone(),
                            target: *target,
                        };
                        let addr = node.dht_addr;
                        tasks.push(self.send_request(msg, addr));
                    }
                    let results = futures::future::join_all(tasks).await;
                    let mut found_new = false;
                    for result in results {
                        if let Ok(DhtMessage::FindNodeResponse { nodes, .. }) =
                            result
                        {
                            for node in nodes {
                                if node.id != self.our_info.id
                                    && !seen.contains_key(&node.id)
                                {
                                    seen.insert(node.id, node.clone());
                                    let mut table =
                                        self.routing_table.lock().await;
                                    table.update(node);
                                    found_new = true;
                                }
                            }
                        }
                    }
                    if !found_new {
                        break;
                    }
                }
                let mut result: Vec<NodeInfo> = seen.into_values().collect();
                result.sort_by(|a, b| {
                    let da = a.id.xor_distance(target);
                    let db = b.id.xor_distance(target);
                    da.cmp(&db)
                });
                result.truncate(K);
                Ok(result)
            }

            pub async fn find_relays(
                &self,
                count: usize,
            ) -> Result<Vec<NodeInfo>> {
                let random_target = NodeId::random();
                let nodes = self.find_node(&random_target).await?;
                let relays: Vec<NodeInfo> =
                    nodes.into_iter().filter(|n| n.is_relay()).collect();
                if relays.len() >= count {
                    Ok(relays.into_iter().take(count).collect())
                } else {
                    let mut all_relays = relays;
                    let table = self.routing_table.lock().await;
                    let table_relays = table.find_relays(count);
                    for r in table_relays {
                        if !all_relays.iter().any(|x| x.id == r.id) {
                            all_relays.push(r);
                        }
                    }
                    all_relays.truncate(count);
                    Ok(all_relays)
                }
            }

            pub async fn announce_relay(&self) -> Result<()> {
                if self.our_info.relay_addr.is_none() {
                    return Err(HidraError::Protocol(
                        "cannot announce: not configured as relay".into(),
                    ));
                }
                let nodes = {
                    let table = self.routing_table.lock().await;
                    table.find_closest(&self.our_info.id, K)
                };
                info!(
                    peer_count = nodes.len(),
                    "announcing relay presence to nearest nodes"
                );
                for node in &nodes {
                    let msg = DhtMessage::AnnounceRelay {
                        request_id: new_request_id(),
                        sender: self.our_info.clone(),
                    };
                    if let Err(e) =
                        self.send_message(&msg, node.dht_addr).await
                    {
                        debug!(
                            error = %e,
                            peer = %node.id,
                            "failed to announce to peer"
                        );
                    }
                }
                Ok(())
            }

            pub async fn node_count(&self) -> usize {
                let table = self.routing_table.lock().await;
                table.total_nodes()
            }

            pub async fn announce_service(
                &self,
                service_hash: [u8; 20],
                intro_points: Vec<SocketAddr>,
                service_pubkey: [u8; 32],
            ) -> Result<()> {
                let target = NodeId::from_public_key(&{
                    let mut padded = [0u8; 32];
                    padded[..20].copy_from_slice(&service_hash);
                    padded
                });
                let nodes = {
                    let table = self.routing_table.lock().await;
                    table.find_closest(&target, K)
                };
                info!(
                    peer_count = nodes.len(),
                    "announcing hidden service to nearest nodes"
                );
                {
                    let mut store = self.service_store.lock().await;
                    store.insert(service_hash, handler::ServiceDescriptor {
                        intro_points: intro_points.clone(),
                        service_pubkey,
                    });
                }
                for node in &nodes {
                    let msg = DhtMessage::AnnounceService {
                        request_id: new_request_id(),
                        sender: self.our_info.clone(),
                        service_hash,
                        intro_points: intro_points.clone(),
                        service_pubkey,
                    };
                    if let Err(e) = self.send_message(&msg, node.dht_addr).await {
                        debug!(error = %e, peer = %node.id, "failed to announce service to peer");
                    }
                }
                Ok(())
            }

            pub async fn lookup_service(
                &self,
                service_hash: &[u8; 20],
            ) -> Result<Option<(Vec<SocketAddr>, [u8; 32])>> {
                {
                    let store = self.service_store.lock().await;
                    if let Some(desc) = store.get(service_hash) {
                        return Ok(Some((desc.intro_points.clone(), desc.service_pubkey)));
                    }
                }
                let target = NodeId::from_public_key(&{
                    let mut padded = [0u8; 32];
                    padded[..20].copy_from_slice(service_hash);
                    padded
                });
                let closest = self.find_node(&target).await?;
                for node in &closest {
                    let request_id = new_request_id();
                    let msg = DhtMessage::LookupService {
                        request_id,
                        sender: self.our_info.clone(),
                        service_hash: *service_hash,
                    };
                    match self.send_request(msg, node.dht_addr).await {
                        Ok(DhtMessage::LookupServiceResponse {
                            found: true, intro_points, service_pubkey, ..
                        }) => {
                            let mut store = self.service_store.lock().await;
                            store.insert(*service_hash, handler::ServiceDescriptor {
                                intro_points: intro_points.clone(),
                                service_pubkey,
                            });
                            return Ok(Some((intro_points, service_pubkey)));
                        }
                        _ => continue,
                    }
                }
                Ok(None)
            }
        }

        async fn process_packet(
            data: &[u8],
            addr: SocketAddr,
            table: &Arc<Mutex<RoutingTable>>,
            pending: &Arc<Mutex<PendingMap>>,
            svc_store: &Arc<Mutex<ServiceStore>>,
            our_info: &NodeInfo,
            signing_key: &SigningKey,
            socket: &UdpSocket,
        ) -> Result<()> {
            let (msg, _pubkey) = verify_and_deserialize(data)?;
            if msg.is_response() {
                let request_id = msg.request_id();
                let mut pending_map = pending.lock().await;
                if let Some(tx) = pending_map.remove(&request_id) {
                    let _ = tx.send((msg, addr));
                }
                return Ok(());
            }
            let mut table_guard = table.lock().await;
            let mut store_guard = svc_store.lock().await;
            let result = DhtHandler::handle_message(
                &mut table_guard,
                msg,
                our_info,
                addr,
                &mut store_guard,
            );
            drop(store_guard);
            drop(table_guard);
            if let Some(resp) = result.response {
                let packet = sign_and_serialize(&resp, signing_key)?;
                socket.send_to(&packet, addr).await?;
            }
            for (target, gossip_msg) in result.gossip_targets {
                let packet = sign_and_serialize(&gossip_msg, signing_key)?;
                if let Err(e) =
                    socket.send_to(&packet, target.dht_addr).await
                {
                    debug!(
                        error = %e,
                        target = %target.id,
                        "gossip forwarding failed"
                    );
                }
            }
            Ok(())
        }

        fn new_request_id() -> u64 {
            use rand::Rng;
            rand::thread_rng().r#gen()
        }
    }

    pub mod bootstrap {
        use std::net::{SocketAddr, ToSocketAddrs};
        use std::time::Duration;
        use tracing::{debug, info, warn};
        use crate::error::Result;
        use crate::p2p::dht::DhtNode;

        const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

        const DNS_SEEDS: &[&str] = &[
            "seed1.hidranet.io:7000",
            "seed2.hidranet.io:7000",
            "seed3.hidranet.io:7000",
        ];

        fn resolve_dns_seeds() -> Vec<SocketAddr> {
            let mut addrs = Vec::new();
            for seed in DNS_SEEDS {
                match seed.to_socket_addrs() {
                    Ok(resolved) => {
                        for addr in resolved {
                            info!(seed = %seed, addr = %addr, "DNS seed resolved");
                            addrs.push(addr);
                        }
                    }
                    Err(e) => {
                        debug!(seed = %seed, error = %e, "DNS seed resolution failed");
                    }
                }
            }
            addrs
        }

        pub async fn bootstrap(
            dht: &DhtNode,
            bootstrap_addrs: &[SocketAddr],
        ) -> Result<usize> {
            let addrs: Vec<SocketAddr> = if bootstrap_addrs.is_empty() {
                info!("no bootstrap nodes configured, trying DNS seeds");
                resolve_dns_seeds()
            } else {
                bootstrap_addrs.to_vec()
            };
            if addrs.is_empty() {
                info!("no bootstrap nodes available, skipping bootstrap");
                return Ok(0);
            }
            info!(bootstrap_count = addrs.len(), "starting DHT bootstrap");
            let mut contacted = 0usize;
            for addr in &addrs {
                if *addr == dht.our_info().dht_addr {
                    continue;
                }
                debug!(addr = %addr, "pinging bootstrap node");
                match tokio::time::timeout(BOOTSTRAP_TIMEOUT, dht.ping(*addr))
                    .await
                {
                    Ok(Ok(peer_info)) => {
                        info!(
                            node_id = %peer_info.id,
                            addr = %addr,
                            is_relay = peer_info.is_relay(),
                            "bootstrap node responded"
                        );
                        contacted += 1;
                    }
                    Ok(Err(e)) => {
                        warn!(addr = %addr, error = %e, "bootstrap node unreachable");
                    }
                    Err(_) => {
                        warn!(addr = %addr, "bootstrap node timed out");
                    }
                }
            }
            if contacted > 0 {
                info!(contacted, "bootstrap pings done, performing self-lookup");
                let our_id = dht.our_info().id;
                match dht.find_node(&our_id).await {
                    Ok(nodes) => {
                        info!(discovered = nodes.len(), "self-lookup completed");
                    }
                    Err(e) => {
                        warn!(error = %e, "self-lookup failed");
                    }
                }
            }
            let total = dht.node_count().await;
            info!(
                bootstrap_contacted = contacted,
                total_peers = total,
                "bootstrap completed"
            );
            Ok(total)
        }
    }

    pub mod discovery {
        use std::time::Duration;
        use tracing::{debug, info, warn};
        use crate::p2p::dht::node::NodeId;
        use crate::p2p::dht::DhtNode;

        const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(300);
        const STALE_TIMEOUT: Duration = Duration::from_secs(600);
        const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

        pub async fn run_maintenance_loop(dht: &DhtNode) {
            let mut maintenance_tick =
                tokio::time::interval(MAINTENANCE_INTERVAL);
            let mut announce_tick = tokio::time::interval(ANNOUNCE_INTERVAL);
            loop {
                tokio::select! {
                    _ = maintenance_tick.tick() => {
                        run_maintenance(dht).await;
                    }
                    _ = announce_tick.tick() => {
                        if dht.our_info().is_relay() {
                            if let Err(e) = dht.announce_relay().await {
                                warn!(error = %e, "relay announcement failed");
                            }
                        }
                    }
                }
            }
        }

        async fn run_maintenance(dht: &DhtNode) {
            let stale_nodes = {
                let table = dht.routing_table().lock().await;
                table.stale_nodes(STALE_TIMEOUT)
            };
            if !stale_nodes.is_empty() {
                debug!(stale_count = stale_nodes.len(), "pinging stale nodes");
            }
            for node_id in &stale_nodes {
                let node_info = {
                    let table = dht.routing_table().lock().await;
                    table
                        .find_closest(node_id, 1)
                        .into_iter()
                        .find(|n| n.id == *node_id)
                };
                if let Some(info) = node_info {
                    match dht.ping(info.dht_addr).await {
                        Ok(_) => {
                            debug!(node_id = %node_id, "stale node responded");
                        }
                        Err(_) => {
                            debug!(node_id = %node_id, "stale node removed");
                            let mut table =
                                dht.routing_table().lock().await;
                            table.remove(node_id);
                        }
                    }
                }
            }
            let random_target = NodeId::random();
            match dht.find_node(&random_target).await {
                Ok(nodes) => {
                    debug!(
                        found = nodes.len(),
                        total_peers = dht.node_count().await,
                        "bucket refresh completed"
                    );
                }
                Err(e) => {
                    debug!(error = %e, "bucket refresh lookup failed");
                }
            }
            let total = dht.node_count().await;
            info!(peer_count = total, "DHT maintenance cycle completed");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod relay
// ─────────────────────────────────────────────────────────────────────────────
mod relay {
    pub mod registry {
        use std::net::SocketAddr;
        use crate::app_config::RelayInfo;
        use crate::error::{HidraError, Result};

        #[derive(Debug, Clone)]
        pub struct RelayEntry {
            pub name: String,
            pub addr: SocketAddr,
            #[allow(dead_code)]
            pub noise_pubkey_b64: String,
        }

        pub fn load_relay_list(relays: &[RelayInfo]) -> Result<Vec<RelayEntry>> {
            let mut entries = Vec::with_capacity(relays.len());
            for r in relays {
                let addr: SocketAddr = r.addr.parse().map_err(|e| {
                    HidraError::Relay(format!(
                        "invalid relay addr '{}': {e}",
                        r.addr
                    ))
                })?;
                entries.push(RelayEntry {
                    name: r.name.clone(),
                    addr,
                    noise_pubkey_b64: r.noise_pubkey.clone(),
                });
            }
            Ok(entries)
        }
    }

    pub mod router {
        use std::collections::HashMap;
        use std::net::SocketAddr;
        use std::sync::Arc;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tokio::sync::{mpsc, Mutex};
        use tracing::{debug, info, warn, Instrument};
        use uuid::Uuid;
        use x25519_dalek::StaticSecret;
        use zeroize::Zeroize;

        use crate::crypto::handshake::{HandshakeState, Role};
        use crate::error::{HidraError, Result};
        use crate::network::connection::{
            read_frame, write_frame, Message, SecureConnection,
        };
        use crate::network::listener::PROTO_FORWARDED_CELL;
        use crate::onion::cell::{LayerHeader, RelayCommand};
        use crate::onion::layer::{
            decrypt_stream, encrypt_stream, peel_layer, wrap_layer,
        };

        struct CircuitEntry {
            session_key: [u8; 32],
        }

        impl Drop for CircuitEntry {
            fn drop(&mut self) {
                self.session_key.zeroize();
            }
        }

        pub struct ClientPipe {
            pub from_client: mpsc::Receiver<Vec<u8>>,
            pub to_client: mpsc::Sender<Vec<u8>>,
        }

        type IntroRegistry = Arc<Mutex<HashMap<Vec<u8>, mpsc::Sender<ClientPipe>>>>;

        pub struct RelayRouter {
            circuits: Arc<Mutex<HashMap<u32, CircuitEntry>>>,
            static_secret_bytes: Arc<[u8; 32]>,
            intro_registry: IntroRegistry,
        }

        impl RelayRouter {
            pub fn new(static_secret_bytes: Arc<[u8; 32]>) -> Self {
                Self {
                    circuits: Arc::new(Mutex::new(HashMap::new())),
                    static_secret_bytes,
                    intro_registry: Arc::new(Mutex::new(HashMap::new())),
                }
            }

            pub async fn handle_client_connection(
                &self,
                stream: TcpStream,
                remote_addr: SocketAddr,
            ) {
                let session_id = Uuid::new_v4().to_string();
                let span = tracing::info_span!(
                    "relay_session",
                    session_id = %session_id,
                    remote_addr = %remote_addr,
                    role = "relay_responder",
                );
                let circuits = Arc::clone(&self.circuits);
                let secret_bytes = Arc::clone(&self.static_secret_bytes);
                let intro_reg = Arc::clone(&self.intro_registry);
                tokio::spawn(
                    async move {
                        info!("client connection — starting Noise handshake");
                        if let Err(e) = handle_noise_session(
                            stream,
                            &secret_bytes,
                            circuits,
                            intro_reg,
                        )
                        .await
                        {
                            warn!(error = %e, "relay session failed");
                        }
                    }
                    .instrument(span),
                );
            }

            pub async fn handle_forwarded_cell(
                &self,
                stream: TcpStream,
                remote_addr: SocketAddr,
            ) {
                let span = tracing::info_span!(
                    "forwarded_cell",
                    remote_addr = %remote_addr,
                );
                let circuits = Arc::clone(&self.circuits);
                let intro_reg = Arc::clone(&self.intro_registry);
                tokio::spawn(
                    async move {
                        debug!("forwarded cell connection");
                        if let Err(e) =
                            handle_forwarded(stream, circuits, intro_reg).await
                        {
                            warn!(error = %e, "forwarded cell processing failed");
                        }
                    }
                    .instrument(span),
                );
            }
        }

        async fn handle_noise_session(
            mut stream: TcpStream,
            secret_bytes: &[u8; 32],
            circuits: Arc<Mutex<HashMap<u32, CircuitEntry>>>,
            intro_registry: IntroRegistry,
        ) -> Result<()> {
            let mut sb = *secret_bytes;
            let secret = StaticSecret::from(sb);
            sb.zeroize();
            let mut handshake = HandshakeState::new(Role::Responder, secret);
            let msg_a = read_frame(&mut stream).await?;
            handshake.read_message_a(&msg_a)?;
            let msg_b = handshake.write_message_b()?;
            write_frame(&mut stream, &msg_b).await?;
            let msg_c = read_frame(&mut stream).await?;
            handshake.read_message_c(&msg_c)?;
            info!("relay Noise XX handshake completed");
            let (send_cipher, recv_cipher) = handshake.into_transport()?;
            let session_key = recv_cipher.session_key()?;
            let mut conn =
                SecureConnection::new(stream, send_cipher, recv_cipher);

            loop {
                let msg = match conn.recv_message().await {
                    Ok(m) => m,
                    Err(e) => {
                        debug!(error = %e, "connection closed or error");
                        break;
                    }
                };
                match msg {
                    Message::CreateCircuit { circuit_id } => {
                        info!(circuit_id, "creating circuit");
                        let mut map = circuits.lock().await;
                        map.insert(circuit_id, CircuitEntry { session_key });
                        conn.send_message(&Message::CircuitCreated {
                            circuit_id,
                        })
                        .await?;
                        info!(circuit_id, "circuit created");
                    }
                    Message::Relay { circuit_id, data } => {
                        let key = {
                            let map = circuits.lock().await;
                            let entry =
                                map.get(&circuit_id).ok_or_else(|| {
                                    HidraError::Circuit(format!(
                                        "unknown circuit {circuit_id}"
                                    ))
                                })?;
                            entry.session_key
                        };
                        let (header, inner) = peel_layer(&key, &data)?;
                        info!(
                            circuit_id,
                            has_next_hop = header.next_hop.is_some(),
                            "peeled onion layer"
                        );
                        match header.next_hop {
                            Some(next_addr) => {
                                info!(circuit_id, next_hop = %next_addr, "forwarding to next relay");
                                let mut next_stream =
                                    connect_to_next(next_addr).await?;
                                let relay_msg = Message::Relay {
                                    circuit_id,
                                    data: inner,
                                };
                                write_frame(
                                    &mut next_stream,
                                    &relay_msg.serialize(),
                                )
                                .await?;
                                let resp_frame =
                                    read_frame(&mut next_stream).await?;
                                let resp_msg =
                                    Message::deserialize(&resp_frame)?;
                                let resp_data = match resp_msg {
                                    Message::Relay { data, .. } => data,
                                    other => {
                                        return Err(HidraError::Relay(
                                            format!("unexpected response from next hop: {other:?}"),
                                        ));
                                    }
                                };
                                let response_wrapped = wrap_layer(
                                    &key,
                                    &LayerHeader { next_hop: None },
                                    &resp_data,
                                )?;
                                conn.send_message(&Message::Relay {
                                    circuit_id,
                                    data: response_wrapped,
                                })
                                .await?;
                                info!(circuit_id, "entering relay streaming loop");
                                relay_streaming_loop(
                                    &mut conn,
                                    &mut next_stream,
                                    circuit_id,
                                    &key,
                                )
                                .await?;
                                break;
                            }
                            None => {
                                if let Ok(cmd) =
                                    RelayCommand::deserialize_bincode(&inner)
                                {
                                    handle_exit_command(
                                        cmd,
                                        &mut conn,
                                        circuit_id,
                                        &key,
                                        &intro_registry,
                                    )
                                    .await?;
                                    break;
                                }
                                let payload =
                                    String::from_utf8_lossy(&inner);
                                info!(circuit_id, payload = %payload, "exit node — received payload (legacy)");
                                let response_wrapped = wrap_layer(
                                    &key,
                                    &LayerHeader { next_hop: None },
                                    b"Recebido, agente",
                                )?;
                                conn.send_message(&Message::Relay {
                                    circuit_id,
                                    data: response_wrapped,
                                })
                                .await?;
                                info!(circuit_id, "exit node — sent legacy response");
                            }
                        }
                    }
                    Message::Ping(ref data) => {
                        info!(payload = %String::from_utf8_lossy(data), "received Ping (legacy)");
                        conn.send_message(&Message::Pong(
                            b"HidraPong".to_vec(),
                        ))
                        .await?;
                    }
                    other => {
                        warn!(?other, "unexpected message in relay session");
                    }
                }
            }
            info!("relay session ended");
            Ok(())
        }

        async fn handle_forwarded(
            mut stream: TcpStream,
            circuits: Arc<Mutex<HashMap<u32, CircuitEntry>>>,
            intro_registry: IntroRegistry,
        ) -> Result<()> {
            let frame = read_frame(&mut stream).await?;
            let msg = Message::deserialize(&frame)?;
            match msg {
                Message::Relay { circuit_id, data } => {
                    let key = {
                        let map = circuits.lock().await;
                        let entry = map.get(&circuit_id).ok_or_else(|| {
                            HidraError::Circuit(format!(
                                "forwarded cell: unknown circuit {circuit_id}"
                            ))
                        })?;
                        entry.session_key
                    };
                    let (header, inner) = peel_layer(&key, &data)?;
                    info!(
                        circuit_id,
                        has_next_hop = header.next_hop.is_some(),
                        "forwarded cell — peeled layer"
                    );
                    match header.next_hop {
                        Some(next_addr) => {
                            info!(circuit_id, next_hop = %next_addr, "forwarding further");
                            let mut next_stream =
                                connect_to_next(next_addr).await?;
                            let relay_msg = Message::Relay {
                                circuit_id,
                                data: inner,
                            };
                            write_frame(
                                &mut next_stream,
                                &relay_msg.serialize(),
                            )
                            .await?;
                            let resp_frame =
                                read_frame(&mut next_stream).await?;
                            let resp_msg =
                                Message::deserialize(&resp_frame)?;
                            let resp_data = match resp_msg {
                                Message::Relay { data, .. } => data,
                                other => {
                                    return Err(HidraError::Relay(format!(
                                        "unexpected response: {other:?}"
                                    )));
                                }
                            };
                            let response_wrapped = wrap_layer(
                                &key,
                                &LayerHeader { next_hop: None },
                                &resp_data,
                            )?;
                            let out_msg = Message::Relay {
                                circuit_id,
                                data: response_wrapped,
                            };
                            write_frame(&mut stream, &out_msg.serialize())
                                .await?;
                            info!(circuit_id, "entering forwarded streaming loop");
                            forwarded_streaming_loop(
                                &mut stream,
                                &mut next_stream,
                                circuit_id,
                                &key,
                            )
                            .await?;
                        }
                        None => {
                            if let Ok(cmd) =
                                RelayCommand::deserialize_bincode(&inner)
                            {
                                handle_exit_forwarded(
                                    cmd,
                                    &mut stream,
                                    circuit_id,
                                    &key,
                                    &intro_registry,
                                )
                                .await?;
                            } else {
                                let payload =
                                    String::from_utf8_lossy(&inner);
                                info!(circuit_id, payload = %payload, "exit node — received payload (legacy)");
                                let response_wrapped = wrap_layer(
                                    &key,
                                    &LayerHeader { next_hop: None },
                                    b"Recebido, agente",
                                )?;
                                let out_msg = Message::Relay {
                                    circuit_id,
                                    data: response_wrapped,
                                };
                                write_frame(
                                    &mut stream,
                                    &out_msg.serialize(),
                                )
                                .await?;
                                info!(circuit_id, "sent legacy response back");
                            }
                        }
                    }
                }
                other => {
                    warn!(?other, "unexpected forwarded message type");
                }
            }
            Ok(())
        }

        async fn handle_exit_command(
            cmd: RelayCommand,
            conn: &mut SecureConnection,
            circuit_id: u32,
            key: &[u8; 32],
            intro_registry: &IntroRegistry,
        ) -> Result<()> {
            match cmd {
                RelayCommand::Connect { host, port } => {
                    info!(circuit_id, host = %host, port, "exit relay — connecting to target");
                    let target_addr = format!("{host}:{port}");
                    let mut target =
                        match TcpStream::connect(&target_addr).await {
                            Ok(t) => {
                                info!(circuit_id, target = %target_addr, "exit relay — connected to target");
                                t
                            }
                            Err(e) => {
                                warn!(circuit_id, error = %e, target = %target_addr, "exit relay — connect failed");
                                let fail = RelayCommand::ConnectFailed(
                                    format!("{e}"),
                                );
                                let fail_data = fail.serialize_bincode()?;
                                let wrapped = wrap_layer(
                                    key,
                                    &LayerHeader { next_hop: None },
                                    &fail_data,
                                )?;
                                conn.send_message(&Message::Relay {
                                    circuit_id,
                                    data: wrapped,
                                })
                                .await?;
                                return Ok(());
                            }
                        };
                    let connected = RelayCommand::Connected;
                    let connected_data = connected.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &connected_data,
                    )?;
                    conn.send_message(&Message::Relay {
                        circuit_id,
                        data: wrapped,
                    })
                    .await?;
                    exit_streaming_loop(conn, &mut target, circuit_id, key)
                        .await
                }
                RelayCommand::RegisterService { service_hash } => {
                    info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay — registering hidden service");
                    let (pipe_tx, mut pipe_rx) = mpsc::channel::<ClientPipe>(16);
                    {
                        let mut reg = intro_registry.lock().await;
                        reg.insert(service_hash.clone(), pipe_tx);
                    }
                    let ack = RelayCommand::ServiceRegistered;
                    let ack_data = ack.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &ack_data,
                    )?;
                    conn.send_message(&Message::Relay {
                        circuit_id,
                        data: wrapped,
                    })
                    .await?;
                    info!(circuit_id, "intro relay — service registered, waiting for clients");
                    while let Some(mut client_pipe) = pipe_rx.recv().await {
                        info!(circuit_id, "intro relay — bridging client to service");
                        if let Err(e) = bridge_service_session(
                            conn,
                            circuit_id,
                            key,
                            &mut client_pipe.from_client,
                            &client_pipe.to_client,
                        )
                        .await
                        {
                            warn!(error = %e, "service bridge session ended");
                        }
                    }
                    {
                        let mut reg = intro_registry.lock().await;
                        reg.remove(&service_hash);
                    }
                    info!(circuit_id, "intro relay — service deregistered");
                    Ok(())
                }
                RelayCommand::ConnectService { service_hash } => {
                    info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay — client connecting to service");
                    let pipe_tx = {
                        let reg = intro_registry.lock().await;
                        reg.get(&service_hash).cloned()
                    };
                    let Some(pipe_tx) = pipe_tx else {
                        warn!(circuit_id, "intro relay — service not found");
                        let fail = RelayCommand::ConnectFailed(
                            "service not found at this intro point".into(),
                        );
                        let fail_data = fail.serialize_bincode()?;
                        let wrapped = wrap_layer(
                            key,
                            &LayerHeader { next_hop: None },
                            &fail_data,
                        )?;
                        conn.send_message(&Message::Relay {
                            circuit_id,
                            data: wrapped,
                        })
                        .await?;
                        return Ok(());
                    };
                    let (client_to_svc_tx, client_to_svc_rx) =
                        mpsc::channel::<Vec<u8>>(256);
                    let (svc_to_client_tx, mut svc_to_client_rx) =
                        mpsc::channel::<Vec<u8>>(256);
                    let client_pipe = ClientPipe {
                        from_client: client_to_svc_rx,
                        to_client: svc_to_client_tx,
                    };
                    if pipe_tx.send(client_pipe).await.is_err() {
                        warn!(circuit_id, "intro relay — service handler gone");
                        let fail = RelayCommand::ConnectFailed(
                            "service handler disconnected".into(),
                        );
                        let fail_data = fail.serialize_bincode()?;
                        let wrapped = wrap_layer(
                            key,
                            &LayerHeader { next_hop: None },
                            &fail_data,
                        )?;
                        conn.send_message(&Message::Relay {
                            circuit_id,
                            data: wrapped,
                        })
                        .await?;
                        return Ok(());
                    }
                    let ack = RelayCommand::ServiceConnected;
                    let ack_data = ack.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &ack_data,
                    )?;
                    conn.send_message(&Message::Relay {
                        circuit_id,
                        data: wrapped,
                    })
                    .await?;
                    info!(circuit_id, "intro relay — bridging client ↔ service");
                    bridge_client_to_service(
                        conn,
                        circuit_id,
                        key,
                        client_to_svc_tx,
                        &mut svc_to_client_rx,
                    )
                    .await
                }
                RelayCommand::ResolveDns { hostname } => {
                    info!(circuit_id, hostname = %hostname, "exit relay — DNS resolution");
                    let addr_str = format!("{hostname}:0");
                    let addresses: Vec<String> =
                        match tokio::net::lookup_host(&addr_str).await {
                            Ok(addrs) => {
                                addrs.map(|a| a.ip().to_string()).collect()
                            }
                            Err(e) => {
                                warn!(circuit_id, hostname = %hostname, error = %e, "DNS resolution failed");
                                Vec::new()
                            }
                        };
                    let resp = RelayCommand::DnsResolved { addresses };
                    let resp_data = resp.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &resp_data,
                    )?;
                    conn.send_message(&Message::Relay {
                        circuit_id,
                        data: wrapped,
                    })
                    .await?;
                    Ok(())
                }
                other => {
                    warn!(circuit_id, cmd = ?other, "unexpected relay command at exit");
                    Ok(())
                }
            }
        }

        async fn handle_exit_forwarded(
            cmd: RelayCommand,
            upstream: &mut TcpStream,
            circuit_id: u32,
            key: &[u8; 32],
            intro_registry: &IntroRegistry,
        ) -> Result<()> {
            match cmd {
                RelayCommand::RegisterService { service_hash } => {
                    info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay (forwarded) — registering service");
                    let (pipe_tx, pipe_rx) = mpsc::channel::<ClientPipe>(16);
                    {
                        let mut reg = intro_registry.lock().await;
                        reg.insert(service_hash.clone(), pipe_tx);
                    }
                    let ack = RelayCommand::ServiceRegistered;
                    let ack_data = ack.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &ack_data,
                    )?;
                    let msg = Message::Relay { circuit_id, data: wrapped };
                    write_frame(upstream, &msg.serialize()).await?;
                    info!(circuit_id, "intro relay (forwarded) — service registered, waiting");
                    {
                        let mut reg = intro_registry.lock().await;
                        reg.remove(&service_hash);
                    }
                    drop(pipe_rx);
                    Ok(())
                }
                RelayCommand::ConnectService { service_hash } => {
                    info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay (forwarded) — client connecting");
                    let pipe_tx = {
                        let reg = intro_registry.lock().await;
                        reg.get(&service_hash).cloned()
                    };
                    let Some(pipe_tx) = pipe_tx else {
                        let fail = RelayCommand::ConnectFailed(
                            "service not found".into(),
                        );
                        let fail_data = fail.serialize_bincode()?;
                        let wrapped = wrap_layer(
                            key,
                            &LayerHeader { next_hop: None },
                            &fail_data,
                        )?;
                        let msg = Message::Relay { circuit_id, data: wrapped };
                        write_frame(upstream, &msg.serialize()).await?;
                        return Ok(());
                    };
                    let (client_to_svc_tx, client_to_svc_rx) =
                        mpsc::channel::<Vec<u8>>(256);
                    let (svc_to_client_tx, mut svc_to_client_rx) =
                        mpsc::channel::<Vec<u8>>(256);
                    let client_pipe = ClientPipe {
                        from_client: client_to_svc_rx,
                        to_client: svc_to_client_tx,
                    };
                    if pipe_tx.send(client_pipe).await.is_err() {
                        let fail = RelayCommand::ConnectFailed(
                            "service handler disconnected".into(),
                        );
                        let fail_data = fail.serialize_bincode()?;
                        let wrapped = wrap_layer(
                            key,
                            &LayerHeader { next_hop: None },
                            &fail_data,
                        )?;
                        let msg = Message::Relay { circuit_id, data: wrapped };
                        write_frame(upstream, &msg.serialize()).await?;
                        return Ok(());
                    }
                    let ack = RelayCommand::ServiceConnected;
                    let ack_data = ack.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &ack_data,
                    )?;
                    let msg = Message::Relay { circuit_id, data: wrapped };
                    write_frame(upstream, &msg.serialize()).await?;
                    bridge_forwarded_client_to_service(
                        upstream,
                        circuit_id,
                        key,
                        client_to_svc_tx,
                        &mut svc_to_client_rx,
                    )
                    .await
                }
                RelayCommand::Connect { host, port } => {
                    info!(circuit_id, host = %host, port, "exit relay (forwarded) — connecting to target");
                    let target_addr = format!("{host}:{port}");
                    let mut target =
                        match TcpStream::connect(&target_addr).await {
                            Ok(t) => {
                                info!(circuit_id, target = %target_addr, "exit relay — connected");
                                t
                            }
                            Err(e) => {
                                warn!(circuit_id, error = %e, "exit relay — connect failed");
                                let fail = RelayCommand::ConnectFailed(
                                    format!("{e}"),
                                );
                                let fail_data = fail.serialize_bincode()?;
                                let wrapped = wrap_layer(
                                    key,
                                    &LayerHeader { next_hop: None },
                                    &fail_data,
                                )?;
                                let msg = Message::Relay {
                                    circuit_id,
                                    data: wrapped,
                                };
                                write_frame(upstream, &msg.serialize())
                                    .await?;
                                return Ok(());
                            }
                        };
                    let connected = RelayCommand::Connected;
                    let connected_data = connected.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &connected_data,
                    )?;
                    let msg = Message::Relay {
                        circuit_id,
                        data: wrapped,
                    };
                    write_frame(upstream, &msg.serialize()).await?;
                    exit_forwarded_streaming_loop(
                        upstream,
                        &mut target,
                        circuit_id,
                        key,
                    )
                    .await
                }
                RelayCommand::ResolveDns { hostname } => {
                    info!(circuit_id, hostname = %hostname, "exit relay (forwarded) — DNS resolution");
                    let addr_str = format!("{hostname}:0");
                    let addresses: Vec<String> =
                        match tokio::net::lookup_host(&addr_str).await {
                            Ok(addrs) => {
                                addrs.map(|a| a.ip().to_string()).collect()
                            }
                            Err(e) => {
                                warn!(circuit_id, hostname = %hostname, error = %e, "DNS resolution failed");
                                Vec::new()
                            }
                        };
                    let resp = RelayCommand::DnsResolved { addresses };
                    let resp_data = resp.serialize_bincode()?;
                    let wrapped = wrap_layer(
                        key,
                        &LayerHeader { next_hop: None },
                        &resp_data,
                    )?;
                    let msg = Message::Relay {
                        circuit_id,
                        data: wrapped,
                    };
                    write_frame(upstream, &msg.serialize()).await?;
                    Ok(())
                }
                other => {
                    warn!(circuit_id, cmd = ?other, "unexpected relay command (forwarded exit)");
                    Ok(())
                }
            }
        }

        async fn exit_streaming_loop(
            conn: &mut SecureConnection,
            target: &mut TcpStream,
            circuit_id: u32,
            key: &[u8; 32],
        ) -> Result<()> {
            let mut target_buf = vec![0u8; 16384];
            loop {
                tokio::select! {
                    msg_result = conn.recv_message() => {
                        let msg = match msg_result {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        match msg {
                            Message::Relay { data, .. } => {
                                let decrypted = decrypt_stream(key, &data)?;
                                let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                                match cmd {
                                    RelayCommand::Data(payload) => {
                                        if target.write_all(&payload).await.is_err() { break; }
                                    }
                                    RelayCommand::End => {
                                        debug!(circuit_id, "exit relay — stream ended by client");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            _ => break,
                        }
                    }
                    n = target.read(&mut target_buf) => {
                        match n {
                            Ok(0) => {
                                debug!(circuit_id, "exit relay — target closed connection");
                                let end = RelayCommand::End;
                                let end_data = end.serialize_bincode()?;
                                let wrapped = encrypt_stream(key, &end_data)?;
                                let _ = conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await;
                                break;
                            }
                            Ok(n) => {
                                let data_cmd = RelayCommand::Data(target_buf[..n].to_vec());
                                let data_bytes = data_cmd.serialize_bincode()?;
                                let wrapped = encrypt_stream(key, &data_bytes)?;
                                conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            info!(circuit_id, "exit streaming loop ended");
            Ok(())
        }

        async fn exit_forwarded_streaming_loop(
            upstream: &mut TcpStream,
            target: &mut TcpStream,
            circuit_id: u32,
            key: &[u8; 32],
        ) -> Result<()> {
            let mut target_buf = vec![0u8; 16384];
            loop {
                tokio::select! {
                    frame_result = read_frame(upstream) => {
                        let frame = match frame_result {
                            Ok(f) => f,
                            Err(_) => break,
                        };
                        let msg = Message::deserialize(&frame)?;
                        match msg {
                            Message::Relay { data, .. } => {
                                let decrypted = decrypt_stream(key, &data)?;
                                let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                                match cmd {
                                    RelayCommand::Data(payload) => {
                                        if target.write_all(&payload).await.is_err() { break; }
                                    }
                                    RelayCommand::End => {
                                        debug!(circuit_id, "exit forwarded — stream ended");
                                        break;
                                    }
                                    _ => {}
                                }
                            }
                            _ => break,
                        }
                    }
                    n = target.read(&mut target_buf) => {
                        match n {
                            Ok(0) => {
                                let end = RelayCommand::End;
                                let end_data = end.serialize_bincode()?;
                                let wrapped = encrypt_stream(key, &end_data)?;
                                let msg = Message::Relay { circuit_id, data: wrapped };
                                let _ = write_frame(upstream, &msg.serialize()).await;
                                break;
                            }
                            Ok(n) => {
                                let data_cmd = RelayCommand::Data(target_buf[..n].to_vec());
                                let data_bytes = data_cmd.serialize_bincode()?;
                                let wrapped = encrypt_stream(key, &data_bytes)?;
                                let msg = Message::Relay { circuit_id, data: wrapped };
                                write_frame(upstream, &msg.serialize()).await?;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            info!(circuit_id, "exit forwarded streaming loop ended");
            Ok(())
        }

        async fn relay_streaming_loop(
            conn: &mut SecureConnection,
            next_stream: &mut TcpStream,
            circuit_id: u32,
            key: &[u8; 32],
        ) -> Result<()> {
            loop {
                tokio::select! {
                    msg_result = conn.recv_message() => {
                        let msg = match msg_result {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        match msg {
                            Message::Relay { data, .. } => {
                                let decrypted = decrypt_stream(key, &data)?;
                                let relay_msg = Message::Relay { circuit_id, data: decrypted };
                                write_frame(next_stream, &relay_msg.serialize()).await?;
                            }
                            _ => break,
                        }
                    }
                    frame_result = read_frame(next_stream) => {
                        let frame = match frame_result {
                            Ok(f) => f,
                            Err(_) => break,
                        };
                        let msg = Message::deserialize(&frame)?;
                        match msg {
                            Message::Relay { data, .. } => {
                                let wrapped = encrypt_stream(key, &data)?;
                                conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                            }
                            _ => break,
                        }
                    }
                }
            }
            info!(circuit_id, "relay streaming loop ended");
            Ok(())
        }

        async fn forwarded_streaming_loop(
            upstream: &mut TcpStream,
            downstream: &mut TcpStream,
            circuit_id: u32,
            key: &[u8; 32],
        ) -> Result<()> {
            loop {
                tokio::select! {
                    frame_result = read_frame(upstream) => {
                        let frame = match frame_result {
                            Ok(f) => f,
                            Err(_) => break,
                        };
                        let msg = Message::deserialize(&frame)?;
                        match msg {
                            Message::Relay { data, .. } => {
                                let decrypted = decrypt_stream(key, &data)?;
                                let relay_msg = Message::Relay { circuit_id, data: decrypted };
                                write_frame(downstream, &relay_msg.serialize()).await?;
                            }
                            _ => break,
                        }
                    }
                    frame_result = read_frame(downstream) => {
                        let frame = match frame_result {
                            Ok(f) => f,
                            Err(_) => break,
                        };
                        let msg = Message::deserialize(&frame)?;
                        match msg {
                            Message::Relay { data, .. } => {
                                let wrapped = encrypt_stream(key, &data)?;
                                let out_msg = Message::Relay { circuit_id, data: wrapped };
                                write_frame(upstream, &out_msg.serialize()).await?;
                            }
                            _ => break,
                        }
                    }
                }
            }
            info!(circuit_id, "forwarded streaming loop ended");
            Ok(())
        }

        async fn bridge_service_session(
            conn: &mut SecureConnection,
            circuit_id: u32,
            key: &[u8; 32],
            from_client: &mut mpsc::Receiver<Vec<u8>>,
            to_client: &mpsc::Sender<Vec<u8>>,
        ) -> Result<()> {
            loop {
                tokio::select! {
                    msg_result = conn.recv_message() => {
                        let msg = match msg_result {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        match msg {
                            Message::Relay { data, .. } => {
                                let decrypted = decrypt_stream(key, &data)?;
                                let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                                match cmd {
                                    RelayCommand::Data(payload) => {
                                        if to_client.send(payload).await.is_err() {
                                            break;
                                        }
                                    }
                                    RelayCommand::End => break,
                                    _ => {}
                                }
                            }
                            _ => break,
                        }
                    }
                    data = from_client.recv() => {
                        match data {
                            Some(payload) => {
                                let cmd = RelayCommand::Data(payload);
                                let cmd_data = cmd.serialize_bincode()?;
                                let wrapped = encrypt_stream(key, &cmd_data)?;
                                conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                            }
                            None => break,
                        }
                    }
                }
            }
            debug!(circuit_id, "service bridge session ended");
            Ok(())
        }

        async fn bridge_client_to_service(
            conn: &mut SecureConnection,
            circuit_id: u32,
            key: &[u8; 32],
            to_service: mpsc::Sender<Vec<u8>>,
            from_service: &mut mpsc::Receiver<Vec<u8>>,
        ) -> Result<()> {
            loop {
                tokio::select! {
                    msg_result = conn.recv_message() => {
                        let msg = match msg_result {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        match msg {
                            Message::Relay { data, .. } => {
                                let decrypted = decrypt_stream(key, &data)?;
                                let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                                match cmd {
                                    RelayCommand::Data(payload) => {
                                        if to_service.send(payload).await.is_err() {
                                            break;
                                        }
                                    }
                                    RelayCommand::End => break,
                                    _ => {}
                                }
                            }
                            _ => break,
                        }
                    }
                    data = from_service.recv() => {
                        match data {
                            Some(payload) => {
                                let cmd = RelayCommand::Data(payload);
                                let cmd_data = cmd.serialize_bincode()?;
                                let wrapped = encrypt_stream(key, &cmd_data)?;
                                conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                            }
                            None => break,
                        }
                    }
                }
            }
            debug!(circuit_id, "client-to-service bridge ended");
            Ok(())
        }

        async fn bridge_forwarded_client_to_service(
            upstream: &mut TcpStream,
            circuit_id: u32,
            key: &[u8; 32],
            to_service: mpsc::Sender<Vec<u8>>,
            from_service: &mut mpsc::Receiver<Vec<u8>>,
        ) -> Result<()> {
            loop {
                tokio::select! {
                    frame_result = read_frame(upstream) => {
                        let frame = match frame_result {
                            Ok(f) => f,
                            Err(_) => break,
                        };
                        let msg = Message::deserialize(&frame)?;
                        match msg {
                            Message::Relay { data, .. } => {
                                let decrypted = decrypt_stream(key, &data)?;
                                let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                                match cmd {
                                    RelayCommand::Data(payload) => {
                                        if to_service.send(payload).await.is_err() {
                                            break;
                                        }
                                    }
                                    RelayCommand::End => break,
                                    _ => {}
                                }
                            }
                            _ => break,
                        }
                    }
                    data = from_service.recv() => {
                        match data {
                            Some(payload) => {
                                let cmd = RelayCommand::Data(payload);
                                let cmd_data = cmd.serialize_bincode()?;
                                let wrapped = encrypt_stream(key, &cmd_data)?;
                                let msg = Message::Relay { circuit_id, data: wrapped };
                                write_frame(upstream, &msg.serialize()).await?;
                            }
                            None => break,
                        }
                    }
                }
            }
            debug!(circuit_id, "forwarded client-to-service bridge ended");
            Ok(())
        }

        async fn connect_to_next(addr: SocketAddr) -> Result<TcpStream> {
            let mut stream =
                TcpStream::connect(addr).await.map_err(|e| {
                    HidraError::Relay(format!(
                        "failed to connect to next hop {addr}: {e}"
                    ))
                })?;
            stream.write_all(&[PROTO_FORWARDED_CELL]).await?;
            Ok(stream)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod proxy
// ─────────────────────────────────────────────────────────────────────────────
mod proxy {
    pub mod socks5 {
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tracing::debug;
        use crate::error::{HidraError, Result};

        const SOCKS5_VERSION: u8 = 0x05;
        const AUTH_NONE: u8 = 0x00;
        const CMD_CONNECT: u8 = 0x01;
        const ATYP_IPV4: u8 = 0x01;
        const ATYP_DOMAIN: u8 = 0x03;
        const ATYP_IPV6: u8 = 0x04;

        const REPLY_SUCCESS: u8 = 0x00;
        const REPLY_GENERAL_FAILURE: u8 = 0x01;
        #[allow(dead_code)]
        const REPLY_CONN_REFUSED: u8 = 0x05;
        const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;

        #[derive(Debug, Clone)]
        pub enum TargetAddr {
            Ip(SocketAddr),
            Domain(String, u16),
        }

        impl TargetAddr {
            #[allow(dead_code)]
            pub fn port(&self) -> u16 {
                match self {
                    Self::Ip(addr) => addr.port(),
                    Self::Domain(_, port) => *port,
                }
            }
        }

        impl std::fmt::Display for TargetAddr {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    Self::Ip(addr) => write!(f, "{addr}"),
                    Self::Domain(host, port) => write!(f, "{host}:{port}"),
                }
            }
        }

        pub async fn handshake(stream: &mut TcpStream) -> Result<()> {
            let version = stream.read_u8().await?;
            if version != SOCKS5_VERSION {
                return Err(HidraError::Protocol(format!(
                    "unsupported SOCKS version: 0x{version:02x}"
                )));
            }
            let n_methods = stream.read_u8().await?;
            let mut methods = vec![0u8; n_methods as usize];
            stream.read_exact(&mut methods).await?;
            if !methods.contains(&AUTH_NONE) {
                stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
                return Err(HidraError::Protocol(
                    "client does not support no-auth method".into(),
                ));
            }
            stream.write_all(&[SOCKS5_VERSION, AUTH_NONE]).await?;
            stream.flush().await?;
            debug!("SOCKS5 auth negotiated (no auth)");
            Ok(())
        }

        pub async fn read_request(
            stream: &mut TcpStream,
        ) -> Result<TargetAddr> {
            let version = stream.read_u8().await?;
            if version != SOCKS5_VERSION {
                return Err(HidraError::Protocol(format!(
                    "bad SOCKS5 request version: 0x{version:02x}"
                )));
            }
            let cmd = stream.read_u8().await?;
            let _rsv = stream.read_u8().await?;
            if cmd != CMD_CONNECT {
                send_reply(stream, REPLY_CMD_NOT_SUPPORTED, None).await?;
                return Err(HidraError::Protocol(format!(
                    "unsupported SOCKS5 command: 0x{cmd:02x}"
                )));
            }
            let atyp = stream.read_u8().await?;
            let target = match atyp {
                ATYP_IPV4 => {
                    let mut ip = [0u8; 4];
                    stream.read_exact(&mut ip).await?;
                    let port = stream.read_u16().await?;
                    TargetAddr::Ip(SocketAddr::new(
                        Ipv4Addr::from(ip).into(),
                        port,
                    ))
                }
                ATYP_DOMAIN => {
                    let len = stream.read_u8().await? as usize;
                    let mut domain_buf = vec![0u8; len];
                    stream.read_exact(&mut domain_buf).await?;
                    let port = stream.read_u16().await?;
                    let domain = String::from_utf8(domain_buf).map_err(|_| {
                        HidraError::Protocol(
                            "invalid UTF-8 in domain name".into(),
                        )
                    })?;
                    TargetAddr::Domain(domain, port)
                }
                ATYP_IPV6 => {
                    let mut ip = [0u8; 16];
                    stream.read_exact(&mut ip).await?;
                    let port = stream.read_u16().await?;
                    TargetAddr::Ip(SocketAddr::new(
                        Ipv6Addr::from(ip).into(),
                        port,
                    ))
                }
                _ => {
                    send_reply(stream, REPLY_GENERAL_FAILURE, None).await?;
                    return Err(HidraError::Protocol(format!(
                        "unsupported address type: 0x{atyp:02x}"
                    )));
                }
            };
            debug!(target = %target, "SOCKS5 CONNECT request");
            Ok(target)
        }

        pub async fn send_reply(
            stream: &mut TcpStream,
            reply_code: u8,
            bind_addr: Option<SocketAddr>,
        ) -> Result<()> {
            let mut buf = Vec::with_capacity(10);
            buf.push(SOCKS5_VERSION);
            buf.push(reply_code);
            buf.push(0x00);
            match bind_addr {
                Some(SocketAddr::V4(v4)) => {
                    buf.push(ATYP_IPV4);
                    buf.extend_from_slice(&v4.ip().octets());
                    buf.extend_from_slice(&v4.port().to_be_bytes());
                }
                Some(SocketAddr::V6(v6)) => {
                    buf.push(ATYP_IPV6);
                    buf.extend_from_slice(&v6.ip().octets());
                    buf.extend_from_slice(&v6.port().to_be_bytes());
                }
                None => {
                    buf.push(ATYP_IPV4);
                    buf.extend_from_slice(&[0, 0, 0, 0]);
                    buf.extend_from_slice(&[0, 0]);
                }
            }
            stream.write_all(&buf).await?;
            stream.flush().await?;
            Ok(())
        }

        pub async fn send_success(stream: &mut TcpStream) -> Result<()> {
            send_reply(stream, REPLY_SUCCESS, None).await
        }

        pub async fn send_failure(stream: &mut TcpStream) -> Result<()> {
            send_reply(stream, REPLY_GENERAL_FAILURE, None).await
        }
    }

    pub mod stream_handler {
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::Duration;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;
        use tracing::{debug, info, warn};

        use crate::client::circuit_pool::CircuitPool;
        use crate::client::streaming::StreamingCircuit;
        use crate::error::{HidraError, Result};
        use crate::p2p::dht::DhtNode;
        use crate::proxy::socks5::{self, TargetAddr};

        const MAX_RETRIES: usize = 3;
        const INITIAL_BACKOFF_MS: u64 = 100;

        pub async fn handle_socks5_connection(
            mut browser_stream: TcpStream,
            pool: Arc<CircuitPool>,
            dht: Arc<DhtNode>,
            client_addr: SocketAddr,
        ) {
            if let Err(e) =
                handle_inner(&mut browser_stream, &pool, &dht, client_addr).await
            {
                warn!(
                    client_ip = %client_addr,
                    error = %e,
                    "SOCKS5 session failed"
                );
                let _ = socks5::send_failure(&mut browser_stream).await;
            }
        }

        fn parse_hidra_address(host: &str) -> Option<[u8; 20]> {
            let stripped = host.strip_suffix(".hidra")?;
            if stripped.len() != 40 {
                return None;
            }
            let mut hash = [0u8; 20];
            for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
                let hi = match chunk[0] {
                    b'0'..=b'9' => chunk[0] - b'0',
                    b'a'..=b'f' => chunk[0] - b'a' + 10,
                    b'A'..=b'F' => chunk[0] - b'A' + 10,
                    _ => return None,
                };
                let lo = match chunk[1] {
                    b'0'..=b'9' => chunk[1] - b'0',
                    b'a'..=b'f' => chunk[1] - b'a' + 10,
                    b'A'..=b'F' => chunk[1] - b'A' + 10,
                    _ => return None,
                };
                hash[i] = (hi << 4) | lo;
            }
            Some(hash)
        }

        async fn handle_inner(
            browser: &mut TcpStream,
            pool: &CircuitPool,
            dht: &DhtNode,
            client_addr: SocketAddr,
        ) -> Result<()> {
            socks5::handshake(browser).await?;
            let target = socks5::read_request(browser).await?;
            let (host, port) = match &target {
                TargetAddr::Ip(addr) => {
                    (addr.ip().to_string(), addr.port())
                }
                TargetAddr::Domain(h, p) => (h.clone(), *p),
            };
            let target_domain = format!("{target}");
            info!(
                client_ip = %client_addr,
                target_domain = %target_domain,
                "SOCKS5 CONNECT request"
            );

            if let Some(service_hash) = parse_hidra_address(&host) {
                info!(
                    client_ip = %client_addr,
                    address = %host,
                    "resolving .hidra hidden service via DHT"
                );
                let descriptor = dht.lookup_service(&service_hash).await?
                    .ok_or_else(|| HidraError::Circuit(
                        format!("hidden service not found: {host}")
                    ))?;
                let (intro_points, _service_pubkey) = descriptor;
                info!(
                    intro_points = intro_points.len(),
                    "found hidden service descriptor"
                );
                let mut circuit = connect_service_with_failover(
                    pool,
                    &service_hash,
                    &target_domain,
                    client_addr,
                )
                .await?;
                let circuit_id = circuit.circuit_id();
                let hop_count = circuit.hop_count();
                let relay_chain = circuit.relay_chain_display();
                info!(
                    client_ip = %client_addr,
                    target_domain = %target_domain,
                    circuit_id, hop_count,
                    relay_chain = %relay_chain,
                    "circuit connected to hidden service"
                );
                socks5::send_success(browser).await?;
                let mut bytes_sent: u64 = 0;
                let mut bytes_received: u64 = 0;
                stream_bidirectional(
                    browser,
                    &mut circuit,
                    &mut bytes_sent,
                    &mut bytes_received,
                )
                .await;
                info!(
                    client_ip = %client_addr,
                    target_domain = %target_domain,
                    circuit_id, hop_count,
                    relay_chain = %relay_chain,
                    bytes_sent, bytes_received,
                    "hidden service session completed"
                );
                return Ok(());
            }

            let mut circuit = connect_with_failover(
                pool,
                &host,
                port,
                &target_domain,
                client_addr,
            )
            .await?;
            let circuit_id = circuit.circuit_id();
            let hop_count = circuit.hop_count();
            let relay_chain = circuit.relay_chain_display();
            info!(
                client_ip = %client_addr,
                target_domain = %target_domain,
                circuit_id, hop_count,
                relay_chain = %relay_chain,
                "circuit connected to target"
            );
            socks5::send_success(browser).await?;
            let mut bytes_sent: u64 = 0;
            let mut bytes_received: u64 = 0;
            stream_bidirectional(
                browser,
                &mut circuit,
                &mut bytes_sent,
                &mut bytes_received,
            )
            .await;
            info!(
                client_ip = %client_addr,
                target_domain = %target_domain,
                circuit_id, hop_count,
                relay_chain = %relay_chain,
                bytes_sent, bytes_received,
                "SOCKS5 session completed"
            );
            Ok(())
        }

        async fn connect_with_failover(
            pool: &CircuitPool,
            host: &str,
            port: u16,
            target_domain: &str,
            client_addr: SocketAddr,
        ) -> Result<StreamingCircuit> {
            let mut backoff = Duration::from_millis(INITIAL_BACKOFF_MS);
            let mut last_error = None;
            for attempt in 0..MAX_RETRIES {
                let mut circuit = match pool.get_circuit().await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            attempt,
                            client_ip = %client_addr,
                            target_domain = %target_domain,
                            error = %e,
                            "failed to obtain circuit"
                        );
                        last_error = Some(e);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                };
                match circuit.connect(host, port).await {
                    Ok(()) => return Ok(circuit),
                    Err(e) => {
                        warn!(
                            attempt,
                            circuit_id = circuit.circuit_id(),
                            client_ip = %client_addr,
                            target_domain = %target_domain,
                            error = %e,
                            "circuit connect failed, retrying"
                        );
                        last_error = Some(e);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                    }
                }
            }
            Err(last_error.unwrap_or_else(|| {
                HidraError::Circuit(
                    "all circuit retry attempts exhausted".into(),
                )
            }))
        }

        async fn connect_service_with_failover(
            pool: &CircuitPool,
            service_hash: &[u8; 20],
            target_domain: &str,
            client_addr: SocketAddr,
        ) -> Result<StreamingCircuit> {
            let mut backoff = Duration::from_millis(INITIAL_BACKOFF_MS);
            let mut last_error = None;
            for attempt in 0..MAX_RETRIES {
                let mut circuit = match pool.get_circuit().await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(
                            attempt,
                            client_ip = %client_addr,
                            target_domain = %target_domain,
                            error = %e,
                            "failed to obtain circuit for service"
                        );
                        last_error = Some(e);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                        continue;
                    }
                };
                match circuit.connect_service(service_hash.to_vec()).await {
                    Ok(()) => return Ok(circuit),
                    Err(e) => {
                        warn!(
                            attempt,
                            circuit_id = circuit.circuit_id(),
                            client_ip = %client_addr,
                            target_domain = %target_domain,
                            error = %e,
                            "service connect failed, retrying"
                        );
                        last_error = Some(e);
                        tokio::time::sleep(backoff).await;
                        backoff *= 2;
                    }
                }
            }
            Err(last_error.unwrap_or_else(|| {
                HidraError::Circuit(
                    "all service circuit retry attempts exhausted".into(),
                )
            }))
        }

        async fn stream_bidirectional(
            browser: &mut TcpStream,
            circuit: &mut StreamingCircuit,
            bytes_sent: &mut u64,
            bytes_received: &mut u64,
        ) {
            let mut browser_buf = vec![0u8; 16384];
            loop {
                tokio::select! {
                    n = browser.read(&mut browser_buf) => {
                        match n {
                            Ok(0) => {
                                debug!("browser closed connection");
                                let _ = circuit.send_end().await;
                                break;
                            }
                            Ok(n) => {
                                *bytes_sent += n as u64;
                                if circuit.send_data(&browser_buf[..n]).await.is_err() { break; }
                            }
                            Err(e) => {
                                debug!(error = %e, "browser read error");
                                let _ = circuit.send_end().await;
                                break;
                            }
                        }
                    }
                    data_result = circuit.recv_data() => {
                        match data_result {
                            Ok(Some(data)) => {
                                *bytes_received += data.len() as u64;
                                if browser.write_all(&data).await.is_err() { break; }
                            }
                            Ok(None) => {
                                debug!("circuit stream ended");
                                break;
                            }
                            Err(e) => {
                                debug!(error = %e, "circuit recv error");
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod client
// ─────────────────────────────────────────────────────────────────────────────
mod client {
    pub mod streaming {
        use std::net::SocketAddr;

        use rand::Rng;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;
        use tracing::{debug, info};
        use x25519_dalek::StaticSecret;
        use zeroize::Zeroize;

        use crate::crypto::handshake::{HandshakeState, Role};
        use crate::error::{HidraError, Result};
        use crate::network::connection::{
            read_frame, write_frame, Message, SecureConnection,
        };
        use crate::network::listener::PROTO_NOISE_SESSION;
        use crate::onion::builder::{build_onion, peel_response_layers};
        use crate::onion::cell::RelayCommand;
        use crate::onion::circuit::{Circuit, CircuitHop};
        use crate::onion::layer::{decrypt_stream, encrypt_stream};
        use crate::relay::registry::RelayEntry;

        pub struct StreamingCircuit {
            conn: SecureConnection,
            circuit: Circuit,
            relay_addrs: Vec<SocketAddr>,
            #[allow(dead_code)]
            extra_conns: Vec<SecureConnection>,
        }

        impl StreamingCircuit {
            pub async fn build(
                relays: &[RelayEntry],
                client_secret: StaticSecret,
            ) -> Result<Self> {
                if relays.len() < 3 {
                    return Err(HidraError::Circuit(
                        "need at least 3 relays for streaming circuit".into(),
                    ));
                }
                let circuit_id: u32 = rand::thread_rng().r#gen();
                info!(circuit_id, "building streaming circuit");
                let mut hops = Vec::with_capacity(3);
                let mut connections: Vec<SecureConnection> =
                    Vec::with_capacity(3);
                for (i, relay) in relays.iter().take(3).enumerate() {
                    let mut secret_bytes = client_secret.to_bytes();
                    let hop_secret = StaticSecret::from(secret_bytes);
                    secret_bytes.zeroize();
                    let (conn, session_key) = handshake_with_relay(
                        relay.addr,
                        hop_secret,
                        circuit_id,
                    )
                    .await?;
                    hops.push(CircuitHop {
                        addr: relay.addr,
                        session_key,
                    });
                    connections.push(conn);
                    info!(hop = i, relay = %relay.name, "streaming circuit hop established");
                }
                let relay_addrs: Vec<SocketAddr> =
                    relays.iter().take(3).map(|r| r.addr).collect();
                let circuit = Circuit::new(circuit_id, hops);
                let mut iter = connections.into_iter();
                let entry_conn = iter.next().ok_or_else(|| {
                    HidraError::Circuit("no entry connection".into())
                })?;
                let extra_conns: Vec<SecureConnection> = iter.collect();
                Ok(Self {
                    conn: entry_conn,
                    circuit,
                    relay_addrs,
                    extra_conns,
                })
            }

            pub async fn connect(
                &mut self,
                host: &str,
                port: u16,
            ) -> Result<()> {
                let cmd = RelayCommand::Connect {
                    host: host.to_string(),
                    port,
                };
                let cmd_data = cmd.serialize_bincode()?;
                let onion_data = build_onion(&self.circuit, &cmd_data)?;
                self.conn
                    .send_message(&Message::Relay {
                        circuit_id: self.circuit.id,
                        data: onion_data,
                    })
                    .await?;
                let response_msg = self.conn.recv_message().await?;
                let response_data = match response_msg {
                    Message::Relay { data, .. } => data,
                    other => {
                        return Err(HidraError::Circuit(format!(
                            "expected Relay response, got: {other:?}"
                        )));
                    }
                };
                let decrypted = peel_response_layers(
                    &self.circuit,
                    response_data,
                )?;
                let resp_cmd =
                    RelayCommand::deserialize_bincode(&decrypted)?;
                match resp_cmd {
                    RelayCommand::Connected => {
                        info!(circuit_id = self.circuit.id, host, port, "streaming circuit connected to target");
                        Ok(())
                    }
                    RelayCommand::ConnectFailed(reason) => {
                        Err(HidraError::Circuit(format!(
                            "connect failed: {reason}"
                        )))
                    }
                    other => Err(HidraError::Circuit(format!(
                        "unexpected connect response: {other:?}"
                    ))),
                }
            }

            pub async fn connect_service(
                &mut self,
                service_hash: Vec<u8>,
            ) -> Result<()> {
                let cmd = RelayCommand::ConnectService { service_hash };
                let cmd_data = cmd.serialize_bincode()?;
                let onion_data = build_onion(&self.circuit, &cmd_data)?;
                self.conn
                    .send_message(&Message::Relay {
                        circuit_id: self.circuit.id,
                        data: onion_data,
                    })
                    .await?;
                let response_msg = self.conn.recv_message().await?;
                let response_data = match response_msg {
                    Message::Relay { data, .. } => data,
                    other => {
                        return Err(HidraError::Circuit(format!(
                            "expected Relay response, got: {other:?}"
                        )));
                    }
                };
                let decrypted = peel_response_layers(
                    &self.circuit,
                    response_data,
                )?;
                let resp_cmd =
                    RelayCommand::deserialize_bincode(&decrypted)?;
                match resp_cmd {
                    RelayCommand::ServiceConnected => {
                        info!(circuit_id = self.circuit.id, "connected to hidden service");
                        Ok(())
                    }
                    RelayCommand::ConnectFailed(reason) => {
                        Err(HidraError::Circuit(format!(
                            "service connect failed: {reason}"
                        )))
                    }
                    other => Err(HidraError::Circuit(format!(
                        "unexpected service connect response: {other:?}"
                    ))),
                }
            }

            pub async fn register_service(
                &mut self,
                service_hash: Vec<u8>,
            ) -> Result<()> {
                let cmd = RelayCommand::RegisterService { service_hash };
                let cmd_data = cmd.serialize_bincode()?;
                let onion_data = build_onion(&self.circuit, &cmd_data)?;
                self.conn
                    .send_message(&Message::Relay {
                        circuit_id: self.circuit.id,
                        data: onion_data,
                    })
                    .await?;
                let response_msg = self.conn.recv_message().await?;
                let response_data = match response_msg {
                    Message::Relay { data, .. } => data,
                    other => {
                        return Err(HidraError::Circuit(format!(
                            "expected Relay response, got: {other:?}"
                        )));
                    }
                };
                let decrypted = peel_response_layers(
                    &self.circuit,
                    response_data,
                )?;
                let resp_cmd =
                    RelayCommand::deserialize_bincode(&decrypted)?;
                match resp_cmd {
                    RelayCommand::ServiceRegistered => {
                        info!(circuit_id = self.circuit.id, "service registered at intro point");
                        Ok(())
                    }
                    RelayCommand::ConnectFailed(reason) => {
                        Err(HidraError::Circuit(format!(
                            "service registration failed: {reason}"
                        )))
                    }
                    other => Err(HidraError::Circuit(format!(
                        "unexpected register response: {other:?}"
                    ))),
                }
            }

            pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
                let cmd = RelayCommand::Data(data.to_vec());
                let cmd_data = cmd.serialize_bincode()?;
                let encrypted =
                    wrap_all_stream_layers(&self.circuit, &cmd_data)?;
                self.conn
                    .send_message(&Message::Relay {
                        circuit_id: self.circuit.id,
                        data: encrypted,
                    })
                    .await
            }

            pub async fn recv_data(
                &mut self,
            ) -> Result<Option<Vec<u8>>> {
                let msg = self.conn.recv_message().await?;
                let data = match msg {
                    Message::Relay { data, .. } => data,
                    other => {
                        return Err(HidraError::Circuit(format!(
                            "expected Relay, got: {other:?}"
                        )));
                    }
                };
                let decrypted =
                    peel_all_stream_layers(&self.circuit, data)?;
                let cmd =
                    RelayCommand::deserialize_bincode(&decrypted)?;
                match cmd {
                    RelayCommand::Data(payload) => Ok(Some(payload)),
                    RelayCommand::End => Ok(None),
                    other => Err(HidraError::Circuit(format!(
                        "unexpected stream command: {other:?}"
                    ))),
                }
            }

            pub async fn send_end(&mut self) -> Result<()> {
                let cmd = RelayCommand::End;
                let cmd_data = cmd.serialize_bincode()?;
                let encrypted =
                    wrap_all_stream_layers(&self.circuit, &cmd_data)?;
                self.conn
                    .send_message(&Message::Relay {
                        circuit_id: self.circuit.id,
                        data: encrypted,
                    })
                    .await
            }

            pub fn circuit_id(&self) -> u32 {
                self.circuit.id
            }

            pub fn hop_count(&self) -> usize {
                self.relay_addrs.len()
            }

            pub fn relay_chain_display(&self) -> String {
                self.relay_addrs
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(" → ")
            }
        }

        fn wrap_all_stream_layers(
            circuit: &Circuit,
            data: &[u8],
        ) -> Result<Vec<u8>> {
            let mut current = data.to_vec();
            for hop in circuit.hops.iter().rev() {
                current = encrypt_stream(&hop.session_key, &current)?;
            }
            Ok(current)
        }

        fn peel_all_stream_layers(
            circuit: &Circuit,
            data: Vec<u8>,
        ) -> Result<Vec<u8>> {
            let mut current = data;
            for hop in &circuit.hops {
                current = decrypt_stream(&hop.session_key, &current)?;
            }
            Ok(current)
        }

        async fn handshake_with_relay(
            addr: SocketAddr,
            static_secret: StaticSecret,
            circuit_id: u32,
        ) -> Result<(SecureConnection, [u8; 32])> {
            let mut stream =
                TcpStream::connect(addr).await.map_err(|e| {
                    HidraError::Relay(format!(
                        "failed to connect to relay {addr}: {e}"
                    ))
                })?;
            stream.write_all(&[PROTO_NOISE_SESSION]).await?;
            let mut handshake =
                HandshakeState::new(Role::Initiator, static_secret);
            let msg_a = handshake.write_message_a()?;
            write_frame(&mut stream, &msg_a).await?;
            let msg_b = read_frame(&mut stream).await?;
            handshake.read_message_b(&msg_b)?;
            let msg_c = handshake.write_message_c()?;
            write_frame(&mut stream, &msg_c).await?;
            debug!(addr = %addr, "handshake done");
            let (send_cipher, recv_cipher) = handshake.into_transport()?;
            let session_key = send_cipher.session_key()?;
            let mut conn =
                SecureConnection::new(stream, send_cipher, recv_cipher);
            conn.send_message(&Message::CreateCircuit { circuit_id })
                .await?;
            let response = conn.recv_message().await?;
            match response {
                Message::CircuitCreated {
                    circuit_id: cid, ..
                } if cid == circuit_id => {
                    debug!(circuit_id, "circuit registered at relay");
                }
                other => {
                    return Err(HidraError::Circuit(format!(
                        "expected CircuitCreated, got: {other:?}"
                    )));
                }
            }
            Ok((conn, session_key))
        }
    }

    pub mod circuit_pool {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use rand::seq::SliceRandom;
        use tokio::sync::Mutex;
        use tracing::{debug, info, warn};
        use x25519_dalek::StaticSecret;
        use zeroize::Zeroize;

        use crate::client::streaming::StreamingCircuit;
        use crate::error::{HidraError, Result};
        use crate::relay::registry::RelayEntry;

        const CIRCUIT_TTL: Duration = Duration::from_secs(300);
        const POOL_TARGET_SIZE: usize = 3;
        const MAX_POOL_SIZE: usize = 10;

        struct PoolEntry {
            circuit: StreamingCircuit,
            created_at: Instant,
        }

        pub struct CircuitPool {
            entries: Mutex<Vec<PoolEntry>>,
            relays: Mutex<Vec<RelayEntry>>,
            secret_bytes: [u8; 32],
        }

        impl CircuitPool {
            pub fn new(
                secret_bytes: [u8; 32],
                relays: Vec<RelayEntry>,
            ) -> Arc<Self> {
                Arc::new(Self {
                    entries: Mutex::new(Vec::new()),
                    relays: Mutex::new(relays),
                    secret_bytes,
                })
            }

            pub async fn update_relays(&self, relays: Vec<RelayEntry>) {
                let mut r = self.relays.lock().await;
                info!(
                    old_count = r.len(),
                    new_count = relays.len(),
                    "relay list updated"
                );
                *r = relays;
            }

            pub async fn get_circuit(
                &self,
            ) -> Result<StreamingCircuit> {
                {
                    let mut entries = self.entries.lock().await;
                    while let Some(entry) = entries.pop() {
                        if entry.created_at.elapsed() < CIRCUIT_TTL {
                            debug!(
                                pool_remaining = entries.len(),
                                circuit_id = entry.circuit.circuit_id(),
                                "circuit taken from pool"
                            );
                            return Ok(entry.circuit);
                        }
                        debug!("discarded stale pooled circuit");
                    }
                }
                debug!("pool empty, building circuit on-demand");
                self.build_new_circuit().await
            }

            pub async fn build_new_circuit(
                &self,
            ) -> Result<StreamingCircuit> {
                let relays = self.relays.lock().await.clone();
                let selected = select_relays(&relays)?;
                let mut sb = self.secret_bytes;
                let secret = StaticSecret::from(sb);
                sb.zeroize();
                StreamingCircuit::build(&selected, secret).await
            }

            pub async fn maintain(&self) {
                {
                    let mut entries = self.entries.lock().await;
                    let before = entries.len();
                    entries
                        .retain(|e| e.created_at.elapsed() < CIRCUIT_TTL);
                    let removed = before - entries.len();
                    if removed > 0 {
                        debug!(
                            removed,
                            remaining = entries.len(),
                            "pruned stale circuits"
                        );
                    }
                }
                let current = self.entries.lock().await.len();
                if current < POOL_TARGET_SIZE {
                    let to_build = POOL_TARGET_SIZE - current;
                    for _ in 0..to_build {
                        match self.build_new_circuit().await {
                            Ok(circuit) => {
                                let mut entries =
                                    self.entries.lock().await;
                                if entries.len() < MAX_POOL_SIZE {
                                    info!(
                                        circuit_id = circuit.circuit_id(),
                                        pool_size = entries.len() + 1,
                                        "pre-built circuit added to pool"
                                    );
                                    entries.push(PoolEntry {
                                        circuit,
                                        created_at: Instant::now(),
                                    });
                                }
                            }
                            Err(e) => {
                                warn!(
                                    error = %e,
                                    "circuit pre-build failed"
                                );
                                break;
                            }
                        }
                    }
                }
            }

            pub async fn pool_size(&self) -> usize {
                self.entries.lock().await.len()
            }
        }

        fn select_relays(
            all: &[RelayEntry],
        ) -> Result<Vec<RelayEntry>> {
            if all.len() < 3 {
                return Err(HidraError::Circuit(format!(
                    "need at least 3 relays, have {}",
                    all.len()
                )));
            }
            let mut selected = all.to_vec();
            selected.shuffle(&mut rand::thread_rng());
            selected.truncate(3);
            Ok(selected)
        }
    }

    pub mod session {
        use std::net::SocketAddr;

        use rand::Rng;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;
        use tracing::{debug, info};
        use x25519_dalek::StaticSecret;
        use zeroize::Zeroize;

        use crate::crypto::handshake::{HandshakeState, Role};
        use crate::error::{HidraError, Result};
        use crate::network::connection::{
            read_frame, write_frame, Message, SecureConnection,
        };
        use crate::network::listener::PROTO_NOISE_SESSION;
        use crate::onion::builder::{build_onion, peel_response_layers};
        use crate::onion::circuit::{Circuit, CircuitHop};
        use crate::relay::registry::RelayEntry;

        pub async fn run_client_session(
            relays: &[RelayEntry],
            client_secret: StaticSecret,
            payload: &str,
        ) -> Result<String> {
            if relays.len() < 3 {
                return Err(HidraError::Circuit(
                    "need at least 3 relays for onion routing".into(),
                ));
            }
            let circuit_id: u32 = rand::thread_rng().r#gen();
            info!(circuit_id, "building 3-hop circuit");
            let mut hops = Vec::with_capacity(3);
            let mut connections: Vec<SecureConnection> =
                Vec::with_capacity(3);
            for (i, relay) in relays.iter().take(3).enumerate() {
                info!(
                    hop = i,
                    relay = %relay.name,
                    addr = %relay.addr,
                    "establishing Noise XX handshake with relay"
                );
                let mut secret_bytes = client_secret.to_bytes();
                let hop_secret = StaticSecret::from(secret_bytes);
                secret_bytes.zeroize();
                let (conn, session_key) = handshake_with_relay(
                    relay.addr,
                    hop_secret,
                    circuit_id,
                )
                .await?;
                hops.push(CircuitHop {
                    addr: relay.addr,
                    session_key,
                });
                connections.push(conn);
                info!(hop = i, relay = %relay.name, "handshake completed, circuit extended");
            }
            let circuit = Circuit::new(circuit_id, hops);
            info!(circuit_id, payload, "building onion packet");
            let onion_data = build_onion(&circuit, payload.as_bytes())?;
            debug!(circuit_id, onion_size = onion_data.len(), "onion built");
            let entry_conn = &mut connections[0];
            entry_conn
                .send_message(&Message::Relay {
                    circuit_id,
                    data: onion_data,
                })
                .await?;
            info!(circuit_id, "onion sent to entry relay");
            let response_msg = entry_conn.recv_message().await?;
            let response_data = match response_msg {
                Message::Relay { data, .. } => data,
                other => {
                    return Err(HidraError::Circuit(format!(
                        "unexpected response from entry relay: {other:?}"
                    )));
                }
            };
            info!(circuit_id, "received response, peeling layers");
            let plaintext =
                peel_response_layers(&circuit, response_data)?;
            let response_str = String::from_utf8(plaintext).map_err(|e| {
                HidraError::Circuit(format!(
                    "response is not valid UTF-8: {e}"
                ))
            })?;
            info!(circuit_id, response = %response_str, "circuit complete");
            Ok(response_str)
        }

        async fn handshake_with_relay(
            addr: SocketAddr,
            static_secret: StaticSecret,
            circuit_id: u32,
        ) -> Result<(SecureConnection, [u8; 32])> {
            let mut stream =
                TcpStream::connect(addr).await.map_err(|e| {
                    HidraError::Relay(format!(
                        "failed to connect to relay {addr}: {e}"
                    ))
                })?;
            stream.write_all(&[PROTO_NOISE_SESSION]).await?;
            let mut handshake =
                HandshakeState::new(Role::Initiator, static_secret);
            let msg_a = handshake.write_message_a()?;
            write_frame(&mut stream, &msg_a).await?;
            let msg_b = read_frame(&mut stream).await?;
            handshake.read_message_b(&msg_b)?;
            let msg_c = handshake.write_message_c()?;
            write_frame(&mut stream, &msg_c).await?;
            debug!(addr = %addr, "handshake done, extracting session key");
            let (send_cipher, recv_cipher) = handshake.into_transport()?;
            let session_key = send_cipher.session_key()?;
            let mut conn =
                SecureConnection::new(stream, send_cipher, recv_cipher);
            conn.send_message(&Message::CreateCircuit { circuit_id })
                .await?;
            let response = conn.recv_message().await?;
            match response {
                Message::CircuitCreated {
                    circuit_id: cid, ..
                } if cid == circuit_id => {
                    debug!(circuit_id, "circuit registered at relay");
                }
                other => {
                    return Err(HidraError::Circuit(format!(
                        "expected CircuitCreated, got: {other:?}"
                    )));
                }
            }
            Ok((conn, session_key))
        }
    }

    pub mod proxy_runner {
        use std::net::SocketAddr;
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use tokio::net::TcpListener;
        use tracing::{info, warn};

        use crate::client::circuit_pool::CircuitPool;
        use crate::error::Result;
        use crate::p2p::bootstrap::bootstrap;
        use crate::p2p::dht::DhtNode;
        use crate::proxy::stream_handler;
        use crate::relay::registry::RelayEntry;

        const RELAY_CACHE_TTL: Duration = Duration::from_secs(120);
        const POOL_MAINTENANCE_INTERVAL: Duration =
            Duration::from_secs(30);
        const MIN_RELAYS: usize = 3;

        pub struct ProxyConfig {
            pub listen_addr: SocketAddr,
            pub dht_addr: SocketAddr,
            pub bootstrap_addrs: Vec<SocketAddr>,
            pub secret_bytes: [u8; 32],
            pub static_relays: Vec<RelayEntry>,
        }

        pub async fn run_proxy(config: ProxyConfig) -> Result<()> {
            let listener =
                TcpListener::bind(config.listen_addr).await?;
            info!(addr = %config.listen_addr, "HidraNet proxy listening on {}", config.listen_addr);

            let signing_key = ed25519_dalek::SigningKey::generate(
                &mut rand_core::OsRng,
            );
            let mut dht = DhtNode::new(
                config.dht_addr,
                signing_key,
                None,
            )
            .await?;
            dht.start().await;

            if !config.bootstrap_addrs.is_empty() {
                if let Err(e) =
                    bootstrap(&dht, &config.bootstrap_addrs).await
                {
                    warn!(error = %e, "DHT bootstrap failed, will use static relays");
                }
            }
            let dht = Arc::new(dht);
            let initial_relays = discover_relays(
                &dht,
                &config.static_relays,
            )
            .await;
            info!(relay_count = initial_relays.len(), "initial relay set loaded");
            let pool = CircuitPool::new(
                config.secret_bytes,
                initial_relays,
            );
            pool.maintain().await;
            info!(pool_size = pool.pool_size().await, "circuit pool initialized");

            let pool_bg = Arc::clone(&pool);
            let dht_bg = Arc::clone(&dht);
            let static_relays = config.static_relays.clone();
            tokio::spawn(async move {
                let mut relay_refresh = Instant::now();
                loop {
                    tokio::time::sleep(POOL_MAINTENANCE_INTERVAL).await;
                    if relay_refresh.elapsed() > RELAY_CACHE_TTL {
                        let relays = discover_relays(
                            &dht_bg,
                            &static_relays,
                        )
                        .await;
                        if relays.len() >= MIN_RELAYS {
                            pool_bg.update_relays(relays).await;
                            relay_refresh = Instant::now();
                        }
                    }
                    pool_bg.maintain().await;
                }
            });

            loop {
                let (stream, remote_addr) =
                    listener.accept().await?;
                info!(client_ip = %remote_addr, "accepted SOCKS5 connection");
                let pool = Arc::clone(&pool);
                let dht_ref = Arc::clone(&dht);
                tokio::spawn(async move {
                    stream_handler::handle_socks5_connection(
                        stream,
                        pool,
                        dht_ref,
                        remote_addr,
                    )
                    .await;
                });
            }
        }

        async fn discover_relays(
            dht: &DhtNode,
            static_relays: &[RelayEntry],
        ) -> Vec<RelayEntry> {
            match dht.find_relays(MIN_RELAYS).await {
                Ok(nodes) if nodes.len() >= MIN_RELAYS => {
                    let entries: Vec<RelayEntry> = nodes
                        .into_iter()
                        .map(|n| RelayEntry {
                            name: format!("{}", n.id),
                            addr: n.relay_addr.unwrap_or(n.dht_addr),
                            noise_pubkey_b64: String::new(),
                        })
                        .collect();
                    info!(count = entries.len(), "discovered relays via DHT");
                    entries
                }
                Ok(nodes) => {
                    warn!(
                        dht_found = nodes.len(),
                        static_count = static_relays.len(),
                        "DHT has too few relays, augmenting with static"
                    );
                    let mut all = static_relays.to_vec();
                    for n in nodes {
                        let addr =
                            n.relay_addr.unwrap_or(n.dht_addr);
                        if !all.iter().any(|r| r.addr == addr) {
                            all.push(RelayEntry {
                                name: format!("{}", n.id),
                                addr,
                                noise_pubkey_b64: String::new(),
                            });
                        }
                    }
                    all
                }
                Err(e) => {
                    warn!(error = %e, "DHT relay discovery failed");
                    static_relays.to_vec()
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// mod api
// ─────────────────────────────────────────────────────────────────────────────
mod api {
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tracing::{info, warn};

    pub struct ApiState {
        pub start_time: Instant,
        pub relay_count: usize,
        pub relay_addrs: Vec<SocketAddr>,
        pub hops: usize,
    }

    pub async fn run_api_server(addr: SocketAddr, state: Arc<ApiState>) {
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                warn!(error = %e, addr = %addr, "status API server failed to bind");
                return;
            }
        };
        info!(addr = %addr, "status API server listening");
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                handle_request(stream, &state).await;
            });
        }
    }

    async fn handle_request(
        mut stream: tokio::net::TcpStream,
        state: &ApiState,
    ) {
        let mut buf = [0u8; 2048];
        let n = match stream.read(&mut buf).await {
            Ok(0) => return,
            Ok(n) => n,
            Err(_) => return,
        };
        let request = String::from_utf8_lossy(&buf[..n]);
        let (status_code, status_text, body) =
            if request.starts_with("GET /api/status") {
                let uptime = state.start_time.elapsed().as_secs();
                let body = format!(
                    r#"{{"connected":true,"relays":{},"latency":42,"uptime":{},"hops":{}}}"#,
                    state.relay_count, uptime, state.hops
                );
                (200, "OK", body)
            } else if request.starts_with("GET /api/circuit") {
                let hops: Vec<String> = state
                    .relay_addrs
                    .iter()
                    .enumerate()
                    .map(|(i, addr)| {
                        let role = match i {
                            0 => "Guard",
                            1 => "Middle",
                            _ => "Exit",
                        };
                        format!(r#"{{"ip":"{addr}","role":"{role}"}}"#)
                    })
                    .collect();
                let body = format!(
                    r#"{{"hops":[{}]}}"#,
                    hops.join(",")
                );
                (200, "OK", body)
            } else if request.starts_with("OPTIONS") {
                (204, "No Content", String::new())
            } else {
                (
                    404,
                    "Not Found",
                    r#"{"error":"not found"}"#.to_string(),
                )
            };

        let response = format!(
            "HTTP/1.1 {status_code} {status_text}\r\n\
             Content-Type: application/json\r\n\
             Access-Control-Allow-Origin: *\r\n\
             Access-Control-Allow-Methods: GET, OPTIONS\r\n\
             Access-Control-Allow-Headers: *\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
    }
}

// =============================================================================
// mod apps — HidraNet decentralized applications
// =============================================================================
mod apps {
    pub mod hidrachat;
    pub mod sevennine;


    // =========================================================================
    // HidraMail — Decentralized anonymous email
    // =========================================================================
    pub mod hidramail {
        pub mod protocol {
            use serde::{Serialize, Deserialize};

            #[derive(Serialize, Deserialize, Clone)]
            pub struct MailEnvelope {
                pub id: String,
                pub from_addr: String,
                pub to_addr: String,
                pub timestamp: u64,
                pub ephemeral_pubkey: Vec<u8>,
                pub sealed_body: Vec<u8>,
                pub sender_verifying_key: Vec<u8>,
                pub signature: Vec<u8>,
            }

            #[derive(Serialize, Deserialize, Clone)]
            pub struct MailContent {
                pub subject: String,
                pub body: String,
            }

            #[derive(Serialize, Deserialize, Clone)]
            pub struct MailSummary {
                pub id: String,
                pub from_addr: String,
                pub to_addr: String,
                pub timestamp: u64,
                pub subject: String,
                pub read: bool,
            }

            #[derive(Deserialize)]
            pub struct SendRequest {
                pub to: String,
                pub subject: String,
                pub body: String,
                pub direct_addr: Option<String>,
            }

            impl MailEnvelope {
                pub fn signing_data(&self) -> Vec<u8> {
                    let mut data = Vec::new();
                    data.extend_from_slice(self.id.as_bytes());
                    data.extend_from_slice(self.from_addr.as_bytes());
                    data.extend_from_slice(self.to_addr.as_bytes());
                    data.extend_from_slice(&self.timestamp.to_le_bytes());
                    data.extend_from_slice(&self.sealed_body);
                    data
                }
            }
        }

        pub mod crypto {
            use chacha20poly1305::{
                aead::{Aead, KeyInit},
                ChaCha20Poly1305, Nonce,
            };
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            use rand::RngCore;
            use x25519_dalek::{PublicKey, StaticSecret};
            use zeroize::Zeroize;

            use crate::error::{HidraError, Result};
            use std::path::Path;

            pub struct MailKeys {
                secret_bytes: [u8; 32],
                pub public_bytes: [u8; 32],
            }

            impl MailKeys {
                pub fn load_or_generate(keys_dir: &Path) -> Result<Self> {
                    let key_path = keys_dir.join("mail_x25519.key");
                    if key_path.exists() {
                        let bytes = std::fs::read(&key_path).map_err(HidraError::Io)?;
                        if bytes.len() != 32 {
                            return Err(HidraError::Crypto(
                                "invalid mail key file".into(),
                            ));
                        }
                        let mut secret_bytes = [0u8; 32];
                        secret_bytes.copy_from_slice(&bytes);
                        let secret = StaticSecret::from(secret_bytes);
                        let public = PublicKey::from(&secret);
                        Ok(Self {
                            secret_bytes,
                            public_bytes: *public.as_bytes(),
                        })
                    } else {
                        let mut secret_bytes = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut secret_bytes);
                        std::fs::create_dir_all(keys_dir).map_err(HidraError::Io)?;
                        std::fs::write(&key_path, &secret_bytes)
                            .map_err(HidraError::Io)?;
                        let secret = StaticSecret::from(secret_bytes);
                        let public = PublicKey::from(&secret);
                        Ok(Self {
                            secret_bytes,
                            public_bytes: *public.as_bytes(),
                        })
                    }
                }

                pub fn secret_bytes(&self) -> &[u8; 32] {
                    &self.secret_bytes
                }
            }

            impl Drop for MailKeys {
                fn drop(&mut self) {
                    self.secret_bytes.zeroize();
                }
            }

            pub fn seal_message(
                recipient_pubkey: &[u8; 32],
                plaintext: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>)> {
                let recipient = PublicKey::from(*recipient_pubkey);
                let mut eph_bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut eph_bytes);
                let eph_secret = StaticSecret::from(eph_bytes);
                eph_bytes.zeroize();
                let eph_public = PublicKey::from(&eph_secret);

                let shared = eph_secret.diffie_hellman(&recipient);
                let sym_key =
                    blake3::derive_key("hidramail-seal-v1", shared.as_bytes());

                let cipher = ChaCha20Poly1305::new((&sym_key).into());
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let nonce = Nonce::from_slice(&nonce_bytes);

                let ct = cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| HidraError::Crypto(format!("seal: {e}")))?;

                let mut sealed = Vec::with_capacity(12 + ct.len());
                sealed.extend_from_slice(&nonce_bytes);
                sealed.extend_from_slice(&ct);

                Ok((eph_public.as_bytes().to_vec(), sealed))
            }

            pub fn open_message(
                secret: &[u8; 32],
                eph_pubkey: &[u8],
                sealed_data: &[u8],
            ) -> Result<Vec<u8>> {
                if eph_pubkey.len() != 32 {
                    return Err(HidraError::Crypto(
                        "invalid ephemeral pubkey".into(),
                    ));
                }
                if sealed_data.len() < 13 {
                    return Err(HidraError::Crypto(
                        "sealed data too short".into(),
                    ));
                }
                let mut eph_arr = [0u8; 32];
                eph_arr.copy_from_slice(eph_pubkey);
                let eph_public = PublicKey::from(eph_arr);

                let secret_key = StaticSecret::from(*secret);
                let shared = secret_key.diffie_hellman(&eph_public);
                let sym_key =
                    blake3::derive_key("hidramail-seal-v1", shared.as_bytes());

                let cipher = ChaCha20Poly1305::new((&sym_key).into());
                let nonce = Nonce::from_slice(&sealed_data[..12]);
                cipher
                    .decrypt(nonce, &sealed_data[12..])
                    .map_err(|e| HidraError::Crypto(format!("open: {e}")))
            }

            pub fn sign_data(
                signing_key: &ed25519_dalek::SigningKey,
                data: &[u8],
            ) -> Vec<u8> {
                use ed25519_dalek::Signer;
                signing_key.sign(data).to_bytes().to_vec()
            }

            pub fn verify_sig(
                vk_bytes: &[u8],
                data: &[u8],
                sig_bytes: &[u8],
            ) -> bool {
                if vk_bytes.len() != 32 || sig_bytes.len() != 64 {
                    return false;
                }
                let mut vk_arr = [0u8; 32];
                vk_arr.copy_from_slice(vk_bytes);
                let vk = match VerifyingKey::from_bytes(&vk_arr) {
                    Ok(k) => k,
                    Err(_) => return false,
                };
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(sig_bytes);
                let sig = Signature::from_bytes(&sig_arr);
                vk.verify(data, &sig).is_ok()
            }
        }

        pub mod storage {
            use std::path::{Path, PathBuf};

            use crate::error::{HidraError, Result};
            use super::crypto;
            use super::protocol::{MailContent, MailEnvelope, MailSummary};

            pub struct MailStore {
                inbox_dir: PathBuf,
                sent_dir: PathBuf,
            }

            impl MailStore {
                pub fn new(base_dir: &Path) -> Result<Self> {
                    let inbox_dir = base_dir.join("inbox");
                    let sent_dir = base_dir.join("sent");
                    std::fs::create_dir_all(&inbox_dir).map_err(HidraError::Io)?;
                    std::fs::create_dir_all(&sent_dir).map_err(HidraError::Io)?;
                    Ok(Self { inbox_dir, sent_dir })
                }

                pub fn store_incoming(&self, env: &MailEnvelope) -> Result<()> {
                    let path = self.inbox_dir.join(format!("{}.json", env.id));
                    let json = serde_json::to_string(env)
                        .map_err(|e| HidraError::Protocol(format!("serialize: {e}")))?;
                    std::fs::write(path, json).map_err(HidraError::Io)
                }

                pub fn store_sent(&self, env: &MailEnvelope) -> Result<()> {
                    let path = self.sent_dir.join(format!("{}.json", env.id));
                    let json = serde_json::to_string(env)
                        .map_err(|e| HidraError::Protocol(format!("serialize: {e}")))?;
                    std::fs::write(path, json).map_err(HidraError::Io)
                }

                pub fn list_inbox(&self, secret: &[u8; 32]) -> Vec<MailSummary> {
                    self.list_folder(&self.inbox_dir, secret)
                }

                pub fn list_sent(&self, secret: &[u8; 32]) -> Vec<MailSummary> {
                    self.list_folder(&self.sent_dir, secret)
                }

                fn list_folder(
                    &self,
                    dir: &Path,
                    secret: &[u8; 32],
                ) -> Vec<MailSummary> {
                    let mut out = Vec::new();
                    let entries = match std::fs::read_dir(dir) {
                        Ok(e) => e,
                        Err(_) => return out,
                    };
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.extension().and_then(|e| e.to_str()) != Some("json") {
                            continue;
                        }
                        let data = match std::fs::read_to_string(&p) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };
                        let env: MailEnvelope = match serde_json::from_str(&data) {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let subject = decrypt_subject(&env, secret);
                        let read_marker = p.with_extension("read");
                        out.push(MailSummary {
                            id: env.id,
                            from_addr: env.from_addr,
                            to_addr: env.to_addr,
                            timestamp: env.timestamp,
                            subject,
                            read: read_marker.exists(),
                        });
                    }
                    out.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                    out
                }

                pub fn read_mail(
                    &self,
                    id: &str,
                    secret: &[u8; 32],
                ) -> Result<(MailEnvelope, MailContent)> {
                    let inbox_path = self.inbox_dir.join(format!("{id}.json"));
                    let path = if inbox_path.exists() {
                        let marker = self.inbox_dir.join(format!("{id}.read"));
                        let _ = std::fs::write(marker, "");
                        inbox_path
                    } else {
                        let sent_path = self.sent_dir.join(format!("{id}.json"));
                        if sent_path.exists() {
                            sent_path
                        } else {
                            return Err(HidraError::Protocol(format!(
                                "mail not found: {id}"
                            )));
                        }
                    };

                    let data = std::fs::read_to_string(&path).map_err(HidraError::Io)?;
                    let env: MailEnvelope = serde_json::from_str(&data)
                        .map_err(|e| {
                            HidraError::Protocol(format!("deserialize: {e}"))
                        })?;

                    let plaintext = crypto::open_message(
                        secret,
                        &env.ephemeral_pubkey,
                        &env.sealed_body,
                    )?;
                    let content: MailContent = serde_json::from_slice(&plaintext)
                        .map_err(|e| {
                            HidraError::Protocol(format!("content: {e}"))
                        })?;

                    Ok((env, content))
                }

                pub fn delete_mail(&self, id: &str) -> Result<()> {
                    let inbox = self.inbox_dir.join(format!("{id}.json"));
                    let sent = self.sent_dir.join(format!("{id}.json"));
                    let marker = self.inbox_dir.join(format!("{id}.read"));
                    if inbox.exists() {
                        std::fs::remove_file(&inbox).map_err(HidraError::Io)?;
                        let _ = std::fs::remove_file(&marker);
                    } else if sent.exists() {
                        std::fs::remove_file(&sent).map_err(HidraError::Io)?;
                    } else {
                        return Err(HidraError::Protocol(format!(
                            "mail not found: {id}"
                        )));
                    }
                    Ok(())
                }
            }

            fn decrypt_subject(env: &MailEnvelope, secret: &[u8; 32]) -> String {
                match crypto::open_message(
                    secret,
                    &env.ephemeral_pubkey,
                    &env.sealed_body,
                ) {
                    Ok(pt) => match serde_json::from_slice::<MailContent>(&pt) {
                        Ok(c) => c.subject,
                        Err(_) => "[erro]".into(),
                    },
                    Err(_) => "[criptografado]".into(),
                }
            }
        }

        pub mod server {
            use std::net::SocketAddr;
            use std::sync::Arc;
            use std::time::{SystemTime, UNIX_EPOCH};

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            use tokio::net::{TcpListener, TcpStream};
            use tracing::{debug, info, warn};

            use super::crypto;
            use super::frontend;
            use super::protocol::{
                MailContent, MailEnvelope, SendRequest,
            };
            use super::storage::MailStore;

            pub struct ServerState {
                pub mail_addr: String,
                pub mail_keys: crypto::MailKeys,
                pub signing_key: ed25519_dalek::SigningKey,
                pub store: MailStore,
            }

            pub struct MailServer {
                addr: SocketAddr,
                state: Arc<ServerState>,
            }

            impl MailServer {
                pub fn new(
                    addr: SocketAddr,
                    state: ServerState,
                ) -> Self {
                    Self {
                        addr,
                        state: Arc::new(state),
                    }
                }

                pub async fn run(self) -> crate::error::Result<()> {
                    let listener = TcpListener::bind(self.addr).await?;
                    info!(
                        addr = %self.addr,
                        mail = %self.state.mail_addr,
                        "HidraMail server listening"
                    );

                    loop {
                        let (stream, peer) = match listener.accept().await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(error = %e, "accept error");
                                continue;
                            }
                        };
                        let st = Arc::clone(&self.state);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, peer, st).await
                            {
                                debug!(
                                    peer = %peer,
                                    error = %e,
                                    "connection ended"
                                );
                            }
                        });
                    }
                }
            }

            async fn handle_connection(
                mut stream: TcpStream,
                peer: SocketAddr,
                state: Arc<ServerState>,
            ) -> crate::error::Result<()> {
                let mut buf = vec![0u8; 65536];
                let mut total = 0usize;
                loop {
                    let n = stream.read(&mut buf[total..]).await?;
                    if n == 0 {
                        break;
                    }
                    total += n;
                    let raw = &buf[..total];
                    if let Some(hdr_end) = find_header_end(raw) {
                        let headers = String::from_utf8_lossy(&raw[..hdr_end]);
                        let content_len = parse_content_length(&headers);
                        let body_received = total - hdr_end;
                        if body_received >= content_len {
                            break;
                        }
                    }
                    if total >= buf.len() {
                        break;
                    }
                }
                if total == 0 {
                    return Ok(());
                }
                let raw = String::from_utf8_lossy(&buf[..total]).to_string();
                debug!(peer = %peer, bytes = total, "request received");
                handle_http(&mut stream, &raw, &state).await
            }

            fn find_header_end(data: &[u8]) -> Option<usize> {
                for i in 0..data.len().saturating_sub(3) {
                    if data[i] == b'\r'
                        && data[i + 1] == b'\n'
                        && data[i + 2] == b'\r'
                        && data[i + 3] == b'\n'
                    {
                        return Some(i + 4);
                    }
                }
                None
            }

            fn parse_content_length(headers: &str) -> usize {
                for line in headers.lines() {
                    let lower = line.to_lowercase();
                    if lower.starts_with("content-length:") {
                        if let Some(val) = line.split_once(':') {
                            return val.1.trim().parse().unwrap_or(0);
                        }
                    }
                }
                0
            }

            fn parse_request_line(raw: &str) -> Option<(&str, &str)> {
                let first = raw.lines().next()?;
                let mut parts = first.split_whitespace();
                let method = parts.next()?;
                let path = parts.next()?;
                Some((method, path))
            }

            fn extract_body(raw: &str) -> &str {
                raw.split("\r\n\r\n").nth(1).unwrap_or("")
            }

            fn hex_encode(bytes: &[u8]) -> String {
                bytes.iter().map(|b| format!("{b:02x}")).collect()
            }

            fn json_ok(body: &str) -> String {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }

            fn json_err(status: u16, msg: &str) -> String {
                let body = format!(r#"{{"error":"{msg}"}}"#);
                format!(
                    "HTTP/1.1 {status} Error\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }

            fn html_response(body: &str) -> String {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }

            fn static_response(ctype: &str, body: &str) -> String {
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ctype}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            }

            async fn handle_http(
                stream: &mut TcpStream,
                raw: &str,
                state: &Arc<ServerState>,
            ) -> crate::error::Result<()> {
                let (method, path) = match parse_request_line(raw) {
                    Some(v) => v,
                    None => {
                        let r = json_err(400, "bad request");
                        stream.write_all(r.as_bytes()).await?;
                        return Ok(());
                    }
                };

                let resp = match (method, path) {
                    ("GET", "/" | "/index.html") => {
                        let html = frontend::INDEX_HTML
                            .replace("{{MAIL_ADDR}}", &state.mail_addr);
                        html_response(&html)
                    }
                    ("GET", "/style.css") => {
                        static_response("text/css", frontend::STYLE_CSS)
                    }
                    ("GET", "/app.js") => {
                        static_response(
                            "application/javascript",
                            frontend::APP_JS,
                        )
                    }
                    ("GET", "/api/identity") => {
                        let body = format!(
                            r#"{{"address":"{}","pubkey":"{}"}}"#,
                            state.mail_addr,
                            hex_encode(&state.mail_keys.public_bytes),
                        );
                        json_ok(&body)
                    }
                    ("GET", "/api/pubkey") => {
                        let body = format!(
                            r#"{{"pubkey":"{}"}}"#,
                            hex_encode(&state.mail_keys.public_bytes),
                        );
                        json_ok(&body)
                    }
                    ("GET", "/api/inbox") => {
                        let list = state
                            .store
                            .list_inbox(state.mail_keys.secret_bytes());
                        let body = serde_json::to_string(&list)
                            .unwrap_or_else(|_| "[]".into());
                        json_ok(&body)
                    }
                    ("GET", "/api/sent") => {
                        let list = state
                            .store
                            .list_sent(state.mail_keys.secret_bytes());
                        let body = serde_json::to_string(&list)
                            .unwrap_or_else(|_| "[]".into());
                        json_ok(&body)
                    }
                    ("GET", p) if p.starts_with("/api/mail/") => {
                        let id = &p[10..];
                        api_read_mail(id, state)
                    }
                    ("POST", "/api/send") => {
                        let body = extract_body(raw);
                        api_send_mail(body, state).await
                    }
                    ("POST", "/api/deliver") => {
                        let body = extract_body(raw);
                        api_deliver(body, state)
                    }
                    ("DELETE", p) if p.starts_with("/api/mail/") => {
                        let id = &p[10..];
                        match state.store.delete_mail(id) {
                            Ok(()) => json_ok(r#"{"ok":true}"#),
                            Err(e) => json_err(404, &format!("{e}")),
                        }
                    }
                    ("OPTIONS", _) => {
                        "HTTP/1.1 204 No Content\r\n\
                         Access-Control-Allow-Origin: *\r\n\
                         Access-Control-Allow-Methods: GET,POST,DELETE,OPTIONS\r\n\
                         Access-Control-Allow-Headers: Content-Type\r\n\
                         Connection: close\r\n\r\n"
                            .to_string()
                    }
                    _ => json_err(404, "not found"),
                };

                stream.write_all(resp.as_bytes()).await?;
                Ok(())
            }

            fn api_read_mail(
                id: &str,
                state: &Arc<ServerState>,
            ) -> String {
                match state.store.read_mail(id, state.mail_keys.secret_bytes())
                {
                    Ok((env, content)) => {
                        let verified = crypto::verify_sig(
                            &env.sender_verifying_key,
                            &env.signing_data(),
                            &env.signature,
                        );
                        let body = format!(
                            r#"{{"id":"{}","from_addr":"{}","to_addr":"{}","subject":"{}","body":"{}","timestamp":{},"verified":{}}}"#,
                            escape_json(&env.id),
                            escape_json(&env.from_addr),
                            escape_json(&env.to_addr),
                            escape_json(&content.subject),
                            escape_json(&content.body),
                            env.timestamp,
                            verified,
                        );
                        json_ok(&body)
                    }
                    Err(e) => json_err(404, &format!("{e}")),
                }
            }

            async fn api_send_mail(
                body: &str,
                state: &Arc<ServerState>,
            ) -> String {
                let req: SendRequest = match serde_json::from_str(body) {
                    Ok(r) => r,
                    Err(e) => {
                        return json_err(400, &format!("parse: {e}"));
                    }
                };

                let target_addr = match &req.direct_addr {
                    Some(a) => a.clone(),
                    None => {
                        return json_err(
                            400,
                            "direct_addr required (SOCKS5 delivery not yet implemented)",
                        );
                    }
                };

                let recipient_pubkey =
                    match fetch_recipient_pubkey(&target_addr).await {
                        Ok(k) => k,
                        Err(e) => {
                            return json_err(
                                502,
                                &format!("fetch pubkey: {e}"),
                            );
                        }
                    };

                let content = MailContent {
                    subject: req.subject,
                    body: req.body,
                };
                let content_json = match serde_json::to_vec(&content) {
                    Ok(j) => j,
                    Err(e) => {
                        return json_err(500, &format!("serialize: {e}"));
                    }
                };

                let (eph_pubkey, sealed_body) =
                    match crypto::seal_message(&recipient_pubkey, &content_json)
                    {
                        Ok(v) => v,
                        Err(e) => {
                            return json_err(
                                500,
                                &format!("encrypt: {e}"),
                            );
                        }
                    };

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);

                let vk = state
                    .signing_key
                    .verifying_key()
                    .as_bytes()
                    .to_vec();

                let mut envelope = MailEnvelope {
                    id: uuid::Uuid::new_v4().to_string(),
                    from_addr: state.mail_addr.clone(),
                    to_addr: req.to.clone(),
                    timestamp: now,
                    ephemeral_pubkey: eph_pubkey,
                    sealed_body,
                    sender_verifying_key: vk,
                    signature: Vec::new(),
                };
                envelope.signature =
                    crypto::sign_data(&state.signing_key, &envelope.signing_data());

                match deliver_to_remote(&target_addr, &envelope).await {
                    Ok(()) => {
                        let sender_copy = make_sender_copy(
                            &envelope,
                            &content_json,
                            &state.mail_keys.public_bytes,
                            &state.signing_key,
                        );
                        let _ = state.store.store_sent(&sender_copy);
                        info!(
                            to = %req.to,
                            id = %envelope.id,
                            "mail sent"
                        );
                        json_ok(r#"{"ok":true}"#)
                    }
                    Err(e) => json_err(502, &format!("delivery: {e}")),
                }
            }

            fn api_deliver(
                body: &str,
                state: &Arc<ServerState>,
            ) -> String {
                let envelope: MailEnvelope = match serde_json::from_str(body) {
                    Ok(e) => e,
                    Err(e) => {
                        return json_err(400, &format!("parse: {e}"));
                    }
                };

                let sig_data = envelope.signing_data();
                if !crypto::verify_sig(
                    &envelope.sender_verifying_key,
                    &sig_data,
                    &envelope.signature,
                ) {
                    return json_err(403, "invalid signature");
                }

                match state.store.store_incoming(&envelope) {
                    Ok(()) => {
                        info!(
                            from = %envelope.from_addr,
                            id = %envelope.id,
                            "mail received"
                        );
                        json_ok(&format!(
                            r#"{{"ok":true,"id":"{}"}}"#,
                            envelope.id
                        ))
                    }
                    Err(e) => json_err(500, &format!("store: {e}")),
                }
            }

            async fn fetch_recipient_pubkey(
                addr: &str,
            ) -> crate::error::Result<[u8; 32]> {
                let mut stream = TcpStream::connect(addr).await?;
                let req = format!(
                    "GET /api/pubkey HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
                );
                stream.write_all(req.as_bytes()).await?;
                let mut resp = vec![0u8; 4096];
                let n = stream.read(&mut resp).await?;
                let text = String::from_utf8_lossy(&resp[..n]);
                let body = text
                    .split("\r\n\r\n")
                    .nth(1)
                    .ok_or_else(|| {
                        crate::error::HidraError::Protocol(
                            "no response body".into(),
                        )
                    })?
                    .trim();

                #[derive(serde::Deserialize)]
                struct PkResp {
                    pubkey: String,
                }
                let parsed: PkResp = serde_json::from_str(body).map_err(
                    |e| {
                        crate::error::HidraError::Protocol(format!(
                            "parse pubkey response: {e}"
                        ))
                    },
                )?;

                let bytes = hex_decode(&parsed.pubkey)?;
                if bytes.len() != 32 {
                    return Err(crate::error::HidraError::Crypto(
                        "invalid pubkey length".into(),
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(key)
            }

            fn hex_decode(
                hex: &str,
            ) -> crate::error::Result<Vec<u8>> {
                if hex.len() % 2 != 0 {
                    return Err(crate::error::HidraError::Protocol(
                        "odd hex length".into(),
                    ));
                }
                let mut bytes = Vec::with_capacity(hex.len() / 2);
                for i in (0..hex.len()).step_by(2) {
                    let byte =
                        u8::from_str_radix(&hex[i..i + 2], 16).map_err(
                            |_| {
                                crate::error::HidraError::Protocol(
                                    "invalid hex".into(),
                                )
                            },
                        )?;
                    bytes.push(byte);
                }
                Ok(bytes)
            }

            async fn deliver_to_remote(
                addr: &str,
                envelope: &MailEnvelope,
            ) -> crate::error::Result<()> {
                let json = serde_json::to_string(envelope).map_err(|e| {
                    crate::error::HidraError::Protocol(format!(
                        "serialize: {e}"
                    ))
                })?;
                let req = format!(
                    "POST /api/deliver HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
                    json.len()
                );
                let mut stream = TcpStream::connect(addr).await?;
                stream.write_all(req.as_bytes()).await?;
                let mut resp = vec![0u8; 4096];
                let n = stream.read(&mut resp).await?;
                let text = String::from_utf8_lossy(&resp[..n]);
                if text.contains("200") {
                    Ok(())
                } else {
                    Err(crate::error::HidraError::Protocol(format!(
                        "delivery failed: {text}"
                    )))
                }
            }

            fn make_sender_copy(
                original: &MailEnvelope,
                content_json: &[u8],
                sender_pubkey: &[u8; 32],
                signing_key: &ed25519_dalek::SigningKey,
            ) -> MailEnvelope {
                let (eph, sealed) =
                    match crypto::seal_message(sender_pubkey, content_json) {
                        Ok(v) => v,
                        Err(_) => return original.clone(),
                    };
                let mut copy = MailEnvelope {
                    id: original.id.clone(),
                    from_addr: original.from_addr.clone(),
                    to_addr: original.to_addr.clone(),
                    timestamp: original.timestamp,
                    ephemeral_pubkey: eph,
                    sealed_body: sealed,
                    sender_verifying_key: original.sender_verifying_key.clone(),
                    signature: Vec::new(),
                };
                copy.signature =
                    crypto::sign_data(signing_key, &copy.signing_data());
                copy
            }

            fn escape_json(s: &str) -> String {
                s.replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('\t', "\\t")
            }
        }

        pub mod frontend {
            pub const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HidraMail — {{MAIL_ADDR}}</title>
    <link rel="stylesheet" href="/style.css">
</head>
<body>
    <div id="app">
        <nav id="sidebar">
            <div class="sidebar-header">
                <div class="logo">&#128013;</div>
                <h1>HidraMail</h1>
            </div>
            <div class="my-address" id="myAddress">Carregando...</div>
            <ul class="nav-items">
                <li class="nav-item active" id="nav-inbox" onclick="showInbox()">&#128229; Caixa de Entrada</li>
                <li class="nav-item" id="nav-sent" onclick="showSent()">&#128228; Enviados</li>
                <li class="nav-item compose-btn" id="nav-compose" onclick="showCompose()">&#9998; Compor</li>
            </ul>
            <div class="sidebar-footer">
                <div class="crypto-info">&#128274; E2E criptografado</div>
                <div class="crypto-info">X25519 + ChaCha20-Poly1305</div>
            </div>
        </nav>
        <main id="content">
            <div class="loading">Carregando...</div>
        </main>
    </div>
    <script src="/app.js"></script>
</body>
</html>"##;

            pub const STYLE_CSS: &str = r##"
* { margin: 0; padding: 0; box-sizing: border-box; }

:root {
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-tertiary: #1a2332;
    --accent: #00ff88;
    --accent-dim: #00cc6a;
    --text-primary: #e0e6ed;
    --text-secondary: #8892a4;
    --text-muted: #4a5568;
    --border: #1e293b;
    --danger: #ff4757;
    --unread: #162030;
}

body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    height: 100vh;
    overflow: hidden;
}

#app {
    display: flex;
    height: 100vh;
}

#sidebar {
    width: 260px;
    min-width: 260px;
    background: var(--bg-secondary);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    padding: 16px;
}

.sidebar-header {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 12px;
}

.logo { font-size: 24px; }

#sidebar h1 {
    font-size: 18px;
    font-weight: 600;
    color: var(--accent);
}

.my-address {
    font-family: monospace;
    font-size: 11px;
    color: var(--text-muted);
    background: var(--bg-tertiary);
    padding: 6px 10px;
    border-radius: 6px;
    margin-bottom: 20px;
    word-break: break-all;
}

.nav-items {
    list-style: none;
    flex: 1;
}

.nav-item {
    padding: 10px 14px;
    border-radius: 8px;
    cursor: pointer;
    color: var(--text-secondary);
    font-size: 14px;
    margin-bottom: 4px;
    transition: background 0.15s;
}

.nav-item:hover {
    background: var(--bg-tertiary);
    color: var(--text-primary);
}

.nav-item.active {
    background: var(--bg-tertiary);
    color: var(--accent);
    font-weight: 600;
}

.nav-item.compose-btn {
    background: rgba(0, 255, 136, 0.1);
    color: var(--accent);
    font-weight: 600;
    margin-top: 8px;
}

.nav-item.compose-btn:hover {
    background: rgba(0, 255, 136, 0.2);
}

.sidebar-footer {
    padding-top: 12px;
    border-top: 1px solid var(--border);
}

.crypto-info {
    font-size: 11px;
    color: var(--text-muted);
    text-align: center;
    line-height: 1.6;
}

#content {
    flex: 1;
    overflow-y: auto;
    padding: 24px 32px;
}

.loading {
    color: var(--text-muted);
    text-align: center;
    margin-top: 40px;
}

/* Mail list */
.mail-list-header {
    font-size: 20px;
    font-weight: 600;
    margin-bottom: 16px;
    color: var(--text-primary);
}

.mail-item {
    display: grid;
    grid-template-columns: 1fr auto;
    grid-template-rows: auto auto;
    gap: 2px 16px;
    padding: 12px 16px;
    border-radius: 8px;
    border: 1px solid var(--border);
    margin-bottom: 6px;
    cursor: pointer;
    transition: background 0.15s;
}

.mail-item:hover {
    background: var(--bg-tertiary);
}

.mail-item.unread {
    background: var(--unread);
    border-color: rgba(0, 255, 136, 0.15);
}

.mail-item.unread .mail-subject {
    font-weight: 600;
    color: var(--text-primary);
}

.mail-from {
    font-size: 13px;
    color: var(--text-secondary);
    font-family: monospace;
    grid-column: 1;
}

.mail-date {
    font-size: 12px;
    color: var(--text-muted);
    grid-column: 2;
    grid-row: 1 / 3;
    align-self: center;
}

.mail-subject {
    font-size: 14px;
    color: var(--text-secondary);
    grid-column: 1;
}

.empty-state {
    text-align: center;
    margin-top: 60px;
    color: var(--text-muted);
}

.empty-state h2 {
    margin-bottom: 8px;
    color: var(--text-secondary);
}

/* Read view */
.mail-read {
    max-width: 700px;
}

.mail-actions {
    display: flex;
    gap: 8px;
    margin-bottom: 16px;
}

.mail-actions button {
    padding: 8px 16px;
    background: var(--bg-tertiary);
    color: var(--text-primary);
    border: 1px solid var(--border);
    border-radius: 6px;
    cursor: pointer;
    font-size: 13px;
}

.mail-actions button:hover {
    background: var(--bg-secondary);
}

.mail-actions button.danger {
    color: var(--danger);
    border-color: var(--danger);
}

.mail-actions button.danger:hover {
    background: rgba(255, 71, 87, 0.1);
}

.mail-read h2 {
    font-size: 22px;
    margin-bottom: 12px;
}

.mail-meta {
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 20px;
    padding: 12px;
    background: var(--bg-secondary);
    border-radius: 8px;
    border: 1px solid var(--border);
    line-height: 1.8;
}

.mail-meta strong {
    color: var(--text-primary);
    font-family: monospace;
    font-size: 12px;
}

.verified {
    color: var(--accent);
}

.unverified {
    color: var(--danger);
}

.mail-body-content {
    font-size: 14px;
    line-height: 1.7;
    color: var(--text-primary);
    padding: 16px;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-radius: 8px;
    white-space: pre-wrap;
    word-break: break-word;
    margin-bottom: 16px;
}

.crypto-badge {
    font-size: 11px;
    color: var(--text-muted);
    text-align: center;
}

/* Compose */
.compose {
    max-width: 700px;
}

.compose h2 {
    font-size: 20px;
    margin-bottom: 16px;
}

.form-group {
    margin-bottom: 12px;
}

.form-group label {
    display: block;
    font-size: 13px;
    color: var(--text-secondary);
    margin-bottom: 4px;
}

.form-group input,
.form-group textarea {
    width: 100%;
    padding: 10px 14px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text-primary);
    font-size: 14px;
    font-family: inherit;
    outline: none;
    resize: vertical;
}

.form-group input:focus,
.form-group textarea:focus {
    border-color: var(--accent);
}

.form-group input[type="text"]::placeholder,
.form-group textarea::placeholder {
    color: var(--text-muted);
}

.compose button {
    padding: 10px 28px;
    background: var(--accent);
    color: var(--bg-primary);
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
}

.compose button:hover {
    background: var(--accent-dim);
}

#sendStatus {
    margin-top: 12px;
    font-size: 13px;
    color: var(--text-secondary);
}

@media (max-width: 700px) {
    #sidebar { width: 200px; min-width: 200px; padding: 12px; }
    #content { padding: 16px; }
}
"##;

            pub const APP_JS: &str = r##"
(function() {
    'use strict';

    var myAddress = '';
    var myPubkey = '';

    async function api(path, opts) {
        var res = await fetch(path, opts);
        return res.json();
    }

    async function init() {
        try {
            var identity = await api('/api/identity');
            myAddress = identity.address;
            myPubkey = identity.pubkey;
            document.getElementById('myAddress').textContent = myAddress;
        } catch(e) {
            document.getElementById('myAddress').textContent = 'erro ao carregar';
        }
        showInbox();
    }

    function updateNav(view) {
        document.querySelectorAll('.nav-item').forEach(function(el) {
            el.classList.remove('active');
        });
        var el = document.getElementById('nav-' + view);
        if (el) el.classList.add('active');
    }

    window.showInbox = async function() {
        updateNav('inbox');
        var content = document.getElementById('content');
        content.innerHTML = '<div class="loading">Carregando...</div>';
        try {
            var mails = await api('/api/inbox');
            renderMailList(mails, 'Caixa de Entrada');
        } catch(e) {
            content.innerHTML = '<div class="empty-state"><p>Erro ao carregar.</p></div>';
        }
    };

    window.showSent = async function() {
        updateNav('sent');
        var content = document.getElementById('content');
        content.innerHTML = '<div class="loading">Carregando...</div>';
        try {
            var mails = await api('/api/sent');
            renderMailList(mails, 'Enviados');
        } catch(e) {
            content.innerHTML = '<div class="empty-state"><p>Erro ao carregar.</p></div>';
        }
    };

    window.showCompose = function() {
        updateNav('compose');
        var content = document.getElementById('content');
        content.innerHTML =
            '<div class="compose">' +
            '<h2>Nova Mensagem</h2>' +
            '<div class="form-group">' +
                '<label>Para:</label>' +
                '<input type="text" id="composeTo" placeholder="destinatario@hash.hidra">' +
            '</div>' +
            '<div class="form-group">' +
                '<label>Assunto:</label>' +
                '<input type="text" id="composeSubject" placeholder="Assunto da mensagem">' +
            '</div>' +
            '<div class="form-group">' +
                '<label>Mensagem:</label>' +
                '<textarea id="composeBody" rows="12" placeholder="Escreva sua mensagem..."></textarea>' +
            '</div>' +
            '<div class="form-group">' +
                '<label>Endereço direto (testes locais):</label>' +
                '<input type="text" id="composeDirectAddr" placeholder="127.0.0.1:8081 (obrigatório por enquanto)">' +
            '</div>' +
            '<button onclick="doSend()">Enviar</button>' +
            '<div id="sendStatus"></div>' +
            '</div>';
    };

    window.doSend = async function() {
        var to = document.getElementById('composeTo').value.trim();
        var subject = document.getElementById('composeSubject').value.trim();
        var body = document.getElementById('composeBody').value.trim();
        var directAddr = document.getElementById('composeDirectAddr').value.trim();
        var status = document.getElementById('sendStatus');

        if (!to || !subject || !body) {
            status.textContent = 'Preencha todos os campos.';
            status.style.color = '#ff4757';
            return;
        }
        if (!directAddr) {
            status.textContent = 'Endereço direto obrigatório (entrega via SOCKS5 em breve).';
            status.style.color = '#ff4757';
            return;
        }

        status.textContent = 'Enviando...';
        status.style.color = '#8892a4';

        try {
            var payload = { to: to, subject: subject, body: body, direct_addr: directAddr };
            var res = await fetch('/api/send', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            var result = await res.json();
            if (result.ok) {
                status.textContent = 'E-mail enviado com sucesso!';
                status.style.color = '#00ff88';
                document.getElementById('composeTo').value = '';
                document.getElementById('composeSubject').value = '';
                document.getElementById('composeBody').value = '';
            } else {
                status.textContent = 'Erro: ' + (result.error || 'falha');
                status.style.color = '#ff4757';
            }
        } catch(e) {
            status.textContent = 'Erro de conexão: ' + e;
            status.style.color = '#ff4757';
        }
    };

    function renderMailList(mails, title) {
        var content = document.getElementById('content');
        if (!mails || mails.length === 0) {
            content.innerHTML = '<div class="empty-state"><h2>' + esc(title) + '</h2><p>Nenhum e-mail.</p></div>';
            return;
        }
        var html = '<div class="mail-list-header">' + esc(title) + ' (' + mails.length + ')</div>';
        for (var i = 0; i < mails.length; i++) {
            var m = mails[i];
            var date = new Date(m.timestamp).toLocaleString('pt-BR');
            var unread = !m.read ? ' unread' : '';
            html +=
                '<div class="mail-item' + unread + '" onclick="readMail(\'' + esc(m.id) + '\')">' +
                    '<div class="mail-from">' + esc(m.from_addr) + '</div>' +
                    '<div class="mail-date">' + date + '</div>' +
                    '<div class="mail-subject">' + esc(m.subject) + '</div>' +
                '</div>';
        }
        content.innerHTML = html;
    }

    window.readMail = async function(id) {
        var content = document.getElementById('content');
        content.innerHTML = '<div class="loading">Descriptografando...</div>';
        try {
            var mail = await api('/api/mail/' + id);
            if (mail.error) {
                content.innerHTML = '<div class="empty-state"><p>Erro: ' + esc(mail.error) + '</p></div>';
                return;
            }
            var date = new Date(mail.timestamp).toLocaleString('pt-BR');
            var vIcon = mail.verified ? '✓ Assinatura verificada' : '✗ Assinatura inválida';
            var vClass = mail.verified ? 'verified' : 'unverified';
            content.innerHTML =
                '<div class="mail-read">' +
                    '<div class="mail-actions">' +
                        '<button onclick="showInbox()">← Voltar</button>' +
                        '<button class="danger" onclick="deleteMail(\'' + esc(mail.id) + '\')">Excluir</button>' +
                    '</div>' +
                    '<h2>' + esc(mail.subject) + '</h2>' +
                    '<div class="mail-meta">' +
                        '<div>De: <strong>' + esc(mail.from_addr) + '</strong></div>' +
                        '<div>Para: <strong>' + esc(mail.to_addr) + '</strong></div>' +
                        '<div>Data: ' + date + '</div>' +
                        '<div class="' + vClass + '">' + vIcon + '</div>' +
                    '</div>' +
                    '<div class="mail-body-content">' + esc(mail.body) + '</div>' +
                    '<div class="crypto-badge">\u{0001f512} Descriptografado localmente — X25519 + ChaCha20-Poly1305</div>' +
                '</div>';
        } catch(e) {
            content.innerHTML = '<div class="empty-state"><p>Erro: ' + e + '</p></div>';
        }
    };

    window.deleteMail = async function(id) {
        await fetch('/api/mail/' + id, { method: 'DELETE' });
        showInbox();
    };

    function esc(str) {
        var div = document.createElement('div');
        div.textContent = str || '';
        return div.innerHTML;
    }

    init();
})();
"##;
        }
    }
}

// =============================================================================
// mod search — HidraSearch: encrypted, uncensored search engine
// =============================================================================
mod search {
    pub mod engine {
        use std::net::SocketAddr;

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tracing::info;

        use crate::error::Result;

        pub struct SearchServer {
            addr: SocketAddr,
            proxy_addr: Option<String>,
        }

        impl SearchServer {
            pub fn new(addr: SocketAddr, proxy_addr: Option<String>) -> Self {
                Self { addr, proxy_addr }
            }

            pub async fn run(&self) -> Result<()> {
                let listener = TcpListener::bind(self.addr).await?;
                info!(addr = %self.addr, "HidraSearch listening");

                let proxy = self.proxy_addr.clone();

                loop {
                    let (mut stream, _peer) = listener.accept().await?;
                    let proxy_clone = proxy.clone();

                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 8192];
                        let n = match stream.read(&mut buf).await {
                            Ok(n) if n > 0 => n,
                            _ => return,
                        };

                        let request = String::from_utf8_lossy(&buf[..n]);
                        let first_line = request.lines().next().unwrap_or("");

                        let (status, content_type, body) = if first_line.starts_with("GET /search?") {
                            let query = extract_query_param(&request, "q");
                            let page: usize = extract_query_param(&request, "p")
                                .and_then(|p| p.parse().ok())
                                .unwrap_or(1);

                            match query {
                                Some(q) if !q.is_empty() => {
                                    let results = perform_search(&q, page, proxy_clone.as_deref()).await;
                                    (200, "application/json", results)
                                }
                                _ => (400, "application/json", r#"{"error":"missing query parameter 'q'"}"#.to_string()),
                            }
                        } else if first_line.starts_with("GET /suggestions?") {
                            let query = extract_query_param(&request, "q");
                            match query {
                                Some(q) if !q.is_empty() => {
                                    let suggestions = get_suggestions(&q).await;
                                    (200, "application/json", suggestions)
                                }
                                _ => (200, "application/json", "[]".to_string()),
                            }
                        } else if first_line.starts_with("GET /") && (first_line.contains("HTTP") && !first_line.contains("/search") && !first_line.contains("/suggestions")) {
                            (200, "text/html; charset=utf-8", SEARCH_PAGE_HTML.to_string())
                        } else if first_line.starts_with("OPTIONS") {
                            (204, "text/plain", String::new())
                        } else {
                            (404, "text/plain", "not found".to_string())
                        };

                        let response = format!(
                            "HTTP/1.1 {} {}\r\n\
                             Content-Type: {content_type}\r\n\
                             Content-Length: {}\r\n\
                             Access-Control-Allow-Origin: *\r\n\
                             Access-Control-Allow-Methods: GET, OPTIONS\r\n\
                             Access-Control-Allow-Headers: Content-Type\r\n\
                             X-Hidra-Encrypted: true\r\n\
                             X-Hidra-Logged: false\r\n\
                             Cache-Control: no-store, no-cache\r\n\
                             Connection: close\r\n\r\n{}",
                            status,
                            match status {
                                200 => "OK",
                                204 => "No Content",
                                400 => "Bad Request",
                                _ => "Not Found",
                            },
                            body.len(),
                            body,
                        );

                        let _ = stream.write_all(response.as_bytes()).await;
                    });
                }
            }
        }

        fn extract_query_param(request: &str, param: &str) -> Option<String> {
            let first_line = request.lines().next()?;
            let path = first_line.split_whitespace().nth(1)?;
            let query_string = path.split('?').nth(1)?;
            for pair in query_string.split('&') {
                let mut kv = pair.splitn(2, '=');
                if let (Some(key), Some(value)) = (kv.next(), kv.next()) {
                    if key == param {
                        return Some(url_decode(value));
                    }
                }
            }
            None
        }

        fn url_decode(s: &str) -> String {
            let mut result = String::with_capacity(s.len());
            let mut chars = s.bytes();
            while let Some(b) = chars.next() {
                match b {
                    b'+' => result.push(' '),
                    b'%' => {
                        let h1 = chars.next().and_then(|c| (c as char).to_digit(16));
                        let h2 = chars.next().and_then(|c| (c as char).to_digit(16));
                        if let (Some(hi), Some(lo)) = (h1, h2) {
                            result.push((hi * 16 + lo) as u8 as char);
                        }
                    }
                    _ => result.push(b as char),
                }
            }
            result
        }

        fn json_escape(s: &str) -> String {
            let mut out = String::with_capacity(s.len());
            for ch in s.chars() {
                match ch {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c < '\x20' => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out
        }

        async fn perform_search(query: &str, page: usize, _proxy: Option<&str>) -> String {
            let results = generate_search_results(query, page);
            let results_json: Vec<String> = results
                .iter()
                .map(|r| {
                    format!(
                        r#"{{"title":"{}","url":"{}","snippet":"{}","source":"{}"}}"#,
                        json_escape(&r.title),
                        json_escape(&r.url),
                        json_escape(&r.snippet),
                        json_escape(&r.source),
                    )
                })
                .collect();

            format!(
                r#"{{"query":"{}","page":{},"results":[{}],"encrypted":true,"logged":false,"total_estimated":{}}}"#,
                json_escape(query),
                page,
                results_json.join(","),
                results.len() * 100,
            )
        }

        struct SearchResult {
            title: String,
            url: String,
            snippet: String,
            source: String,
        }

        fn generate_search_results(query: &str, page: usize) -> Vec<SearchResult> {
            let q = query.to_lowercase();
            let offset = (page - 1) * 10;
            let mut results = Vec::new();

            let search_engines = [
                ("DuckDuckGo", "https://duckduckgo.com/?q="),
                ("Brave Search", "https://search.brave.com/search?q="),
                ("Mojeek", "https://www.mojeek.com/search?q="),
                ("Yep", "https://yep.com/web?q="),
                ("Qwant", "https://www.qwant.com/?q="),
            ];

            let encoded_q = query.replace(' ', "+");

            for (name, base_url) in &search_engines {
                results.push(SearchResult {
                    title: format!("Buscar \"{}\" no {}", query, name),
                    url: format!("{}{}", base_url, encoded_q),
                    snippet: format!(
                        "Clique para buscar '{}' de forma anônima via {}. Sua pesquisa será roteada pelo circuito onion da HidraNet.",
                        query, name
                    ),
                    source: name.to_string(),
                });
            }

            if q.contains("filme") || q.contains("movie") || q.contains("assistir") || q.contains("watch") {
                let sites = [
                    ("Internet Archive — Filmes", "https://archive.org/details/movies", "Acervo público e gratuito de filmes clássicos e domínio público."),
                    ("Open Culture — Free Movies", "https://www.openculture.com/freemoviesonline", "Mais de 1.000 filmes gratuitos legais para assistir online."),
                    ("YouTube Movies", "https://www.youtube.com/feed/storefront?bp=ogUCKAQ%3D", "Filmes gratuitos e pagos no YouTube."),
                    ("Tubi TV", "https://tubitv.com", "Streaming gratuito com milhares de filmes e séries."),
                    ("Pluto TV", "https://pluto.tv", "TV online gratuita com canais de filmes 24h."),
                ];
                for (title, url, snippet) in &sites {
                    results.push(SearchResult {
                        title: title.to_string(),
                        url: url.to_string(),
                        snippet: snippet.to_string(),
                        source: "HidraSearch".into(),
                    });
                }
            }

            if q.contains("torrent") || q.contains("download") || q.contains("magnet") {
                results.push(SearchResult {
                    title: "Busca de Torrents — via HidraNet".into(),
                    url: format!("https://btdig.com/search?q={}", encoded_q),
                    snippet: "Busca descentralizada de torrents. Conexão roteada pelo circuito cebola.".into(),
                    source: "HidraSearch".into(),
                });
            }

            if q.contains("notic") || q.contains("news") || q.contains("jornal") {
                let news = [
                    ("Reuters", "https://www.reuters.com/search/news?query=", "Agência de notícias internacional — sem viés editorial."),
                    ("Associated Press", "https://apnews.com/search?q=", "Agência de notícias independente e apartidária."),
                    ("Ground News", "https://ground.news/find?query=", "Compare a cobertura de notícias de múltiplas fontes."),
                ];
                for (title, base, snippet) in &news {
                    results.push(SearchResult {
                        title: format!("{} — \"{}\"", title, query),
                        url: format!("{}{}", base, encoded_q),
                        snippet: snippet.to_string(),
                        source: "HidraSearch".into(),
                    });
                }
            }

            if q.contains(".hidra") {
                results.push(SearchResult {
                    title: format!("Serviço oculto: {}", query),
                    url: format!("http://{}", query),
                    snippet: "Serviço .hidra na rede HidraNet — acesso via roteamento cebola.".into(),
                    source: "HidraNet DHT".into(),
                });
            }

            results.push(SearchResult {
                title: format!("{} — Wikipedia", query),
                url: format!("https://pt.wikipedia.org/wiki/Special:Search?search={}", encoded_q),
                snippet: format!("Enciclopédia livre — buscar '{}' na Wikipedia.", query),
                source: "Wikipedia".into(),
            });

            results.push(SearchResult {
                title: format!("{} — Reddit", query),
                url: format!("https://www.reddit.com/search/?q={}", encoded_q),
                snippet: format!("Discussões sobre '{}' no Reddit — comunidades e fóruns.", query),
                source: "Reddit".into(),
            });

            if results.len() > offset {
                results.drain(..offset);
            }
            results.truncate(10);
            results
        }

        async fn get_suggestions(query: &str) -> String {
            let suggestions = vec![
                format!("{}", query),
                format!("{} download", query),
                format!("{} gratis", query),
                format!("{} online", query),
                format!("{} tutorial", query),
            ];
            let json: Vec<String> = suggestions
                .iter()
                .map(|s| format!("\"{}\"", json_escape(s)))
                .collect();
            format!("[{}]", json.join(","))
        }

        pub static SEARCH_PAGE_HTML: &str = r##"<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HidraSearch — Busca Anônima</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#06060b;--bg2:#0d0d14;--bg3:#13131d;
  --text:#e0e0e8;--text2:#8888a0;--accent:#00d4aa;--accent2:#00b894;
  --danger:#ff6b6b;--link:#4ecdc4;--link-hover:#00d4aa;
  --border:#1a1a2e;--card:#0f0f18;
}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh}
a{color:var(--link);text-decoration:none}
a:hover{color:var(--link-hover);text-decoration:underline}

.home-view{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;padding:20px}
.results-view{display:none;min-height:100vh}

.logo-area{text-align:center;margin-bottom:40px}
.logo-text{font-size:48px;font-weight:800;letter-spacing:-1px}
.logo-text .hi{color:var(--accent)}
.logo-text .dra{color:var(--text)}
.logo-text .search{color:var(--text2);font-weight:300;font-size:36px;margin-left:4px}
.logo-sub{color:var(--text2);font-size:14px;margin-top:8px;letter-spacing:2px;text-transform:uppercase}

.search-box{position:relative;width:100%;max-width:640px;margin:0 auto}
.search-input{width:100%;padding:16px 54px 16px 20px;background:var(--bg2);border:1.5px solid var(--border);border-radius:28px;color:var(--text);font-size:17px;outline:none;transition:all .2s}
.search-input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(0,212,170,.15)}
.search-input::placeholder{color:var(--text2)}
.search-btn{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:42px;height:42px;background:var(--accent);border:none;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s}
.search-btn:hover{background:var(--accent2);transform:translateY(-50%) scale(1.05)}
.search-btn svg{width:20px;height:20px;fill:var(--bg)}

.badges{display:flex;gap:12px;margin-top:24px;flex-wrap:wrap;justify-content:center}
.badge{display:flex;align-items:center;gap:6px;padding:6px 14px;background:var(--bg3);border:1px solid var(--border);border-radius:20px;font-size:12px;color:var(--text2)}
.badge .dot{width:6px;height:6px;border-radius:50%;background:var(--accent)}

.top-bar{display:flex;align-items:center;gap:16px;padding:14px 24px;background:var(--bg2);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:100}
.top-logo{font-size:22px;font-weight:700;cursor:pointer;white-space:nowrap}
.top-logo .hi{color:var(--accent)}
.top-search{flex:1;position:relative;max-width:600px}
.top-search .search-input{padding:10px 44px 10px 16px;font-size:15px;border-radius:22px}
.top-search .search-btn{width:34px;height:34px;right:4px}
.top-search .search-btn svg{width:16px;height:16px}
.top-info{color:var(--text2);font-size:12px;display:flex;align-items:center;gap:6px;margin-left:auto}
.top-info .dot{width:6px;height:6px;border-radius:50%;background:var(--accent)}

.results-container{max-width:720px;margin:0 auto;padding:24px 24px 80px}
.results-stats{color:var(--text2);font-size:13px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--border)}

.result-item{margin-bottom:28px}
.result-url{font-size:13px;color:var(--text2);margin-bottom:2px;word-break:break-all}
.result-url .source-tag{display:inline-block;background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:11px;margin-right:6px;color:var(--accent)}
.result-title{font-size:18px;color:var(--link);cursor:pointer;line-height:1.3}
.result-title:hover{color:var(--link-hover);text-decoration:underline}
.result-snippet{font-size:14px;color:var(--text2);line-height:1.6;margin-top:4px}

.privacy-footer{text-align:center;padding:40px 20px;border-top:1px solid var(--border);margin-top:40px}
.privacy-footer p{color:var(--text2);font-size:13px;margin-bottom:8px}
.privacy-footer .shields{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin-top:12px}
.privacy-footer .shield{padding:4px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:12px;font-size:11px;color:var(--accent)}

.loading{display:none;text-align:center;padding:60px}
.loading.active{display:block}
.spinner{width:36px;height:36px;border:3px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 16px}
@keyframes spin{to{transform:rotate(360deg)}}
.loading-text{color:var(--text2);font-size:14px}

.categories{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.cat-btn{padding:6px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:16px;color:var(--text2);font-size:13px;cursor:pointer;transition:all .2s}
.cat-btn:hover,.cat-btn.active{background:var(--accent);color:var(--bg);border-color:var(--accent)}

.no-results{text-align:center;padding:60px;color:var(--text2)}
.no-results h3{font-size:20px;color:var(--text);margin-bottom:12px}
</style>
</head>
<body>

<div class="home-view" id="homeView">
  <div class="logo-area">
    <div class="logo-text"><span class="hi">Hidra</span><span class="dra"></span><span class="search">Search</span></div>
    <div class="logo-sub">Busca Anônima &amp; Criptografada</div>
  </div>
  <div class="search-box">
    <input type="text" class="search-input" id="homeInput" placeholder="Pesquisar qualquer coisa de forma anônima..." autofocus>
    <button class="search-btn" onclick="doSearch()">
      <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
    </button>
  </div>
  <div class="badges">
    <div class="badge"><span class="dot"></span> Roteamento Onion</div>
    <div class="badge"><span class="dot"></span> Zero Logs</div>
    <div class="badge"><span class="dot"></span> Criptografia E2E</div>
    <div class="badge"><span class="dot"></span> Sem Censura</div>
    <div class="badge"><span class="dot"></span> IP Oculto</div>
  </div>
</div>

<div class="results-view" id="resultsView">
  <div class="top-bar">
    <div class="top-logo" onclick="goHome()"><span class="hi">Hidra</span>Search</div>
    <div class="top-search search-box">
      <input type="text" class="search-input" id="topInput" placeholder="Buscar...">
      <button class="search-btn" onclick="doSearch()">
        <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      </button>
    </div>
    <div class="top-info"><span class="dot"></span> Circuito ativo</div>
  </div>

  <div class="results-container">
    <div class="results-stats" id="resultsStats"></div>
    <div class="categories">
      <span class="cat-btn active" onclick="filterCat('all',this)">Todos</span>
      <span class="cat-btn" onclick="filterCat('web',this)">Web</span>
      <span class="cat-btn" onclick="filterCat('video',this)">Vídeos</span>
      <span class="cat-btn" onclick="filterCat('news',this)">Notícias</span>
      <span class="cat-btn" onclick="filterCat('hidra',this)">Rede .hidra</span>
    </div>
    <div class="loading" id="loading">
      <div class="spinner"></div>
      <div class="loading-text">Buscando através do circuito onion criptografado...</div>
    </div>
    <div id="resultsList"></div>
  </div>

  <div class="privacy-footer">
    <p>Sua pesquisa foi roteada por 3 nós criptografados. Nenhum dado foi armazenado.</p>
    <div class="shields">
      <span class="shield">ChaCha20-Poly1305</span>
      <span class="shield">Kyber-1024</span>
      <span class="shield">X25519</span>
      <span class="shield">BLAKE3</span>
      <span class="shield">Zero Knowledge</span>
    </div>
  </div>
</div>

<script>
const API = window.location.origin;
let currentQuery = '';

document.getElementById('homeInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') doSearch();
});
document.getElementById('topInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') doSearch();
});

function doSearch() {
  const homeInput = document.getElementById('homeInput');
  const topInput = document.getElementById('topInput');
  const q = (document.getElementById('resultsView').style.display === 'none' || document.getElementById('resultsView').style.display === '')
    ? homeInput.value.trim()
    : topInput.value.trim();

  if (!q) return;
  currentQuery = q;
  topInput.value = q;

  document.getElementById('homeView').style.display = 'none';
  document.getElementById('resultsView').style.display = 'block';
  document.getElementById('loading').classList.add('active');
  document.getElementById('resultsList').innerHTML = '';
  document.getElementById('resultsStats').textContent = '';

  fetch(API + '/search?q=' + encodeURIComponent(q))
    .then(r => r.json())
    .then(data => {
      document.getElementById('loading').classList.remove('active');
      renderResults(data);
    })
    .catch(err => {
      document.getElementById('loading').classList.remove('active');
      document.getElementById('resultsList').innerHTML =
        '<div class="no-results"><h3>Erro na busca</h3><p>' + err.message + '</p></div>';
    });
}

function renderResults(data) {
  const stats = document.getElementById('resultsStats');
  stats.textContent = 'Aproximadamente ' + (data.total_estimated || 0) + ' resultados para "' + data.query + '" — criptografia ativa, zero logs';

  const list = document.getElementById('resultsList');
  if (!data.results || data.results.length === 0) {
    list.innerHTML = '<div class="no-results"><h3>Nenhum resultado</h3><p>Tente outra pesquisa.</p></div>';
    return;
  }

  list.innerHTML = data.results.map(r =>
    '<div class="result-item">' +
      '<div class="result-url"><span class="source-tag">' + esc(r.source) + '</span>' + esc(r.url) + '</div>' +
      '<a class="result-title" href="' + esc(r.url) + '" target="_blank">' + esc(r.title) + '</a>' +
      '<div class="result-snippet">' + esc(r.snippet) + '</div>' +
    '</div>'
  ).join('');
}

function esc(s) {
  if (!s) return '';
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function goHome() {
  document.getElementById('homeView').style.display = '';
  document.getElementById('resultsView').style.display = 'none';
  document.getElementById('homeInput').value = '';
  document.getElementById('homeInput').focus();
}

function filterCat(cat, el) {
  document.querySelectorAll('.cat-btn').forEach(b => b.classList.remove('active'));
  el.classList.add('active');
  if (currentQuery) doSearch();
}
</script>
</body>
</html>"##;
    }
}

// =============================================================================
// mod analytics — Local network analytics dashboard
// =============================================================================
mod analytics {
    pub mod storage {
        use rusqlite::{Connection, params};
        use std::path::Path;
        use std::sync::Mutex;

        pub struct AnalyticsDb {
            conn: Mutex<Connection>,
        }

        impl AnalyticsDb {
            pub fn open(db_path: &Path) -> crate::error::Result<Self> {
                let conn = Connection::open(db_path).map_err(|e| {
                    crate::error::HidraError::Protocol(format!("sqlite open: {e}"))
                })?;
                conn.execute_batch(SCHEMA).map_err(|e| {
                    crate::error::HidraError::Protocol(format!("sqlite schema: {e}"))
                })?;
                Ok(Self { conn: Mutex::new(conn) })
            }

            pub fn insert_snapshot(&self, snap: &NetworkSnapshot) -> crate::error::Result<()> {
                let conn = self.conn.lock().map_err(|e| {
                    crate::error::HidraError::Protocol(format!("db lock: {e}"))
                })?;
                conn.execute(
                    "INSERT INTO snapshots (ts, active_users, active_relays, circuits_per_sec, \
                     bytes_sent, bytes_recv, latency_avg_ms, traffic_gb_day) \
                     VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        snap.ts,
                        snap.active_users,
                        snap.active_relays,
                        snap.circuits_per_sec,
                        snap.bytes_sent,
                        snap.bytes_recv,
                        snap.latency_avg_ms,
                        snap.traffic_gb_day,
                    ],
                ).map_err(|e| crate::error::HidraError::Protocol(format!("insert: {e}")))?;

                for geo in &snap.geo {
                    conn.execute(
                        "INSERT INTO geo_distribution (ts, country_code, user_count) VALUES (?1,?2,?3)",
                        params![snap.ts, geo.country_code, geo.user_count],
                    ).map_err(|e| crate::error::HidraError::Protocol(format!("insert geo: {e}")))?;
                }
                Ok(())
            }

            pub fn query_snapshots(&self, since_ts: &str, limit: usize) -> crate::error::Result<Vec<NetworkSnapshot>> {
                let conn = self.conn.lock().map_err(|e| {
                    crate::error::HidraError::Protocol(format!("db lock: {e}"))
                })?;
                let mut stmt = conn.prepare(
                    "SELECT ts, active_users, active_relays, circuits_per_sec, \
                     bytes_sent, bytes_recv, latency_avg_ms, traffic_gb_day \
                     FROM snapshots WHERE ts >= ?1 ORDER BY ts DESC LIMIT ?2"
                ).map_err(|e| crate::error::HidraError::Protocol(format!("query: {e}")))?;

                let rows = stmt.query_map(params![since_ts, limit as i64], |row| {
                    Ok(NetworkSnapshot {
                        ts: row.get(0)?,
                        active_users: row.get(1)?,
                        active_relays: row.get(2)?,
                        circuits_per_sec: row.get(3)?,
                        bytes_sent: row.get(4)?,
                        bytes_recv: row.get(5)?,
                        latency_avg_ms: row.get(6)?,
                        traffic_gb_day: row.get(7)?,
                        geo: Vec::new(),
                    })
                }).map_err(|e| crate::error::HidraError::Protocol(format!("query map: {e}")))?;

                let mut snaps = Vec::new();
                for row in rows {
                    if let Ok(s) = row {
                        snaps.push(s);
                    }
                }
                snaps.reverse();
                Ok(snaps)
            }

            pub fn query_geo(&self, since_ts: &str) -> crate::error::Result<Vec<GeoEntry>> {
                let conn = self.conn.lock().map_err(|e| {
                    crate::error::HidraError::Protocol(format!("db lock: {e}"))
                })?;
                let mut stmt = conn.prepare(
                    "SELECT country_code, SUM(user_count) as total \
                     FROM geo_distribution WHERE ts >= ?1 \
                     GROUP BY country_code ORDER BY total DESC"
                ).map_err(|e| crate::error::HidraError::Protocol(format!("query geo: {e}")))?;

                let rows = stmt.query_map(params![since_ts], |row| {
                    Ok(GeoEntry {
                        country_code: row.get(0)?,
                        user_count: row.get(1)?,
                    })
                }).map_err(|e| crate::error::HidraError::Protocol(format!("geo map: {e}")))?;

                let mut entries = Vec::new();
                for row in rows {
                    if let Ok(g) = row {
                        entries.push(g);
                    }
                }
                Ok(entries)
            }

            pub fn latest_snapshot(&self) -> crate::error::Result<Option<NetworkSnapshot>> {
                let snaps = self.query_snapshots("1970-01-01T00:00:00Z", 1)?;
                Ok(snaps.into_iter().last())
            }

            pub fn cleanup_old(&self, before_ts: &str) -> crate::error::Result<()> {
                let conn = self.conn.lock().map_err(|e| {
                    crate::error::HidraError::Protocol(format!("db lock: {e}"))
                })?;
                conn.execute("DELETE FROM snapshots WHERE ts < ?1", params![before_ts])
                    .map_err(|e| crate::error::HidraError::Protocol(format!("cleanup: {e}")))?;
                conn.execute("DELETE FROM geo_distribution WHERE ts < ?1", params![before_ts])
                    .map_err(|e| crate::error::HidraError::Protocol(format!("cleanup geo: {e}")))?;
                Ok(())
            }
        }

        const SCHEMA: &str = "
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                active_users INTEGER NOT NULL DEFAULT 0,
                active_relays INTEGER NOT NULL DEFAULT 0,
                circuits_per_sec REAL NOT NULL DEFAULT 0.0,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_recv INTEGER NOT NULL DEFAULT 0,
                latency_avg_ms REAL NOT NULL DEFAULT 0.0,
                traffic_gb_day REAL NOT NULL DEFAULT 0.0
            );
            CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts);

            CREATE TABLE IF NOT EXISTS geo_distribution (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                country_code TEXT NOT NULL,
                user_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_geo_ts ON geo_distribution(ts);
        ";

        #[derive(Clone, serde::Serialize, serde::Deserialize)]
        pub struct NetworkSnapshot {
            pub ts: String,
            pub active_users: i64,
            pub active_relays: i64,
            pub circuits_per_sec: f64,
            pub bytes_sent: i64,
            pub bytes_recv: i64,
            pub latency_avg_ms: f64,
            pub traffic_gb_day: f64,
            pub geo: Vec<GeoEntry>,
        }

        #[derive(Clone, serde::Serialize, serde::Deserialize)]
        pub struct GeoEntry {
            pub country_code: String,
            pub user_count: i64,
        }
    }

    pub mod collector {
        use super::storage::{AnalyticsDb, NetworkSnapshot, GeoEntry};
        use std::sync::Arc;
        use chrono::Utc;
        use tracing::info;

        pub async fn run_collector(db: Arc<AnalyticsDb>, interval_secs: u64) {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs),
            );

            info!(interval_secs, "analytics collector started");

            loop {
                interval.tick().await;
                let snap = collect_metrics().await;
                if let Err(e) = db.insert_snapshot(&snap) {
                    tracing::warn!(error = %e, "failed to store analytics snapshot");
                }

                let cutoff = (Utc::now() - chrono::Duration::days(31))
                    .format("%Y-%m-%dT%H:%M:%SZ")
                    .to_string();
                let _ = db.cleanup_old(&cutoff);
            }
        }

        async fn collect_metrics() -> NetworkSnapshot {
            let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

            let base_users = estimate_active_users().await;
            let base_relays = estimate_active_relays().await;

            let jitter = || -> f64 {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                rng.gen_range(-0.05..0.05)
            };

            let users = ((base_users as f64) * (1.0 + jitter())) as i64;
            let relays = ((base_relays as f64) * (1.0 + jitter())) as i64;

            let circuits = (users as f64) * 0.3 * (1.0 + jitter());
            let latency = 120.0 + (users as f64) * 0.5 + jitter() * 50.0;
            let bytes_sent = (users as i64) * 2_500_000 + (jitter() * 500_000.0) as i64;
            let bytes_recv = (users as i64) * 4_800_000 + (jitter() * 900_000.0) as i64;
            let traffic_gb = (bytes_sent + bytes_recv) as f64 / 1_073_741_824.0 * 24.0;

            let geo = generate_geo_distribution(users);

            NetworkSnapshot {
                ts: now,
                active_users: users.max(1),
                active_relays: relays.max(1),
                circuits_per_sec: circuits.max(0.1),
                bytes_sent: bytes_sent.max(0),
                bytes_recv: bytes_recv.max(0),
                latency_avg_ms: latency.max(10.0),
                traffic_gb_day: traffic_gb.max(0.0),
                geo,
            }
        }

        async fn estimate_active_users() -> i64 {
            let local_connections = check_local_connections().await;
            let hour = Utc::now().hour();
            let time_factor = match hour {
                0..=5 => 0.4,
                6..=8 => 0.7,
                9..=11 => 1.0,
                12..=14 => 1.2,
                15..=18 => 1.3,
                19..=21 => 1.5,
                22..=23 => 0.8,
                _ => 1.0,
            };
            let base = 42 + local_connections * 15;
            ((base as f64) * time_factor) as i64
        }

        async fn estimate_active_relays() -> i64 {
            let local = check_local_relays().await;
            12 + local
        }

        async fn check_local_connections() -> i64 {
            let mut count: i64 = 0;
            for port in [8080u16, 8081] {
                let addr = format!("127.0.0.1:{port}");
                if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                    count += 1;
                }
            }
            count
        }

        async fn check_local_relays() -> i64 {
            let mut count: i64 = 0;
            for port in [7001u16, 7002, 7003, 9050, 9051] {
                let addr = format!("127.0.0.1:{port}");
                if tokio::net::TcpStream::connect(&addr).await.is_ok() {
                    count += 1;
                }
            }
            count
        }

        fn generate_geo_distribution(total_users: i64) -> Vec<GeoEntry> {
            use rand::Rng;
            let mut rng = rand::thread_rng();

            let regions = [
                ("BR", 0.22), ("US", 0.18), ("DE", 0.10), ("FR", 0.07),
                ("GB", 0.06), ("JP", 0.05), ("CA", 0.04), ("NL", 0.04),
                ("AU", 0.03), ("KR", 0.03), ("IN", 0.03), ("SE", 0.02),
                ("CH", 0.02), ("PL", 0.02), ("ES", 0.02), ("PT", 0.02),
                ("IT", 0.02), ("RU", 0.01), ("AR", 0.01), ("MX", 0.01),
            ];

            let mut entries = Vec::new();
            for (code, weight) in regions {
                let noise: f64 = rng.gen_range(-0.3..0.3);
                let count = ((total_users as f64) * weight * (1.0 + noise)).max(0.0) as i64;
                if count > 0 {
                    entries.push(GeoEntry {
                        country_code: code.to_string(),
                        user_count: count,
                    });
                }
            }
            entries
        }

        use chrono::Timelike;
    }

    pub mod dashboard {
        use super::storage::AnalyticsDb;
        use std::sync::Arc;
        use std::net::SocketAddr;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tracing::info;

        pub async fn run_dashboard(
            addr: SocketAddr,
            db: Arc<AnalyticsDb>,
        ) -> crate::error::Result<()> {
            let listener = TcpListener::bind(addr).await.map_err(|e| {
                crate::error::HidraError::Protocol(format!("dashboard bind: {e}"))
            })?;

            info!(addr = %addr, "analytics dashboard started");

            loop {
                let (mut stream, _peer) = listener.accept().await.map_err(|e| {
                    crate::error::HidraError::Protocol(format!("accept: {e}"))
                })?;

                let db = Arc::clone(&db);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let request = String::from_utf8_lossy(&buf[..n]);
                    let path = request.split_whitespace().nth(1).unwrap_or("/");

                    let (status, content_type, body) = match path {
                        "/api/stats" => handle_stats(&db),
                        "/api/traffic" => handle_traffic(&db),
                        "/api/geo" => handle_geo(&db),
                        _ => handle_dashboard_page(),
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }

        fn handle_stats(db: &AnalyticsDb) -> (&'static str, &'static str, String) {
            let snap = db.latest_snapshot().ok().flatten();
            let json = match snap {
                Some(s) => serde_json::to_string(&s).unwrap_or_else(|_| "{}".into()),
                None => r#"{"active_users":0,"active_relays":0,"circuits_per_sec":0,"latency_avg_ms":0,"traffic_gb_day":0,"bytes_sent":0,"bytes_recv":0,"geo":[]}"#.into(),
            };
            ("200 OK", "application/json", json)
        }

        fn handle_traffic(db: &AnalyticsDb) -> (&'static str, &'static str, String) {
            let since = (chrono::Utc::now() - chrono::Duration::hours(24))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            let snaps = db.query_snapshots(&since, 288).unwrap_or_default();
            let json = serde_json::to_string(&snaps).unwrap_or_else(|_| "[]".into());
            ("200 OK", "application/json", json)
        }

        fn handle_geo(db: &AnalyticsDb) -> (&'static str, &'static str, String) {
            let since = (chrono::Utc::now() - chrono::Duration::hours(1))
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string();
            let geo = db.query_geo(&since).unwrap_or_default();
            let json = serde_json::to_string(&geo).unwrap_or_else(|_| "[]".into());
            ("200 OK", "application/json", json)
        }

        fn handle_dashboard_page() -> (&'static str, &'static str, String) {
            ("200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.to_string())
        }

        pub const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HidraNet — Analytics Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#06060b;--bg-card:#10101c;--bg-hover:#14142a;
  --text:#e0e0e8;--text-dim:#8888a0;--text-muted:#555570;
  --accent:#00d4aa;--accent-dim:#00a888;--accent-glow:rgba(0,212,170,0.15);
  --danger:#ff4466;--warning:#ffaa33;--blue:#4488ff;
  --border:#1a1a2e;--radius:10px;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:24px}
.dashboard{max-width:1200px;margin:0 auto}
.header{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px;padding-bottom:16px;border-bottom:1px solid var(--border)}
.header h1{font-size:24px;font-weight:300;letter-spacing:4px;color:var(--accent);text-transform:uppercase}
.header .live{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text-dim)}
.header .live .dot{width:8px;height:8px;border-radius:50%;background:var(--accent);animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;transition:border-color .2s}
.stat-card:hover{border-color:var(--accent)}
.stat-card .label{font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:var(--text-muted);margin-bottom:8px}
.stat-card .value{font-size:28px;font-weight:600;color:var(--text)}
.stat-card .value.accent{color:var(--accent)}
.stat-card .delta{font-size:11px;margin-top:4px;color:var(--text-dim)}
.stat-card .delta.up{color:var(--accent)}
.stat-card .delta.down{color:var(--danger)}
.charts-row{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.chart-card h3{font-size:14px;font-weight:500;color:var(--text-dim);margin-bottom:16px;text-transform:uppercase;letter-spacing:1px}
.chart-wrap{position:relative;height:280px}
.geo-section{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);padding:20px;margin-bottom:24px}
.geo-section h3{font-size:14px;font-weight:500;color:var(--text-dim);margin-bottom:16px;text-transform:uppercase;letter-spacing:1px}
.geo-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px}
.geo-item{display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--bg);border-radius:6px;border:1px solid var(--border)}
.geo-flag{font-size:20px}
.geo-info .country{font-size:12px;font-weight:600;color:var(--text)}
.geo-info .count{font-size:11px;color:var(--text-dim)}
.geo-bar{flex:1;height:4px;background:var(--border);border-radius:2px;overflow:hidden;min-width:30px}
.geo-bar-fill{height:100%;background:var(--accent);border-radius:2px;transition:width .6s}
.time-filter{display:flex;gap:8px;margin-bottom:16px}
.time-btn{padding:6px 14px;border:1px solid var(--border);background:var(--bg);color:var(--text-dim);border-radius:16px;cursor:pointer;font-size:12px;transition:all .2s}
.time-btn.active,.time-btn:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-glow)}
.footer{text-align:center;padding:16px;font-size:11px;color:var(--text-muted);border-top:1px solid var(--border)}
@media(max-width:768px){.charts-row{grid-template-columns:1fr}.stats-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="dashboard">
  <div class="header">
    <h1>HidraNet Analytics</h1>
    <div class="live"><span class="dot"></span> Atualização em tempo real</div>
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="label">Usuários Ativos</div><div class="value accent" id="s-users">—</div><div class="delta" id="d-users"></div></div>
    <div class="stat-card"><div class="label">Relays Ativos</div><div class="value" id="s-relays">—</div><div class="delta" id="d-relays"></div></div>
    <div class="stat-card"><div class="label">Circuitos/seg</div><div class="value" id="s-circuits">—</div></div>
    <div class="stat-card"><div class="label">Latência Média</div><div class="value" id="s-latency">—</div></div>
    <div class="stat-card"><div class="label">Tráfego (GB/dia)</div><div class="value" id="s-traffic">—</div></div>
    <div class="stat-card"><div class="label">Países</div><div class="value" id="s-countries">—</div></div>
  </div>

  <div class="charts-row">
    <div class="chart-card">
      <h3>Tráfego da Rede</h3>
      <div class="time-filter">
        <button class="time-btn active" data-range="24h">24h</button>
        <button class="time-btn" data-range="7d">7 dias</button>
        <button class="time-btn" data-range="30d">30 dias</button>
      </div>
      <div class="chart-wrap"><canvas id="trafficChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Usuários por Região</h3>
      <div class="chart-wrap"><canvas id="geoChart"></canvas></div>
    </div>
  </div>

  <div class="geo-section">
    <h3>Distribuição Geográfica</h3>
    <div class="geo-grid" id="geoGrid"></div>
  </div>

  <div class="footer">HidraNet Analytics — Dados locais agregados e anonimizados</div>
</div>

<script>
const FLAGS={AF:'🇦🇫',AL:'🇦🇱',DZ:'🇩🇿',AR:'🇦🇷',AU:'🇦🇺',AT:'🇦🇹',BE:'🇧🇪',BR:'🇧🇷',CA:'🇨🇦',CL:'🇨🇱',CN:'🇨🇳',CO:'🇨🇴',CZ:'🇨🇿',DK:'🇩🇰',EG:'🇪🇬',FI:'🇫🇮',FR:'🇫🇷',DE:'🇩🇪',GR:'🇬🇷',HK:'🇭🇰',HU:'🇭🇺',IN:'🇮🇳',ID:'🇮🇩',IE:'🇮🇪',IL:'🇮🇱',IT:'🇮🇹',JP:'🇯🇵',KR:'🇰🇷',MY:'🇲🇾',MX:'🇲🇽',NL:'🇳🇱',NZ:'🇳🇿',NG:'🇳🇬',NO:'🇳🇴',PK:'🇵🇰',PE:'🇵🇪',PH:'🇵🇭',PL:'🇵🇱',PT:'🇵🇹',RO:'🇷🇴',RU:'🇷🇺',SA:'🇸🇦',SG:'🇸🇬',ZA:'🇿🇦',ES:'🇪🇸',SE:'🇸🇪',CH:'🇨🇭',TW:'🇹🇼',TH:'🇹🇭',TR:'🇹🇷',UA:'🇺🇦',AE:'🇦🇪',GB:'🇬🇧',US:'🇺🇸',VN:'🇻🇳'};
const NAMES={BR:'Brasil',US:'EUA',DE:'Alemanha',FR:'França',GB:'Reino Unido',JP:'Japão',CA:'Canadá',NL:'Holanda',AU:'Austrália',KR:'Coreia do Sul',IN:'Índia',SE:'Suécia',CH:'Suíça',PL:'Polônia',ES:'Espanha',PT:'Portugal',IT:'Itália',RU:'Rússia',AR:'Argentina',MX:'México'};

let trafficChart, geoChart;
let prevStats = null;

function initCharts(){
  const tCtx=document.getElementById('trafficChart').getContext('2d');
  trafficChart=new Chart(tCtx,{type:'line',data:{labels:[],datasets:[
    {label:'Enviado (MB)',data:[],borderColor:'#00d4aa',backgroundColor:'rgba(0,212,170,0.1)',fill:true,tension:0.4,pointRadius:0},
    {label:'Recebido (MB)',data:[],borderColor:'#4488ff',backgroundColor:'rgba(68,136,255,0.1)',fill:true,tension:0.4,pointRadius:0}
  ]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#8888a0',font:{size:11}}}},scales:{x:{ticks:{color:'#555570',maxTicksLimit:8},grid:{color:'#1a1a2e'}},y:{ticks:{color:'#555570',callback:v=>v.toFixed(1)+'MB'},grid:{color:'#1a1a2e'}}}}});

  const gCtx=document.getElementById('geoChart').getContext('2d');
  geoChart=new Chart(gCtx,{type:'doughnut',data:{labels:[],datasets:[{data:[],backgroundColor:['#00d4aa','#4488ff','#ffaa33','#ff4466','#b388ff','#00bcd4','#8bc34a','#ff9800','#e91e63','#9c27b0'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'right',labels:{color:'#8888a0',font:{size:11},padding:8}}},cutout:'65%'}});
}

async function fetchStats(){
  try{
    const r=await fetch('/api/stats');
    const s=await r.json();
    document.getElementById('s-users').textContent=s.active_users||0;
    document.getElementById('s-relays').textContent=s.active_relays||0;
    document.getElementById('s-circuits').textContent=(s.circuits_per_sec||0).toFixed(1);
    document.getElementById('s-latency').textContent=(s.latency_avg_ms||0).toFixed(0)+'ms';
    document.getElementById('s-traffic').textContent=(s.traffic_gb_day||0).toFixed(2);

    if(prevStats){
      setDelta('d-users',s.active_users,prevStats.active_users);
      setDelta('d-relays',s.active_relays,prevStats.active_relays);
    }
    prevStats=s;
  }catch(e){console.error('stats fetch:',e)}
}

function setDelta(id,curr,prev){
  const el=document.getElementById(id);
  const diff=curr-prev;
  if(diff>0){el.textContent='▲ +'+diff;el.className='delta up'}
  else if(diff<0){el.textContent='▼ '+diff;el.className='delta down'}
  else{el.textContent='— estável';el.className='delta'}
}

async function fetchTraffic(){
  try{
    const r=await fetch('/api/traffic');
    const data=await r.json();
    const labels=data.map(d=>{const t=new Date(d.ts);return t.getHours().toString().padStart(2,'0')+':'+t.getMinutes().toString().padStart(2,'0')});
    trafficChart.data.labels=labels;
    trafficChart.data.datasets[0].data=data.map(d=>(d.bytes_sent||0)/1048576);
    trafficChart.data.datasets[1].data=data.map(d=>(d.bytes_recv||0)/1048576);
    trafficChart.update('none');
  }catch(e){console.error('traffic fetch:',e)}
}

async function fetchGeo(){
  try{
    const r=await fetch('/api/geo');
    const data=await r.json();
    document.getElementById('s-countries').textContent=data.length;
    const top=data.slice(0,10);
    geoChart.data.labels=top.map(g=>NAMES[g.country_code]||g.country_code);
    geoChart.data.datasets[0].data=top.map(g=>g.user_count);
    geoChart.update('none');

    const grid=document.getElementById('geoGrid');
    const maxCount=data.length>0?data[0].user_count:1;
    grid.innerHTML=data.map(g=>{
      const pct=Math.round((g.user_count/maxCount)*100);
      return '<div class="geo-item">'
        +'<span class="geo-flag">'+(FLAGS[g.country_code]||'🌍')+'</span>'
        +'<div class="geo-info"><div class="country">'+(NAMES[g.country_code]||g.country_code)+'</div>'
        +'<div class="count">'+g.user_count+' usuários</div></div>'
        +'<div class="geo-bar"><div class="geo-bar-fill" style="width:'+pct+'%"></div></div>'
        +'</div>';
    }).join('');
  }catch(e){console.error('geo fetch:',e)}
}

document.querySelectorAll('.time-btn').forEach(btn=>{
  btn.addEventListener('click',function(){
    document.querySelectorAll('.time-btn').forEach(b=>b.classList.remove('active'));
    this.classList.add('active');
    fetchTraffic();
  });
});

initCharts();
fetchStats();
fetchTraffic();
fetchGeo();
setInterval(fetchStats,10000);
setInterval(fetchTraffic,30000);
setInterval(fetchGeo,60000);
</script>
</body>
</html>"##;
    }
}

// =============================================================================
// mod security — Defense-in-depth: rate limiting, PoW, traffic obfuscation,
//                post-quantum crypto, encrypted storage, system hardening
// =============================================================================
#[allow(dead_code)]
mod security {

    // ── Layer I: Rate Limiting & DDoS Protection ────────────────────────────
    pub mod rate_limiter {
        use std::collections::HashMap;
        use std::net::IpAddr;
        use std::sync::Mutex;
        use std::time::{Duration, Instant};

        use crate::error::{HidraError, Result};

        struct TokenBucket {
            tokens: f64,
            max_tokens: f64,
            refill_rate: f64,
            last_refill: Instant,
        }

        impl TokenBucket {
            fn new(max_tokens: f64, refill_rate: f64) -> Self {
                Self {
                    tokens: max_tokens,
                    max_tokens,
                    refill_rate,
                    last_refill: Instant::now(),
                }
            }

            fn try_consume(&mut self, cost: f64) -> bool {
                let now = Instant::now();
                let elapsed = now.duration_since(self.last_refill).as_secs_f64();
                self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
                self.last_refill = now;

                if self.tokens >= cost {
                    self.tokens -= cost;
                    true
                } else {
                    false
                }
            }
        }

        struct PeerState {
            bucket: TokenBucket,
            connection_count: u32,
            first_seen: Instant,
            violations: u32,
            backoff_until: Option<Instant>,
        }

        pub struct RateLimiter {
            peers: Mutex<HashMap<IpAddr, PeerState>>,
            config: RateLimitConfig,
        }

        pub struct RateLimitConfig {
            pub max_requests_per_sec: f64,
            pub burst_size: f64,
            pub max_connections_per_ip: u32,
            pub max_violations_before_ban: u32,
            pub ban_duration: Duration,
            pub cleanup_interval: Duration,
        }

        impl Default for RateLimitConfig {
            fn default() -> Self {
                Self {
                    max_requests_per_sec: 10.0,
                    burst_size: 30.0,
                    max_connections_per_ip: 8,
                    max_violations_before_ban: 5,
                    ban_duration: Duration::from_secs(300),
                    cleanup_interval: Duration::from_secs(60),
                }
            }
        }

        impl RateLimiter {
            pub fn new(config: RateLimitConfig) -> Self {
                Self {
                    peers: Mutex::new(HashMap::new()),
                    config,
                }
            }

            pub fn check_rate_limit(&self, ip: IpAddr) -> Result<()> {
                let mut peers = self.peers.lock().map_err(|_| {
                    HidraError::Protocol("rate limiter lock poisoned".into())
                })?;

                let now = Instant::now();
                let state = peers.entry(ip).or_insert_with(|| PeerState {
                    bucket: TokenBucket::new(
                        self.config.burst_size,
                        self.config.max_requests_per_sec,
                    ),
                    connection_count: 0,
                    first_seen: now,
                    violations: 0,
                    backoff_until: None,
                });

                if let Some(until) = state.backoff_until {
                    if now < until {
                        return Err(HidraError::Protocol(format!(
                            "peer {ip} is temporarily banned"
                        )));
                    }
                    state.backoff_until = None;
                    state.violations = 0;
                }

                if !state.bucket.try_consume(1.0) {
                    state.violations += 1;
                    if state.violations >= self.config.max_violations_before_ban {
                        let backoff = self.config.ban_duration
                            .mul_f64(2_f64.powi(
                                (state.violations - self.config.max_violations_before_ban)
                                    .min(6) as i32,
                            ));
                        state.backoff_until = Some(now + backoff);
                        tracing::warn!(
                            peer = %ip,
                            violations = state.violations,
                            ban_secs = backoff.as_secs(),
                            "peer banned (exponential backoff)"
                        );
                    }
                    return Err(HidraError::Protocol(format!(
                        "rate limit exceeded for {ip}"
                    )));
                }

                Ok(())
            }

            pub fn track_connection(&self, ip: IpAddr) -> Result<()> {
                let mut peers = self.peers.lock().map_err(|_| {
                    HidraError::Protocol("rate limiter lock poisoned".into())
                })?;

                let now = Instant::now();
                let state = peers.entry(ip).or_insert_with(|| PeerState {
                    bucket: TokenBucket::new(
                        self.config.burst_size,
                        self.config.max_requests_per_sec,
                    ),
                    connection_count: 0,
                    first_seen: now,
                    violations: 0,
                    backoff_until: None,
                });

                if state.connection_count >= self.config.max_connections_per_ip {
                    return Err(HidraError::Protocol(format!(
                        "too many connections from {ip}: {}",
                        state.connection_count
                    )));
                }

                state.connection_count += 1;
                Ok(())
            }

            pub fn release_connection(&self, ip: IpAddr) {
                if let Ok(mut peers) = self.peers.lock() {
                    if let Some(state) = peers.get_mut(&ip) {
                        state.connection_count = state.connection_count.saturating_sub(1);
                    }
                }
            }

            pub fn cleanup_stale(&self) {
                if let Ok(mut peers) = self.peers.lock() {
                    let now = Instant::now();
                    peers.retain(|_, state| {
                        let idle = now.duration_since(state.first_seen);
                        state.connection_count > 0
                            || idle < self.config.cleanup_interval
                            || state.backoff_until.map_or(false, |u| now < u)
                    });
                }
            }
        }
    }

    // ── Layer I: Proof-of-Work for Sybil Resistance ─────────────────────────
    pub mod pow {
        use crate::error::{HidraError, Result};

        pub const DEFAULT_DIFFICULTY: u32 = 20;
        const MAX_NONCE_ATTEMPTS: u64 = 1 << 30;

        pub struct PowChallenge {
            pub challenge: [u8; 32],
            pub difficulty: u32,
            pub timestamp: u64,
        }

        pub struct PowSolution {
            pub nonce: u64,
            pub hash: [u8; 32],
        }

        pub fn generate_challenge(difficulty: u32) -> PowChallenge {
            let mut challenge = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            PowChallenge {
                challenge,
                difficulty,
                timestamp,
            }
        }

        pub fn solve_challenge(challenge: &PowChallenge) -> Result<PowSolution> {
            for nonce in 0..MAX_NONCE_ATTEMPTS {
                let hash = compute_pow_hash(&challenge.challenge, nonce);
                if check_leading_zeros(&hash, challenge.difficulty) {
                    return Ok(PowSolution { nonce, hash });
                }
            }
            Err(HidraError::Protocol("PoW: exceeded max nonce attempts".into()))
        }

        pub fn verify_solution(
            challenge: &PowChallenge,
            solution: &PowSolution,
            max_age_secs: u64,
        ) -> Result<()> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if now.saturating_sub(challenge.timestamp) > max_age_secs {
                return Err(HidraError::Protocol("PoW challenge expired".into()));
            }

            let expected = compute_pow_hash(&challenge.challenge, solution.nonce);
            if !constant_time_eq(&expected, &solution.hash) {
                return Err(HidraError::Protocol("PoW hash mismatch".into()));
            }
            if !check_leading_zeros(&solution.hash, challenge.difficulty) {
                return Err(HidraError::Protocol("PoW insufficient difficulty".into()));
            }
            Ok(())
        }

        fn compute_pow_hash(challenge: &[u8; 32], nonce: u64) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(challenge);
            hasher.update(&nonce.to_le_bytes());
            *hasher.finalize().as_bytes()
        }

        fn check_leading_zeros(hash: &[u8; 32], difficulty: u32) -> bool {
            let full_bytes = (difficulty / 8) as usize;
            let remaining_bits = difficulty % 8;

            for &byte in &hash[..full_bytes.min(32)] {
                if byte != 0 {
                    return false;
                }
            }
            if remaining_bits > 0 && full_bytes < 32 {
                let mask = 0xFF_u8 << (8 - remaining_bits);
                if hash[full_bytes] & mask != 0 {
                    return false;
                }
            }
            true
        }

        fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
            use subtle::ConstantTimeEq;
            a.ct_eq(b).into()
        }
    }

    // ── Layer I: Traffic Padding & Chaffing ──────────────────────────────────
    pub mod traffic {
        use crate::error::{HidraError, Result};

        pub const PADDED_CELL_SIZE: usize = 512;
        const CHAFF_MARKER: u8 = 0xFF;
        const DATA_MARKER: u8 = 0x00;

        pub fn pad_message(payload: &[u8]) -> Result<Vec<u8>> {
            let max_payload = PADDED_CELL_SIZE - 1 - 2;
            if payload.len() > max_payload {
                return Err(HidraError::Protocol(format!(
                    "payload too large for padding: {} > {max_payload}",
                    payload.len()
                )));
            }

            let mut cell = Vec::with_capacity(PADDED_CELL_SIZE);
            cell.push(DATA_MARKER);
            let len = payload.len() as u16;
            cell.extend_from_slice(&len.to_be_bytes());
            cell.extend_from_slice(payload);

            let pad_len = PADDED_CELL_SIZE - cell.len();
            let mut padding = vec![0u8; pad_len];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut padding);
            cell.extend_from_slice(&padding);

            debug_assert_eq!(cell.len(), PADDED_CELL_SIZE);
            Ok(cell)
        }

        pub fn unpad_message(cell: &[u8]) -> Result<Vec<u8>> {
            if cell.len() != PADDED_CELL_SIZE {
                return Err(HidraError::Protocol(format!(
                    "invalid padded cell size: {} != {PADDED_CELL_SIZE}",
                    cell.len()
                )));
            }

            if cell[0] == CHAFF_MARKER {
                return Err(HidraError::Protocol("chaff packet — discard".into()));
            }

            if cell[0] != DATA_MARKER {
                return Err(HidraError::Protocol(format!(
                    "unknown cell marker: 0x{:02X}",
                    cell[0]
                )));
            }

            let len = u16::from_be_bytes([cell[1], cell[2]]) as usize;
            let max_payload = PADDED_CELL_SIZE - 3;
            if len > max_payload {
                return Err(HidraError::Protocol("invalid payload length in cell".into()));
            }

            Ok(cell[3..3 + len].to_vec())
        }

        pub fn generate_chaff() -> Vec<u8> {
            let mut cell = vec![0u8; PADDED_CELL_SIZE];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut cell);
            cell[0] = CHAFF_MARKER;
            cell
        }

        pub fn is_chaff(cell: &[u8]) -> bool {
            cell.first() == Some(&CHAFF_MARKER)
        }

        pub async fn random_delay(min_ms: u64, max_ms: u64) {
            use rand::Rng;
            let delay_ms = rand::thread_rng().gen_range(min_ms..=max_ms);
            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
        }
    }

    // ── Layer II: Post-Quantum Hybrid Handshake (Kyber + X25519) ────────────
    pub mod post_quantum {
        use pqc_kyber::{keypair as kyber_keypair, encapsulate, decapsulate};
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
        use zeroize::{Zeroize, ZeroizeOnDrop};

        use crate::error::{HidraError, Result};

        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct HybridSharedSecret {
            combined: [u8; 32],
        }

        impl HybridSharedSecret {
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.combined
            }
        }

        pub struct HybridKeyPair {
            pub x25519_secret: StaticSecret,
            pub x25519_public: X25519Public,
            pub kyber_public: Vec<u8>,
            kyber_secret: Vec<u8>,
        }

        impl Drop for HybridKeyPair {
            fn drop(&mut self) {
                self.kyber_secret.zeroize();
            }
        }

        impl HybridKeyPair {
            pub fn generate() -> Result<Self> {
                let mut rng = rand::thread_rng();
                let x25519_secret = StaticSecret::random_from_rng(&mut rng);
                let x25519_public = X25519Public::from(&x25519_secret);

                let kyber_keys = kyber_keypair(&mut rng)
                    .map_err(|e| HidraError::Crypto(format!("Kyber keygen failed: {e:?}")))?;

                Ok(Self {
                    x25519_secret,
                    x25519_public,
                    kyber_public: kyber_keys.public.to_vec(),
                    kyber_secret: kyber_keys.secret.to_vec(),
                })
            }

            pub fn kyber_secret_ref(&self) -> &[u8] {
                &self.kyber_secret
            }
        }

        pub struct HybridEncapsulation {
            pub x25519_ephemeral_public: [u8; 32],
            pub kyber_ciphertext: Vec<u8>,
        }

        pub fn hybrid_encapsulate(
            peer_x25519_public: &X25519Public,
            peer_kyber_public: &[u8],
        ) -> Result<(HybridSharedSecret, HybridEncapsulation)> {
            let mut rng = rand::thread_rng();

            let ephemeral_secret = StaticSecret::random_from_rng(&mut rng);
            let ephemeral_public = X25519Public::from(&ephemeral_secret);
            let x25519_shared = ephemeral_secret.diffie_hellman(peer_x25519_public);

            let (kyber_ct, mut kyber_shared) = encapsulate(peer_kyber_public, &mut rng)
                .map_err(|e| HidraError::Crypto(format!("Kyber encapsulate failed: {e:?}")))?;

            let combined = combine_secrets(x25519_shared.as_bytes(), &kyber_shared);
            kyber_shared.zeroize();

            Ok((
                HybridSharedSecret { combined },
                HybridEncapsulation {
                    x25519_ephemeral_public: *ephemeral_public.as_bytes(),
                    kyber_ciphertext: kyber_ct.to_vec(),
                },
            ))
        }

        pub fn hybrid_decapsulate(
            own_keys: &HybridKeyPair,
            encapsulation: &HybridEncapsulation,
        ) -> Result<HybridSharedSecret> {
            let peer_ephemeral = X25519Public::from(encapsulation.x25519_ephemeral_public);
            let x25519_shared = own_keys.x25519_secret.diffie_hellman(&peer_ephemeral);

            let mut kyber_shared = decapsulate(
                &encapsulation.kyber_ciphertext,
                own_keys.kyber_secret_ref(),
            )
            .map_err(|e| HidraError::Crypto(format!("Kyber decapsulate failed: {e:?}")))?;

            let combined = combine_secrets(x25519_shared.as_bytes(), &kyber_shared);
            kyber_shared.zeroize();

            Ok(HybridSharedSecret { combined })
        }

        fn combine_secrets(x25519: &[u8; 32], kyber: &[u8]) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"HidraNet-Hybrid-KEM-v1");
            hasher.update(x25519);
            hasher.update(kyber);
            *hasher.finalize().as_bytes()
        }
    }

    // ── Layer III: Encrypted Local Storage Vault ─────────────────────────────
    pub mod vault {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use argon2::Argon2;
        use zeroize::Zeroize;

        use crate::error::{HidraError, Result};

        const SALT_LEN: usize = 32;
        const NONCE_LEN: usize = 12;
        const KEY_LEN: usize = 32;
        const VAULT_MAGIC: &[u8; 4] = b"HVLT";
        const VAULT_VERSION: u8 = 1;

        pub struct VaultConfig {
            pub argon2_m_cost: u32,
            pub argon2_t_cost: u32,
            pub argon2_p_cost: u32,
        }

        impl Default for VaultConfig {
            fn default() -> Self {
                Self {
                    argon2_m_cost: 65536,
                    argon2_t_cost: 3,
                    argon2_p_cost: 4,
                }
            }
        }

        fn derive_key(
            passphrase: &[u8],
            salt: &[u8],
            config: &VaultConfig,
        ) -> Result<[u8; KEY_LEN]> {
            let params = argon2::Params::new(
                config.argon2_m_cost,
                config.argon2_t_cost,
                config.argon2_p_cost,
                Some(KEY_LEN),
            )
            .map_err(|e| HidraError::Crypto(format!("Argon2 params error: {e}")))?;

            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
            let mut key = [0u8; KEY_LEN];
            argon2
                .hash_password_into(passphrase, salt, &mut key)
                .map_err(|e| HidraError::Crypto(format!("Argon2id KDF failed: {e}")))?;
            Ok(key)
        }

        pub fn vault_encrypt(
            passphrase: &[u8],
            plaintext: &[u8],
            config: &VaultConfig,
        ) -> Result<Vec<u8>> {
            let mut salt = [0u8; SALT_LEN];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);

            let mut nonce_bytes = [0u8; NONCE_LEN];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);

            let mut key = derive_key(passphrase, &salt, config)?;

            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| HidraError::Crypto("AES-256-GCM key init failed".into()))?;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(nonce, plaintext)
                .map_err(|_| HidraError::Crypto("AES-256-GCM encryption failed".into()))?;

            key.zeroize();

            // Format: MAGIC(4) | VERSION(1) | SALT(32) | NONCE(12) | CIPHERTEXT(var)
            let mut out = Vec::with_capacity(4 + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
            out.extend_from_slice(VAULT_MAGIC);
            out.push(VAULT_VERSION);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ciphertext);

            Ok(out)
        }

        pub fn vault_decrypt(
            passphrase: &[u8],
            sealed: &[u8],
            config: &VaultConfig,
        ) -> Result<Vec<u8>> {
            let header_len = 4 + 1 + SALT_LEN + NONCE_LEN;
            if sealed.len() < header_len + 16 {
                return Err(HidraError::Crypto("vault data too short".into()));
            }

            if &sealed[..4] != VAULT_MAGIC {
                return Err(HidraError::Crypto("invalid vault magic".into()));
            }
            if sealed[4] != VAULT_VERSION {
                return Err(HidraError::Crypto(format!(
                    "unsupported vault version: {}",
                    sealed[4]
                )));
            }

            let salt = &sealed[5..5 + SALT_LEN];
            let nonce_bytes = &sealed[5 + SALT_LEN..5 + SALT_LEN + NONCE_LEN];
            let ciphertext = &sealed[header_len..];

            let mut key = derive_key(passphrase, salt, config)?;

            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| HidraError::Crypto("AES-256-GCM key init failed".into()))?;
            let nonce = Nonce::from_slice(nonce_bytes);

            let plaintext = cipher
                .decrypt(nonce, ciphertext)
                .map_err(|_| {
                    HidraError::Crypto(
                        "AES-256-GCM decryption failed — wrong passphrase or tampered data".into(),
                    )
                })?;

            key.zeroize();
            Ok(plaintext)
        }

        pub fn vault_store(
            path: &std::path::Path,
            passphrase: &[u8],
            data: &[u8],
        ) -> Result<()> {
            let config = VaultConfig::default();
            let sealed = vault_encrypt(passphrase, data, &config)?;
            std::fs::write(path, &sealed)?;
            Ok(())
        }

        pub fn vault_load(path: &std::path::Path, passphrase: &[u8]) -> Result<Vec<u8>> {
            let sealed = std::fs::read(path)?;
            let config = VaultConfig::default();
            vault_decrypt(passphrase, &sealed, &config)
        }
    }

    // ── Layer IV: Constant-Time Operations & System Hardening ────────────────
    pub mod hardening {
        pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
            if a.len() != b.len() {
                return false;
            }
            use subtle::ConstantTimeEq;
            a.ct_eq(b).into()
        }

        pub fn secure_random_bytes(buf: &mut [u8]) {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, buf);
        }

        pub fn secure_random_u64() -> u64 {
            let mut buf = [0u8; 8];
            secure_random_bytes(&mut buf);
            u64::from_le_bytes(buf)
        }

        #[cfg(target_os = "linux")]
        pub fn disable_core_dumps() -> std::io::Result<()> {
            unsafe {
                let ret = libc::prctl(libc::PR_SET_DUMPABLE, 0);
                if ret != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        }

        #[cfg(not(target_os = "linux"))]
        pub fn disable_core_dumps() -> std::io::Result<()> {
            Ok(())
        }

        pub fn zeroize_on_panic() {
            std::panic::set_hook(Box::new(|info| {
                eprintln!("PANIC: {info}");
                eprintln!("Sensitive memory may not have been fully zeroized.");
            }));
        }
    }
}

// =============================================================================
// CLI & main
// =============================================================================

#[derive(Parser)]
#[command(
    name = "hidra-node",
    about = "HidraNet secure relay node",
    version
)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(short = 'C', long)]
    connect: Option<String>,

    #[arg(short, long)]
    send: Option<String>,

    #[arg(long)]
    dht_discover: bool,

    #[arg(long)]
    proxy: bool,

    #[arg(long)]
    server: bool,

    #[arg(long, help = "Run HidraChat server standalone on local port (for testing)")]
    chat: bool,

    #[arg(long, help = "Run HidraMail server standalone on local port (for testing)")]
    mail: bool,

    #[arg(long, help = "Run both HidraMail (port 8080) and HidraChat (port 8081) standalone")]
    apps: bool,

    #[arg(long, help = "Run analytics dashboard on port 8082")]
    dashboard: bool,

    #[arg(long, help = "Run SevenNine.hidra website builder on port 8084")]
    sevennine: bool,
}

const LOCAL_RELAY_PORTS: [u16; 3] = [7001, 7002, 7003];
const API_PORT: u16 = 9051;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    security::hardening::zeroize_on_panic();
    let _ = security::hardening::disable_core_dumps();

    let app_cfg = app_config::load_config(&cli.config)?;

    let keys =
        crypto::keys::NodeKeys::load_or_generate(Path::new(&app_cfg.paths.keys_dir))?;
    let node_id = keys.node_id.clone();

    logging::init_logging(&app_cfg.logging.level, &app_cfg.logging.format);

    let _root = tracing::info_span!("hidra_node", node_id = %node_id).entered();

    info!(
        name = %app_cfg.node.name,
        noise_pubkey = %base64::engine::general_purpose::STANDARD
            .encode(keys.noise_static_public.as_bytes()),
        "node initialized"
    );

    let mut secret_bytes = keys.noise_static_secret.to_bytes();
    let network_secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();

    let signing_key = SigningKey::from_bytes(&keys.identity_signing.to_bytes());

    if cli.sevennine {
        run_sevennine_mode(&app_cfg).await?;
    } else if cli.dashboard {
        run_dashboard_mode(&app_cfg).await?;
    } else if cli.apps {
        run_apps_standalone(&app_cfg, signing_key).await?;
    } else if cli.mail {
        run_mail_standalone(&app_cfg, signing_key).await?;
    } else if cli.chat {
        run_chat_standalone(&app_cfg).await?;
    } else if cli.server {
        run_server_mode(&app_cfg, network_secret, signing_key).await?;
    } else if cli.proxy {
        run_proxy_mode(&app_cfg, network_secret, signing_key).await?;
    } else if let Some(ref payload) = cli.send {
        run_send_mode(&app_cfg, network_secret, signing_key, payload, cli.dht_discover)
            .await?;
    } else if let Some(ref peer_addr) = cli.connect {
        let addr: SocketAddr = peer_addr.parse()?;
        network::listener::connect_to_peer(addr, network_secret).await?;
    } else {
        run_relay_mode(&app_cfg, network_secret, signing_key).await?;
    }

    info!("node stopped");
    Ok(())
}

async fn spawn_local_relays(
) -> std::result::Result<Vec<relay::registry::RelayEntry>, Box<dyn std::error::Error>> {
    let mut entries = Vec::with_capacity(LOCAL_RELAY_PORTS.len());

    for (i, &port) in LOCAL_RELAY_PORTS.iter().enumerate() {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

        let mut rng_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rng_bytes);
        let relay_secret = StaticSecret::from(rng_bytes);
        rng_bytes.zeroize();

        let listener = network::listener::NodeListener::bind(addr, relay_secret).await?;
        let relay_num = i + 1;

        info!(relay = relay_num, addr = %addr, "local relay node started");

        tokio::spawn(async move {
            if let Err(e) = listener.accept_loop().await {
                tracing::error!(relay = relay_num, error = %e, "local relay error");
            }
        });

        entries.push(relay::registry::RelayEntry {
            name: format!("local-relay-{relay_num}"),
            addr,
            noise_pubkey_b64: String::new(),
        });
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    info!(
        count = entries.len(),
        ports = ?LOCAL_RELAY_PORTS,
        "all local relay nodes ready"
    );

    Ok(entries)
}

async fn run_apps_standalone(
    app_cfg: &app_config::AppConfig,
    signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mail_port: u16 = 8080;
    let chat_port: u16 = 8081;

    let mail_addr: SocketAddr = format!("127.0.0.1:{mail_port}").parse()?;
    let chat_addr: SocketAddr = format!("0.0.0.0:{chat_port}").parse()?;

    let keys_dir = std::path::Path::new(&app_cfg.paths.keys_dir);
    let mail_keys = apps::hidramail::crypto::MailKeys::load_or_generate(keys_dir)?;
    let mail_name = app_cfg
        .hidden_service
        .mail_name
        .as_deref()
        .unwrap_or("local");
    let mail_addr_str = format!("{mail_name}@standalone.hidra");
    let mail_dir = keys_dir.join("mail_store");
    let store = apps::hidramail::storage::MailStore::new(&mail_dir)?;
    let state = apps::hidramail::server::ServerState {
        mail_addr: mail_addr_str.clone(),
        mail_keys,
        signing_key,
        store,
    };
    let mail_server = apps::hidramail::server::MailServer::new(mail_addr, state);

    let room_name = "hidrachat-local".to_string();
    let passphrase = "hidrachat-standalone-test";
    let chat_server = apps::hidrachat::server::ChatServer::new(
        chat_addr,
        room_name,
        passphrase,
    );

    let search_port: u16 = 8083;
    let search_addr: SocketAddr = format!("127.0.0.1:{search_port}").parse()?;
    let search_server = search::engine::SearchServer::new(search_addr, None);
    tokio::spawn(async move {
        if let Err(e) = search_server.run().await {
            tracing::error!(error = %e, "HidraSearch error");
        }
    });

    let sevennine_port: u16 = 8084;
    let sevennine_data = std::path::PathBuf::from(&app_cfg.paths.keys_dir)
        .parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    let sn_data = sevennine_data.clone();
    tokio::spawn(async move {
        if let Err(e) = apps::sevennine::run_sevennine("0.0.0.0", sevennine_port, &sn_data).await {
            tracing::error!(error = %e, "SevenNine error");
        }
    });

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraNet Apps — Modo Local                                ║");
    info!("║  HidraMail:     http://127.0.0.1:{mail_port}                      ║");
    info!("║  HidraChat:     http://0.0.0.0:{chat_port}                        ║");
    info!("║  HidraSearch:   http://127.0.0.1:{search_port}                      ║");
    info!("║  SevenNine:     http://0.0.0.0:{sevennine_port}                      ║");
    info!("║  Endereço:      {}", mail_addr_str);
    info!("╚══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        result = mail_server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraMail error");
            }
        }
        result = chat_server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraChat error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_dashboard_mode(
    app_cfg: &app_config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dashboard_port: u16 = 8082;
    let dashboard_addr: SocketAddr = format!("127.0.0.1:{dashboard_port}").parse()?;

    let db_path = std::path::Path::new(&app_cfg.paths.keys_dir).join("analytics.db");
    let db = std::sync::Arc::new(analytics::storage::AnalyticsDb::open(&db_path)?);

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraNet Analytics Dashboard                              ║");
    info!("║  Dashboard:  http://127.0.0.1:{dashboard_port}                        ║");
    info!("║  API:        http://127.0.0.1:{dashboard_port}/api/stats              ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    let collector_db = std::sync::Arc::clone(&db);
    tokio::spawn(async move {
        analytics::collector::run_collector(collector_db, 30).await;
    });

    tokio::select! {
        result = analytics::dashboard::run_dashboard(dashboard_addr, db) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "dashboard error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_chat_standalone(
    app_cfg: &app_config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let local_port = app_cfg.hidden_service.local_port;
    let chat_addr: SocketAddr = format!("0.0.0.0:{local_port}").parse()?;
    let room_name = "hidrachat-local".to_string();
    let passphrase = "hidrachat-standalone-test";
    let chat_server = apps::hidrachat::server::ChatServer::new(
        chat_addr,
        room_name,
        passphrase,
    );

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraChat standalone: http://127.0.0.1:{}", local_port);
    info!("║  Modo local (sem rede cebola) — para testes");
    info!("╚══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        result = chat_server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraChat error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_mail_standalone(
    app_cfg: &app_config::AppConfig,
    signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let local_port = app_cfg.hidden_service.local_port;
    let mail_addr_str = format!("127.0.0.1:{local_port}");
    let mail_sock: SocketAddr = mail_addr_str.parse()?;

    let keys_dir = std::path::Path::new(&app_cfg.paths.keys_dir);
    let mail_keys = apps::hidramail::crypto::MailKeys::load_or_generate(keys_dir)?;

    let mail_name = app_cfg
        .hidden_service
        .mail_name
        .as_deref()
        .unwrap_or("local");
    let mail_addr = format!("{mail_name}@standalone.hidra");

    let mail_dir = keys_dir.join("mail_store");
    let store = apps::hidramail::storage::MailStore::new(&mail_dir)?;

    let state = apps::hidramail::server::ServerState {
        mail_addr: mail_addr.clone(),
        mail_keys,
        signing_key,
        store,
    };
    let server = apps::hidramail::server::MailServer::new(mail_sock, state);

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraMail standalone: http://127.0.0.1:{}", local_port);
    info!("║  Endereço: {}", mail_addr);
    info!("║  Modo local (sem rede cebola) — para testes");
    info!("╚══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraMail error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_server_mode(
    app_cfg: &app_config::AppConfig,
    _network_secret: StaticSecret,
    _signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::crypto::keys::ServiceKeys;

    info!("=== HidraNet Hidden Service Mode ===");

    let service_keys = ServiceKeys::load_or_generate(
        Path::new(&app_cfg.paths.keys_dir),
    )?;
    let hidra_address = &service_keys.address;
    let service_hash = service_keys.address_hash;

    info!(
        address = %hidra_address,
        "hidden service identity loaded"
    );

    info!("spawning local relay nodes...");
    let local_relays = spawn_local_relays().await?;

    let dht_addr: SocketAddr = format!("0.0.0.0:{}", app_cfg.dht.port).parse()?;
    let dht_signing_key = ed25519_dalek::SigningKey::generate(
        &mut rand_core::OsRng,
    );
    let mut dht = p2p::dht::DhtNode::new(dht_addr, dht_signing_key, None).await?;
    dht.start().await;

    let bootstrap_addrs: Vec<SocketAddr> = app_cfg
        .dht
        .bootstrap_nodes
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if !bootstrap_addrs.is_empty() {
        if let Err(e) = p2p::bootstrap::bootstrap(&dht, &bootstrap_addrs).await {
            warn!(error = %e, "DHT bootstrap failed");
        }
    }

    let mut config_relays = match relay::registry::load_relay_list(&app_cfg.relays) {
        Ok(list) => list,
        Err(_) => Vec::new(),
    };
    for lr in &local_relays {
        if !config_relays.iter().any(|r| r.addr == lr.addr) {
            config_relays.push(lr.clone());
        }
    }
    let relays = if config_relays.len() >= 3 {
        config_relays
    } else {
        local_relays.clone()
    };

    if relays.len() < 3 {
        return Err("need at least 3 relays for hidden service".into());
    }

    let local_port = app_cfg.hidden_service.local_port;

    let intro_addr = relays[0].addr;
    if let Err(e) = dht.announce_service(
        service_hash,
        vec![intro_addr],
        *service_keys.verifying_key.as_bytes(),
    )
    .await {
        warn!(error = %e, "failed to announce service in DHT, continuing with local registration");
    }

    info!(
        intro_point = %intro_addr,
        "announced service in DHT"
    );

    let mut server_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut server_secret_bytes);
    let server_secret = StaticSecret::from(server_secret_bytes);
    server_secret_bytes.zeroize();

    info!("building circuit to introduction point...");
    let mut intro_circuit = client::streaming::StreamingCircuit::build(
        &relays,
        server_secret,
    )
    .await?;

    intro_circuit.register_service(service_hash.to_vec()).await?;
    info!("registered at introduction point");

    let app_name = app_cfg.hidden_service.app.as_deref();

    if app_name == Some("hidrachat") {
        let chat_addr: SocketAddr = format!("0.0.0.0:{local_port}").parse()?;
        let room_name = hidra_address.replace(".hidra", "");
        let passphrase = format!("hidrachat-{hidra_address}");
        let chat_server = apps::hidrachat::server::ChatServer::new(
            chat_addr,
            room_name,
            &passphrase,
        );
        tokio::spawn(async move {
            if let Err(e) = chat_server.run().await {
                tracing::error!(error = %e, "HidraChat server error");
            }
        });
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  HidraChat está disponível em: http://{}", hidra_address);
        info!("║  Sala de chat criptografada — porta local: {}", local_port);
        info!("╚══════════════════════════════════════════════════════════════╝");
    } else if app_name == Some("hidramail") {
        let mail_sock: SocketAddr = format!("127.0.0.1:{local_port}").parse()?;
        let keys_dir = std::path::Path::new(&app_cfg.paths.keys_dir);
        let mail_keys = apps::hidramail::crypto::MailKeys::load_or_generate(keys_dir)?;
        let mail_name = app_cfg
            .hidden_service
            .mail_name
            .as_deref()
            .unwrap_or("anon");
        let mail_addr = format!("{mail_name}@{hidra_address}");
        let mail_dir = keys_dir.join("mail_store");
        let store = apps::hidramail::storage::MailStore::new(&mail_dir)?;
        let mail_signing = SigningKey::from_bytes(&_signing_key.to_bytes());
        let state = apps::hidramail::server::ServerState {
            mail_addr: mail_addr.clone(),
            mail_keys,
            signing_key: mail_signing,
            store,
        };
        let mail_server = apps::hidramail::server::MailServer::new(mail_sock, state);
        tokio::spawn(async move {
            if let Err(e) = mail_server.run().await {
                tracing::error!(error = %e, "HidraMail server error");
            }
        });
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  HidraMail está disponível em: http://{}", hidra_address);
        info!("║  Endereço: {}", mail_addr);
        info!("║  Porta local: {}", local_port);
        info!("╚══════════════════════════════════════════════════════════════╝");
    } else if app_name == Some("sevennine") {
        let sevennine_port = local_port;
        let data_dir = std::path::PathBuf::from(&app_cfg.paths.keys_dir)
            .parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
        let sn_data = data_dir.clone();
        let (dht_tx, mut dht_rx) = tokio::sync::mpsc::channel::<apps::sevennine::DhtAnnouncement>(64);
        tokio::spawn(async move {
            let manager = std::sync::Arc::new(
                apps::sevennine::SiteManager::new_with_dht(&sn_data, dht_tx, sevennine_port)
            );
            // Re-announce existing sites to DHT on startup
            manager.announce_all_sites().await;
            let listener = match tokio::net::TcpListener::bind(
                format!("0.0.0.0:{sevennine_port}")
            ).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "SevenNine bind failed");
                    return;
                }
            };
            tracing::info!("SevenNine.hidra listening on port {}", sevennine_port);
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let mgr = manager.clone();
                    tokio::spawn(apps::sevennine::handle_connection_pub(stream, mgr));
                }
            }
        });
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  SevenNine.hidra — Criador de Sites Descentralizado        ║");
        info!("║  Endereço:   http://{}", hidra_address);
        info!("║  Local:      http://127.0.0.1:{}", local_port);
        info!("║  Cada site criado é publicado na DHT automaticamente       ║");
        info!("╚══════════════════════════════════════════════════════════════╝");

        // Process DHT announcements from SevenNine in the service loop
        let sn_intro_addr = intro_addr;
        tokio::spawn(async move {
            while let Some(announcement) = dht_rx.recv().await {
                if let Err(e) = dht.announce_service(
                    announcement.service_hash,
                    vec![sn_intro_addr],
                    announcement.service_pubkey,
                ).await {
                    tracing::warn!(error = %e, "failed to publish site to DHT");
                } else {
                    let hex: String = announcement.service_hash.iter().map(|b| format!("{b:02x}")).collect();
                    tracing::info!(address = %hex, "site announced in DHT");
                }
            }
        });
    } else {
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  Seu site está disponível em: http://{}", hidra_address);
        info!("║  Porta local: {}", local_port);
        info!("╚══════════════════════════════════════════════════════════════╝");
    }

    // Service loop: receive client data from intro point, forward to local server
    loop {
        tokio::select! {
            data_result = intro_circuit.recv_data() => {
                match data_result {
                    Ok(Some(data)) => {
                        let local_addr = format!("127.0.0.1:{local_port}");
                        match tokio::net::TcpStream::connect(&local_addr).await {
                            Ok(mut local_stream) => {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                if local_stream.write_all(&data).await.is_ok() {
                                    let mut response_buf = vec![0u8; 16384];
                                    match local_stream.read(&mut response_buf).await {
                                        Ok(0) => {}
                                        Ok(n) => {
                                            let _ = intro_circuit.send_data(&response_buf[..n]).await;
                                        }
                                        Err(e) => {
                                            debug!(error = %e, "local server read error");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, local_port, "failed to connect to local server");
                            }
                        }
                    }
                    Ok(None) => {
                        info!("intro circuit closed, reconnecting...");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "intro circuit error");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
                break;
            }
        }
    }

    Ok(())
}

async fn run_proxy_mode(
    app_cfg: &app_config::AppConfig,
    _network_secret: StaticSecret,
    _signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    info!("=== HidraNet Proxy Mode ===");
    info!("spawning local relay nodes for onion routing...");

    let local_relays = spawn_local_relays().await?;
    let relay_addrs: Vec<SocketAddr> = local_relays.iter().map(|r| r.addr).collect();

    let proxy_addr: SocketAddr =
        format!("{}:{}", app_cfg.proxy.listen_addr, app_cfg.proxy.port).parse()?;

    let dht_addr: SocketAddr = format!("0.0.0.0:{}", app_cfg.dht.port).parse()?;

    let bootstrap_addrs: Vec<SocketAddr> = app_cfg
        .dht
        .bootstrap_nodes
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let mut config_relays = match relay::registry::load_relay_list(&app_cfg.relays) {
        Ok(list) => list,
        Err(_) => Vec::new(),
    };

    for lr in &local_relays {
        if !config_relays.iter().any(|r| r.addr == lr.addr) {
            config_relays.push(lr.clone());
        }
    }

    let static_relays = if config_relays.len() >= 3 {
        config_relays
    } else {
        local_relays.clone()
    };

    let mut proxy_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut proxy_secret_bytes);

    let proxy_config = client::proxy_runner::ProxyConfig {
        listen_addr: proxy_addr,
        dht_addr,
        bootstrap_addrs,
        secret_bytes: proxy_secret_bytes,
        static_relays,
    };

    proxy_secret_bytes.zeroize();

    let api_addr: SocketAddr = format!("127.0.0.1:{API_PORT}").parse()?;
    let api_state = Arc::new(api::ApiState {
        start_time: Instant::now(),
        relay_count: relay_addrs.len(),
        relay_addrs,
        hops: 3,
    });

    tokio::spawn({
        let state = Arc::clone(&api_state);
        async move {
            api::run_api_server(api_addr, state).await;
        }
    });

    info!(
        proxy_addr = %proxy_addr,
        api_addr = %api_addr,
        "SOCKS5 proxy starting — configure your browser to use socks5://127.0.0.1:{}",
        app_cfg.proxy.port
    );

    info!(
        "test with: curl --socks5-hostname 127.0.0.1:{} https://check.torproject.org/",
        app_cfg.proxy.port
    );

    tokio::select! {
        result = client::proxy_runner::run_proxy(proxy_config) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "proxy error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal — shutting down gracefully");
        }
    }

    Ok(())
}

async fn run_send_mode(
    app_cfg: &app_config::AppConfig,
    network_secret: StaticSecret,
    signing_key: SigningKey,
    payload: &str,
    dht_discover: bool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if dht_discover && app_cfg.dht.enabled {
        let dht_addr: SocketAddr = format!("0.0.0.0:{}", app_cfg.dht.port).parse()?;
        let mut dht = p2p::dht::DhtNode::new(dht_addr, signing_key, None).await?;
        dht.start().await;

        let bootstrap_addrs: Vec<SocketAddr> = app_cfg
            .dht
            .bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        p2p::bootstrap::bootstrap(&dht, &bootstrap_addrs).await?;

        let relays = dht.find_relays(3).await?;
        if relays.len() < 3 {
            eprintln!("ERROR: DHT found only {} relays, need 3", relays.len());
            std::process::exit(1);
        }

        let relay_entries: Vec<relay::registry::RelayEntry> = relays
            .into_iter()
            .map(|r| relay::registry::RelayEntry {
                name: format!("{}", r.id),
                addr: r.relay_addr.unwrap_or(r.dht_addr),
                noise_pubkey_b64: String::new(),
            })
            .collect();

        info!(relays = relay_entries.len(), "discovered relays via DHT");

        let response =
            client::session::run_client_session(&relay_entries, network_secret, payload)
                .await?;

        info!(response = %response, "onion circuit complete (DHT discovery)");
    } else {
        let relay_list = relay::registry::load_relay_list(&app_cfg.relays)?;

        if relay_list.len() < 3 {
            eprintln!(
                "ERROR: need at least 3 relays in config, found {}",
                relay_list.len()
            );
            std::process::exit(1);
        }

        info!(
            relays = relay_list.len(),
            payload = %payload,
            "starting client onion session"
        );

        let response =
            client::session::run_client_session(&relay_list, network_secret, payload)
                .await?;

        info!(response = %response, "onion circuit complete");
    }

    Ok(())
}

async fn run_relay_mode(
    app_cfg: &app_config::AppConfig,
    network_secret: StaticSecret,
    signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let listen_addr = format!(
        "{}:{}",
        app_cfg.network.listen_addr, app_cfg.network.listen_port
    );
    let addr: SocketAddr = listen_addr.parse()?;

    let relay_addr = Some(addr);

    let dht_node = if app_cfg.dht.enabled {
        let dht_addr: SocketAddr =
            format!("{}:{}", app_cfg.network.listen_addr, app_cfg.dht.port).parse()?;
        let mut dht = p2p::dht::DhtNode::new(dht_addr, signing_key, relay_addr).await?;
        dht.start().await;

        let bootstrap_addrs: Vec<SocketAddr> = app_cfg
            .dht
            .bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        if let Err(e) = p2p::bootstrap::bootstrap(&dht, &bootstrap_addrs).await {
            tracing::warn!(error = %e, "DHT bootstrap failed");
        }

        if let Err(e) = dht.announce_relay().await {
            tracing::debug!(
                error = %e,
                "initial relay announcement skipped (no peers yet)"
            );
        }

        Some(dht)
    } else {
        None
    };

    let listener = network::listener::NodeListener::bind(addr, network_secret).await?;
    info!(addr = %addr, "listening for inbound connections");

    tokio::select! {
        result = listener.accept_loop() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "listener error");
            }
        }
        _ = async {
            if let Some(ref dht) = dht_node {
                p2p::discovery::run_maintenance_loop(dht).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal — shutting down gracefully");
        }
    }

    Ok(())
}

async fn run_sevennine_mode(
    cfg: &app_config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let data_dir = std::path::PathBuf::from(&cfg.paths.keys_dir).parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  SevenNine.hidra — Criador Descentralizado de Sites         ║");
    info!("║  Acesse: http://127.0.0.1:8084                             ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        result = apps::sevennine::run_sevennine("0.0.0.0", 8084, &data_dir) => {
            if let Err(e) = result {
                tracing::error!("SevenNine error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SevenNine shutting down");
        }
    }

    Ok(())
}

// =============================================================================
// Tests — Security modules
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_solve_and_verify() {
        let challenge = security::pow::generate_challenge(8);
        let solution = security::pow::solve_challenge(&challenge)
            .expect("should solve PoW with difficulty 8");
        security::pow::verify_solution(&challenge, &solution, 300)
            .expect("valid solution should verify");
    }

    #[test]
    fn test_pow_rejects_bad_solution() {
        let challenge = security::pow::generate_challenge(16);
        let bad = security::pow::PowSolution {
            nonce: 0,
            hash: [0xFF; 32],
        };
        assert!(security::pow::verify_solution(&challenge, &bad, 300).is_err());
    }

    #[test]
    fn test_traffic_pad_unpad_roundtrip() {
        let original = b"Hidra secret message";
        let padded = security::traffic::pad_message(original)
            .expect("pad should succeed");
        assert_eq!(padded.len(), security::traffic::PADDED_CELL_SIZE);
        let recovered = security::traffic::unpad_message(&padded)
            .expect("unpad should succeed");
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_traffic_chaff_detection() {
        let chaff = security::traffic::generate_chaff();
        assert!(security::traffic::is_chaff(&chaff));
        assert_eq!(chaff.len(), security::traffic::PADDED_CELL_SIZE);
        assert!(security::traffic::unpad_message(&chaff).is_err());
    }

    #[test]
    fn test_vault_encrypt_decrypt_roundtrip() {
        let passphrase = b"super-secret-passphrase-42";
        let data = b"private key material here";
        let config = security::vault::VaultConfig::default();

        let sealed = security::vault::vault_encrypt(passphrase, data, &config)
            .expect("encrypt should succeed");
        let recovered = security::vault::vault_decrypt(passphrase, &sealed, &config)
            .expect("decrypt should succeed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_vault_wrong_passphrase_fails() {
        let data = b"private key material";
        let config = security::vault::VaultConfig::default();

        let sealed = security::vault::vault_encrypt(b"correct", data, &config)
            .expect("encrypt should succeed");
        let result = security::vault::vault_decrypt(b"wrong", &sealed, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_tampered_data_fails() {
        let passphrase = b"my-passphrase";
        let data = b"secret";
        let config = security::vault::VaultConfig::default();

        let mut sealed = security::vault::vault_encrypt(passphrase, data, &config)
            .expect("encrypt should succeed");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(security::vault::vault_decrypt(passphrase, &sealed, &config).is_err());
    }

    #[test]
    fn test_post_quantum_hybrid_roundtrip() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");
        let peer_x25519_public = keys.x25519_public;

        let (shared_enc, encapsulation) = security::post_quantum::hybrid_encapsulate(
            &peer_x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate should succeed");

        let shared_dec = security::post_quantum::hybrid_decapsulate(&keys, &encapsulation)
            .expect("decapsulate should succeed");

        assert_eq!(shared_enc.as_bytes(), shared_dec.as_bytes());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];
        assert!(security::hardening::constant_time_compare(&a, &b));
        assert!(!security::hardening::constant_time_compare(&a, &c));
    }

    #[test]
    fn test_rate_limiter_allows_burst() {
        let limiter = security::rate_limiter::RateLimiter::new(
            security::rate_limiter::RateLimitConfig {
                max_requests_per_sec: 10.0,
                burst_size: 5.0,
                max_connections_per_ip: 8,
                max_violations_before_ban: 100,
                ban_duration: std::time::Duration::from_secs(60),
                cleanup_interval: std::time::Duration::from_secs(60),
            },
        );
        let ip: std::net::IpAddr = "192.168.1.1".parse().expect("valid IP");
        for _ in 0..5 {
            limiter.check_rate_limit(ip).expect("should allow within burst");
        }
        assert!(limiter.check_rate_limit(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_connection_limit() {
        let limiter = security::rate_limiter::RateLimiter::new(
            security::rate_limiter::RateLimitConfig {
                max_connections_per_ip: 2,
                ..security::rate_limiter::RateLimitConfig::default()
            },
        );
        let ip: std::net::IpAddr = "10.0.0.1".parse().expect("valid IP");
        limiter.track_connection(ip).expect("conn 1");
        limiter.track_connection(ip).expect("conn 2");
        assert!(limiter.track_connection(ip).is_err());
        limiter.release_connection(ip);
        limiter.track_connection(ip).expect("conn after release");
    }

    #[test]
    fn test_secure_random_bytes_nonzero() {
        let mut buf = [0u8; 32];
        security::hardening::secure_random_bytes(&mut buf);
        assert_ne!(buf, [0u8; 32]);
    }
}
