//! HidraMail: the node's mail server.
//!
//! One mailbox per node. The owner reads it over loopback; other nodes hand
//! messages in through `/api/deliver`, which is the one endpoint that answers
//! requests from off this machine. A message is sealed to the recipient's
//! X25519 key and signed with the sender's Ed25519 key, and the sender's
//! address is derived from that signing key, so a signature that verifies
//! also proves who sent it.
//!
//! Delivery goes through the node's own SOCKS5 proxy to the recipient's
//! `.hidra` address, so neither side learns the other's IP. A plain TCP
//! address can still be given for testing, but only on loopback.

pub mod protocol {
    use serde::{Deserialize, Serialize};

    /// The signed, sealed unit that travels between nodes.
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
        /// A loopback `host:port` for local testing. Any other address is
        /// refused: delivery between machines goes through the circuit.
        pub direct_addr: Option<String>,
    }

    /// Longest mail address accepted, in bytes. A name of up to 64
    /// characters, `@`, forty hex digits and `.hidra`.
    pub const MAX_ADDRESS_LEN: usize = 64 + 1 + 40 + 6;

    /// Domain separation for the envelope signature.
    const SIG_DOMAIN: &[u8] = b"hidramail-sig-v2";

    /// The mail address of a node whose signing key is `vk`: the mailbox name
    /// at the `.hidra` address that key produces. Deriving the host from the
    /// key is what lets a recipient check that the key which signed a message
    /// owns the address it claims to come from.
    pub fn mail_address(name: &str, vk: &ed25519_dalek::VerifyingKey) -> String {
        let (host, _) = crate::crypto::keys::derive_hidra_address(vk);
        format!("{name}@{host}")
    }

    /// A configured mailbox name as the address grammar allows it: lower
    /// case, ASCII letters, digits, `.`, `_` and `-`, at most 64 of them,
    /// and `mail` when nothing is left.
    pub fn mailbox_name(configured: &str) -> String {
        let mut name: String = configured
            .chars()
            .map(|c| c.to_ascii_lowercase())
            .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
            .take(64)
            .collect();
        if name.is_empty() {
            name = "mail".to_string();
        }
        name
    }

    /// The part after `@`, when the address is well formed.
    pub fn address_host(addr: &str) -> Option<&str> {
        if !valid_address(addr) {
            return None;
        }
        addr.split_once('@').map(|(_, host)| host)
    }

    /// `name@<40 hex digits>.hidra`, with a name of ASCII letters, digits,
    /// `.`, `_` or `-`. Nothing else is a mail address this server handles,
    /// and nothing else is allowed into a log, a file name or a reply.
    pub fn valid_address(addr: &str) -> bool {
        if addr.is_empty() || addr.len() > MAX_ADDRESS_LEN {
            return false;
        }
        let Some((name, host)) = addr.split_once('@') else {
            return false;
        };
        let name_ok = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-');
        name_ok && valid_hidra_host(host)
    }

    /// `<40 lowercase hex digits>.hidra`: the form a hidden-service address
    /// takes, and the only host a `.hidra` lookup can resolve.
    pub fn valid_hidra_host(host: &str) -> bool {
        let Some(hex) = host.strip_suffix(".hidra") else {
            return false;
        };
        hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// A message id is a lowercase hyphenated UUID and nothing else. The id
    /// becomes a file name on the recipient's disk, and it arrives from
    /// whoever is sending, so the check is strict rather than merely
    /// excluding path separators.
    pub fn valid_mail_id(id: &str) -> bool {
        if id.len() != 36 {
            return false;
        }
        id.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        })
    }

    /// True when `vk` is the key the host part of `from_addr` was derived
    /// from. The name part is the sender's to choose; the host is not.
    pub fn sender_owns_address(from_addr: &str, vk_bytes: &[u8]) -> bool {
        let Some(host) = address_host(from_addr) else {
            return false;
        };
        let Ok(arr) = <[u8; 32]>::try_from(vk_bytes) else {
            return false;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&arr) else {
            return false;
        };
        let (derived, _) = crate::crypto::keys::derive_hidra_address(&vk);
        derived == host
    }

    impl MailEnvelope {
        /// The bytes the signature covers: every field a recipient acts on,
        /// each with its length in front, so no field can borrow bytes from
        /// its neighbour and still verify.
        pub fn signing_data(&self) -> Vec<u8> {
            let mut data = Vec::new();
            data.extend_from_slice(SIG_DOMAIN);
            for field in [
                self.id.as_bytes(),
                self.from_addr.as_bytes(),
                self.to_addr.as_bytes(),
                &self.timestamp.to_le_bytes(),
                &self.ephemeral_pubkey,
                &self.sealed_body,
            ] {
                data.extend_from_slice(&(field.len() as u32).to_le_bytes());
                data.extend_from_slice(field);
            }
            data
        }
    }
}

pub mod crypto {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::Zeroize;

    use crate::crypto::keystore;
    use crate::error::{HidraError, Result};
    use std::path::Path;

    pub struct MailKeys {
        secret_bytes: [u8; 32],
        pub public_bytes: [u8; 32],
    }

    impl MailKeys {
        /// Load the mailbox key, or make one. The file is created readable by
        /// this user only and, with `HIDRA_KEY_PASSPHRASE` set, sealed like the
        /// node's other keys. An older key written as raw bytes with the
        /// default permissions is read once and rewritten the new way.
        pub fn load_or_generate(keys_dir: &Path) -> Result<Self> {
            let key_path = keys_dir.join("mail_x25519.key");
            let secret_bytes = if key_path.exists() {
                let raw = std::fs::read(&key_path).map_err(HidraError::Io)?;
                if raw.len() == 32 {
                    // Legacy: raw bytes, written with fs::write.
                    let mut secret = [0u8; 32];
                    secret.copy_from_slice(&raw);
                    keystore::write_secret(&key_path, BASE64.encode(secret).as_bytes())?;
                    secret
                } else {
                    let read = keystore::read_secret(&key_path)?;
                    let decoded = BASE64.decode(&read.plaintext).map_err(|_| {
                        HidraError::Crypto("invalid mail key file".into())
                    })?;
                    let secret: [u8; 32] = decoded
                        .try_into()
                        .map_err(|_| HidraError::Crypto("invalid mail key file".into()))?;
                    if read.needs_sealing {
                        keystore::write_secret(&key_path, BASE64.encode(secret).as_bytes())?;
                    }
                    secret
                }
            } else {
                let mut secret = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut secret);
                keystore::write_secret(&key_path, BASE64.encode(secret).as_bytes())?;
                secret
            };
            let secret = StaticSecret::from(secret_bytes);
            let public = PublicKey::from(&secret);
            Ok(Self {
                secret_bytes,
                public_bytes: *public.as_bytes(),
            })
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

    use super::crypto;
    use super::protocol::{valid_mail_id, MailContent, MailEnvelope, MailSummary};
    use crate::error::{HidraError, Result};

    /// Most messages the inbox holds before new ones are refused.
    pub const MAX_INBOX_MESSAGES: usize = 5000;
    /// Most bytes the inbox holds before new ones are refused.
    pub const MAX_INBOX_BYTES: u64 = 256 * 1024 * 1024;

    pub struct MailStore {
        inbox_dir: PathBuf,
        sent_dir: PathBuf,
    }

    /// Every file name under the store is `<id>.json` or `<id>.read` for an
    /// id that passed `valid_mail_id`. The id comes from the network, so this
    /// is the one place a path is ever built from it.
    fn mail_path(dir: &Path, id: &str, ext: &str) -> Result<PathBuf> {
        if !valid_mail_id(id) {
            return Err(HidraError::Protocol("invalid mail id".into()));
        }
        Ok(dir.join(format!("{id}.{ext}")))
    }

    impl MailStore {
        pub fn new(base_dir: &Path) -> Result<Self> {
            let inbox_dir = base_dir.join("inbox");
            let sent_dir = base_dir.join("sent");
            std::fs::create_dir_all(&inbox_dir).map_err(HidraError::Io)?;
            std::fs::create_dir_all(&sent_dir).map_err(HidraError::Io)?;
            crate::crypto::keys::restrict_dir(base_dir)?;
            crate::crypto::keys::restrict_dir(&inbox_dir)?;
            crate::crypto::keys::restrict_dir(&sent_dir)?;
            Ok(Self { inbox_dir, sent_dir })
        }

        /// File a message that arrived from another node. Fails with
        /// `AlreadyExists` when a message with this id is already filed, so
        /// a repeated delivery cannot overwrite the first.
        pub fn store_incoming(&self, env: &MailEnvelope) -> Result<()> {
            let path = mail_path(&self.inbox_dir, &env.id, "json")?;
            let json = serde_json::to_string(env)
                .map_err(|e| HidraError::Protocol(format!("serialize: {e}")))?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(HidraError::Io)?;
            std::io::Write::write_all(&mut file, json.as_bytes()).map_err(HidraError::Io)
        }

        pub fn store_sent(&self, env: &MailEnvelope) -> Result<()> {
            let path = mail_path(&self.sent_dir, &env.id, "json")?;
            let json = serde_json::to_string(env)
                .map_err(|e| HidraError::Protocol(format!("serialize: {e}")))?;
            std::fs::write(path, json).map_err(HidraError::Io)
        }

        /// How many messages the inbox holds, and how many bytes.
        pub fn inbox_usage(&self) -> (usize, u64) {
            let mut count = 0usize;
            let mut bytes = 0u64;
            if let Ok(entries) = std::fs::read_dir(&self.inbox_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    count += 1;
                    bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
            (count, bytes)
        }

        /// True when the inbox cannot take a message of `incoming_bytes`.
        pub fn inbox_full(&self, incoming_bytes: u64) -> bool {
            let (count, bytes) = self.inbox_usage();
            count >= MAX_INBOX_MESSAGES || bytes.saturating_add(incoming_bytes) > MAX_INBOX_BYTES
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
                if !valid_mail_id(&env.id) {
                    continue;
                }
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
            let inbox_path = mail_path(&self.inbox_dir, id, "json")?;
            let path = if inbox_path.exists() {
                let marker = mail_path(&self.inbox_dir, id, "read")?;
                let _ = std::fs::write(marker, "");
                inbox_path
            } else {
                let sent_path = mail_path(&self.sent_dir, id, "json")?;
                if sent_path.exists() {
                    sent_path
                } else {
                    return Err(HidraError::Protocol("mail not found".into()));
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
            let inbox = mail_path(&self.inbox_dir, id, "json")?;
            let sent = mail_path(&self.sent_dir, id, "json")?;
            let marker = mail_path(&self.inbox_dir, id, "read")?;
            if inbox.exists() {
                std::fs::remove_file(&inbox).map_err(HidraError::Io)?;
                let _ = std::fs::remove_file(&marker);
            } else if sent.exists() {
                std::fs::remove_file(&sent).map_err(HidraError::Io)?;
            } else {
                return Err(HidraError::Protocol("mail not found".into()));
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
                Err(_) => "[error]".into(),
            },
            Err(_) => "[encrypted]".into(),
        }
    }
}

pub mod server {
    use crate::safelog::sensitive;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tracing::{debug, info, warn};

    use super::crypto;
    use super::frontend;
    use super::protocol::{
        self, MailContent, MailEnvelope, SendRequest,
    };
    use super::storage::MailStore;
    use crate::error::{HidraError, Result};

    /// Largest request this server reads, headers and body together. A
    /// message is a subject and a body of text; nothing legitimate is near
    /// this.
    pub const MAX_REQUEST_BYTES: usize = 64 * 1024;
    /// Largest envelope `/api/deliver` accepts.
    pub const MAX_DELIVERY_BYTES: usize = 48 * 1024;
    /// Largest subject-plus-body a message may carry before sealing.
    pub const MAX_CONTENT_BYTES: usize = 32 * 1024;
    /// How many deliveries are accepted per minute, over all senders. Every
    /// remote request arrives over loopback from the circuit, so there is no
    /// peer address to count per sender; what this bounds is how fast anyone
    /// can fill the disk.
    pub const DELIVERIES_PER_MINUTE: usize = 60;
    /// How long a connection may take to send its request.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
    /// How long the sender waits on the recipient, per round trip.
    const REMOTE_TIMEOUT: Duration = Duration::from_secs(60);
    /// Connections served at once.
    const MAX_CONNECTIONS: usize = 64;
    /// A timestamp further ahead than this is a clock no one has.
    const MAX_CLOCK_SKEW_MS: u64 = 60 * 60 * 1000;

    pub struct ServerState {
        pub mail_addr: String,
        pub mail_keys: crypto::MailKeys,
        pub signing_key: ed25519_dalek::SigningKey,
        pub store: MailStore,
        /// The node's SOCKS5 proxy, through which `.hidra` recipients are
        /// reached. Without one, only loopback test delivery works.
        pub socks_proxy: Option<SocketAddr>,
        deliveries: Mutex<VecDeque<Instant>>,
    }

    impl ServerState {
        /// The mailbox `name` at the address the signing key produces. A
        /// name the address grammar does not allow is bent into one it does,
        /// since a mailbox whose own address fails validation could never
        /// receive anything.
        pub fn new(
            mail_name: &str,
            mail_keys: crypto::MailKeys,
            signing_key: ed25519_dalek::SigningKey,
            store: MailStore,
            socks_proxy: Option<SocketAddr>,
        ) -> Self {
            let name = protocol::mailbox_name(mail_name);
            let mail_addr = protocol::mail_address(&name, &signing_key.verifying_key());
            Self {
                mail_addr,
                mail_keys,
                signing_key,
                store,
                socks_proxy,
                deliveries: Mutex::new(VecDeque::new()),
            }
        }

        /// Count a delivery against the per-minute budget. False when the
        /// budget is spent.
        fn allow_delivery(&self) -> bool {
            let now = Instant::now();
            let mut recent = match self.deliveries.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            while recent
                .front()
                .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
            {
                recent.pop_front();
            }
            if recent.len() >= DELIVERIES_PER_MINUTE {
                return false;
            }
            recent.push_back(now);
            true
        }
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

        pub async fn run(self) -> Result<()> {
            let listener = TcpListener::bind(self.addr).await?;
            info!(
                addr = %self.addr,
                mail = %self.state.mail_addr,
                "HidraMail server listening"
            );
            serve(listener, self.state).await
        }
    }

    /// Accept connections on `listener` forever.
    pub async fn serve(listener: TcpListener, state: Arc<ServerState>) -> Result<()> {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "accept error");
                    continue;
                }
            };
            let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                // Full. Say so and move on; holding the socket open would be
                // one more way to keep the others waiting.
                let mut stream = stream;
                let _ = stream.write_all(json_err(503, "server busy").as_bytes()).await;
                continue;
            };
            let st = Arc::clone(&state);
            tokio::spawn(async move {
                let _slot = slot;
                if let Err(e) = handle_connection(stream, peer, st).await {
                    debug!(
                        peer = %sensitive(&peer),
                        error = %e,
                        "connection ended"
                    );
                }
            });
        }
    }

    /// Read one HTTP request, bounded in size and in time.
    async fn read_request(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; MAX_REQUEST_BYTES];
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
                if content_len > MAX_REQUEST_BYTES - hdr_end {
                    return Err(HidraError::Protocol("request too large".into()));
                }
                let body_received = total - hdr_end;
                if body_received >= content_len {
                    break;
                }
            } else if total >= buf.len() {
                return Err(HidraError::Protocol("request too large".into()));
            }
        }
        if total == 0 {
            return Ok(None);
        }
        buf.truncate(total);
        Ok(Some(buf))
    }

    async fn handle_connection(
        mut stream: TcpStream,
        peer: SocketAddr,
        state: Arc<ServerState>,
    ) -> Result<()> {
        let raw = match tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
            Ok(Ok(Some(raw))) => raw,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => {
                let _ = stream.write_all(json_err(413, "request too large").as_bytes()).await;
                return Err(e);
            }
            Err(_) => {
                let _ = stream.write_all(json_err(408, "request timed out").as_bytes()).await;
                return Err(HidraError::Protocol("request timed out".into()));
            }
        };
        let raw = String::from_utf8_lossy(&raw).to_string();
        debug!(peer = %sensitive(&peer), bytes = raw.len(), "request received");
        handle_http(&mut stream, &raw, &state).await
    }

    fn find_header_end(data: &[u8]) -> Option<usize> {
        data.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
    }

    fn parse_content_length(headers: &str) -> usize {
        for line in headers.lines() {
            if let Some((key, val)) = line.split_once(':') {
                if key.trim().eq_ignore_ascii_case("content-length") {
                    return val.trim().parse().unwrap_or(0);
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
        raw.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn reason(status: u16) -> &'static str {
        match status {
            200 => "OK",
            204 => "No Content",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            408 => "Request Timeout",
            409 => "Conflict",
            413 => "Payload Too Large",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            507 => "Insufficient Storage",
            _ => "Error",
        }
    }

    fn response(status: u16, ctype: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: {ctype}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\n{}Connection: close\r\n\r\n{body}",
            reason(status),
            body.len(),
            crate::local_guard::response_headers(None),
        )
    }

    /// A JSON reply. The value is serialised by serde, so a quote in a
    /// message or an error never breaks the document around it.
    fn json_response(status: u16, value: serde_json::Value) -> String {
        response(status, "application/json", &value.to_string())
    }

    fn json_ok(value: serde_json::Value) -> String {
        json_response(200, value)
    }

    fn json_err(status: u16, msg: &str) -> String {
        json_response(status, json!({ "error": msg }))
    }

    async fn handle_http(
        stream: &mut TcpStream,
        raw: &str,
        state: &Arc<ServerState>,
    ) -> Result<()> {
        let (method, path) = match parse_request_line(raw) {
            Some(v) => v,
            None => {
                let r = json_err(400, "bad request");
                stream.write_all(r.as_bytes()).await?;
                return Ok(());
            }
        };

        // Without this, a page on any site the user visited could POST
        // /api/send as a simple request — no preflight, so the browser sends
        // it and only hides the reply — and mail went out in the owner's
        // name. The read endpoints were already unreadable cross-origin
        // (no CORS header is sent); the write side was not protected by
        // anything.
        //
        // Two endpoints answer requests from off this machine, because they
        // are how another node hands this one a message: /api/pubkey, which
        // the sender needs to seal it, and /api/deliver, which takes it.
        // Neither carries any authority of the owner's.
        let from_this_machine =
            matches!(crate::local_guard::screen(raw), crate::local_guard::Access::Allow(_));
        let public = matches!((method, path), ("GET", "/api/pubkey") | ("POST", "/api/deliver"));
        if !from_this_machine && !public {
            let r = json_err(403, "request did not come from this machine");
            stream.write_all(r.as_bytes()).await?;
            return Ok(());
        }

        let resp = match (method, path) {
            ("GET", "/" | "/index.html") => {
                let html = frontend::INDEX_HTML
                    .replace("{{MAIL_ADDR}}", &state.mail_addr);
                response(200, "text/html", &html)
            }
            ("GET", "/style.css") => {
                response(200, "text/css", frontend::STYLE_CSS)
            }
            ("GET", "/app.js") => {
                response(200, "application/javascript", frontend::APP_JS)
            }
            ("GET", "/api/identity") => json_ok(json!({
                "address": state.mail_addr,
                "pubkey": hex_encode(&state.mail_keys.public_bytes),
            })),
            ("GET", "/api/pubkey") => json_ok(json!({
                "pubkey": hex_encode(&state.mail_keys.public_bytes),
            })),
            ("GET", "/api/inbox") => {
                let list = state
                    .store
                    .list_inbox(state.mail_keys.secret_bytes());
                json_ok(serde_json::to_value(list).unwrap_or_else(|_| json!([])))
            }
            ("GET", "/api/sent") => {
                let list = state
                    .store
                    .list_sent(state.mail_keys.secret_bytes());
                json_ok(serde_json::to_value(list).unwrap_or_else(|_| json!([])))
            }
            ("GET", p) if p.starts_with("/api/mail/") => {
                api_read_mail(&p[10..], state)
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
                if !protocol::valid_mail_id(id) {
                    json_err(400, "invalid mail id")
                } else {
                    match state.store.delete_mail(id) {
                        Ok(()) => json_ok(json!({ "ok": true })),
                        Err(_) => json_err(404, "mail not found"),
                    }
                }
            }
            ("OPTIONS", _) => {
                // No Access-Control-Allow-Origin: this mailbox is not for
                // other origins to reach.
                format!(
                    "HTTP/1.1 204 No Content\r\n\
                     Access-Control-Allow-Methods: GET,POST,DELETE,OPTIONS\r\n\
                     {}Connection: close\r\n\r\n",
                    crate::local_guard::response_headers(None)
                )
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
        if !protocol::valid_mail_id(id) {
            return json_err(400, "invalid mail id");
        }
        match state.store.read_mail(id, state.mail_keys.secret_bytes())
        {
            Ok((env, content)) => {
                // Verified means two things: the signature is good, and the
                // key that made it owns the address in From. The second is
                // what stops anyone from writing another person's address
                // into a message they signed themselves.
                let verified = crypto::verify_sig(
                    &env.sender_verifying_key,
                    &env.signing_data(),
                    &env.signature,
                ) && protocol::sender_owns_address(
                    &env.from_addr,
                    &env.sender_verifying_key,
                );
                json_ok(json!({
                    "id": env.id,
                    "from_addr": env.from_addr,
                    "to_addr": env.to_addr,
                    "subject": content.subject,
                    "body": content.body,
                    "timestamp": env.timestamp,
                    "verified": verified,
                }))
            }
            Err(HidraError::Protocol(_)) => json_err(404, "mail not found"),
            Err(_) => json_err(500, "could not read mail"),
        }
    }

    /// Where a message goes out.
    enum Route {
        /// A loopback address, for testing on one machine.
        Direct(SocketAddr),
        /// A `.hidra` host, reached through the node's SOCKS5 proxy.
        Hidden { proxy: SocketAddr, host: String },
    }

    impl Route {
        fn host_header(&self) -> String {
            match self {
                Route::Direct(addr) => addr.to_string(),
                Route::Hidden { host, .. } => host.clone(),
            }
        }

        async fn connect(&self) -> Result<TcpStream> {
            match self {
                Route::Direct(addr) => Ok(TcpStream::connect(addr).await?),
                Route::Hidden { proxy, host } => socks5_connect(*proxy, host, 80).await,
            }
        }
    }

    fn choose_route(req: &SendRequest, state: &ServerState) -> std::result::Result<Route, String> {
        if let Some(a) = &req.direct_addr {
            let addr: SocketAddr = a
                .parse()
                .map_err(|_| "direct_addr must be host:port".to_string())?;
            // A direct connection shows each side the other's IP. On
            // loopback that is nothing; anywhere else it is the one thing
            // this network exists to hide.
            if !addr.ip().is_loopback() {
                return Err("direct_addr is for loopback testing only; other recipients are reached by their .hidra address".into());
            }
            return Ok(Route::Direct(addr));
        }
        let host = protocol::address_host(&req.to)
            .ok_or_else(|| "recipient must be name@<address>.hidra".to_string())?;
        let proxy = state
            .socks_proxy
            .ok_or_else(|| "this node has no SOCKS5 proxy to reach .hidra addresses through".to_string())?;
        Ok(Route::Hidden { proxy, host: host.to_string() })
    }

    async fn api_send_mail(
        body: &str,
        state: &Arc<ServerState>,
    ) -> String {
        let req: SendRequest = match serde_json::from_str(body) {
            Ok(r) => r,
            Err(_) => return json_err(400, "could not parse the send request"),
        };
        if !protocol::valid_address(&req.to) {
            return json_err(400, "recipient must be name@<address>.hidra");
        }
        if req.subject.len() + req.body.len() > MAX_CONTENT_BYTES {
            return json_err(413, "message too large");
        }

        let route = match choose_route(&req, state) {
            Ok(r) => r,
            Err(msg) => return json_err(400, &msg),
        };

        let recipient_pubkey = match fetch_recipient_pubkey(&route).await {
            Ok(k) => k,
            Err(e) => {
                return json_err(502, &format!("could not fetch the recipient's key: {e}"));
            }
        };

        let content = MailContent {
            subject: req.subject,
            body: req.body,
        };
        let content_json = match serde_json::to_vec(&content) {
            Ok(j) => j,
            Err(_) => return json_err(500, "could not serialize the message"),
        };

        let (eph_pubkey, sealed_body) =
            match crypto::seal_message(&recipient_pubkey, &content_json) {
                Ok(v) => v,
                Err(_) => return json_err(500, "could not encrypt the message"),
            };

        let vk = state
            .signing_key
            .verifying_key()
            .as_bytes()
            .to_vec();

        let mut envelope = MailEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            from_addr: state.mail_addr.clone(),
            to_addr: req.to.clone(),
            timestamp: now_ms(),
            ephemeral_pubkey: eph_pubkey,
            sealed_body,
            sender_verifying_key: vk,
            signature: Vec::new(),
        };
        envelope.signature =
            crypto::sign_data(&state.signing_key, &envelope.signing_data());

        match deliver_to_remote(&route, &envelope).await {
            Ok(()) => {
                let sender_copy = make_sender_copy(
                    &envelope,
                    &content_json,
                    &state.mail_keys.public_bytes,
                    &state.signing_key,
                );
                let _ = state.store.store_sent(&sender_copy);
                info!(
                    to = %sensitive(&req.to),
                    id = %sensitive(&envelope.id),
                    "mail sent"
                );
                json_ok(json!({ "ok": true, "id": envelope.id }))
            }
            Err(e) => json_err(502, &format!("delivery failed: {e}")),
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    fn api_deliver(
        body: &str,
        state: &Arc<ServerState>,
    ) -> String {
        if body.len() > MAX_DELIVERY_BYTES {
            return json_err(413, "message too large");
        }
        let envelope: MailEnvelope = match serde_json::from_str(body) {
            Ok(e) => e,
            Err(_) => return json_err(400, "could not parse the envelope"),
        };
        if !state.allow_delivery() {
            return json_err(429, "too many deliveries, try again later");
        }
        if !protocol::valid_mail_id(&envelope.id) {
            return json_err(400, "invalid mail id");
        }
        if !protocol::valid_address(&envelope.from_addr)
            || !protocol::valid_address(&envelope.to_addr)
        {
            return json_err(400, "invalid address");
        }
        if envelope.to_addr != state.mail_addr {
            return json_err(404, "no such mailbox here");
        }
        if envelope.ephemeral_pubkey.len() != 32 || envelope.sealed_body.len() < 13 {
            return json_err(400, "malformed envelope");
        }
        if envelope.timestamp > now_ms().saturating_add(MAX_CLOCK_SKEW_MS) {
            return json_err(400, "timestamp is in the future");
        }

        if !crypto::verify_sig(
            &envelope.sender_verifying_key,
            &envelope.signing_data(),
            &envelope.signature,
        ) {
            return json_err(403, "invalid signature");
        }
        // The signature proves the key; this proves the key owns the From
        // address. Without it a valid signature from anyone's key could sit
        // under anyone's address.
        if !protocol::sender_owns_address(&envelope.from_addr, &envelope.sender_verifying_key) {
            return json_err(403, "sender key does not own the From address");
        }

        if state.store.inbox_full(body.len() as u64) {
            return json_err(507, "mailbox full");
        }

        match state.store.store_incoming(&envelope) {
            Ok(()) => {
                info!(
                    from = %sensitive(&envelope.from_addr),
                    id = %sensitive(&envelope.id),
                    "mail received"
                );
                json_ok(json!({ "ok": true, "id": envelope.id }))
            }
            Err(HidraError::Io(e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                json_err(409, "a message with this id is already here")
            }
            Err(_) => json_err(500, "could not store the message"),
        }
    }

    /// Connect to `host:port` through the SOCKS5 proxy at `proxy`, with the
    /// name left for the proxy to resolve: a `.hidra` name is looked up in
    /// the DHT and reached over a circuit, and never touches DNS.
    async fn socks5_connect(proxy: SocketAddr, host: &str, port: u16) -> Result<TcpStream> {
        if host.len() > 255 {
            return Err(HidraError::Protocol("host name too long for SOCKS5".into()));
        }
        let mut stream = TcpStream::connect(proxy).await?;
        // Greeting: version 5, one method, no authentication.
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut reply = [0u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply != [0x05, 0x00] {
            return Err(HidraError::Protocol("SOCKS5 proxy refused the connection".into()));
        }
        // CONNECT, domain name.
        let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        stream.write_all(&req).await?;
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await?;
        if head[0] != 0x05 || head[1] != 0x00 {
            return Err(HidraError::Protocol(format!(
                "SOCKS5 proxy could not reach the recipient (code {})",
                head[1]
            )));
        }
        // Bound address, which we do not use but must consume.
        let addr_len = match head[3] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut n = [0u8; 1];
                stream.read_exact(&mut n).await?;
                n[0] as usize
            }
            _ => return Err(HidraError::Protocol("SOCKS5 reply malformed".into())),
        };
        let mut rest = vec![0u8; addr_len + 2];
        stream.read_exact(&mut rest).await?;
        Ok(stream)
    }

    /// Send one request and read the whole reply, bounded in size and time.
    /// Returns the status code and the body.
    async fn http_exchange(route: &Route, request: &str) -> Result<(u16, String)> {
        let exchange = async {
            let mut stream = route.connect().await?;
            stream.write_all(request.as_bytes()).await?;
            let mut resp = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    break;
                }
                resp.extend_from_slice(&chunk[..n]);
                if resp.len() > MAX_REQUEST_BYTES {
                    return Err(HidraError::Protocol("reply too large".into()));
                }
            }
            let text = String::from_utf8_lossy(&resp).to_string();
            let status = text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or_else(|| HidraError::Protocol("no HTTP status in reply".into()))?;
            let body = extract_body(&text).trim().to_string();
            Ok((status, body))
        };
        tokio::time::timeout(REMOTE_TIMEOUT, exchange)
            .await
            .map_err(|_| HidraError::Protocol("the recipient did not answer in time".into()))?
    }

    async fn fetch_recipient_pubkey(route: &Route) -> Result<[u8; 32]> {
        let req = format!(
            "GET /api/pubkey HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            route.host_header()
        );
        let (status, body) = http_exchange(route, &req).await?;
        if status != 200 {
            return Err(HidraError::Protocol(format!(
                "recipient answered {status} to the key request"
            )));
        }

        #[derive(serde::Deserialize)]
        struct PkResp {
            pubkey: String,
        }
        let parsed: PkResp = serde_json::from_str(&body)
            .map_err(|_| HidraError::Protocol("could not parse the recipient's key".into()))?;

        let bytes = hex_decode(&parsed.pubkey)?;
        let key: [u8; 32] = bytes
            .try_into()
            .map_err(|_| HidraError::Crypto("invalid pubkey length".into()))?;
        Ok(key)
    }

    fn hex_decode(hex: &str) -> Result<Vec<u8>> {
        if hex.len() % 2 != 0 {
            return Err(HidraError::Protocol("odd hex length".into()));
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|_| HidraError::Protocol("invalid hex".into()))
            })
            .collect()
    }

    async fn deliver_to_remote(route: &Route, envelope: &MailEnvelope) -> Result<()> {
        let json = serde_json::to_string(envelope)
            .map_err(|e| HidraError::Protocol(format!("serialize: {e}")))?;
        let req = format!(
            "POST /api/deliver HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
            route.host_header(),
            json.len()
        );
        let (status, body) = http_exchange(route, &req).await?;
        if status == 200 {
            Ok(())
        } else {
            let detail = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                .unwrap_or_default();
            Err(HidraError::Protocol(format!(
                "recipient answered {status} {detail}"
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
}

pub mod frontend {
    pub const INDEX_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
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
    <div class="my-address" id="myAddress">Loading…</div>
    <ul class="nav-items">
        <li class="nav-item active" id="nav-inbox" onclick="showInbox()">&#128229; Inbox</li>
        <li class="nav-item" id="nav-sent" onclick="showSent()">&#128228; Sent</li>
        <li class="nav-item compose-btn" id="nav-compose" onclick="showCompose()">&#9998; Compose</li>
    </ul>
    <div class="sidebar-footer">
        <div class="crypto-info">&#128274; E2E encrypted</div>
        <div class="crypto-info">X25519 + ChaCha20-Poly1305</div>
    </div>
</nav>
<main id="content">
    <div class="loading">Loading…</div>
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
    document.getElementById('myAddress').textContent = 'failed to load';
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
content.innerHTML = '<div class="loading">Loading…</div>';
try {
    var mails = await api('/api/inbox');
    renderMailList(mails, 'Inbox');
} catch(e) {
    content.innerHTML = '<div class="empty-state"><p>Failed to load.</p></div>';
}
    };

    window.showSent = async function() {
updateNav('sent');
var content = document.getElementById('content');
content.innerHTML = '<div class="loading">Loading…</div>';
try {
    var mails = await api('/api/sent');
    renderMailList(mails, 'Sent');
} catch(e) {
    content.innerHTML = '<div class="empty-state"><p>Failed to load.</p></div>';
}
    };

    window.showCompose = function() {
updateNav('compose');
var content = document.getElementById('content');
content.innerHTML =
    '<div class="compose">' +
    '<h2>New message</h2>' +
    '<div class="form-group">' +
        '<label>To:</label>' +
        '<input type="text" id="composeTo" placeholder="name@address.hidra">' +
    '</div>' +
    '<div class="form-group">' +
        '<label>Subject:</label>' +
        '<input type="text" id="composeSubject" placeholder="Subject">' +
    '</div>' +
    '<div class="form-group">' +
        '<label>Message:</label>' +
        '<textarea id="composeBody" rows="12" placeholder="Write your message..."></textarea>' +
    '</div>' +
    '<div class="form-group">' +
        '<label>Direct address (optional, loopback only, for testing on this machine):</label>' +
        '<input type="text" id="composeDirectAddr" placeholder="127.0.0.1:8081">' +
    '</div>' +
    '<button onclick="doSend()">Send</button>' +
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
    status.textContent = 'Fill in every field.';
    status.style.color = '#ff4757';
    return;
}

status.textContent = 'Sending through the network…';
status.style.color = '#8892a4';

try {
    var payload = { to: to, subject: subject, body: body };
    if (directAddr) payload.direct_addr = directAddr;
    var res = await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });
    var result = await res.json();
    if (result.ok) {
        status.textContent = 'Mail sent.';
        status.style.color = '#00ff88';
        document.getElementById('composeTo').value = '';
        document.getElementById('composeSubject').value = '';
        document.getElementById('composeBody').value = '';
    } else {
        status.textContent = 'Error: ' + (result.error || 'failed');
        status.style.color = '#ff4757';
    }
} catch(e) {
    status.textContent = 'Connection error: ' + e;
    status.style.color = '#ff4757';
}
    };

    function renderMailList(mails, title) {
var content = document.getElementById('content');
if (!mails || mails.length === 0) {
    content.innerHTML = '<div class="empty-state"><h2>' + esc(title) + '</h2><p>No mail.</p></div>';
    return;
}
var html = '<div class="mail-list-header">' + esc(title) + ' (' + mails.length + ')</div>';
for (var i = 0; i < mails.length; i++) {
    var m = mails[i];
    var date = new Date(m.timestamp).toLocaleString('en-US');
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
content.innerHTML = '<div class="loading">Decrypting...</div>';
try {
    var mail = await api('/api/mail/' + id);
    if (mail.error) {
        content.innerHTML = '<div class="empty-state"><p>Error: ' + esc(mail.error) + '</p></div>';
        return;
    }
    var date = new Date(mail.timestamp).toLocaleString('en-US');
    var vIcon = mail.verified ? '✓ Sender verified' : '✗ Sender not verified';
    var vClass = mail.verified ? 'verified' : 'unverified';
    content.innerHTML =
        '<div class="mail-read">' +
            '<div class="mail-actions">' +
                '<button onclick="showInbox()">← Back</button>' +
                '<button class="danger" onclick="deleteMail(\'' + esc(mail.id) + '\')">Delete</button>' +
            '</div>' +
            '<h2>' + esc(mail.subject) + '</h2>' +
            '<div class="mail-meta">' +
                '<div>From: <strong>' + esc(mail.from_addr) + '</strong></div>' +
                '<div>To: <strong>' + esc(mail.to_addr) + '</strong></div>' +
                '<div>Date: ' + date + '</div>' +
                '<div class="' + vClass + '">' + vIcon + '</div>' +
            '</div>' +
            '<div class="mail-body-content">' + esc(mail.body) + '</div>' +
            '<div class="crypto-badge">\u{0001f512} Decrypted locally — X25519 + ChaCha20-Poly1305</div>' +
        '</div>';
} catch(e) {
    content.innerHTML = '<div class="empty-state"><p>Error: ' + e + '</p></div>';
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

#[cfg(test)]
mod tests {
    //! The server as another node sees it, over a real loopback socket, and
    //! the pieces it is made of. Every case here is a thing that was wrong
    //! or missing: a forged From that read as verified, a message id that
    //! became a path, an inbox with no ceiling, a key file anyone could read.

    use super::crypto::{self, MailKeys};
    use super::protocol::*;
    use super::server::{self, ServerState};
    use super::storage::MailStore;
    use ed25519_dalek::SigningKey;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A fresh directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path = std::env::temp_dir().join(format!(
                "hidramail-test-{}-{}-{n}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A node: its keys, its mailbox and the socket it answers on.
    struct Node {
        addr: SocketAddr,
        state: Arc<ServerState>,
        _dir: TempDir,
    }

    async fn start_node(name: &str, socks_proxy: Option<SocketAddr>) -> Node {
        let dir = TempDir::new();
        let mail_keys = MailKeys::load_or_generate(dir.path()).unwrap();
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let store = MailStore::new(&dir.path().join("mail_store")).unwrap();
        let state = Arc::new(ServerState::new(name, mail_keys, signing_key, store, socks_proxy));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = server::serve(listener, st).await;
        });
        Node { addr, state, _dir: dir }
    }

    /// One raw HTTP exchange. Returns the status and the parsed JSON body.
    async fn http(addr: SocketAddr, raw: &str) -> (u16, serde_json::Value) {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        s.read_to_end(&mut out).await.unwrap();
        let text = String::from_utf8_lossy(&out).to_string();
        let status: u16 = text
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
        let json = serde_json::from_str(body).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn get(path: &str, host: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
    }

    fn post(path: &str, host: &str, body: &str) -> String {
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    fn local_host(addr: SocketAddr) -> String {
        addr.to_string()
    }

    /// An envelope from `sender` to `to`, sealed to `to_pubkey`, with every
    /// field the way a well-behaved node sends it.
    fn envelope(sender: &SigningKey, from: &str, to: &str, to_pubkey: &[u8; 32], subject: &str) -> MailEnvelope {
        let content = serde_json::to_vec(&MailContent {
            subject: subject.into(),
            body: "hello there".into(),
        })
        .unwrap();
        let (eph, sealed) = crypto::seal_message(to_pubkey, &content).unwrap();
        let mut env = MailEnvelope {
            id: uuid::Uuid::new_v4().to_string(),
            from_addr: from.into(),
            to_addr: to.into(),
            timestamp: 1_700_000_000_000,
            ephemeral_pubkey: eph,
            sealed_body: sealed,
            sender_verifying_key: sender.verifying_key().as_bytes().to_vec(),
            signature: Vec::new(),
        };
        env.signature = crypto::sign_data(sender, &env.signing_data());
        env
    }

    fn deliver_body(env: &MailEnvelope) -> String {
        serde_json::to_string(env).unwrap()
    }

    // ───────── pieces ─────────

    #[test]
    fn seal_and_open_round_trip_and_reject_tampering() {
        let dir = TempDir::new();
        let keys = MailKeys::load_or_generate(dir.path()).unwrap();
        let (eph, mut sealed) = crypto::seal_message(&keys.public_bytes, b"secret").unwrap();
        assert_eq!(crypto::open_message(keys.secret_bytes(), &eph, &sealed).unwrap(), b"secret");

        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(crypto::open_message(keys.secret_bytes(), &eph, &sealed).is_err());

        let other = MailKeys::load_or_generate(TempDir::new().path()).unwrap();
        sealed[last] ^= 1;
        assert!(crypto::open_message(other.secret_bytes(), &eph, &sealed).is_err());
    }

    #[test]
    fn the_mail_key_is_written_for_this_user_only_and_reloads() {
        let dir = TempDir::new();
        let first = MailKeys::load_or_generate(dir.path()).unwrap();
        let again = MailKeys::load_or_generate(dir.path()).unwrap();
        assert_eq!(first.public_bytes, again.public_bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join("mail_x25519.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "mail key is readable by others");
        }
    }

    #[test]
    fn a_legacy_raw_key_is_read_once_and_rewritten() {
        let dir = TempDir::new();
        let raw = [7u8; 32];
        std::fs::write(dir.path().join("mail_x25519.key"), raw).unwrap();
        let keys = MailKeys::load_or_generate(dir.path()).unwrap();
        assert_eq!(keys.secret_bytes(), &raw);
        let on_disk = std::fs::read(dir.path().join("mail_x25519.key")).unwrap();
        assert_ne!(on_disk.len(), 32, "legacy raw key was left as it was");
        let again = MailKeys::load_or_generate(dir.path()).unwrap();
        assert_eq!(again.secret_bytes(), &raw);
    }

    #[test]
    fn mail_ids_are_uuids_and_nothing_else() {
        assert!(valid_mail_id(&uuid::Uuid::new_v4().to_string()));
        for bad in [
            "",
            "../../../../tmp/evil",
            "/etc/passwd",
            "123e4567-e89b-12d3-a456-42661417400",   // short
            "123e4567-e89b-12d3-a456-4266141740000", // long
            "123E4567-E89B-12D3-A456-426614174000",  // upper case
            "123e4567/e89b-12d3-a456-426614174000",
            "..e4567-e89b-12d3-a456-426614174000.",
        ] {
            assert!(!valid_mail_id(bad), "{bad:?} accepted as a mail id");
        }
    }

    #[test]
    fn addresses_are_a_name_at_a_hidra_host() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let addr = mail_address("alice", &key.verifying_key());
        assert!(valid_address(&addr), "{addr}");
        assert!(address_host(&addr).unwrap().ends_with(".hidra"));
        for bad in [
            "alice",
            "alice@standalone.hidra",
            "alice@example.com",
            "@0123456789abcdef0123456789abcdef01234567.hidra",
            "Alice@0123456789abcdef0123456789abcdef01234567.hidra",
            "a@b@0123456789abcdef0123456789abcdef01234567.hidra",
            "alice@0123456789ABCDEF0123456789abcdef01234567.hidra",
            "ali\nce@0123456789abcdef0123456789abcdef01234567.hidra",
        ] {
            assert!(!valid_address(bad), "{bad:?} accepted as an address");
        }
    }

    #[test]
    fn a_configured_name_is_bent_into_the_address_grammar() {
        assert_eq!(mailbox_name("alice"), "alice");
        assert_eq!(mailbox_name("Alice Smith"), "alicesmith");
        assert_eq!(mailbox_name("a@b/c"), "abc");
        assert_eq!(mailbox_name(""), "mail");
        assert_eq!(mailbox_name("Al!ce#"), "alce");
        assert_eq!(mailbox_name(&"x".repeat(100)).len(), 64);
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        assert!(valid_address(&mail_address(&mailbox_name("Alice Smith"), &key.verifying_key())));
    }

    #[test]
    fn only_the_key_an_address_was_made_from_owns_it() {
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let eve = SigningKey::generate(&mut rand::rngs::OsRng);
        let addr = mail_address("alice", &alice.verifying_key());
        assert!(sender_owns_address(&addr, alice.verifying_key().as_bytes()));
        assert!(!sender_owns_address(&addr, eve.verifying_key().as_bytes()));
        // Any name at the right host belongs to the key; the name is a label.
        let other_name = mail_address("bob", &alice.verifying_key());
        assert!(sender_owns_address(&other_name, alice.verifying_key().as_bytes()));
        assert!(!sender_owns_address(&addr, &[0u8; 31]));
    }

    #[test]
    fn signing_data_keeps_fields_apart() {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let to = mail_address("bob", &key.verifying_key());
        let from = mail_address("alice", &key.verifying_key());
        let a = envelope(&key, &from, &to, &[1u8; 32], "x");
        let mut b = a.clone();
        // Move the last byte of the ephemeral key into the sealed body:
        // the plain concatenation signed the same bytes for both.
        let moved = b.ephemeral_pubkey.pop().unwrap();
        b.sealed_body.insert(0, moved);
        assert_ne!(a.signing_data(), b.signing_data());
    }

    #[test]
    fn the_store_refuses_bad_ids_and_duplicates() {
        let dir = TempDir::new();
        let store = MailStore::new(dir.path()).unwrap();
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let to = mail_address("bob", &key.verifying_key());
        let mut env = envelope(&key, &mail_address("a", &key.verifying_key()), &to, &[1u8; 32], "x");

        store.store_incoming(&env).unwrap();
        let again = store.store_incoming(&env);
        assert!(again.is_err(), "a second message with the same id overwrote the first");

        env.id = "../../escaped".into();
        assert!(store.store_incoming(&env).is_err());
        assert!(!dir.path().join("escaped.json").exists());
        assert!(!dir.path().parent().unwrap().join("escaped.json").exists());

        assert!(store.read_mail("../x", &[0u8; 32]).is_err());
        assert!(store.delete_mail("../x").is_err());
        assert_eq!(store.inbox_usage().0, 1);
    }

    // ───────── the server, from outside ─────────

    #[tokio::test]
    async fn a_genuine_message_is_delivered_and_reads_as_verified() {
        let bob = start_node("bob", None).await;
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let from = mail_address("alice", &alice.verifying_key());
        let env = envelope(&alice, &from, &bob.state.mail_addr, &bob.state.mail_keys.public_bytes, "hi");

        // From off this machine, as the circuit would deliver it.
        let (status, body) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&env))).await;
        assert_eq!(status, 200, "{body}");

        let (status, inbox) = http(bob.addr, &get("/api/inbox", &local_host(bob.addr))).await;
        assert_eq!(status, 200);
        assert_eq!(inbox.as_array().unwrap().len(), 1);
        assert_eq!(inbox[0]["subject"], "hi");
        assert_eq!(inbox[0]["from_addr"], from);

        let (status, mail) = http(bob.addr, &get(&format!("/api/mail/{}", env.id), &local_host(bob.addr))).await;
        assert_eq!(status, 200);
        assert_eq!(mail["body"], "hello there");
        assert_eq!(mail["verified"], true);
    }

    #[tokio::test]
    async fn a_forged_from_is_refused_and_never_reads_as_verified() {
        let bob = start_node("bob", None).await;
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let eve = SigningKey::generate(&mut rand::rngs::OsRng);
        let alices_addr = mail_address("alice", &alice.verifying_key());
        // Eve writes Alice's address in From and signs with her own key.
        let env = envelope(&eve, &alices_addr, &bob.state.mail_addr, &bob.state.mail_keys.public_bytes, "urgent");
        let (status, body) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&env))).await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(bob.state.store.inbox_usage().0, 0);

        // Filed anyway, by some older server: the reader still does not call it verified.
        bob.state.store.store_incoming(&env).unwrap();
        let (_, mail) = http(bob.addr, &get(&format!("/api/mail/{}", env.id), &local_host(bob.addr))).await;
        assert_eq!(mail["verified"], false);
    }

    #[tokio::test]
    async fn a_bad_signature_is_refused() {
        let bob = start_node("bob", None).await;
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut env = envelope(&alice, &mail_address("alice", &alice.verifying_key()), &bob.state.mail_addr, &bob.state.mail_keys.public_bytes, "x");
        env.timestamp += 1;
        let (status, _) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&env))).await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn a_message_id_cannot_become_a_path() {
        let bob = start_node("bob", None).await;
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let mut env = envelope(&alice, &mail_address("alice", &alice.verifying_key()), &bob.state.mail_addr, &bob.state.mail_keys.public_bytes, "x");
        for id in ["../../../../tmp/hidramail-escaped", "/tmp/hidramail-escaped", "plain"] {
            env.id = id.into();
            env.signature = crypto::sign_data(&alice, &env.signing_data());
            let (status, _) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&env))).await;
            assert_eq!(status, 400, "id {id:?} was accepted");
        }
        assert!(!std::path::Path::new("/tmp/hidramail-escaped.json").exists());
        assert_eq!(bob.state.store.inbox_usage().0, 0);
    }

    #[tokio::test]
    async fn a_repeated_delivery_does_not_overwrite_the_first() {
        let bob = start_node("bob", None).await;
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let env = envelope(&alice, &mail_address("alice", &alice.verifying_key()), &bob.state.mail_addr, &bob.state.mail_keys.public_bytes, "first");
        let (status, _) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&env))).await;
        assert_eq!(status, 200);
        let mut second = envelope(&alice, &mail_address("alice", &alice.verifying_key()), &bob.state.mail_addr, &bob.state.mail_keys.public_bytes, "second");
        second.id = env.id.clone();
        second.signature = crypto::sign_data(&alice, &second.signing_data());
        let (status, _) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&second))).await;
        assert_eq!(status, 409);
        let (_, mail) = http(bob.addr, &get(&format!("/api/mail/{}", env.id), &local_host(bob.addr))).await;
        assert_eq!(mail["subject"], "first");
    }

    #[tokio::test]
    async fn mail_for_another_mailbox_is_not_filed_here() {
        let bob = start_node("bob", None).await;
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let carol = SigningKey::generate(&mut rand::rngs::OsRng);
        let env = envelope(&alice, &mail_address("alice", &alice.verifying_key()), &mail_address("carol", &carol.verifying_key()), &bob.state.mail_keys.public_bytes, "x");
        let (status, _) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&env))).await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn only_the_two_delivery_endpoints_answer_off_machine() {
        let bob = start_node("bob", None).await;
        let (status, _) = http(bob.addr, &get("/api/pubkey", "remote.example")).await;
        assert_eq!(status, 200);
        for path in ["/api/inbox", "/api/sent", "/api/identity", "/"] {
            let (status, _) = http(bob.addr, &get(path, "remote.example")).await;
            assert_eq!(status, 403, "{path} answered a remote Host");
        }
        let (status, _) = http(bob.addr, &post("/api/send", "remote.example", "{}")).await;
        assert_eq!(status, 403);
        // And a cross-origin page on this machine is still refused.
        let raw = format!(
            "GET /api/inbox HTTP/1.1\r\nHost: {}\r\nOrigin: https://evil.example\r\nConnection: close\r\n\r\n",
            local_host(bob.addr)
        );
        let (status, _) = http(bob.addr, &raw).await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn oversized_requests_are_refused_before_they_are_read() {
        let bob = start_node("bob", None).await;
        let raw = format!(
            "POST /api/deliver HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            server::MAX_REQUEST_BYTES * 4
        );
        let (status, _) = http(bob.addr, &raw).await;
        assert_eq!(status, 413);

        // Within the request bound but over the envelope bound.
        let big = format!("{{\"pad\":\"{}\"}}", "a".repeat(server::MAX_DELIVERY_BYTES + 100));
        let (status, _) = http(bob.addr, &post("/api/deliver", "x", &big)).await;
        assert_eq!(status, 413);
    }

    #[tokio::test]
    async fn deliveries_are_rate_limited() {
        let bob = start_node("bob", None).await;
        let alice = SigningKey::generate(&mut rand::rngs::OsRng);
        let from = mail_address("alice", &alice.verifying_key());
        let mut last = 0;
        for _ in 0..=server::DELIVERIES_PER_MINUTE {
            let env = envelope(&alice, &from, &bob.state.mail_addr, &bob.state.mail_keys.public_bytes, "x");
            let (status, _) = http(bob.addr, &post("/api/deliver", "remote.example", &deliver_body(&env))).await;
            last = status;
        }
        assert_eq!(last, 429);
        assert_eq!(bob.state.store.inbox_usage().0, server::DELIVERIES_PER_MINUTE);
    }

    #[tokio::test]
    async fn the_inbox_has_a_ceiling() {
        let dir = TempDir::new();
        let store = MailStore::new(dir.path()).unwrap();
        assert!(!store.inbox_full(1));
        assert!(store.inbox_full(super::storage::MAX_INBOX_BYTES + 1));
    }

    // ───────── sending ─────────

    #[tokio::test]
    async fn sending_to_a_loopback_test_address_delivers_a_verified_message() {
        let alice = start_node("alice", None).await;
        let bob = start_node("bob", None).await;
        let req = serde_json::json!({
            "to": bob.state.mail_addr,
            "subject": "lunch",
            "body": "noon?",
            "direct_addr": bob.addr.to_string(),
        });
        let (status, body) = http(alice.addr, &post("/api/send", &local_host(alice.addr), &req.to_string())).await;
        assert_eq!(status, 200, "{body}");

        let (_, inbox) = http(bob.addr, &get("/api/inbox", &local_host(bob.addr))).await;
        assert_eq!(inbox.as_array().unwrap().len(), 1);
        let id = inbox[0]["id"].as_str().unwrap();
        let (_, mail) = http(bob.addr, &get(&format!("/api/mail/{id}"), &local_host(bob.addr))).await;
        assert_eq!(mail["from_addr"], alice.state.mail_addr);
        assert_eq!(mail["body"], "noon?");
        assert_eq!(mail["verified"], true);

        // The sender keeps a copy it can read.
        let (_, sent) = http(alice.addr, &get("/api/sent", &local_host(alice.addr))).await;
        assert_eq!(sent.as_array().unwrap().len(), 1);
        assert_eq!(sent[0]["subject"], "lunch");
    }

    #[tokio::test]
    async fn a_direct_address_off_loopback_is_refused() {
        let alice = start_node("alice", None).await;
        let bob_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let req = serde_json::json!({
            "to": mail_address("bob", &bob_key.verifying_key()),
            "subject": "s",
            "body": "b",
            "direct_addr": "203.0.113.9:8080",
        });
        let (status, body) = http(alice.addr, &post("/api/send", &local_host(alice.addr), &req.to_string())).await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("loopback"));
    }

    #[tokio::test]
    async fn without_a_proxy_a_hidra_recipient_cannot_be_reached_directly() {
        let alice = start_node("alice", None).await;
        let bob_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let req = serde_json::json!({
            "to": mail_address("bob", &bob_key.verifying_key()),
            "subject": "s",
            "body": "b",
        });
        let (status, body) = http(alice.addr, &post("/api/send", &local_host(alice.addr), &req.to_string())).await;
        assert_eq!(status, 400);
        assert!(body["error"].as_str().unwrap().contains("SOCKS5"));
    }

    /// A SOCKS5 proxy that accepts one CONNECT to `expect_host` and pipes it
    /// to `target`, standing in for the node's proxy and its circuit.
    async fn fake_socks5(expect_host: String, target: SocketAddr) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut client, _) = listener.accept().await.unwrap();
                let expect = expect_host.clone();
                tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    client.read_exact(&mut greet).await.unwrap();
                    assert_eq!(greet, [5, 1, 0]);
                    client.write_all(&[5, 0]).await.unwrap();
                    let mut head = [0u8; 5];
                    client.read_exact(&mut head).await.unwrap();
                    assert_eq!(&head[..4], &[5, 1, 0, 3], "not a CONNECT by name");
                    let mut name = vec![0u8; head[4] as usize];
                    client.read_exact(&mut name).await.unwrap();
                    let mut port = [0u8; 2];
                    client.read_exact(&mut port).await.unwrap();
                    assert_eq!(String::from_utf8(name).unwrap(), expect);
                    assert_eq!(u16::from_be_bytes(port), 80);
                    let mut upstream = TcpStream::connect(target).await.unwrap();
                    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn a_hidra_recipient_is_reached_through_the_socks5_proxy() {
        let bob = start_node("bob", None).await;
        let bob_host = address_host(&bob.state.mail_addr).unwrap().to_string();
        let proxy = fake_socks5(bob_host, bob.addr).await;
        let alice = start_node("alice", Some(proxy)).await;

        let req = serde_json::json!({
            "to": bob.state.mail_addr,
            "subject": "over the circuit",
            "body": "no addresses exchanged",
        });
        let (status, body) = http(alice.addr, &post("/api/send", &local_host(alice.addr), &req.to_string())).await;
        assert_eq!(status, 200, "{body}");

        let (_, inbox) = http(bob.addr, &get("/api/inbox", &local_host(bob.addr))).await;
        assert_eq!(inbox.as_array().unwrap().len(), 1);
        assert_eq!(inbox[0]["subject"], "over the circuit");
        let id = inbox[0]["id"].as_str().unwrap();
        let (_, mail) = http(bob.addr, &get(&format!("/api/mail/{id}"), &local_host(bob.addr))).await;
        assert_eq!(mail["verified"], true);
    }

    #[tokio::test]
    async fn a_recipient_that_is_not_a_hidra_address_is_refused_before_any_connection() {
        let alice = start_node("alice", None).await;
        let req = serde_json::json!({ "to": "bob@example.com", "subject": "s", "body": "b" });
        let (status, _) = http(alice.addr, &post("/api/send", &local_host(alice.addr), &req.to_string())).await;
        assert_eq!(status, 400);
    }

    #[tokio::test]
    async fn an_overlong_message_is_refused_before_sending() {
        let alice = start_node("alice", None).await;
        let bob_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let req = serde_json::json!({
            "to": mail_address("bob", &bob_key.verifying_key()),
            "subject": "s",
            "body": "b".repeat(server::MAX_CONTENT_BYTES + 1),
            "direct_addr": "127.0.0.1:1",
        });
        let (status, _) = http(alice.addr, &post("/api/send", &local_host(alice.addr), &req.to_string())).await;
        assert_eq!(status, 413);
    }
}
