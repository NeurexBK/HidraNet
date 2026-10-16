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
        /// The ML-DSA-87 half of the sender's identity. Empty from a sender
        /// that predates hybrid signatures; the envelope then verifies on
        /// Ed25519 alone and is marked as such.
        #[serde(default)]
        pub sender_pq_verifying_key: Vec<u8>,
        /// The ML-DSA-87 signature over the same bytes as `signature`.
        #[serde(default)]
        pub pq_signature: Vec<u8>,
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
    use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
    use ml_kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit};
    use rand::RngCore;
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::Zeroize;

    use crate::crypto::hybrid_sig::HybridSigningKey;
    use crate::crypto::keys::{load_or_create_pq_identity_seed, write_private_file};
    use crate::error::{HidraError, Result};
    use std::path::Path;

    /// Marks a body sealed the hybrid way. A v1 body starts with a random
    /// nonce, so the chance of a collision is 2^-24 per message, and the
    /// consequence of one is a failed decryption rather than a wrong one.
    const V2_MARKER: &[u8; 3] = b"HM2";
    const KEM_CT_LEN: usize = 1568;
    const NONCE_LEN: usize = 12;

    /// The mailbox's keys: the X25519 key every sender has used so far, the
    /// ML-KEM-1024 key that makes a sealed message safe against a recording
    /// opened by a quantum computer, and the ML-DSA seed that pairs with the
    /// node's Ed25519 identity for hybrid signatures.
    ///
    /// Mail is the one place in HidraNet where "record now, decrypt later"
    /// is not theoretical: a mailbox *is* a recording. The transport between
    /// nodes was already hybrid; the body it carried was X25519 alone, so a
    /// copy of a mailbox taken today would have opened the day the curve
    /// fell. From here on a body is sealed under both, and the key is only
    /// recoverable by breaking both.
    pub struct MailKeys {
        secret_bytes: [u8; 32],
        pub public_bytes: [u8; 32],
        kem_dk: DecapsulationKey,
        /// The ML-KEM-1024 encapsulation key senders use, 1568 bytes.
        pub kem_public_bytes: Vec<u8>,
        pq_seed: [u8; 32],
    }

    impl MailKeys {
        pub fn load_or_generate(keys_dir: &Path) -> Result<Self> {
            let key_path = keys_dir.join("mail_x25519.key");
            let secret_bytes: [u8; 32] = if key_path.exists() {
                let mut bytes = std::fs::read(&key_path).map_err(HidraError::Io)?;
                if bytes.len() != 32 {
                    bytes.zeroize();
                    return Err(HidraError::Crypto(
                        "invalid mail key file".into(),
                    ));
                }
                let mut secret_bytes = [0u8; 32];
                secret_bytes.copy_from_slice(&bytes);
                bytes.zeroize();
                crate::crypto::keys::warn_if_group_or_world_readable(&key_path);
                secret_bytes
            } else {
                let mut secret_bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut secret_bytes);
                // Owner-only from the moment it exists. It used to be
                // written with fs::write, which left the mailbox's private
                // key readable by every account on the machine.
                write_private_file(&key_path, &secret_bytes)?;
                secret_bytes
            };
            let secret = StaticSecret::from(secret_bytes);
            let public = PublicKey::from(&secret);

            // The ML-KEM key is kept as its 64-byte seed, which regenerates
            // it. A mailbox from before this gets one on first load; its
            // X25519 key and address stay exactly what they were.
            let kem_path = keys_dir.join("mail_mlkem.seed");
            let kem_seed: [u8; 64] = if kem_path.exists() {
                let mut bytes = std::fs::read(&kem_path).map_err(HidraError::Io)?;
                if bytes.len() != 64 {
                    bytes.zeroize();
                    return Err(HidraError::Crypto(
                        "invalid mail ML-KEM seed file".into(),
                    ));
                }
                let mut seed = [0u8; 64];
                seed.copy_from_slice(&bytes);
                bytes.zeroize();
                crate::crypto::keys::warn_if_group_or_world_readable(&kem_path);
                seed
            } else {
                let mut seed = [0u8; 64];
                rand::thread_rng().fill_bytes(&mut seed);
                write_private_file(&kem_path, &seed)?;
                tracing::info!("generated the mailbox's ML-KEM-1024 key");
                seed
            };
            let kem_dk = DecapsulationKey::from_seed(ml_kem::Seed::from(kem_seed));
            let kem_public_bytes = kem_dk.encapsulation_key().to_bytes().to_vec();

            let pq_seed = load_or_create_pq_identity_seed(keys_dir)?;

            Ok(Self {
                secret_bytes,
                public_bytes: *public.as_bytes(),
                kem_dk,
                kem_public_bytes,
                pq_seed,
            })
        }

        /// Open a body sealed to this mailbox, whichever way it was sealed.
        pub fn open(&self, eph_pubkey: &[u8], sealed_data: &[u8]) -> Result<Vec<u8>> {
            if sealed_data.starts_with(V2_MARKER) {
                open_message_v2(
                    &self.secret_bytes,
                    &self.kem_dk,
                    &self.kem_public_bytes,
                    eph_pubkey,
                    sealed_data,
                )
            } else {
                open_message(&self.secret_bytes, eph_pubkey, sealed_data)
            }
        }

        /// The node's identity with its post-quantum half, for signing
        /// envelopes.
        pub fn hybrid_signing_key(
            &self,
            identity: &ed25519_dalek::SigningKey,
        ) -> HybridSigningKey {
            HybridSigningKey::from_parts(identity.clone(), &self.pq_seed)
        }
    }

    impl Drop for MailKeys {
        fn drop(&mut self) {
            self.secret_bytes.zeroize();
            self.pq_seed.zeroize();
        }
    }

    /// Seal a body under X25519 *and* ML-KEM-1024.
    ///
    /// The symmetric key is derived from both shared secrets and the whole
    /// transcript (the ephemeral X25519 key, the KEM ciphertext and the
    /// recipient's KEM key), each part length-prefixed, so neither half can
    /// be replayed against a different exchange. The body on the wire is
    /// `"HM2" ‖ kem_ct ‖ nonce ‖ ciphertext`; the X25519 ephemeral travels in
    /// the envelope field it always did, so the envelope schema is unchanged.
    pub fn seal_message_v2(
        recipient_pubkey: &[u8; 32],
        recipient_kem_pubkey: &[u8],
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let recipient = PublicKey::from(*recipient_pubkey);
        let mut eph_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut eph_bytes);
        let eph_secret = StaticSecret::from(eph_bytes);
        eph_bytes.zeroize();
        let eph_public = PublicKey::from(&eph_secret);
        let x_shared = eph_secret.diffie_hellman(&recipient);
        if !x_shared.was_contributory() {
            return Err(HidraError::Crypto(
                "recipient X25519 key is a low-order point".into(),
            ));
        }

        let ek = EncapsulationKey::new_from_slice(recipient_kem_pubkey).map_err(|_| {
            HidraError::Crypto("recipient ML-KEM key rejected".into())
        })?;
        let (kem_ct, mut kem_shared) = ek.encapsulate();

        let mut sym_key = derive_v2_key(
            x_shared.as_bytes(),
            &kem_shared,
            eph_public.as_bytes(),
            &kem_ct,
            recipient_kem_pubkey,
        );
        kem_shared.as_mut_slice().zeroize();

        let cipher = ChaCha20Poly1305::new((&sym_key).into());
        sym_key.zeroize();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HidraError::Crypto(format!("seal: {e}")))?;

        let mut sealed = Vec::with_capacity(3 + KEM_CT_LEN + NONCE_LEN + ct.len());
        sealed.extend_from_slice(V2_MARKER);
        sealed.extend_from_slice(&kem_ct);
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ct);
        Ok((eph_public.as_bytes().to_vec(), sealed))
    }

    pub fn open_message_v2(
        secret: &[u8; 32],
        kem_dk: &DecapsulationKey,
        own_kem_pubkey: &[u8],
        eph_pubkey: &[u8],
        sealed_data: &[u8],
    ) -> Result<Vec<u8>> {
        if eph_pubkey.len() != 32 {
            return Err(HidraError::Crypto("invalid ephemeral pubkey".into()));
        }
        let min = 3 + KEM_CT_LEN + NONCE_LEN + 16;
        if sealed_data.len() < min || !sealed_data.starts_with(V2_MARKER) {
            return Err(HidraError::Crypto("sealed data too short".into()));
        }
        let kem_ct_bytes = &sealed_data[3..3 + KEM_CT_LEN];
        let nonce_bytes = &sealed_data[3 + KEM_CT_LEN..3 + KEM_CT_LEN + NONCE_LEN];
        let body = &sealed_data[3 + KEM_CT_LEN + NONCE_LEN..];

        let mut eph_arr = [0u8; 32];
        eph_arr.copy_from_slice(eph_pubkey);
        let eph_public = PublicKey::from(eph_arr);
        let secret_key = StaticSecret::from(*secret);
        let x_shared = secret_key.diffie_hellman(&eph_public);
        if !x_shared.was_contributory() {
            return Err(HidraError::Crypto(
                "sender X25519 key is a low-order point".into(),
            ));
        }

        let kem_ct = Ciphertext::try_from(kem_ct_bytes)
            .map_err(|_| HidraError::Crypto("ML-KEM ciphertext has the wrong length".into()))?;
        // Implicit rejection: a tampered ciphertext yields an unrelated key,
        // and the AEAD tag below is what refuses it.
        let mut kem_shared = kem_dk.decapsulate(&kem_ct);

        let mut sym_key = derive_v2_key(
            x_shared.as_bytes(),
            &kem_shared,
            eph_pubkey,
            kem_ct_bytes,
            own_kem_pubkey,
        );
        kem_shared.as_mut_slice().zeroize();

        let cipher = ChaCha20Poly1305::new((&sym_key).into());
        sym_key.zeroize();
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), body)
            .map_err(|e| HidraError::Crypto(format!("open: {e}")))
    }

    fn derive_v2_key(
        x25519_shared: &[u8],
        kem_shared: &[u8],
        eph_public: &[u8],
        kem_ct: &[u8],
        recipient_kem_pubkey: &[u8],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("hidramail-seal-v2");
        for part in [x25519_shared, kem_shared, eph_public, kem_ct, recipient_kem_pubkey] {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        *hasher.finalize().as_bytes()
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
        if !shared.was_contributory() {
            return Err(HidraError::Crypto(
                "sender X25519 key is a low-order point".into(),
            ));
        }
        let sym_key =
            blake3::derive_key("hidramail-seal-v1", shared.as_bytes());

        let cipher = ChaCha20Poly1305::new((&sym_key).into());
        let nonce = Nonce::from_slice(&sealed_data[..12]);
        cipher
            .decrypt(nonce, &sealed_data[12..])
            .map_err(|e| HidraError::Crypto(format!("open: {e}")))
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

        pub fn list_inbox(&self, keys: &crypto::MailKeys) -> Vec<MailSummary> {
            self.list_folder(&self.inbox_dir, keys)
        }

        pub fn list_sent(&self, keys: &crypto::MailKeys) -> Vec<MailSummary> {
            self.list_folder(&self.sent_dir, keys)
        }

        fn list_folder(
            &self,
            dir: &Path,
            keys: &crypto::MailKeys,
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
                let subject = decrypt_subject(&env, keys);
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
            keys: &crypto::MailKeys,
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

            let plaintext = keys.open(&env.ephemeral_pubkey, &env.sealed_body)?;
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

    fn decrypt_subject(env: &MailEnvelope, keys: &crypto::MailKeys) -> String {
        match keys.open(&env.ephemeral_pubkey, &env.sealed_body) {
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
                            peer = %sensitive(&peer),
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
        debug!(peer = %sensitive(&peer), bytes = total, "request received");
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

        // Without this, a page on any site the user visited could
        // POST /api/send as a simple request — no preflight, so the
        // browser sends it and only hides the reply — and mail went
        // out in the owner's name. The read endpoints were already
        // unreadable cross-origin (json_ok sends no CORS header at
        // all); the write side was not protected by anything.
        //
        // /api/deliver is how another node hands this one a message,
        // so it is screened separately: it carries no authority of
        // the owner's and has to answer requests from off-machine.
        let from_this_machine =
            matches!(crate::local_guard::screen(raw), crate::local_guard::Access::Allow(_));
        if !from_this_machine && path != "/api/deliver" {
            let r = json_err(403, "request did not come from this machine");
            stream.write_all(r.as_bytes()).await?;
            return Ok(());
        }

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
                    r#"{{"address":"{}","pubkey":"{}","kem_pubkey":"{}","post_quantum":true}}"#,
                    state.mail_addr,
                    hex_encode(&state.mail_keys.public_bytes),
                    hex_encode(&state.mail_keys.kem_public_bytes),
                );
                json_ok(&body)
            }
            ("GET", "/api/pubkey") => {
                // Both keys. A sender that knows only `pubkey` seals the old
                // way; one that reads `kem_pubkey` seals under both.
                let body = format!(
                    r#"{{"pubkey":"{}","kem_pubkey":"{}"}}"#,
                    hex_encode(&state.mail_keys.public_bytes),
                    hex_encode(&state.mail_keys.kem_public_bytes),
                );
                json_ok(&body)
            }
            ("GET", "/api/inbox") => {
                let list = state
                    .store
                    .list_inbox(&state.mail_keys);
                let body = serde_json::to_string(&list)
                    .unwrap_or_else(|_| "[]".into());
                json_ok(&body)
            }
            ("GET", "/api/sent") => {
                let list = state
                    .store
                    .list_sent(&state.mail_keys);
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
                // No Access-Control-Allow-Origin: this mailbox is not
                // for other origins to reach, and the wildcard that
                // used to be here invited them to try.
                "HTTP/1.1 204 No Content\r\n\
                 Access-Control-Allow-Methods: GET,POST,DELETE,OPTIONS\r\n\
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
        match state.store.read_mail(id, &state.mail_keys)
        {
            Ok((env, content)) => {
                let verified = crypto::verify_sig(
                    &env.sender_verifying_key,
                    &env.signing_data(),
                    &env.signature,
                );
                // True only when the sender signed with both halves and both
                // verify; false for a legacy envelope, so the panel can say
                // which kind it is looking at rather than guess.
                let pq_verified = envelope_pq_verified(&env);
                let body = format!(
                    r#"{{"id":"{}","from_addr":"{}","to_addr":"{}","subject":"{}","body":"{}","timestamp":{},"verified":{},"pq_verified":{}}}"#,
                    escape_json(&env.id),
                    escape_json(&env.from_addr),
                    escape_json(&env.to_addr),
                    escape_json(&content.subject),
                    escape_json(&content.body),
                    env.timestamp,
                    verified,
                    pq_verified,
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

        let recipient =
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

        let sealed = match &recipient.kem_pubkey {
            Some(kem) => crypto::seal_message_v2(&recipient.pubkey, kem, &content_json),
            None => {
                // An older mailbox. The body is still encrypted, but under
                // X25519 alone, which a recording and a quantum computer
                // would open one day. Said, not hidden.
                warn!(
                    "recipient mailbox advertises no post-quantum key; \
                     sealing this message with X25519 only"
                );
                crypto::seal_message(&recipient.pubkey, &content_json)
            }
        };
        let (eph_pubkey, sealed_body) = match sealed {
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
            sender_pq_verifying_key: Vec::new(),
            pq_signature: Vec::new(),
        };
        if let Err(e) = sign_envelope(&mut envelope, state) {
            return json_err(500, &format!("sign: {e}"));
        }

        match deliver_to_remote(&target_addr, &envelope).await {
            Ok(()) => {
                let sender_copy = make_sender_copy(
                    &envelope,
                    &content_json,
                    state,
                );
                let _ = state.store.store_sent(&sender_copy);
                info!(
                    to = %sensitive(&req.to),
                    id = %sensitive(&envelope.id),
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
        // A sender that offers the post-quantum half is held to it: a
        // present-but-wrong ML-DSA signature is a forgery attempt or a
        // broken sender, and neither is stored. One that offers none is a
        // sender from before hybrid signatures, accepted as such.
        if !envelope.pq_signature.is_empty() || !envelope.sender_pq_verifying_key.is_empty()
        {
            if !envelope_pq_verified(&envelope) {
                return json_err(403, "invalid post-quantum signature");
            }
        } else {
            debug!("mail arrived with an Ed25519-only signature (legacy sender)");
        }

        match state.store.store_incoming(&envelope) {
            Ok(()) => {
                info!(
                    from = %sensitive(&envelope.from_addr),
                    id = %sensitive(&envelope.id),
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

    /// What a recipient's mailbox advertises: always the X25519 key, and the
    /// ML-KEM key when the mailbox is new enough to have one.
    struct RecipientKeys {
        pubkey: [u8; 32],
        kem_pubkey: Option<Vec<u8>>,
    }

    async fn fetch_recipient_pubkey(
        addr: &str,
    ) -> crate::error::Result<RecipientKeys> {
        let mut stream = TcpStream::connect(addr).await?;
        let req = format!(
            "GET /api/pubkey HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await?;
        // The whole reply, not the first 4 KiB: the ML-KEM key alone is
        // 3136 hex characters. Capped, because the far end is a stranger.
        let mut resp = Vec::new();
        tokio::io::AsyncReadExt::take(&mut stream, 64 * 1024)
            .read_to_end(&mut resp)
            .await?;
        let text = String::from_utf8_lossy(&resp);
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
            #[serde(default)]
            kem_pubkey: Option<String>,
        }
        let parsed: PkResp = serde_json::from_str(body).map_err(
            |e| {
                crate::error::HidraError::Protocol(format!(
                    "parse pubkey response: {e}"
                ))
            },
        )?;

        let kem_pubkey = match parsed.kem_pubkey.as_deref() {
            Some(hex) if !hex.is_empty() => {
                let kem = hex_decode(hex)?;
                if kem.len() != 1568 {
                    return Err(crate::error::HidraError::Crypto(
                        "invalid kem_pubkey length".into(),
                    ));
                }
                Some(kem)
            }
            _ => None,
        };

        let bytes = hex_decode(&parsed.pubkey)?;
        if bytes.len() != 32 {
            return Err(crate::error::HidraError::Crypto(
                "invalid pubkey length".into(),
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(RecipientKeys { pubkey: key, kem_pubkey })
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
        state: &ServerState,
    ) -> MailEnvelope {
        // Our own copy is sealed to our own keys, both of them.
        let (eph, sealed) = match crypto::seal_message_v2(
            &state.mail_keys.public_bytes,
            &state.mail_keys.kem_public_bytes,
            content_json,
        ) {
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
            sender_pq_verifying_key: Vec::new(),
            pq_signature: Vec::new(),
        };
        if sign_envelope(&mut copy, state).is_err() {
            return original.clone();
        }
        copy
    }

    /// Sign with the node identity, both halves: Ed25519 into the field
    /// every reader knows, ML-DSA-87 beside it.
    fn sign_envelope(envelope: &mut MailEnvelope, state: &ServerState) -> crate::error::Result<()> {
        let key = state.mail_keys.hybrid_signing_key(&state.signing_key);
        let sig = key.sign(&envelope.signing_data())?;
        envelope.signature = sig.ed25519;
        envelope.pq_signature = sig.mldsa;
        // The ML-DSA half only; the Ed25519 half is sender_verifying_key.
        envelope.sender_pq_verifying_key = key.verifying_key().to_bytes()[32..].to_vec();
        Ok(())
    }

    /// Both halves present and both verifying.
    pub fn envelope_pq_verified(env: &MailEnvelope) -> bool {
        use crate::crypto::hybrid_sig::{HybridSignature, HybridVerifyingKey};
        if env.pq_signature.is_empty() || env.sender_pq_verifying_key.is_empty() {
            return false;
        }
        let Ok(vk) =
            HybridVerifyingKey::from_parts(&env.sender_verifying_key, &env.sender_pq_verifying_key)
        else {
            return false;
        };
        let sig = HybridSignature {
            ed25519: env.signature.clone(),
            mldsa: env.pq_signature.clone(),
        };
        vk.verify(&env.signing_data(), &sig).is_ok()
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
        '<input type="text" id="composeTo" placeholder="recipient@hash.hidra">' +
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
        '<label>Direct address (local testing):</label>' +
        '<input type="text" id="composeDirectAddr" placeholder="127.0.0.1:8081 (required for now)">' +
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
if (!directAddr) {
    status.textContent = 'Direct address required (SOCKS5 delivery coming).';
    status.style.color = '#ff4757';
    return;
}

status.textContent = 'Sending…';
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
    var vIcon = mail.verified ? '✓ Signature verified' : '✗ Invalid signature';
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
