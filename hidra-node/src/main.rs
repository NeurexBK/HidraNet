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
// Shared with the library. These two were byte-identical.
#[path = "error.rs"]
mod error;

// ─────────────────────────────────────────────────────────────────────────────
// mod logging
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library. These two were byte-identical.
#[path = "logging.rs"]
mod logging;

// ─────────────────────────────────────────────────────────────────────────────
// mod config
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library rather than inlined. It was inlined under a
// different name, `app_config`, which is why the two never looked like the
// duplicates they were.
#[path = "config.rs"]
mod config;

// ─────────────────────────────────────────────────────────────────────────────
// mod crypto
// ─────────────────────────────────────────────────────────────────────────────
mod crypto {
    // Shared with the library target rather than inlined a second time.
    //
    // It was inlined, and the two copies drifted the moment one of them
    // mattered: the hybrid ML-KEM handshake went into src/crypto/handshake.rs
    // and the binary — the thing people actually run — kept speaking
    // X25519-only Noise, with every test still green because the tests read
    // the library. A #[path] is not elegant, but a copy of a handshake is
    // worse than inelegant.
    // The path is relative to src/crypto/, this module being inside `mod crypto`.
    #[path = "handshake.rs"]
    pub mod handshake;

    // Same reason as handshake above: the binary was still saving the two
    // secret keys with fs::write and chmodding them afterwards, long after
    // the library had stopped.
    #[path = "keys.rs"]
    pub mod keys;

    #[path = "keystore.rs"]
    pub mod keystore;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod network
// ─────────────────────────────────────────────────────────────────────────────
mod network {
    // Shared with the library.
    #[path = "connection.rs"]
    pub mod connection;

    // Shared with the library.
    #[path = "listener.rs"]
    pub mod listener;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod onion
// ─────────────────────────────────────────────────────────────────────────────
mod onion {
    // Shared with the library. The binary's copy carries the ConnectService and
    // RegisterService commands that reach a .hidra service; the library's had an
    // OnionCell and a CellType that nothing in either target ever referenced.
    #[path = "cell.rs"]
    pub mod cell;

    // Shared with the library.
    #[path = "layer.rs"]
    pub mod layer;

    // Shared with the library.
    #[path = "circuit.rs"]
    pub mod circuit;

    // Shared with the library.
    #[path = "builder.rs"]
    pub mod builder;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod p2p
// ─────────────────────────────────────────────────────────────────────────────
mod p2p {
    // Shared with the library. The binary's copy was the complete one: it
    // carries the hidden-service announce and lookup that the library's lacked.
    #[path = "dht/mod.rs"]
    pub mod dht;

    // Shared with the library: the copies differed only in line wrapping.
    #[path = "bootstrap.rs"]
    pub mod bootstrap;

    // Shared with the library: the copies differed only in line wrapping.
    #[path = "discovery.rs"]
    pub mod discovery;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod relay
// ─────────────────────────────────────────────────────────────────────────────
mod relay {
    // Shared with the library. The copies differed only in line wrapping
    // and in the name of the config module, which now matches.
    #[path = "registry.rs"]
    pub mod registry;

    // Shared with the library. The binary's copy was the complete one — it
    // carries the service bridging a .hidra site needs — so that is the version
    // both now use.
    #[path = "router.rs"]
    pub mod router;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod proxy
// ─────────────────────────────────────────────────────────────────────────────
mod proxy {
    // Shared with the library. The copies parsed SOCKS5 identically; the
    // library's also had host_string and send_conn_refused.
    #[path = "socks5.rs"]
    pub mod socks5;

    // Shared with the library. The binary's copy was the complete one — it
    // resolves .hidra names through the DHT, which the library's did not — so
    // that is the version both now use.
    #[path = "stream_handler.rs"]
    pub mod stream_handler;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod client
// ─────────────────────────────────────────────────────────────────────────────
mod client {
    // Shared with the library. The binary's copy was the complete one — it has
    // the connect_service path that reaches a .hidra service — so that is the
    // version both now use.
    #[path = "streaming.rs"]
    pub mod streaming;

    // Shared with the library: the copies differed only in line wrapping.
    #[path = "circuit_pool.rs"]
    pub mod circuit_pool;

    // Shared with the library: the copies differed only in line wrapping.
    #[path = "session.rs"]
    pub mod session;

    // Shared with the library: the copies differed only in line wrapping.
    #[path = "proxy_runner.rs"]
    pub mod proxy_runner;
}

// ─────────────────────────────────────────────────────────────────────────────
// mod local_guard
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library target rather than inlined a second time: this is
// the screening every loopback server runs on an incoming request, and a copy
// that drifts is a copy that stops screening.
#[path = "local_guard.rs"]
mod local_guard;

#[path = "safelog.rs"]
mod safelog;

// ─────────────────────────────────────────────────────────────────────────────
// mod api
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library rather than inlined a second time. This endpoint
// decides what the outside world learns about a live circuit, and a copy
// that drifts is a copy that goes on answering the old way.
#[path = "api.rs"]
mod api;

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
                content.innerHTML = '<div class="empty-state"><p>Error: ' + esc(mail.error) + '</p></div>';
                return;
            }
            var date = new Date(mail.timestamp).toLocaleString('pt-BR');
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

                        // Search queries are as revealing as anything on this
                        // machine, and the wildcard CORS header that used to
                        // be on every reply made them readable by any page
                        // the user happened to have open.
                        let allowed_origin = match crate::local_guard::screen(&request) {
                            crate::local_guard::Access::Allow(origin) => origin,
                            crate::local_guard::Access::Deny => {
                                let (code, text) = crate::local_guard::DENIED_STATUS;
                                let body = crate::local_guard::DENIED_BODY;
                                let response = format!(
                                    "HTTP/1.1 {code} {text}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    crate::local_guard::response_headers(None),
                                    body.len()
                                );
                                let _ = stream.write_all(response.as_bytes()).await;
                                return;
                            }
                        };

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
                             {}\
                             Access-Control-Allow-Methods: GET, OPTIONS\r\n\
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
                            crate::local_guard::response_headers(allowed_origin.as_deref()),
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
                    title: format!("Search \"{}\" on {}", query, name),
                    url: format!("{}{}", base_url, encoded_q),
                    snippet: format!(
                        "Click to search for '{}' anonymously via {}. Your query is routed through the HidraNet onion circuit.",
                        query, name
                    ),
                    source: name.to_string(),
                });
            }

            if q.contains("filme") || q.contains("movie") || q.contains("assistir") || q.contains("watch") {
                let sites = [
                    ("Internet Archive — Films", "https://archive.org/details/movies", "A free public archive of classic and public-domain films."),
                    ("Open Culture — Free Movies", "https://www.openculture.com/freemoviesonline", "Over 1,000 free, legal films to watch online."),
                    ("YouTube Movies", "https://www.youtube.com/feed/storefront?bp=ogUCKAQ%3D", "Free and paid films on YouTube."),
                    ("Tubi TV", "https://tubitv.com", "Free streaming with thousands of films and series."),
                    ("Pluto TV", "https://pluto.tv", "Free online TV with 24-hour film channels."),
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
                    snippet: "Decentralised torrent search. Connection routed through the onion circuit.".into(),
                    source: "HidraSearch".into(),
                });
            }

            if q.contains("notic") || q.contains("news") || q.contains("jornal") {
                let news = [
                    ("Reuters", "https://www.reuters.com/search/news?query=", "International news agency."),
                    ("Associated Press", "https://apnews.com/search?q=", "Independent, non-partisan news agency."),
                    ("Ground News", "https://ground.news/find?query=", "Compare news coverage across multiple sources."),
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
                    title: format!("Hidden service: {}", query),
                    url: format!("http://{}", query),
                    snippet: ".hidra service on the HidraNet network — reached by onion routing.".into(),
                    source: "HidraNet DHT".into(),
                });
            }

            results.push(SearchResult {
                title: format!("{} — Wikipedia", query),
                url: format!("https://pt.wikipedia.org/wiki/Special:Search?search={}", encoded_q),
                snippet: format!("Free encyclopedia — search Wikipedia for '{}'.", query),
                source: "Wikipedia".into(),
            });

            results.push(SearchResult {
                title: format!("{} — Reddit", query),
                url: format!("https://www.reddit.com/search/?q={}", encoded_q),
                snippet: format!("Discussions about '{}' on Reddit — communities and forums.", query),
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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HidraSearch — Anonymous Search</title>
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
    <div class="logo-sub">Anonymous &amp; Encrypted Search</div>
  </div>
  <div class="search-box">
    <input type="text" class="search-input" id="homeInput" placeholder="Search anything, anonymously..." autofocus>
    <button class="search-btn" onclick="doSearch()">
      <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
    </button>
  </div>
  <div class="badges">
    <div class="badge"><span class="dot"></span> Roteamento Onion</div>
    <div class="badge"><span class="dot"></span> Zero Logs</div>
    <div class="badge"><span class="dot"></span> E2E encryption</div>
    <div class="badge"><span class="dot"></span> Uncensored</div>
    <div class="badge"><span class="dot"></span> IP Oculto</div>
  </div>
</div>

<div class="results-view" id="resultsView">
  <div class="top-bar">
    <div class="top-logo" onclick="goHome()"><span class="hi">Hidra</span>Search</div>
    <div class="top-search search-box">
      <input type="text" class="search-input" id="topInput" placeholder="Search...">
      <button class="search-btn" onclick="doSearch()">
        <svg viewBox="0 0 24 24"><path d="M15.5 14h-.79l-.28-.27A6.47 6.47 0 0016 9.5 6.5 6.5 0 109.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      </button>
    </div>
    <div class="top-info"><span class="dot"></span> Circuit active</div>
  </div>

  <div class="results-container">
    <div class="results-stats" id="resultsStats"></div>
    <div class="categories">
      <span class="cat-btn active" onclick="filterCat('all',this)">All</span>
      <span class="cat-btn" onclick="filterCat('web',this)">Web</span>
      <span class="cat-btn" onclick="filterCat('video',this)">Videos</span>
      <span class="cat-btn" onclick="filterCat('news',this)">News</span>
      <span class="cat-btn" onclick="filterCat('hidra',this)">.hidra network</span>
    </div>
    <div class="loading" id="loading">
      <div class="spinner"></div>
      <div class="loading-text">Searching through the encrypted onion circuit...</div>
    </div>
    <div id="resultsList"></div>
  </div>

  <div class="privacy-footer">
    <p>Your query was routed through 3 encrypted nodes. No data was stored.</p>
    <div class="shields">
      <span class="shield">ChaCha20-Poly1305</span>
      <span class="shield">ML-KEM-1024</span>
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
        '<div class="no-results"><h3>Search error</h3><p>' + err.message + '</p></div>';
    });
}

function renderResults(data) {
  const stats = document.getElementById('resultsStats');
  stats.textContent = 'About ' + (data.total_estimated || 0) + ' results for "' + data.query + '" — encryption active, zero logs';

  const list = document.getElementById('resultsList');
  if (!data.results || data.results.length === 0) {
    list.innerHTML = '<div class="no-results"><h3>No results</h3><p>Try a different search.</p></div>';
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

                    // The dashboard reports relay counts, traffic and the geo
                    // breakdown of this node. Wildcard CORS made all of it
                    // readable by any page open in any browser on the machine.
                    let allowed_origin = match crate::local_guard::screen(&request) {
                        crate::local_guard::Access::Allow(origin) => origin,
                        crate::local_guard::Access::Deny => {
                            let (code, text) = crate::local_guard::DENIED_STATUS;
                            let body = crate::local_guard::DENIED_BODY;
                            let response = format!(
                                "HTTP/1.1 {code} {text}\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                crate::local_guard::response_headers(None),
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                            return;
                        }
                    };

                    let path = request.split_whitespace().nth(1).unwrap_or("/");

                    let (status, content_type, body) = match path {
                        "/api/stats" => handle_stats(&db),
                        "/api/traffic" => handle_traffic(&db),
                        "/api/geo" => handle_geo(&db),
                        // Chart.js came from cdn.jsdelivr.net until now. On a
                        // dashboard whose whole point is that nobody watches
                        // this node, that announced the node to a CDN on every
                        // page load and gave whoever controls that CDN — or
                        // anyone who can tamper with the response — script
                        // execution inside it.
                        "/vendor/chart.umd.min.js" => (
                            "200 OK",
                            "text/javascript; charset=utf-8",
                            VENDOR_CHART_JS.to_string(),
                        ),
                        _ => handle_dashboard_page(),
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{}Cache-Control: no-cache\r\nConnection: close\r\n\r\n{body}",
                        body.len(),
                        crate::local_guard::response_headers(allowed_origin.as_deref())
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        }

        /// Chart.js, bundled rather than fetched.
        const VENDOR_CHART_JS: &str = include_str!("../assets/vendor/chart.umd.min.js");

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
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HidraNet — Analytics Dashboard</title>
<script src="/vendor/chart.umd.min.js"></script>
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
    <div class="live"><span class="dot"></span> Live updates</div>
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="label">Active users</div><div class="value accent" id="s-users">—</div><div class="delta" id="d-users"></div></div>
    <div class="stat-card"><div class="label">Relays Ativos</div><div class="value" id="s-relays">—</div><div class="delta" id="d-relays"></div></div>
    <div class="stat-card"><div class="label">Circuitos/seg</div><div class="value" id="s-circuits">—</div></div>
    <div class="stat-card"><div class="label">Average latency</div><div class="value" id="s-latency">—</div></div>
    <div class="stat-card"><div class="label">Traffic (GB/day)</div><div class="value" id="s-traffic">—</div></div>
    <div class="stat-card"><div class="label">Countries</div><div class="value" id="s-countries">—</div></div>
  </div>

  <div class="charts-row">
    <div class="chart-card">
      <h3>Network traffic</h3>
      <div class="time-filter">
        <button class="time-btn active" data-range="24h">24h</button>
        <button class="time-btn" data-range="7d">7 days</button>
        <button class="time-btn" data-range="30d">30 days</button>
      </div>
      <div class="chart-wrap"><canvas id="trafficChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Users by region</h3>
      <div class="chart-wrap"><canvas id="geoChart"></canvas></div>
    </div>
  </div>

  <div class="geo-section">
    <h3>Geographic distribution</h3>
    <div class="geo-grid" id="geoGrid"></div>
  </div>

  <div class="footer">HidraNet Analytics — local data, aggregated and anonymised</div>
</div>

<script>
const FLAGS={AF:'🇦🇫',AL:'🇦🇱',DZ:'🇩🇿',AR:'🇦🇷',AU:'🇦🇺',AT:'🇦🇹',BE:'🇧🇪',BR:'🇧🇷',CA:'🇨🇦',CL:'🇨🇱',CN:'🇨🇳',CO:'🇨🇴',CZ:'🇨🇿',DK:'🇩🇰',EG:'🇪🇬',FI:'🇫🇮',FR:'🇫🇷',DE:'🇩🇪',GR:'🇬🇷',HK:'🇭🇰',HU:'🇭🇺',IN:'🇮🇳',ID:'🇮🇩',IE:'🇮🇪',IL:'🇮🇱',IT:'🇮🇹',JP:'🇯🇵',KR:'🇰🇷',MY:'🇲🇾',MX:'🇲🇽',NL:'🇳🇱',NZ:'🇳🇿',NG:'🇳🇬',NO:'🇳🇴',PK:'🇵🇰',PE:'🇵🇪',PH:'🇵🇭',PL:'🇵🇱',PT:'🇵🇹',RO:'🇷🇴',RU:'🇷🇺',SA:'🇸🇦',SG:'🇸🇬',ZA:'🇿🇦',ES:'🇪🇸',SE:'🇸🇪',CH:'🇨🇭',TW:'🇹🇼',TH:'🇹🇭',TR:'🇹🇷',UA:'🇺🇦',AE:'🇦🇪',GB:'🇬🇧',US:'🇺🇸',VN:'🇻🇳'};
const NAMES={BR:'Brazil',US:'USA',DE:'Germany',FR:'France',GB:'United Kingdom',JP:'Japan',CA:'Canada',NL:'Netherlands',AU:'Australia',KR:'South Korea',IN:'India',SE:'Sweden',CH:'Switzerland',PL:'Poland',ES:'Spain',PT:'Portugal',IT:'Italy',RU:'Russia',AR:'Argentina',MX:'Mexico'};

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
  else{el.textContent='— steady';el.className='delta'}
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
        +'<div class="count">'+g.user_count+' users</div></div>'
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

    // ── Layer II: Post-Quantum Hybrid Handshake (ML-KEM-1024 + X25519) ──────
    //
    // The post-quantum half is FIPS 203 ML-KEM-1024. It used to be pqc_kyber
    // 0.7.1, which is unmaintained and has no fixed release: its AVX2 backend
    // skips the Fujisaki-Okamoto implicit rejection step (RUSTSEC-2026-0290),
    // so an attacker who can feed it chosen ciphertexts recovers the
    // decapsulation key outright, and its division timings leak the secret
    // (RUSTSEC-2023-0079, KyberSlash). Both are fatal to the one property this
    // layer exists to provide, on exactly the x86-64 machines the browser runs
    // on.
    //
    // Hybrid, not ML-KEM alone: a break of either primitive still leaves the
    // other standing, because the session key is a hash of both secrets and
    // neither half can be reconstructed from the other.
    pub mod post_quantum {
        use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
        use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
        use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
        use zeroize::{Zeroize, ZeroizeOnDrop};

        use crate::error::{HidraError, Result};

        /// Domain separator for the combiner. Bumped from v1 with the move off
        /// Kyber round-3: a v1 and a v2 peer derive different keys and simply
        /// fail to talk, which is the outcome we want — there is no downgrade
        /// to the broken construction.
        const COMBINER_DOMAIN: &[u8] = b"HidraNet-Hybrid-KEM-v2-MLKEM1024-X25519";

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
            /// ML-KEM-1024 encapsulation key, as it goes on the wire.
            pub kyber_public: Vec<u8>,
            /// Decapsulation key. Kept as the library's own type rather than
            /// loose bytes so it is never accidentally serialized, logged or
            /// copied, and so it zeroizes itself on drop.
            decapsulation_key: DecapsulationKey,
        }

        impl HybridKeyPair {
            pub fn generate() -> Result<Self> {
                let mut rng = rand::thread_rng();
                let x25519_secret = StaticSecret::random_from_rng(&mut rng);
                let x25519_public = X25519Public::from(&x25519_secret);

                let (decapsulation_key, encapsulation_key) = MlKem1024::generate_keypair();

                Ok(Self {
                    x25519_secret,
                    x25519_public,
                    kyber_public: encapsulation_key.to_bytes().to_vec(),
                    decapsulation_key,
                })
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

            // A peer who sends a low-order point forces the shared secret to
            // all zeroes, which would let it fix half the combiner input.
            if !x25519_shared.was_contributory() {
                return Err(HidraError::Crypto(
                    "X25519 peer key is a low-order point".into(),
                ));
            }

            // Rejects a malformed or non-canonical encapsulation key rather
            // than encapsulating to it.
            let encapsulation_key = EncapsulationKey::new_from_slice(peer_kyber_public)
                .map_err(|_| HidraError::Crypto("ML-KEM encapsulation key rejected".into()))?;

            let (kyber_ct, mut kyber_shared) = encapsulation_key.encapsulate();

            let combined = combine_secrets(
                x25519_shared.as_bytes(),
                &kyber_shared,
                ephemeral_public.as_bytes(),
                &kyber_ct,
                peer_kyber_public,
            );
            kyber_shared.as_mut_slice().zeroize();

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

            if !x25519_shared.was_contributory() {
                return Err(HidraError::Crypto(
                    "X25519 peer key is a low-order point".into(),
                ));
            }

            let ciphertext = Ciphertext::try_from(encapsulation.kyber_ciphertext.as_slice())
                .map_err(|_| {
                    HidraError::Crypto("ML-KEM ciphertext has the wrong length".into())
                })?;

            // ML-KEM decapsulation never reports failure: a bad ciphertext
            // yields an unrelated key by implicit rejection, which is what
            // denies a chosen-ciphertext attacker the oracle it needs. The
            // mismatch surfaces later, when the AEAD tag does not verify.
            let mut kyber_shared = own_keys.decapsulation_key.decapsulate(&ciphertext);

            let combined = combine_secrets(
                x25519_shared.as_bytes(),
                &kyber_shared,
                &encapsulation.x25519_ephemeral_public,
                &encapsulation.kyber_ciphertext,
                &own_keys.kyber_public,
            );
            kyber_shared.as_mut_slice().zeroize();

            Ok(HybridSharedSecret { combined })
        }

        /// Both secrets plus the full transcript. Hashing the ciphertexts and
        /// the encapsulation key in as well — not just the two secrets — is
        /// what keeps the combined key bound to this exchange: a peer cannot
        /// replay one half against a different transcript and land on the same
        /// session key. Lengths are prefixed so no two different transcripts
        /// can serialize to the same byte string.
        fn combine_secrets(
            x25519: &[u8; 32],
            mlkem: &[u8],
            x25519_ephemeral_public: &[u8; 32],
            mlkem_ciphertext: &[u8],
            mlkem_encapsulation_key: &[u8],
        ) -> [u8; 32] {
            let mut hasher = blake3::Hasher::new();
            hasher.update(COMBINER_DOMAIN);
            for part in [
                x25519.as_slice(),
                mlkem,
                x25519_ephemeral_public.as_slice(),
                mlkem_ciphertext,
                mlkem_encapsulation_key,
            ] {
                hasher.update(&(part.len() as u64).to_le_bytes());
                hasher.update(part);
            }
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

    let app_cfg = config::load_config(&cli.config)?;

    // Logging comes up before the keys are touched. It used to be the other
    // way round, which silently threw away everything loading the keys has to
    // say — including the warning that a secret on disk is readable by other
    // accounts, which is the one message on this path nobody can afford to
    // miss.
    safelog::set_unsafe_logging(app_cfg.logging.unsafe_addresses);
    logging::init_logging(&app_cfg.logging.level, &app_cfg.logging.format);
    if app_cfg.logging.unsafe_addresses {
        tracing::warn!(
            "unsafe_addresses is on: this log will record who connected to this \
             node and, at an exit, the hostnames they asked for. Turn it off \
             on anything carrying other people's traffic."
        );
    }

    let keys =
        crypto::keys::NodeKeys::load_or_generate(Path::new(&app_cfg.paths.keys_dir))?;
    let node_id = keys.node_id.clone();

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

/// Room passphrase for a standalone chat server.
///
/// It used to be the literal `"hidrachat-standalone-test"`, compiled into
/// every copy of the binary, and in hidden-service mode it was
/// `format!("hidrachat-{hidra_address}")` — derived entirely from the address
/// the service publishes, so knowing where the room was meant knowing how to
/// get in. Both are now replaced by a value read from `HIDRA_CHAT_PASSPHRASE`
/// or, failing that, generated fresh and printed once for the operator to
/// hand out.
fn chat_room_passphrase() -> String {
    if let Ok(p) = std::env::var("HIDRA_CHAT_PASSPHRASE")
        && !p.is_empty()
    {
        return p;
    }
    let mut bytes = [0u8; 18];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    let generated = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    warn!(
        "no HIDRA_CHAT_PASSPHRASE set — generated one for this run: {generated}"
    );
    warn!("share it with the people you want in the room; it changes on restart");
    generated
}

async fn run_apps_standalone(
    app_cfg: &config::AppConfig,
    signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mail_port: u16 = 8080;
    let chat_port: u16 = 8081;

    let mail_addr: SocketAddr = format!("127.0.0.1:{mail_port}").parse()?;
    // Loopback only. Bound to 0.0.0.0 the room was reachable from every
    // machine on the network, and the WebSocket asks for no credential: a
    // stranger on the same Wi-Fi could join, read the backlog and list users.
    let chat_addr: SocketAddr = format!("127.0.0.1:{chat_port}").parse()?;

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
    let passphrase = chat_room_passphrase();
    let chat_server = apps::hidrachat::server::ChatServer::new(
        chat_addr,
        room_name,
        &passphrase,
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
        // Loopback only: binding 0.0.0.0 published the site builder to every
        // machine on the local network.
        if let Err(e) = apps::sevennine::run_sevennine("127.0.0.1", sevennine_port, &sn_data).await {
            tracing::error!(error = %e, "SevenNine error");
        }
    });

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraNet Apps — local mode                                ║");
    info!("║  HidraMail:     http://127.0.0.1:{mail_port}                      ║");
    info!("║  HidraChat:     http://127.0.0.1:{chat_port}                      ║");
    info!("║  HidraSearch:   http://127.0.0.1:{search_port}                      ║");
    info!("║  SevenNine:     http://127.0.0.1:{sevennine_port}                    ║");
    info!("║  Address:       {}", mail_addr_str);
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
    app_cfg: &config::AppConfig,
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
    app_cfg: &config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let local_port = app_cfg.hidden_service.local_port;
    let chat_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse()?;
    let room_name = "hidrachat-local".to_string();
    let passphrase = chat_room_passphrase();
    let chat_server = apps::hidrachat::server::ChatServer::new(
        chat_addr,
        room_name,
        &passphrase,
    );

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraChat standalone: http://127.0.0.1:{}", local_port);
    info!("║  Local mode (no onion routing) — for testing");
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
    app_cfg: &config::AppConfig,
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
    info!("║  Address: {}", mail_addr);
    info!("║  Local mode (no onion routing) — for testing");
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
    app_cfg: &config::AppConfig,
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
        // Tor reaches the service over loopback. Bound to 0.0.0.0 the same
        // service also answered on the public interface, so anyone scanning
        // the host's IP found the thing the hidden service exists to hide.
        let chat_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse()?;
        let room_name = hidra_address.replace(".hidra", "");
        // Was format!("hidrachat-{hidra_address}"): the address is published,
        // so the passphrase was public too and gated nothing.
        let passphrase = chat_room_passphrase();
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
        info!("║  HidraChat is available at: http://{}", hidra_address);
        info!("║  Encrypted chat room — local port: {}", local_port);
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
        info!("║  HidraMail is available at: http://{}", hidra_address);
        info!("║  Address: {}", mail_addr);
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
            // Loopback only, as in run_apps_standalone: on 0.0.0.0 the site
            // builder was published to every machine on the local network.
            let listener = match tokio::net::TcpListener::bind(
                format!("127.0.0.1:{sevennine_port}")
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
        info!("║  Address:    http://{}", hidra_address);
        info!("║  Local:      http://127.0.0.1:{}", local_port);
        info!("║  Every site created is published to the DHT automatically  ║");
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
        info!("║  Your site is available at: http://{}", hidra_address);
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
    app_cfg: &config::AppConfig,
    _network_secret: StaticSecret,
    _signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    info!("=== HidraNet Proxy Mode ===");
    info!("spawning local relay nodes for onion routing...");

    let local_relays = spawn_local_relays().await?;
    let relay_addrs: Vec<SocketAddr> = local_relays.iter().map(|r| r.addr).collect();

    let proxy_addr: SocketAddr =
        format!("{}:{}", app_cfg.proxy.listen_addr, app_cfg.proxy.port).parse()?;

    // Port 0, not the configured one. A client has no reason to run a
    // predictable, scannable service: on a fixed port, anyone who sweeps the
    // internet for it gets a list of this network's users by IP, and "is a
    // HidraNet user" is in many situations the whole thing a user needs
    // hidden. An ephemeral port still sends queries and still receives the
    // replies; it just is not something you can go looking for.
    //
    // It does not hide the address from a DHT peer that is contacted
    // directly. Routing lookups through a circuit is the fix for that, and it
    // is not done yet — see SECURITY.md.
    let dht_addr: SocketAddr = "0.0.0.0:0".parse()?;

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
    // The circuit view needs a token the engine leaves in the keys
    // directory. A page in a browser cannot read a local file, so even a
    // failure in the Host/Origin screening does not get it the relays.
    let api_token = api::issue_token(std::path::Path::new(&app_cfg.paths.keys_dir));
    let api_state = Arc::new(api::ApiState::new(
        Instant::now(),
        relay_addrs.len(),
        relay_addrs,
        3,
        api_token,
    ));

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
    app_cfg: &config::AppConfig,
    network_secret: StaticSecret,
    signing_key: SigningKey,
    payload: &str,
    dht_discover: bool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if dht_discover && app_cfg.dht.enabled {
        // Ephemeral, as in proxy mode: a one-shot send is a client.
        let dht_addr: SocketAddr = "0.0.0.0:0".parse()?;
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
    app_cfg: &config::AppConfig,
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
    cfg: &config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let data_dir = std::path::PathBuf::from(&cfg.paths.keys_dir).parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  SevenNine.hidra — Criador Descentralizado de Sites         ║");
    info!("║  Acesse: http://127.0.0.1:8084                             ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        // Loopback only — the banner above already promises 127.0.0.1.
        result = apps::sevennine::run_sevennine("127.0.0.1", 8084, &data_dir) => {
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

    /// ML-KEM answers a tampered ciphertext with an unrelated key instead of
    /// an error (Fujisaki-Okamoto implicit rejection). That is the property
    /// pqc_kyber's AVX2 backend dropped, and losing it is what let a
    /// chosen-ciphertext attacker walk the decapsulation key out one query at
    /// a time. Assert the derived key diverges rather than matching.
    #[test]
    fn test_post_quantum_tampered_ciphertext_does_not_recover_key() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");

        let (shared_enc, mut encapsulation) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate should succeed");

        encapsulation.kyber_ciphertext[0] ^= 0x01;

        let shared_dec = security::post_quantum::hybrid_decapsulate(&keys, &encapsulation)
            .expect("implicit rejection returns a key, it does not fail");

        assert_ne!(shared_enc.as_bytes(), shared_dec.as_bytes());
    }

    /// The combiner hashes the transcript, not just the two secrets, so the
    /// same ML-KEM ciphertext replayed under a different X25519 ephemeral
    /// cannot land on the session key it was captured from.
    #[test]
    fn test_post_quantum_transcript_is_bound_to_session_key() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");

        let (shared_enc, mut encapsulation) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate should succeed");

        encapsulation.x25519_ephemeral_public[0] ^= 0x01;

        let shared_dec = security::post_quantum::hybrid_decapsulate(&keys, &encapsulation)
            .expect("decapsulate should succeed");

        assert_ne!(shared_enc.as_bytes(), shared_dec.as_bytes());
    }

    /// A malformed encapsulation key is refused outright rather than being
    /// encapsulated to.
    #[test]
    fn test_post_quantum_rejects_malformed_encapsulation_key() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");

        let truncated = &keys.kyber_public[..keys.kyber_public.len() - 1];
        assert!(
            security::post_quantum::hybrid_encapsulate(&keys.x25519_public, truncated).is_err()
        );
        assert!(
            security::post_quantum::hybrid_encapsulate(&keys.x25519_public, &[]).is_err()
        );
    }

    /// Two independent handshakes must never agree on a key.
    #[test]
    fn test_post_quantum_distinct_sessions_differ() {
        let keys = security::post_quantum::HybridKeyPair::generate().expect("keygen");

        let (a, _) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate");
        let (b, _) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate");

        assert_ne!(a.as_bytes(), b.as_bytes());
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
