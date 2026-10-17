pub mod crypto {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use rand::RngCore;
    use crate::error::{HidraError, Result};

    /// Room key from the room passphrase.
    ///
    /// This was a bare `blake3::hash` of the passphrase: one pass of a fast
    /// hash, no salt, no stretching. A room password people can actually type
    /// falls to a dictionary run at billions of guesses a second, and because
    /// there was no salt the same password gave the same key in every room, so
    /// one cracked password unlocked all of them at once.
    ///
    /// Argon2id at the vault's parameters costs 64 MiB and three passes per
    /// guess, which is unnoticeable once per room and ruinous a few billion
    /// times over. The salt is the room name, so two rooms never share a key
    /// even on the same passphrase, and both sides still derive it offline
    /// with nothing to exchange.
    pub fn derive_room_key(passphrase: &str, room: &str) -> Result<[u8; 32]> {
        // Argon2id requires at least 8 salt bytes; short room names are
        // domain-separated and padded through BLAKE3 rather than rejected.
        let salt = blake3::hash(
            &[b"hidrachat-room-salt-v1:".as_slice(), room.as_bytes()].concat(),
        );

        let params = argon2::Params::new(65536, 3, 4, Some(32))
            .map_err(|e| HidraError::Crypto(format!("Argon2 params error: {e}")))?;
        let argon2 =
            argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        let mut key = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut key)
            .map_err(|e| HidraError::Crypto(format!("Argon2id room KDF failed: {e}")))?;
        Ok(key)
    }

    #[allow(dead_code)]
    pub fn encrypt_message(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| HidraError::Crypto(format!("chat encrypt: {e}")))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    #[allow(dead_code)]
    pub fn decrypt_message(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 13 {
            return Err(HidraError::Crypto("chat message too short".into()));
        }
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&data[..12]);
        cipher
            .decrypt(nonce, &data[12..])
            .map_err(|e| HidraError::Crypto(format!("chat decrypt: {e}")))
    }
}

pub mod server {
    use std::collections::{HashMap, VecDeque};
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::Engine as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use subtle::ConstantTimeEq;
    use tokio::sync::{Mutex, Semaphore, broadcast};
    use tracing::{debug, info, warn};

    use crate::safelog::sensitive;

    use super::frontend;

    const MAX_CLIENTS: usize = 512;
    /// Concurrent Argon2id verifications. Each costs 64 MiB while it runs.
    const MAX_CONCURRENT_KDF: usize = 4;
    /// The largest WebSocket frame a client may send. A chat message is at
    /// most 2000 characters, which encrypted and base64-encoded is a few
    /// kilobytes. A frame header announcing more than this is a client
    /// filling the server's memory: before this bound the receive buffer
    /// grew to whatever the header promised, up to the full 64-bit length.
    pub(super) const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
    /// What the page lets a user type, applied again here so a hand-written
    /// client cannot push a nickname or a room name of any length into every
    /// other member's user list and into the room map.
    const MAX_NICK_CHARS: usize = 24;
    const MAX_ROOM_CHARS: usize = 64;
    const BROADCAST_CAP: usize = 1024;
    const HISTORY_LIMIT: usize = 200;
    const PING_SECS: u64 = 30;

    const COLORS: &[&str] = &[
        "#00d4aa", "#ff6b6b", "#4ecdc4", "#45b7d1", "#f9ca24",
        "#fd79a8", "#6c5ce7", "#e17055", "#0984e3", "#00b894",
        "#e84393", "#00cec9", "#fdcb6e", "#a29bfe", "#74b9ff",
        "#55efc4", "#fab1a0", "#81ecec", "#ffeaa7", "#ff9ff3",
    ];

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn nick_color(nick: &str) -> &'static str {
        let h = blake3::hash(nick.as_bytes());
        COLORS[h.as_bytes()[0] as usize % COLORS.len()]
    }

    fn gen_id() -> String {
        let mut b = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
        format!("m_{:016x}", u64::from_le_bytes(b))
    }

    struct RoomState {
        tx: broadcast::Sender<String>,
        users: Mutex<HashMap<u64, UserInfo>>,
        history: Mutex<VecDeque<String>>,
    }

    struct UserInfo {
        nick: String,
        color: String,
    }

    pub struct ChatServer {
        addr: SocketAddr,
        rooms: Arc<Mutex<HashMap<String, Arc<RoomState>>>>,
        next_id: Arc<AtomicU64>,
        #[allow(dead_code)]
        default_room: String,
        /// Argon2id(passphrase, default_room). The passphrase used to be taken
        /// and thrown away — the parameter was literally named `_passphrase` —
        /// so the join handler admitted anyone who opened a socket, handed
        /// them the backlog and the user list, and never asked for anything.
        room_key: [u8; 32],
        /// Every join attempt has to run the same Argon2id to be checked, and
        /// that costs 64 MiB. Without a bound, a few hundred concurrent joins
        /// would exhaust memory; with it they queue instead.
        kdf_slots: Arc<Semaphore>,
    }

    impl ChatServer {
        pub fn new(addr: SocketAddr, default_room: String, passphrase: &str) -> Self {
            let room_key = super::crypto::derive_room_key(passphrase, &default_room)
                .expect("Argon2id parameters are constant and valid");
            Self {
                addr,
                rooms: Arc::new(Mutex::new(HashMap::new())),
                next_id: Arc::new(AtomicU64::new(1)),
                default_room,
                room_key,
                kdf_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_KDF)),
            }
        }

        pub async fn run(self) -> crate::error::Result<()> {
            let listener = TcpListener::bind(self.addr).await?;
            info!(addr = %self.addr, "HidraChat server listening");

            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "accept error");
                        continue;
                    }
                };
                let rooms = Arc::clone(&self.rooms);
                let next_id = Arc::clone(&self.next_id);
                let room_key = self.room_key;
                let default_room = self.default_room.clone();
                let kdf_slots = Arc::clone(&self.kdf_slots);
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(
                        stream, peer, rooms, next_id, room_key, default_room, kdf_slots,
                    )
                    .await
                    {
                        debug!(peer = %sensitive(&peer), error = %e, "connection ended");
                    }
                });
            }
        }
    }

    // ── Connection handler ──────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    async fn handle_conn(
        mut stream: TcpStream,
        peer: SocketAddr,
        rooms: Arc<Mutex<HashMap<String, Arc<RoomState>>>>,
        next_id: Arc<AtomicU64>,
        room_key: [u8; 32],
        default_room: String,
        kdf_slots: Arc<Semaphore>,
    ) -> crate::error::Result<()> {
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        let req = String::from_utf8_lossy(&buf[..n]);

        if req.to_lowercase().contains("upgrade: websocket") {
            let key = extract_hdr(&req, "sec-websocket-key")
                .ok_or_else(|| crate::error::HidraError::Protocol("missing ws key".into()))?;
            let accept = ws_accept(key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            stream.write_all(resp.as_bytes()).await?;
            let hdr_end = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
            let leftover = if hdr_end < n {
                buf[hdr_end..n].to_vec()
            } else {
                vec![]
            };
            ws_session(
                stream, peer, rooms, next_id, leftover, room_key, default_room, kdf_slots,
            )
            .await
        } else {
            serve_http(&mut stream, &req).await
        }
    }

    fn extract_hdr<'a>(req: &'a str, name: &str) -> Option<&'a str> {
        let lower = name.to_lowercase();
        for line in req.lines() {
            if line.to_lowercase().starts_with(&lower) {
                return line.split_once(':').map(|(_, v)| v.trim());
            }
        }
        None
    }

    fn ws_accept(key: &str) -> String {
        use sha1::{Digest, Sha1};
        let input = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let hash = Sha1::digest(input.as_bytes());
        base64::engine::general_purpose::STANDARD.encode(hash)
    }

    // ── WebSocket frame I/O (handles TCP fragmentation properly) ────────

    pub(super) enum Frame {
        /// The header or the body has not fully arrived yet.
        Incomplete,
        /// The header promises more than MAX_FRAME_PAYLOAD: the connection
        /// is closed rather than buffered.
        TooLarge,
        Ready {
            opcode: u8,
            payload: Vec<u8>,
            consumed: usize,
        },
    }

    pub(super) fn try_parse_frame(buf: &[u8]) -> Frame {
        if buf.len() < 2 {
            return Frame::Incomplete;
        }
        let opcode = buf[0] & 0x0F;
        let masked = (buf[1] & 0x80) != 0;
        let mut payload_len = (buf[1] & 0x7F) as u64;
        let mut offset = 2usize;

        if payload_len == 126 {
            if buf.len() < 4 {
                return Frame::Incomplete;
            }
            payload_len = u16::from_be_bytes([buf[2], buf[3]]) as u64;
            offset = 4;
        } else if payload_len == 127 {
            if buf.len() < 10 {
                return Frame::Incomplete;
            }
            payload_len = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]);
            offset = 10;
        }

        if payload_len > MAX_FRAME_PAYLOAD as u64 {
            return Frame::TooLarge;
        }
        let payload_len = payload_len as usize;

        let mask_len = if masked { 4 } else { 0 };
        let total = offset + mask_len + payload_len;
        if buf.len() < total {
            return Frame::Incomplete;
        }

        let mut payload = buf[offset + mask_len..total].to_vec();
        if masked {
            let mask = &buf[offset..offset + 4];
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Frame::Ready {
            opcode,
            payload,
            consumed: total,
        }
    }

    /// A string from a client, cut to what the page itself allows, with a
    /// fallback for an empty one.
    pub(super) fn bounded(s: &str, max_chars: usize, fallback: &str) -> String {
        let s: String = s.trim().chars().take(max_chars).collect();
        if s.is_empty() { fallback.to_string() } else { s }
    }

    fn encode_frame(opcode: u8, data: &[u8]) -> Vec<u8> {
        let len = data.len();
        let mut f = Vec::with_capacity(10 + len);
        f.push(0x80 | opcode);
        if len < 126 {
            f.push(len as u8);
        } else if len <= 65535 {
            f.push(126);
            f.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            f.push(127);
            f.extend_from_slice(&(len as u64).to_be_bytes());
        }
        f.extend_from_slice(data);
        f
    }

    // ── WebSocket session with room management ──────────────────────────

    #[allow(clippy::too_many_arguments)]
    async fn ws_session(
        mut stream: TcpStream,
        peer: SocketAddr,
        rooms: Arc<Mutex<HashMap<String, Arc<RoomState>>>>,
        next_id: Arc<AtomicU64>,
        leftover: Vec<u8>,
        room_key: [u8; 32],
        default_room: String,
        kdf_slots: Arc<Semaphore>,
    ) -> crate::error::Result<()> {
        let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
        let mut ws_buf = leftover;
        let mut tmp = [0u8; 16384];

        // ── Wait for join message ──
        let (nick, room_id, color) = 'join: loop {
            loop {
                let (op, payload) = match try_parse_frame(&ws_buf) {
                    Frame::Incomplete => break,
                    Frame::TooLarge => {
                        debug!(peer = %sensitive(&peer), "frame over the size limit before join");
                        return Ok(());
                    }
                    Frame::Ready { opcode, payload, consumed } => {
                        ws_buf.drain(..consumed);
                        (opcode, payload)
                    }
                };
                if op == 1 {
                    if let Ok(text) = std::str::from_utf8(&payload) {
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(text) {
                            if msg.get("type").and_then(|t| t.as_str()) == Some("join") {
                                let n = bounded(
                                    msg.get("nick").and_then(|v| v.as_str()).unwrap_or(""),
                                    MAX_NICK_CHARS,
                                    "Anon",
                                );
                                let r = bounded(
                                    msg.get("room").and_then(|v| v.as_str()).unwrap_or(""),
                                    MAX_ROOM_CHARS,
                                    "lobby",
                                );
                                let pass = msg
                                    .get("pass")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");

                                // The room key is derived from the server's
                                // own room name, so a client cannot pick a
                                // room it does not have the passphrase for.
                                let offered = {
                                    let _slot = kdf_slots.acquire().await.map_err(|_| {
                                        crate::error::HidraError::Protocol(
                                            "KDF semaphore closed".into(),
                                        )
                                    })?;
                                    let pass = pass.to_string();
                                    let room = default_room.clone();
                                    tokio::task::spawn_blocking(move || {
                                        super::crypto::derive_room_key(&pass, &room)
                                    })
                                    .await
                                    .map_err(|e| {
                                        crate::error::HidraError::Protocol(format!(
                                            "KDF task failed: {e}"
                                        ))
                                    })??
                                };

                                if offered.ct_ne(&room_key).into() {
                                    warn!(peer = %sensitive(&peer), "join rejected: wrong room passphrase");
                                    let body = serde_json::json!({
                                        "type": "error",
                                        "msg": "Wrong room passphrase."
                                    })
                                    .to_string();
                                    let _ = stream.write_all(&encode_frame(1, body.as_bytes())).await;
                                    let _ = stream.write_all(&encode_frame(8, &[])).await;
                                    return Ok(());
                                }

                                let c = nick_color(&n).to_string();
                                break 'join (n, r, c);
                            }
                        }
                    }
                }
            }
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Ok(());
            }
            ws_buf.extend_from_slice(&tmp[..n]);
        };

        info!(
            peer = %sensitive(&peer),
            nick = %sensitive(&nick),
            room = %sensitive(&room_id),
            "user joined"
        );

        // ── Get or create room ──
        let room = {
            let mut rm = rooms.lock().await;
            let r = rm.entry(room_id.clone()).or_insert_with(|| {
                let (tx, _) = broadcast::channel(BROADCAST_CAP);
                Arc::new(RoomState {
                    tx,
                    users: Mutex::new(HashMap::new()),
                    history: Mutex::new(VecDeque::new()),
                })
            });
            Arc::clone(r)
        };

        // ── Register user ──
        {
            let mut users = room.users.lock().await;
            if users.len() >= MAX_CLIENTS {
                let err_msg = serde_json::json!({"type":"error","msg":"Room is full"});
                let _ = stream
                    .write_all(&encode_frame(1, err_msg.to_string().as_bytes()))
                    .await;
                return Ok(());
            }
            users.insert(
                conn_id,
                UserInfo {
                    nick: nick.clone(),
                    color: color.clone(),
                },
            );
        }

        // ── Send welcome (history + user list) ──
        {
            let users = room.users.lock().await;
            let history = room.history.lock().await;
            let user_list: Vec<serde_json::Value> = users
                .values()
                .map(|u| serde_json::json!({"nick": u.nick, "color": u.color}))
                .collect();
            let hist: Vec<serde_json::Value> = history
                .iter()
                .filter_map(|s| serde_json::from_str(s).ok())
                .collect();
            let welcome = serde_json::json!({
                "type": "welcome",
                "room": room_id,
                "users": user_list,
                "history": hist,
                "count": users.len()
            });
            let frame = encode_frame(1, welcome.to_string().as_bytes());
            if stream.write_all(&frame).await.is_err() {
                room.users.lock().await.remove(&conn_id);
                return Ok(());
            }
        }

        // ── Broadcast join ──
        {
            let count = room.users.lock().await.len();
            let msg = serde_json::json!({
                "type": "joined",
                "nick": nick,
                "color": color,
                "count": count,
                "time": now_ms()
            });
            let _ = room.tx.send(msg.to_string());
        }

        // ── Main event loop ──
        let mut rx = room.tx.subscribe();
        let mut ping_timer = tokio::time::interval(Duration::from_secs(PING_SECS));
        ping_timer.tick().await;

        'main: loop {
            enum Act {
                Data(usize),
                Bcast(String),
                Ping,
                Done,
            }

            let act = tokio::select! {
                r = stream.read(&mut tmp) => match r {
                    Ok(0) | Err(_) => Act::Done,
                    Ok(n) => Act::Data(n),
                },
                msg = rx.recv() => match msg {
                    Ok(d) => Act::Bcast(d),
                    Err(broadcast::error::RecvError::Lagged(_)) => Act::Bcast(String::new()),
                    Err(_) => Act::Done,
                },
                _ = ping_timer.tick() => Act::Ping,
            };

            match act {
                Act::Data(n) => {
                    ws_buf.extend_from_slice(&tmp[..n]);
                    loop {
                        let (opcode, payload) = match try_parse_frame(&ws_buf) {
                            Frame::Incomplete => break,
                            Frame::TooLarge => {
                                debug!(peer = %sensitive(&peer), "frame over the size limit");
                                break 'main;
                            }
                            Frame::Ready { opcode, payload, consumed } => {
                                ws_buf.drain(..consumed);
                                (opcode, payload)
                            }
                        };
                        match opcode {
                            1 | 2 => on_message(&payload, &room, &nick, &color).await,
                            8 => break 'main,
                            9 => {
                                let _ = stream
                                    .write_all(&encode_frame(0x0A, &payload))
                                    .await;
                            }
                            _ => {}
                        }
                    }
                }
                Act::Bcast(data) => {
                    if !data.is_empty() {
                        let frame = encode_frame(1, data.as_bytes());
                        if stream.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                }
                Act::Ping => {
                    if stream.write_all(&encode_frame(9, b"")).await.is_err() {
                        break;
                    }
                }
                Act::Done => break,
            }
        }

        // ── Cleanup ──
        {
            let mut users = room.users.lock().await;
            users.remove(&conn_id);
            let count = users.len();
            let msg = serde_json::json!({
                "type": "left",
                "nick": nick,
                "count": count,
                "time": now_ms()
            });
            let _ = room.tx.send(msg.to_string());
        }
        info!(peer = %sensitive(&peer), nick = %sensitive(&nick), "user left");
        Ok(())
    }

    async fn on_message(payload: &[u8], room: &Arc<RoomState>, nick: &str, color: &str) {
        let Ok(text) = std::str::from_utf8(payload) else {
            return;
        };
        let Ok(mut msg) = serde_json::from_str::<serde_json::Value>(text) else {
            return;
        };
        let msg_type = msg
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        match msg_type.as_str() {
            "msg" => {
                if let Some(obj) = msg.as_object_mut() {
                    obj.insert("nick".into(), serde_json::json!(nick));
                    obj.insert("color".into(), serde_json::json!(color));
                    obj.insert("time".into(), serde_json::json!(now_ms()));
                    obj.insert("id".into(), serde_json::json!(gen_id()));
                }
                let s = msg.to_string();
                {
                    let mut hist = room.history.lock().await;
                    hist.push_back(s.clone());
                    while hist.len() > HISTORY_LIMIT {
                        hist.pop_front();
                    }
                }
                let _ = room.tx.send(s);
            }
            "typing" => {
                let state = msg.get("state").and_then(|s| s.as_bool()).unwrap_or(false);
                let t = serde_json::json!({"type":"typing","nick":nick,"state":state});
                let _ = room.tx.send(t.to_string());
            }
            _ => {}
        }
    }

    // Discover the host's primary LAN IP without sending any packets:
    // a UDP socket "connected" to a routable address makes the OS pick the
    // outbound interface; we then read its local address. No traffic leaves.
    fn local_ip() -> Option<String> {
        let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        sock.connect("8.8.8.8:80").ok()?;
        let addr = sock.local_addr().ok()?;
        let ip = addr.ip();
        if ip.is_loopback() || ip.is_unspecified() {
            None
        } else {
            Some(ip.to_string())
        }
    }

    async fn serve_http(stream: &mut TcpStream, req: &str) -> crate::error::Result<()> {
        // /api/whoami below answers with this machine's LAN address, and it
        // did so under `Access-Control-Allow-Origin: *` — handing any site the
        // user visited the local IP that browsers go out of their way to hide
        // (it is the same value a WebRTC leak exposes).
        if matches!(
            crate::local_guard::screen(req),
            crate::local_guard::Access::Deny
        ) {
            let (code, text) = crate::local_guard::DENIED_STATUS;
            let body = crate::local_guard::DENIED_BODY;
            let header = format!(
                "HTTP/1.1 {code} {text}\r\n\
                 Content-Type: application/json\r\n\
                 {}\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                crate::local_guard::response_headers(None),
                body.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(body.as_bytes()).await?;
            return Ok(());
        }

        let path = req
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/");

        if path == "/" || path == "/index.html" {
            let body = frontend::PAGE_HTML;
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-cache\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(body.as_bytes()).await?;
        } else if let Some((body, cache)) = match path {
            // Served from here rather than from a CDN. This page holds the
            // end-to-end encryption: a script fetched from someone else's
            // host at load time can read every message before it is encrypted,
            // and there is no integrity check on a <script src> pointing at a
            // moving "@5" tag. The browser's own copy of this app was moved
            // off the CDN already; this one was still loading it.
            "/vendor/mqtt.min.js" => Some((frontend::VENDOR_MQTT, "public, max-age=86400")),
            // The two files the page shares with the browser, at fixed
            // paths: nothing here concatenates the request path.
            "/hidra-store.js" => Some((frontend::STORE_JS, "no-cache")),
            "/hidrachat-crypto.js" => Some((frontend::ROOM_JS, "no-cache")),
            _ => None,
        } {
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/javascript; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: {cache}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(body.as_bytes()).await?;
        } else if path == "/api/whoami" {
            let ip = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
            let body = format!("{{\"lan_ip\":\"{ip}\",\"port\":8081}}");
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(body.as_bytes()).await?;
        } else {
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found")
                .await?;
        }
        Ok(())
    }
}

pub mod frontend {
    /// mqtt.js, bundled instead of fetched. Same file the browser ships in
    /// hidra-browser/src/ui/vendor/, kept byte-identical on purpose.
    pub const VENDOR_MQTT: &str = include_str!("../../assets/vendor/mqtt.min.js");

    /// The chat page. The same file the browser ships in
    /// hidra-browser/src/ui/hidrachat.html, kept byte-identical: it used to be
    /// a second copy written out here, which had already drifted from the
    /// browser's (no vault, an older password generator, a join that the
    /// server rejected). The browser's test chat-crypto.js checks the copies.
    pub const PAGE_HTML: &str = include_str!("../../assets/hidrachat.html");
    /// The vault shim the page loads. Outside the browser there is no vault
    /// bridge, and the shim falls back to localStorage as the page always did.
    pub const STORE_JS: &str = include_str!("../../assets/hidra-store.js");
    /// The room cryptography, shared with the browser the same way.
    pub const ROOM_JS: &str = include_str!("../../assets/hidrachat-crypto.js");
}

#[cfg(test)]
mod tests {
    use super::crypto::derive_room_key;

    /// The old derivation was an unsalted blake3 of the passphrase, so the
    /// same password produced the same key everywhere. Salting by room name
    /// is what stops one cracked password from opening every room.
    #[test]
    fn room_key_differs_per_room() {
        let a = derive_room_key("same passphrase", "room-a").unwrap();
        let b = derive_room_key("same passphrase", "room-b").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn room_key_differs_per_passphrase() {
        let a = derive_room_key("passphrase one", "room").unwrap();
        let b = derive_room_key("passphrase two", "room").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn room_key_is_deterministic() {
        let a = derive_room_key("passphrase", "room").unwrap();
        let b = derive_room_key("passphrase", "room").unwrap();
        assert_eq!(a, b);
    }

    /// A room name shorter than Argon2id's eight-byte salt minimum has to
    /// still derive, not error out.
    #[test]
    fn short_room_names_still_derive() {
        assert!(derive_room_key("passphrase", "a").is_ok());
        assert!(derive_room_key("passphrase", "").is_ok());
    }

    /// An empty passphrase is a real key, not a bypass: it must not collide
    /// with any other passphrase.
    #[test]
    fn empty_passphrase_is_not_a_wildcard() {
        let empty = derive_room_key("", "room").unwrap();
        let real = derive_room_key("actual passphrase", "room").unwrap();
        assert_ne!(empty, real);
    }

    use super::server::{Frame, MAX_FRAME_PAYLOAD, bounded, try_parse_frame};

    /// A client frame, masked as browsers send them.
    fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x80 | opcode];
        let len = payload.len();
        if len < 126 {
            f.push(0x80 | len as u8);
        } else if len <= 65535 {
            f.push(0x80 | 126);
            f.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            f.push(0x80 | 127);
            f.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask = [0x12, 0x34, 0x56, 0x78];
        f.extend_from_slice(&mask);
        f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        f
    }

    #[test]
    fn a_masked_frame_is_unmasked_and_consumed() {
        let mut bytes = masked_frame(1, b"{\"type\":\"typing\"}");
        let total = bytes.len();
        bytes.extend_from_slice(b"next");
        match try_parse_frame(&bytes) {
            Frame::Ready { opcode, payload, consumed } => {
                assert_eq!(opcode, 1);
                assert_eq!(payload, b"{\"type\":\"typing\"}");
                assert_eq!(consumed, total);
            }
            _ => panic!("a complete frame must parse"),
        }
    }

    #[test]
    fn a_partial_frame_waits_for_the_rest() {
        let bytes = masked_frame(1, &[7u8; 300]);
        for cut in [0, 1, 3, 4, 7, 8, 100, bytes.len() - 1] {
            assert!(
                matches!(try_parse_frame(&bytes[..cut]), Frame::Incomplete),
                "cut at {cut}"
            );
        }
        assert!(matches!(try_parse_frame(&bytes), Frame::Ready { .. }));
    }

    #[test]
    fn the_largest_allowed_frame_still_parses() {
        let bytes = masked_frame(2, &[1u8; MAX_FRAME_PAYLOAD]);
        assert!(matches!(try_parse_frame(&bytes), Frame::Ready { .. }));
    }

    /// The header alone decides: a client announcing a huge frame is cut
    /// off before any of it is buffered, and the 64-bit length that would
    /// have asked for an impossible allocation is refused the same way.
    #[test]
    fn a_frame_over_the_limit_is_refused_from_its_header() {
        let mut too_big = vec![0x81, 0x80 | 127];
        too_big.extend_from_slice(&((MAX_FRAME_PAYLOAD + 1) as u64).to_be_bytes());
        assert!(matches!(try_parse_frame(&too_big), Frame::TooLarge));

        let mut huge = vec![0x81, 0x80 | 127];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(try_parse_frame(&huge), Frame::TooLarge));
    }

    #[test]
    fn nicknames_and_rooms_are_cut_to_what_the_page_allows() {
        assert_eq!(bounded("  alice ", 24, "Anon"), "alice");
        assert_eq!(bounded("", 24, "Anon"), "Anon");
        assert_eq!(bounded("   ", 24, "Anon"), "Anon");
        let long = "x".repeat(500);
        assert_eq!(bounded(&long, 24, "Anon").chars().count(), 24);
        // Multi-byte characters are counted as characters, not cut in half.
        assert_eq!(bounded(&"é".repeat(30), 24, "Anon"), "é".repeat(24));
    }

    /// The engine serves the browser's own page, and the copy under assets/
    /// has to be the browser's bytes. The browser's test checks the same
    /// thing from its side; this one runs wherever the sibling checkout is
    /// present, and passes quietly where it is not.
    #[test]
    fn the_served_page_is_the_browsers_page() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for (ours, theirs) in [
            (super::frontend::PAGE_HTML, "hidra-browser/src/ui/hidrachat.html"),
            (super::frontend::STORE_JS, "hidra-browser/src/ui/hidra-store.js"),
            (super::frontend::ROOM_JS, "hidra-browser/src/ui/hidrachat-crypto.js"),
            (super::frontend::VENDOR_MQTT, "hidra-browser/src/ui/vendor/mqtt.min.js"),
        ] {
            if let Ok(browser) = std::fs::read_to_string(root.join(theirs)) {
                assert!(ours == browser, "{theirs} differs from the copy under assets/");
            }
        }
    }
}
