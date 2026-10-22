pub mod crypto {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use rand::RngCore;
    use zeroize::Zeroize;
    use crate::error::{HidraError, Result};

    /// What a client shows this server to be let into the room.
    ///
    /// The browser turns the room password into everything the room needs
    /// (hidra-browser/src/ui/hidrachat-crypto.js, `deriveRoom`): scrypt at
    /// N=2^16, r=8, p=1 with the salt `hidrachat-room-v2` gives a seed, and
    /// HKDF-SHA256 over that seed gives, under separate labels, the message
    /// key, the relay topic, the room code and this verifier. The server
    /// derives the verifier the same way from its passphrase, once, and
    /// compares.
    ///
    /// The password itself used to be sent and checked with Argon2id here.
    /// Over a plain ws: connection that handed the whole room to anyone on
    /// the path, since the same password is the message key; and every join
    /// attempt cost the server 64 MiB, which a stranger could ask for in a
    /// loop. The verifier opens the door and nothing else, and checking it
    /// costs a comparison.
    pub fn derive_join_verifier(passphrase: &str) -> Result<[u8; 32]> {
        let params = scrypt::Params::new(16, 8, 1, 32)
            .map_err(|e| HidraError::Crypto(format!("scrypt params error: {e}")))?;
        let mut seed = [0u8; 32];
        scrypt::scrypt(passphrase.as_bytes(), b"hidrachat-room-v2", &params, &mut seed)
            .map_err(|e| HidraError::Crypto(format!("scrypt failed: {e}")))?;
        // HKDF with no salt, as Web Crypto does with an empty one: both come
        // down to an HMAC key of zeros.
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &seed);
        let mut out = [0u8; 32];
        hk.expand(b"hidrachat-join-v2", &mut out)
            .map_err(|e| HidraError::Crypto(format!("HKDF expand failed: {e}")))?;
        seed.zeroize();
        Ok(out)
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
    use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, broadcast};
    use tracing::{debug, info, warn};

    use crate::safelog::sensitive;

    use super::frontend;

    const MAX_CLIENTS: usize = 512;
    /// Open connections, joined or not. A client that connects and says
    /// nothing used to hold a task and its buffers for ever; enough of them
    /// ran the process out of file descriptors, which took every other
    /// listener in the process down with the chat.
    const MAX_CONNECTIONS: usize = 1024;
    /// How long a connection may take to finish the handshake and to join.
    const HANDSHAKE_SECS: u64 = 30;
    /// How long a write may wait for the peer to take bytes. A peer that
    /// stops reading used to hold the connection, and its permit, for ever.
    const WRITE_SECS: u64 = 15;
    /// A member that has sent nothing, not even a pong, for this long is
    /// gone: its nickname is freed for the person who reconnects.
    const IDLE_SECS: u64 = PING_SECS * 2 + 10;
    /// The largest WebSocket frame a client may send. A chat message is at
    /// most 2000 characters, which encrypted and base64-encoded is a few
    /// kilobytes. A frame header announcing more than this is a client
    /// filling the server's memory: before this bound the receive buffer
    /// grew to whatever the header promised, up to the full 64-bit length.
    pub(super) const MAX_FRAME_PAYLOAD: usize = 64 * 1024;
    /// The largest chat message kept and relayed. The frame limit above is a
    /// transport bound; this is what a room's history and every member's
    /// socket are asked to carry per message.
    pub(super) const MAX_MESSAGE_BYTES: usize = 8 * 1024;
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
        /// What a client must show to join: see `crypto::derive_join_verifier`.
        /// The passphrase used to be taken and thrown away — the parameter
        /// was literally named `_passphrase` — so the join handler admitted
        /// anyone who opened a socket, handed them the backlog and the user
        /// list, and never asked for anything.
        join_verifier: [u8; 32],
        /// One permit per open connection, joined or not.
        conns: Arc<Semaphore>,
    }

    impl ChatServer {
        pub fn new(addr: SocketAddr, default_room: String, passphrase: &str) -> Self {
            let join_verifier = super::crypto::derive_join_verifier(passphrase)
                .expect("scrypt parameters are constant and valid");
            Self {
                addr,
                rooms: Arc::new(Mutex::new(HashMap::new())),
                next_id: Arc::new(AtomicU64::new(1)),
                default_room,
                join_verifier,
                conns: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            }
        }

        pub async fn run(self) -> crate::error::Result<()> {
            let listener = TcpListener::bind(self.addr).await?;
            info!(addr = %self.addr, "HidraChat server listening");

            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        // Out of descriptors, most likely: a tight loop here
                        // would spin at full CPU until one freed up.
                        warn!(error = %e, "accept error");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = Arc::clone(&self.conns).try_acquire_owned() else {
                    debug!(peer = %sensitive(&peer), "connection refused: at the connection limit");
                    drop(stream);
                    continue;
                };
                let rooms = Arc::clone(&self.rooms);
                let next_id = Arc::clone(&self.next_id);
                let join_verifier = self.join_verifier;
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, rooms, next_id, join_verifier, permit).await {
                        debug!(peer = %sensitive(&peer), error = %e, "connection ended");
                    }
                });
            }
        }
    }

    // ── Connection handler ──────────────────────────────────────────────

    async fn handle_conn(
        mut stream: TcpStream,
        peer: SocketAddr,
        rooms: Arc<Mutex<HashMap<String, Arc<RoomState>>>>,
        next_id: Arc<AtomicU64>,
        join_verifier: [u8; 32],
        _permit: OwnedSemaphorePermit,
    ) -> crate::error::Result<()> {
        let mut buf = vec![0u8; 8192];
        let n = match tokio::time::timeout(Duration::from_secs(HANDSHAKE_SECS), stream.read(&mut buf)).await {
            Ok(r) => r?,
            Err(_) => return Ok(()),           // said nothing in time
        };
        if n == 0 {
            return Ok(());
        }
        let req = String::from_utf8_lossy(&buf[..n]);

        if req.to_lowercase().contains("upgrade: websocket") {
            // The same screen the HTTP side applies. A page on any site the
            // user visits can open a WebSocket to 127.0.0.1, and the browser
            // marks it with the page's Origin; without this the one endpoint
            // that takes credentials and the room's backlog answered it.
            if matches!(crate::local_guard::screen(&req), crate::local_guard::Access::Deny) {
                let (code, text) = crate::local_guard::DENIED_STATUS;
                let body = crate::local_guard::DENIED_BODY;
                let header = format!(
                    "HTTP/1.1 {code} {text}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                send(&mut stream, header.as_bytes()).await;
                send(&mut stream, body.as_bytes()).await;
                return Ok(());
            }
            let key = extract_hdr(&req, "sec-websocket-key")
                .ok_or_else(|| crate::error::HidraError::Protocol("missing ws key".into()))?;
            let accept = ws_accept(key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            if !send(&mut stream, resp.as_bytes()).await {
                return Ok(());
            }
            let hdr_end = req.find("\r\n\r\n").map(|i| i + 4).unwrap_or(n);
            let leftover = if hdr_end < n {
                buf[hdr_end..n].to_vec()
            } else {
                vec![]
            };
            ws_session(stream, peer, rooms, next_id, leftover, join_verifier).await
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

    /// Every complete frame at the front of the buffer, taken off it in one
    /// move. Draining per frame made receive processing quadratic: a read
    /// full of two-byte frames moved the rest of the buffer once per frame.
    pub(super) fn take_frames(buf: &mut Vec<u8>) -> (Vec<(u8, Vec<u8>)>, bool) {
        let mut frames = Vec::new();
        let mut pos = 0usize;
        let mut too_large = false;
        loop {
            match try_parse_frame(&buf[pos..]) {
                Frame::Incomplete => break,
                Frame::TooLarge => {
                    too_large = true;
                    break;
                }
                Frame::Ready { opcode, payload, consumed } => {
                    pos += consumed;
                    frames.push((opcode, payload));
                }
            }
        }
        buf.drain(..pos);
        (frames, too_large)
    }

    /// A string from a client, cut to what the page itself allows, with a
    /// fallback for an empty one.
    pub(super) fn bounded(s: &str, max_chars: usize, fallback: &str) -> String {
        let s: String = s.trim().chars().take(max_chars).collect();
        if s.is_empty() { fallback.to_string() } else { s }
    }

    /// Code points that take no space on screen and so cannot be part of a
    /// name. The same list as the page's (hidrachat-crypto.js, INVISIBLE),
    /// tested against the same strings.
    pub(super) fn is_invisible(c: char) -> bool {
        let u = c as u32;
        matches!(u,
            0x0000..=0x001f | 0x007f..=0x009f | 0x00ad | 0x034f | 0x061c | 0x115f | 0x1160
            | 0x17b4 | 0x17b5 | 0x180b..=0x180f | 0x200b..=0x200f | 0x2028..=0x202e
            | 0x2060..=0x206f | 0x3164 | 0xe000..=0xf8ff | 0xfe00..=0xfe0f | 0xfeff | 0xffa0
            | 0xfff9..=0xfffb | 0x1bca0..=0x1bca3 | 0x1d173..=0x1d17a | 0xe0000..=0xe007f
            | 0xe0100..=0xe01ef | 0xf0000..=0xffffd | 0x100000..=0x10fffd)
    }

    /// Two nicknames are the same name when they read the same: after
    /// compatibility normalisation, with invisible characters dropped, with
    /// runs of whitespace as one space, ignoring case. The page compares and
    /// displays them the same way, and the room refuses a second member on a
    /// name already in it. A weaker rule here let a member join as a
    /// look-alike of another that the page then showed as the same name.
    pub(super) fn nick_key(nick: &str) -> String {
        use unicode_normalization::UnicodeNormalization;
        let folded: String = nick.nfkc().filter(|c| !is_invisible(*c)).collect();
        folded.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()
    }

    /// The verifier a client sent, as bytes, if it has the shape of one.
    pub(super) fn parse_auth(auth: &str) -> Option<[u8; 32]> {
        if auth.len() != 64 || !auth.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, chunk) in auth.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16)? as u8;
            let lo = (chunk[1] as char).to_digit(16)? as u8;
            out[i] = (hi << 4) | lo;
        }
        Some(out)
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

    /// write_all with a deadline. False when the peer would not take the
    /// bytes in time, which callers treat as the connection having ended.
    async fn send(stream: &mut TcpStream, bytes: &[u8]) -> bool {
        matches!(
            tokio::time::timeout(Duration::from_secs(WRITE_SECS), stream.write_all(bytes)).await,
            Ok(Ok(()))
        )
    }

    async fn refuse(stream: &mut TcpStream, msg: &str) {
        let body = serde_json::json!({"type": "error", "msg": msg}).to_string();
        if send(stream, &encode_frame(1, body.as_bytes())).await {
            send(stream, &encode_frame(8, &[])).await;
        }
    }

    // ── WebSocket session with room management ──────────────────────────

    /// What a join request says, once one has arrived; None when the
    /// connection ended or sent a frame over the limit first.
    async fn read_join(
        stream: &mut TcpStream,
        ws_buf: &mut Vec<u8>,
        tmp: &mut [u8],
    ) -> crate::error::Result<Option<(String, String, Option<[u8; 32]>)>> {
        loop {
            // One frame at a time here, so that whatever a client sent in the
            // same segment as its join stays in the buffer for the session.
            let (op, payload) = match try_parse_frame(ws_buf) {
                Frame::TooLarge => return Ok(None),
                Frame::Ready { opcode, payload, consumed } => {
                    ws_buf.drain(..consumed);
                    (opcode, payload)
                }
                Frame::Incomplete => {
                    let n = stream.read(tmp).await?;
                    if n == 0 {
                        return Ok(None);
                    }
                    ws_buf.extend_from_slice(&tmp[..n]);
                    continue;
                }
            };
            if op == 8 {
                return Ok(None);
            }
            if op != 1 {
                continue;
            }
            let Ok(text) = std::str::from_utf8(&payload) else { continue };
            let Ok(msg) = serde_json::from_str::<serde_json::Value>(text) else { continue };
            if msg.get("type").and_then(|t| t.as_str()) != Some("join") {
                continue;
            }
            let nick = bounded(msg.get("nick").and_then(|v| v.as_str()).unwrap_or(""), MAX_NICK_CHARS, "Anon");
            let room = bounded(msg.get("room").and_then(|v| v.as_str()).unwrap_or(""), MAX_ROOM_CHARS, "lobby");
            let auth = msg.get("auth").and_then(|v| v.as_str()).and_then(parse_auth);
            return Ok(Some((nick, room, auth)));
        }
    }

    async fn ws_session(
        mut stream: TcpStream,
        peer: SocketAddr,
        rooms: Arc<Mutex<HashMap<String, Arc<RoomState>>>>,
        next_id: Arc<AtomicU64>,
        leftover: Vec<u8>,
        join_verifier: [u8; 32],
    ) -> crate::error::Result<()> {
        let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
        let mut ws_buf = leftover;
        let mut tmp = [0u8; 16384];

        // ── Wait for the join, but not for ever ──
        let joined = tokio::time::timeout(
            Duration::from_secs(HANDSHAKE_SECS),
            read_join(&mut stream, &mut ws_buf, &mut tmp),
        )
        .await;
        let (nick, room_id, auth) = match joined {
            Ok(Ok(Some(j))) => j,
            Ok(Ok(None)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                debug!(peer = %sensitive(&peer), "no join within the handshake window");
                return Ok(());
            }
        };

        // A wrong or missing verifier and a right one cost the same here.
        let offered = auth.unwrap_or([0u8; 32]);
        let ok: bool = offered.ct_eq(&join_verifier).into();
        if auth.is_none() || !ok {
            warn!(peer = %sensitive(&peer), "join rejected: wrong room passphrase");
            refuse(&mut stream, "Wrong room passphrase.").await;
            return Ok(());
        }
        let color = nick_color(&nick).to_string();

        info!(
            peer = %sensitive(&peer),
            nick = %sensitive(&nick),
            room = %sensitive(&room_id),
            "user joined"
        );

        // ── Get or create the room and register, under one lock ──
        //
        // Looking the room up and joining it used to be two steps; a reap of
        // the room between them left the member in a room no longer in the
        // map, invisible to everyone who came after.
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
            let room = Arc::clone(r);
            let refusal = {
                let mut users = room.users.lock().await;
                // One nickname, one member. The page shows a message as the
                // reader's own by the connection it came from, but the
                // nickname is still what everyone reads under it.
                let wanted = nick_key(&nick);
                if users.len() >= MAX_CLIENTS {
                    Some("Room is full")
                } else if users.values().any(|u| nick_key(&u.nick) == wanted) {
                    Some("That nickname is already in the room.")
                } else {
                    users.insert(
                        conn_id,
                        UserInfo {
                            nick: nick.clone(),
                            color: color.clone(),
                        },
                    );
                    None
                }
            };
            if let Some(why) = refusal {
                if room.users.lock().await.is_empty() {
                    rm.remove(&room_id);
                }
                drop(rm);
                refuse(&mut stream, why).await;
                return Ok(());
            }
            room
        };

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
                "you": conn_id,
                "users": user_list,
                "history": hist,
                "count": users.len()
            });
            let frame = encode_frame(1, welcome.to_string().as_bytes());
            drop(history);
            drop(users);
            if !send(&mut stream, &frame).await {
                room.users.lock().await.remove(&conn_id);
                reap_room(&rooms, &room_id, &room).await;
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
        let mut last_seen = std::time::Instant::now();

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
                    last_seen = std::time::Instant::now();
                    ws_buf.extend_from_slice(&tmp[..n]);
                    let (frames, too_large) = take_frames(&mut ws_buf);
                    for (opcode, payload) in frames {
                        match opcode {
                            1 | 2 => on_message(&payload, &room, conn_id, &nick, &color).await,
                            8 => break 'main,
                            9 => {
                                if !send(&mut stream, &encode_frame(0x0A, &payload)).await {
                                    break 'main;
                                }
                            }
                            _ => {}
                        }
                    }
                    if too_large {
                        debug!(peer = %sensitive(&peer), "frame over the size limit");
                        break 'main;
                    }
                }
                Act::Bcast(data) => {
                    if !data.is_empty() && !send(&mut stream, &encode_frame(1, data.as_bytes())).await {
                        break;
                    }
                }
                Act::Ping => {
                    // A pong, or anything else, arrives as Data and resets the
                    // clock; a peer silent for IDLE_SECS is gone, whatever the
                    // socket says.
                    if last_seen.elapsed() > Duration::from_secs(IDLE_SECS) {
                        debug!(peer = %sensitive(&peer), "no pong; connection considered dead");
                        break;
                    }
                    if !send(&mut stream, &encode_frame(9, b"")).await {
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
        reap_room(&rooms, &room_id, &room).await;
        info!(peer = %sensitive(&peer), nick = %sensitive(&nick), "user left");
        Ok(())
    }

    /// A room with nobody left in it is forgotten, history and all. Rooms
    /// used to live for the life of the process, so a member could leave
    /// hundreds of them behind, each holding its backlog.
    async fn reap_room(
        rooms: &Arc<Mutex<HashMap<String, Arc<RoomState>>>>,
        room_id: &str,
        room: &Arc<RoomState>,
    ) {
        let mut rm = rooms.lock().await;
        let empty = room.users.lock().await.is_empty();
        if empty {
            if let Some(current) = rm.get(room_id) {
                if Arc::ptr_eq(current, room) {
                    rm.remove(room_id);
                }
            }
        }
    }

    async fn on_message(payload: &[u8], room: &Arc<RoomState>, conn_id: u64, nick: &str, color: &str) {
        if payload.len() > MAX_MESSAGE_BYTES {
            return;
        }
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
                    obj.insert("from".into(), serde_json::json!(conn_id));
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
                let t = serde_json::json!({"type":"typing","nick":nick,"from":conn_id,"state":state});
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
            send(stream, header.as_bytes()).await;
            send(stream, body.as_bytes()).await;
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
            if send(stream, header.as_bytes()).await {
                send(stream, body.as_bytes()).await;
            }
        } else if let Some((body, cache)) = match path {
            // Served from here rather than from a CDN. This page holds the
            // end-to-end encryption: a script fetched from someone else's
            // host at load time can read every message before it is encrypted,
            // and there is no integrity check on a <script src> pointing at a
            // moving "@5" tag. The browser's own copy of this app was moved
            // off the CDN already; this one was still loading it.
            "/vendor/mqtt.min.js" => Some((frontend::VENDOR_MQTT, "public, max-age=86400")),
            // The files the page shares with the browser, at fixed paths:
            // nothing here concatenates the request path.
            "/hidra-store.js" => Some((frontend::STORE_JS, "no-cache")),
            "/hidrachat-crypto.js" => Some((frontend::ROOM_JS, "no-cache")),
            "/hidra-relays.js" => Some((frontend::RELAYS_JS, "no-cache")),
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
            if send(stream, header.as_bytes()).await {
                send(stream, body.as_bytes()).await;
            }
        } else if let Some(body) = match path {
            // The HidraNet logo and the tab icon the page shows, the same
            // files the browser serves. Fixed paths again.
            "/img/hidranet-logo.png" => Some(frontend::LOGO_PNG),
            "/img/favicon.png" => Some(frontend::FAVICON_PNG),
            _ => None,
        } {
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: image/png\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: public, max-age=86400\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            if send(stream, header.as_bytes()).await {
                send(stream, body).await;
            }
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
            if send(stream, header.as_bytes()).await {
                send(stream, body.as_bytes()).await;
            }
        } else {
            send(stream, b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nNot Found").await;
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
    /// The relay connections (every public broker at once), shared the same way.
    pub const RELAYS_JS: &str = include_str!("../../assets/hidra-relays.js");
    /// The HidraNet logo and tab icon, the browser's files (src/ui/img/).
    pub const LOGO_PNG: &[u8] = include_bytes!("../../assets/img/hidranet-logo.png");
    pub const FAVICON_PNG: &[u8] = include_bytes!("../../assets/img/favicon.png");
}

#[cfg(test)]
mod tests {
    use super::crypto::derive_join_verifier;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// The browser computes the same value (hidra-browser/src/ui/
    /// hidrachat-crypto.js, `deriveRoom(...).join`); this vector was taken
    /// from it, so the two sides are known to agree byte for byte.
    #[test]
    fn join_verifier_matches_the_browser() {
        let v = derive_join_verifier("test passphrase").unwrap();
        assert_eq!(
            hex(&v),
            "32585c8aad2f832cb79f808518e71d53df8dc2b1151df339a6e9a610c8421fec"
        );
    }

    #[test]
    fn join_verifier_differs_per_passphrase_and_is_deterministic() {
        let a = derive_join_verifier("passphrase one").unwrap();
        let b = derive_join_verifier("passphrase two").unwrap();
        let c = derive_join_verifier("passphrase one").unwrap();
        assert_ne!(a, b);
        assert_eq!(a, c);
    }

    /// An empty passphrase is a real value, not a bypass: it must not collide
    /// with any other passphrase, and a client sending no verifier at all is
    /// compared against zeros, which no passphrase derives to in practice.
    #[test]
    fn empty_passphrase_is_not_a_wildcard() {
        let empty = derive_join_verifier("").unwrap();
        let real = derive_join_verifier("actual passphrase").unwrap();
        assert_ne!(empty, real);
        assert_ne!(empty, [0u8; 32]);
    }

    use super::server::{
        Frame, MAX_FRAME_PAYLOAD, MAX_MESSAGE_BYTES, bounded, nick_key, parse_auth, take_frames,
        try_parse_frame,
    };

    #[test]
    fn a_verifier_is_sixty_four_hex_digits_and_nothing_else() {
        let good = "32585c8aad2f832cb79f808518e71d53df8dc2b1151df339a6e9a610c8421fec";
        assert_eq!(hex(&parse_auth(good).unwrap()), good);
        for bad in ["", "abc", &good[..63], &format!("{good}0"), &good.replace('a', "g"), "the password itself"] {
            assert!(parse_auth(bad).is_none(), "{bad:?}");
        }
    }

    /// The same strings the browser's test uses (test/chat-crypto.js): the
    /// two sides must agree on what reads the same.
    #[test]
    fn nicknames_that_read_the_same_are_the_same_name() {
        assert_eq!(nick_key("Alice"), nick_key("alice"));
        assert_eq!(nick_key("  alice  "), nick_key("alice"));
        assert_eq!(nick_key("al  ice"), nick_key("Al Ice"));
        assert_ne!(nick_key("alice"), nick_key("alice2"));
        for look_alike in [
            "al\u{200b}ice", "al\u{fe0f}ice", "al\u{034f}ice", "al\u{3164}ice", "al\u{e0041}ice",
            "al\u{180e}ice", "al\u{061c}ice", "al\u{fff9}ice", "\u{ff21}lice", "al\u{f0000}ice",
            "al\u{ad}ice", "al\u{feff}ice", "al\u{2060}ice", "al\u{115f}ice",
        ] {
            assert_eq!(nick_key(look_alike), "alice", "{look_alike:?}");
        }
        assert_eq!(nick_key("  al\u{a0} ice "), "al ice");
        assert_ne!(nick_key("ali\u{e7}a"), "alica", "a real accent stays");
    }

    #[test]
    fn frames_are_taken_off_the_buffer_in_one_move() {
        let mut buf = Vec::new();
        for i in 0..100u8 {
            buf.extend(masked_frame(1, &[i]));
        }
        let partial = masked_frame(1, &[7u8; 50]);
        buf.extend_from_slice(&partial[..partial.len() - 1]);
        let (frames, too_large) = take_frames(&mut buf);
        assert_eq!(frames.len(), 100);
        assert!(!too_large);
        assert_eq!(frames[42].1, vec![42u8]);
        assert_eq!(buf.len(), partial.len() - 1, "the partial frame stays");
        buf.push(partial[partial.len() - 1]);
        let (frames, _) = take_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert!(buf.is_empty());
    }

    #[test]
    fn a_message_over_the_limit_is_smaller_than_a_frame_over_the_limit() {
        assert!(MAX_MESSAGE_BYTES < MAX_FRAME_PAYLOAD);
    }


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
            (super::frontend::RELAYS_JS, "hidra-browser/src/ui/hidra-relays.js"),
            (super::frontend::VENDOR_MQTT, "hidra-browser/src/ui/vendor/mqtt.min.js"),
        ] {
            if let Ok(browser) = std::fs::read_to_string(root.join(theirs)) {
                assert!(ours == browser, "{theirs} differs from the copy under assets/");
            }
        }
        for (ours, theirs) in [
            (super::frontend::LOGO_PNG, "hidra-browser/src/ui/img/hidranet-logo.png"),
            (super::frontend::FAVICON_PNG, "hidra-browser/src/ui/img/favicon.png"),
        ] {
            if let Ok(browser) = std::fs::read(root.join(theirs)) {
                assert!(ours == browser.as_slice(), "{theirs} differs from the copy under assets/");
            }
        }
    }
}
