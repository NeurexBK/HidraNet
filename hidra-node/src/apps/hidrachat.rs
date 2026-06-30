pub mod crypto {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        ChaCha20Poly1305, Nonce,
    };
    use rand::RngCore;
    use crate::error::{HidraError, Result};

    #[allow(dead_code)]
    pub fn derive_room_key(passphrase: &str) -> [u8; 32] {
        *blake3::hash(passphrase.as_bytes()).as_bytes()
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
    use tokio::sync::{Mutex, broadcast};
    use tracing::{debug, info, warn};

    use super::frontend;

    const MAX_CLIENTS: usize = 512;
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
    }

    impl ChatServer {
        pub fn new(addr: SocketAddr, default_room: String, _passphrase: &str) -> Self {
            Self {
                addr,
                rooms: Arc::new(Mutex::new(HashMap::new())),
                next_id: Arc::new(AtomicU64::new(1)),
                default_room,
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
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, peer, rooms, next_id).await {
                        debug!(peer = %peer, error = %e, "connection ended");
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
            ws_session(stream, peer, rooms, next_id, leftover).await
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

    fn try_parse_frame(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
        if buf.len() < 2 {
            return None;
        }
        let opcode = buf[0] & 0x0F;
        let masked = (buf[1] & 0x80) != 0;
        let mut payload_len = (buf[1] & 0x7F) as usize;
        let mut offset = 2usize;

        if payload_len == 126 {
            if buf.len() < 4 {
                return None;
            }
            payload_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
            offset = 4;
        } else if payload_len == 127 {
            if buf.len() < 10 {
                return None;
            }
            payload_len = u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
            ]) as usize;
            offset = 10;
        }

        let mask_len = if masked { 4 } else { 0 };
        let total = offset + mask_len + payload_len;
        if buf.len() < total {
            return None;
        }

        let mut payload = buf[offset + mask_len..total].to_vec();
        if masked {
            let mask = &buf[offset..offset + 4];
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Some((opcode, payload, total))
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

    async fn ws_session(
        mut stream: TcpStream,
        peer: SocketAddr,
        rooms: Arc<Mutex<HashMap<String, Arc<RoomState>>>>,
        next_id: Arc<AtomicU64>,
        leftover: Vec<u8>,
    ) -> crate::error::Result<()> {
        let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
        let mut ws_buf = leftover;
        let mut tmp = [0u8; 16384];

        // ── Wait for join message ──
        let (nick, room_id, color) = 'join: loop {
            while let Some((op, payload, consumed)) = try_parse_frame(&ws_buf) {
                ws_buf.drain(..consumed);
                if op == 1 {
                    if let Ok(text) = std::str::from_utf8(&payload) {
                        if let Ok(msg) = serde_json::from_str::<serde_json::Value>(text) {
                            if msg.get("type").and_then(|t| t.as_str()) == Some("join") {
                                let n = msg
                                    .get("nick")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("Anon")
                                    .to_string();
                                let r = msg
                                    .get("room")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("lobby")
                                    .to_string();
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

        info!(peer = %peer, nick = %nick, room = %room_id, "user joined");

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
                let err_msg = serde_json::json!({"type":"error","msg":"Sala lotada"});
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
                    while let Some((opcode, payload, consumed)) = try_parse_frame(&ws_buf) {
                        ws_buf.drain(..consumed);
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
        info!(peer = %peer, nick = %nick, "user left");
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
        } else if path == "/api/whoami" {
            let ip = local_ip().unwrap_or_else(|| "127.0.0.1".to_string());
            let body = format!("{{\"lan_ip\":\"{ip}\",\"port\":8081}}");
            let header = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Access-Control-Allow-Origin: *\r\n\
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
    pub const PAGE_HTML: &str = r##"<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HidraChat</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --bg:#0a0e17;--bg2:#111827;--bg3:#1a2332;--bg4:#243044;
  --accent:#00d4aa;--accent2:#00a88a;--accentg:rgba(0,212,170,.12);
  --txt:#e0e6ed;--txt2:#8892a4;--muted:#4a5568;--border:#1e293b;
  --red:#ff4757;--own:#0d2818;--own-b:#0f3d22;--other:#1a2332;--other-b:#1e293b;
  --sys:#1a1a2e;--sys-b:#2d2b55;
}
html,body{height:100%;overflow:hidden}
body{font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,sans-serif;background:var(--bg);color:var(--txt)}

/* ── Layout ── */
#app{display:none;height:100vh;flex-direction:column}
#app.active{display:flex}

header{display:flex;justify-content:space-between;align-items:center;padding:12px 20px;background:var(--bg2);border-bottom:1px solid var(--border);flex-shrink:0}
.h-left{display:flex;align-items:center;gap:10px}
.h-left .logo{font-size:22px;filter:drop-shadow(0 0 6px rgba(0,212,170,.4))}
.h-left h1{font-size:17px;font-weight:600;color:var(--accent);letter-spacing:.5px}
.room-tag{background:var(--bg3);color:var(--txt2);padding:3px 10px;border-radius:12px;font-size:11px;font-family:monospace;cursor:pointer;border:1px solid var(--border);transition:.2s}
.room-tag:hover{border-color:var(--accent);color:var(--accent)}
.h-right{display:flex;align-items:center;gap:14px}
.status{font-size:13px;color:var(--muted);display:flex;align-items:center;gap:6px}
.status.on{color:var(--accent)}
.status.on::before{content:'';width:8px;height:8px;border-radius:50%;background:var(--accent);box-shadow:0 0 6px var(--accent);animation:pulse 2s infinite}
.count-badge{font-size:11px;color:var(--txt2);background:var(--bg3);padding:3px 10px;border-radius:10px}
.sidebar-toggle{display:none;background:none;border:1px solid var(--border);color:var(--txt2);width:32px;height:32px;border-radius:6px;cursor:pointer;font-size:16px}

.main-area{display:flex;flex:1;overflow:hidden}

/* ── Sidebar ── */
aside{width:220px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;flex-shrink:0;overflow-y:auto}
aside .section{padding:16px}
aside .section-title{font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1.2px;margin-bottom:10px}
.user-item{display:flex;align-items:center;gap:8px;padding:5px 0;font-size:13px}
.user-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.user-nick{color:var(--txt)}
.room-info{margin-top:auto;padding:16px;border-top:1px solid var(--border)}
.room-info .label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px}
.room-info .code{font-family:monospace;font-size:14px;color:var(--accent);background:var(--bg);padding:8px 12px;border-radius:6px;border:1px solid var(--border);display:flex;justify-content:space-between;align-items:center}
.room-info .code button{background:none;border:none;color:var(--txt2);cursor:pointer;font-size:12px;padding:2px 6px}
.room-info .code button:hover{color:var(--accent)}
.encryption-badge{margin-top:10px;font-size:11px;color:var(--accent2);display:flex;align-items:center;gap:5px}
.share-hint{margin-top:10px;font-size:11px;color:var(--muted);line-height:1.5}

/* ── Messages ── */
.chat-col{flex:1;display:flex;flex-direction:column;min-width:0}
#messages{flex:1;overflow-y:auto;padding:16px 20px;scroll-behavior:smooth}
#messages::-webkit-scrollbar{width:6px}
#messages::-webkit-scrollbar-track{background:transparent}
#messages::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}

.msg{display:flex;gap:10px;margin-bottom:10px;animation:fadeIn .2s ease-out;max-width:85%}
.msg.own{margin-left:auto;flex-direction:row-reverse}
.msg.sys{max-width:100%;justify-content:center}

.avatar{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;flex-shrink:0;text-transform:uppercase}
.msg.own .avatar{display:none}

.bubble{padding:10px 14px;border-radius:12px;max-width:100%;word-break:break-word}
.msg.other .bubble{background:var(--other);border:1px solid var(--other-b);border-top-left-radius:4px}
.msg.own .bubble{background:var(--own);border:1px solid var(--own-b);border-top-right-radius:4px}
.msg.sys .bubble{background:var(--sys);border:1px solid var(--sys-b);font-size:12px;color:var(--txt2);padding:6px 16px;border-radius:20px}

.bubble-header{display:flex;justify-content:space-between;align-items:baseline;gap:12px;margin-bottom:3px}
.bubble-nick{font-size:12px;font-weight:600}
.bubble-time{font-size:10px;color:var(--muted);white-space:nowrap}
.bubble-text{font-size:14px;line-height:1.55;color:var(--txt)}
.bubble-text.encrypted{color:var(--muted);font-style:italic;font-size:12px}

.typing-bar{padding:4px 20px;font-size:12px;color:var(--txt2);min-height:22px;flex-shrink:0}
.typing-bar .dots{display:inline-flex;gap:3px;vertical-align:middle;margin-left:4px}
.typing-bar .dots span{width:5px;height:5px;border-radius:50%;background:var(--txt2);animation:typeDot 1.2s infinite}
.typing-bar .dots span:nth-child(2){animation-delay:.2s}
.typing-bar .dots span:nth-child(3){animation-delay:.4s}
@keyframes typeDot{0%,100%{opacity:.3;transform:translateY(0)}50%{opacity:1;transform:translateY(-3px)}}

/* ── Input ── */
footer{padding:12px 20px;background:var(--bg2);border-top:1px solid var(--border);flex-shrink:0}
.input-row{display:flex;gap:8px}
.input-row input{flex:1;padding:12px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:10px;color:var(--txt);font-size:14px;outline:none;font-family:inherit}
.input-row input:focus{border-color:var(--accent)}
.input-row button{padding:12px 24px;background:var(--accent);color:var(--bg);border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;transition:.2s}
.input-row button:hover{background:var(--accent2)}
.footer-badge{text-align:center;font-size:10px;color:var(--muted);margin-top:6px}

/* ── Welcome modal ── */
#welcome{position:fixed;inset:0;background:var(--bg);display:flex;align-items:center;justify-content:center;z-index:100}
#welcome.hidden{display:none}
.wc{background:var(--bg2);border:1px solid var(--border);border-radius:16px;padding:40px;text-align:center;max-width:420px;width:90%}
.wc .logo-big{font-size:48px;margin-bottom:12px;filter:drop-shadow(0 0 16px rgba(0,212,170,.3))}
.wc h2{color:var(--accent);margin-bottom:4px;font-size:24px;font-weight:600}
.wc .sub{color:var(--txt2);margin-bottom:24px;font-size:13px}
.wc input{width:100%;padding:13px 16px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;color:var(--txt);font-size:15px;outline:none;margin-bottom:10px;font-family:inherit}
.wc input:focus{border-color:var(--accent)}
.wc input[type=password]{border-color:#2d4a2d;font-family:monospace;font-size:14px;letter-spacing:1px}
.wc input[type=password]:focus{border-color:var(--accent)}
.wc button{width:100%;padding:14px;background:var(--accent);color:var(--bg);border:none;border-radius:8px;font-size:16px;font-weight:700;cursor:pointer;transition:.2s;margin-top:4px}
.wc button:hover{background:var(--accent2)}
.wc .hint{color:var(--muted);font-size:11px;margin-top:12px;line-height:1.5}
.my-addr{margin-top:14px;padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;font-size:11px;color:var(--muted);line-height:1.7}
.my-addr.hidden{display:none}
.my-addr span{display:inline-block;margin-top:2px;font-family:monospace;font-size:14px;color:var(--accent);cursor:pointer;font-weight:600}
.adv-toggle{color:var(--muted);font-size:11px;cursor:pointer;margin-top:14px;display:inline-block;user-select:none}
.adv-toggle:hover{color:var(--accent)}
.adv{margin-top:10px}
.adv.hidden{display:none}

.date-sep{text-align:center;margin:16px 0;font-size:11px;color:var(--muted);position:relative}
.date-sep::before,.date-sep::after{content:'';position:absolute;top:50%;width:calc(50% - 50px);height:1px;background:var(--border)}
.date-sep::before{left:0}
.date-sep::after{right:0}

.copied-toast{position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:var(--accent);color:var(--bg);padding:8px 20px;border-radius:20px;font-size:13px;font-weight:600;opacity:0;transition:.3s;pointer-events:none;z-index:200}
.copied-toast.show{opacity:1}

.pass-row{display:flex;gap:6px;width:100%;margin-bottom:10px}
.pass-row input{flex:1;margin-bottom:0}
.pass-row .mini{width:46px;flex-shrink:0;padding:0;font-size:17px;background:var(--bg3);border:1px solid var(--border);color:var(--txt);border-radius:8px;cursor:pointer;transition:.15s}
.pass-row .mini:hover{border-color:var(--accent);color:var(--accent)}
.recent{margin-top:14px;text-align:left}
.recent.hidden{display:none}
.recent-t{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:7px}
.recent-chip{display:inline-flex;align-items:center;gap:7px;background:var(--bg3);border:1px solid var(--border);border-radius:16px;padding:5px 11px;margin:0 6px 6px 0;font-size:12px;color:var(--txt2);cursor:pointer;font-family:monospace}
.recent-chip:hover{border-color:var(--accent);color:var(--accent)}
.recent-chip .rm{color:var(--muted);font-size:13px}
.recent-chip .rm:hover{color:#ff6b6b}

@keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}

@media(max-width:700px){
  aside{position:fixed;left:-260px;top:0;bottom:0;z-index:50;transition:left .3s;width:260px;box-shadow:4px 0 20px rgba(0,0,0,.5)}
  aside.open{left:0}
  .sidebar-toggle{display:flex;align-items:center;justify-content:center}
  header{padding:12px 14px}
  #messages{padding:12px 14px}
  footer{padding:10px 14px}
  .msg{max-width:92%}
}
</style>
</head>
<body>

<div id="welcome">
  <div class="wc">
    <div class="logo-big">🐍</div>
    <h2>HidraChat</h2>
    <p class="sub">Chat criptografado de ponta a ponta na rede HidraNet</p>
    <input type="text" id="inNick" placeholder="Seu apelido" maxlength="24" autofocus>
    <div class="pass-row">
      <input type="text" id="inPass" placeholder="Senha da sala (combine com os amigos)" maxlength="128" autocomplete="off" spellcheck="false">
      <button id="btnGen" class="mini" title="Gerar senha forte">🎲</button>
      <button id="btnCopyPass" class="mini" title="Copiar senha">⧉</button>
    </div>
    <button id="btnJoin">Entrar na Sala 🔒</button>
    <p class="hint"><b>Mesma senha = mesma sala.</b> Funciona de qualquer lugar — redes e IPs diferentes. Combine uma senha com seus amigos: todos que digitarem a mesma senha caem na mesma sala. O conteúdo é criptografado de ponta a ponta; ninguém no meio lê.</p>
    <div id="recentBox" class="recent hidden">
      <div class="recent-t">Salas recentes (clique para reentrar)</div>
      <div id="recentList"></div>
    </div>
    <div id="advToggle" class="adv-toggle">⚙ Opções avançadas</div>
    <div id="advBox" class="adv hidden">
      <input type="text" id="inServer" placeholder="(opcional) Servidor próprio — ex.: meuhub.com:8081" maxlength="80" autocomplete="off" spellcheck="false">
      <p class="hint" style="margin-top:6px"><b>Deixe vazio</b> para usar a rede pública da HidraNet (recomendado — funciona entre redes diferentes). Preencha só se você tiver um servidor/hub próprio na sua rede.</p>
      <div id="myAddr" class="my-addr hidden">Para hospedar na sua rede, seus amigos usam:<br><span id="myAddrVal" title="Clique para copiar">—</span></div>
    </div>
  </div>
</div>

<div id="app">
  <header>
    <div class="h-left">
      <button class="sidebar-toggle" id="sidebarBtn">☰</button>
      <span class="logo">🐍</span>
      <h1>HidraChat</h1>
      <span class="room-tag" id="roomTag" title="Clique para copiar">—</span>
    </div>
    <div class="h-right">
      <span class="status" id="connStatus">Conectando...</span>
      <span class="count-badge" id="countBadge">0 online</span>
    </div>
  </header>
  <div class="main-area">
    <aside id="sidebar">
      <div class="section">
        <div class="section-title">Online</div>
        <div id="userList"></div>
      </div>
      <div class="room-info">
        <div class="label">Código da sala</div>
        <div class="code"><span id="roomCode">—</span><button onclick="copyRoom()">Copiar</button></div>
        <div class="encryption-badge" id="encBadge">🔒 E2E: AES-256-GCM</div>
        <div class="share-hint">Compartilhe a senha com amigos. Quem usar a mesma senha entra na mesma sala criptografada.</div>
      </div>
    </aside>
    <div class="chat-col">
      <div id="messages"></div>
      <div class="typing-bar" id="typingBar"></div>
      <footer>
        <div class="input-row">
          <input type="text" id="msgInput" placeholder="Digite sua mensagem..." maxlength="2000" autocomplete="off">
          <button id="sendBtn">Enviar</button>
        </div>
        <div class="footer-badge">🔒 Criptografia de ponta a ponta ativa — servidor nunca vê suas mensagens</div>
      </footer>
    </div>
  </div>
</div>

<div class="copied-toast" id="toast">Copiado!</div>

<script src="https://unpkg.com/mqtt@5/dist/mqtt.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/mqtt@5/dist/mqtt.min.js"></script>
<script>
(function(){
'use strict';

// DEFAULT_HUB: endereço de um servidor sempre-ligado que TODOS os apps usam
// por padrão. Quando preenchido, basta a senha igual para amigos em redes
// diferentes caírem na mesma sala. Vazio = modo "hospede você mesmo" (LAN).
var DEFAULT_HUB='';

var ws=null, nick='', roomId='', cryptoKey=null, e2e=false, serverAddr='';
var reconnAttempts=0, MAX_RECONN=15, typingTimeout=null, myTyping=false;
var typingUsers={}, soundEnabled=true;

// ── Relay (public hub) mode state ──
var mode='ws';                 // 'ws' = servidor direto/LAN | 'relay' = rede pública (MQTT)
var mqttClient=null, relayTopic='', relayReconn=0;
var myCid='', myColor='', peers={}, presenceTimer=null, startTime=0;
var MQTT_BROKERS=['wss://broker.emqx.io:8084/mqtt','wss://broker.hivemq.com:8884/mqtt'];
var PALETTE=['#00d4aa','#ff6b6b','#4ecdc4','#45b7d1','#f9ca24','#fd79a8','#6c5ce7','#e17055','#0984e3','#00b894','#e84393','#00cec9','#fdcb6e','#a29bfe','#74b9ff'];
function colorFor(s){var h=0;s=s||'';for(var i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))>>>0;return PALETTE[h%PALETTE.length];}
function genCid(){var a=crypto.getRandomValues(new Uint8Array(8)),s='';for(var i=0;i<8;i++)s+=a[i].toString(16).padStart(2,'0');return s;}

var $=function(id){return document.getElementById(id)};
var messagesEl=$('messages'), msgInput=$('msgInput');
var inNick=$('inNick'), inPass=$('inPass'), inServer=$('inServer');

// ── E2E Crypto (AES-256-GCM via Web Crypto API) ──

async function deriveKey(pass){
  var enc=new TextEncoder();
  var km=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt:enc.encode('hidrachat-e2e-v1'),iterations:100000,hash:'SHA-256'},
    km,{name:'AES-GCM',length:256},false,['encrypt','decrypt']
  );
}

async function computeRoom(pass){
  var enc=new TextEncoder();
  var buf=await crypto.subtle.digest('SHA-256',enc.encode(pass));
  var arr=new Uint8Array(buf);
  var hex='';
  for(var i=0;i<6;i++) hex+=arr[i].toString(16).padStart(2,'0');
  return hex;
}

// Topic público derivado da senha (hash, não revela a senha)
async function computeTopic(pass){
  var enc=new TextEncoder();
  var buf=await crypto.subtle.digest('SHA-256',enc.encode('hidra-topic-v1:'+pass));
  var arr=new Uint8Array(buf),hex='';
  for(var i=0;i<16;i++) hex+=arr[i].toString(16).padStart(2,'0');
  return 'hidra-'+hex;
}

// ── Relay público (ntfy.sh): encontro por senha, conteúdo cifrado E2E ──

function connectRelay(){
  mode='relay';
  startTime=Date.now();
  myCid=genCid();
  myColor=colorFor(nick);
  peers={};
  peers[myCid]={nick:nick,color:myColor,last:Date.now()};
  updatePresence();
  addSys('🔒 Sala criptografada de ponta a ponta. Encontro pela senha na rede HidraNet.');
  relayOpen();
  startPresence();
  window.addEventListener('beforeunload',function(){try{relayPublish({k:'leave',nick:nick,cid:myCid})}catch(e){}});
}

function relayOpen(){
  if(typeof mqtt==='undefined'){
    $('connStatus').textContent='Sem rede';$('connStatus').className='status';
    addSys('⚠️ Não foi possível carregar a rede de mensagens. Verifique a internet e recarregue a página (↻).');
    return;
  }
  var topic='hidra/'+relayTopic;
  $('connStatus').textContent='Conectando...';$('connStatus').className='status';
  try{
    mqttClient=mqtt.connect(MQTT_BROKERS[0],{
      clientId:'hidra_'+myCid+Math.floor(Math.random()*99999),
      clean:true, connectTimeout:9000, reconnectPeriod:4000, keepalive:30
    });
  }catch(e){
    $('connStatus').textContent='Falha na conexão';$('connStatus').className='status';return;
  }
  mqttClient.on('connect',function(){
    $('connStatus').textContent='Conectado (rede HidraNet)';
    $('connStatus').className='status on';
    mqttClient.subscribe(topic,{qos:0});
    relayPublish({k:'join',nick:nick,color:myColor,cid:myCid,t:Date.now()});
  });
  mqttClient.on('reconnect',function(){
    $('connStatus').textContent='Reconectando...';$('connStatus').className='status';
  });
  mqttClient.on('message',function(t,payload){ onRelayMessage(payload.toString()); });
  mqttClient.on('error',function(){});
}

async function relayPublish(obj){
  if(!cryptoKey||!mqttClient) return;
  var enc=await encryptMsg(JSON.stringify(obj));
  if(!enc) return;
  try{ mqttClient.publish('hidra/'+relayTopic, enc, {qos:0}); }catch(e){}
}

async function onRelayMessage(ciphertext){
  var plain=await decryptMsg(ciphertext);
  if(plain===null) return;               // mensagem de outra sala/senha
  var o;try{o=JSON.parse(plain)}catch(e){return}
  if(!o||!o.k) return;
  if(o.cid&&o.cid!==myCid){
    peers[o.cid]={nick:o.nick||(peers[o.cid]&&peers[o.cid].nick)||'Anon',color:o.color||colorFor(o.nick),last:Date.now()};
    updatePresence();
  }
  switch(o.k){
    case 'msg':
      if(o.cid===myCid) return;          // minha propria mensagem (ja exibida localmente)
      renderChatMsg({nick:o.nick,color:o.color,text:o.text,time:o.t,cid:o.cid});
      beep();
      break;
    case 'join':
      if(o.cid!==myCid) addSys((o.nick||'Alguém')+' entrou na sala');
      break;
    case 'leave':
      if(o.cid){delete peers[o.cid];updatePresence();addSys((o.nick||'Alguém')+' saiu da sala')}
      break;
    case 'typing':
      if(o.cid!==myCid) setTyping(o.nick,o.state);
      break;
  }
}

function startPresence(){
  if(presenceTimer) clearInterval(presenceTimer);
  presenceTimer=setInterval(function(){
    peers[myCid]={nick:nick,color:myColor,last:Date.now()};
    relayPublish({k:'presence',nick:nick,color:myColor,cid:myCid,t:Date.now()});
    updatePresence();
  },25000);
}

function updatePresence(){
  var now=Date.now();
  Object.keys(peers).forEach(function(c){if(c!==myCid&&now-peers[c].last>70000) delete peers[c]});
  var list=Object.keys(peers).map(function(c){return {nick:peers[c].nick,color:peers[c].color}});
  $('countBadge').textContent=list.length+' online';
  renderUsers(list);
}

async function encryptMsg(text){
  if(!cryptoKey) return null;
  var enc=new TextEncoder();
  var iv=crypto.getRandomValues(new Uint8Array(12));
  var ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:iv},cryptoKey,enc.encode(text));
  var buf=new Uint8Array(12+ct.byteLength);
  buf.set(iv);buf.set(new Uint8Array(ct),12);
  var b='';for(var i=0;i<buf.length;i++) b+=String.fromCharCode(buf[i]);
  return btoa(b);
}

async function decryptMsg(b64){
  if(!cryptoKey) return null;
  try{
    var raw=atob(b64);var arr=new Uint8Array(raw.length);
    for(var i=0;i<raw.length;i++) arr[i]=raw.charCodeAt(i);
    if(arr.length<13) return null;
    var pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:arr.slice(0,12)},cryptoKey,arr.slice(12));
    return new TextDecoder().decode(pt);
  }catch(e){return null}
}

// ── Sound ──

function beep(){
  if(!soundEnabled) return;
  try{
    var ctx=new(window.AudioContext||window.webkitAudioContext)();
    var o=ctx.createOscillator(),g=ctx.createGain();
    o.connect(g);g.connect(ctx.destination);
    o.frequency.value=880;o.type='sine';g.gain.value=0.08;
    g.gain.exponentialRampToValueAtTime(0.001,ctx.currentTime+0.2);
    o.start(ctx.currentTime);o.stop(ctx.currentTime+0.2);
  }catch(e){}
}

// ── Join ──

async function doJoin(){
  var n=inNick.value.trim();
  if(!n) return;
  nick=n;
  var sv=inServer.value.trim()||DEFAULT_HUB;
  if(sv){
    sv=sv.replace(/^wss?:\/\//i,'').replace(/^https?:\/\//i,'').replace(/\/+$/,'');
    if(sv.indexOf(':')<0) sv+=':8081';
  }
  serverAddr=sv;
  var pass=inPass.value;
  if(pass.length>0){
    try{
      cryptoKey=await deriveKey(pass);
      roomId=await computeRoom(pass);
      e2e=true;
    }catch(e){
      alert('Erro ao derivar chave de criptografia');
      return;
    }
  }else{
    roomId='lobby';
    e2e=false;
  }
  if(pass && e2e){ saveRecent(pass, nick); }
  $('welcome').classList.add('hidden');
  $('app').classList.add('active');
  $('roomTag').textContent='#'+roomId;
  $('roomCode').textContent=roomId;
  if(!e2e){
    $('encBadge').innerHTML='⚠️ Sem E2E — use uma senha';
    $('encBadge').style.color='var(--muted)';
    document.querySelector('.footer-badge').textContent='⚠️ Sem criptografia E2E — defina uma senha para criptografar';
  }
  msgInput.focus();
  if(serverAddr){
    connectWS();                          // servidor direto / LAN / hub fixo
  }else if(e2e){
    relayTopic=await computeTopic(pass);
    connectRelay();                       // rede pública por senha (ntfy)
  }else{
    connectWS();                          // sem senha e sem servidor: hospeda localmente
  }
}

$('btnJoin').onclick=doJoin;
inNick.onkeydown=function(e){if(e.key==='Enter'){if(inPass.value||!inNick.value.trim())doJoin();else inPass.focus()}};
inPass.onkeydown=function(e){if(e.key==='Enter')doJoin()};
inServer.onkeydown=function(e){if(e.key==='Enter')doJoin()};
$('sidebarBtn').onclick=function(){$('sidebar').classList.toggle('open')};

// Advanced server section toggle + hub prefill
$('advToggle').onclick=function(){$('advBox').classList.toggle('hidden')};
if(DEFAULT_HUB){ inServer.value=DEFAULT_HUB; }

// ── Gerar senha / copiar ──
var GENWORDS=['tigre','vento','lua','rio','pedra','fogo','neve','onda','raio','folha','ouro','prata','noite','sol','mar','flor','gelo','trem','nuvem','pinha','aguia','lobo','vale','monte','chama'];
function genPassword(){
  var w=function(){return GENWORDS[Math.floor(Math.random()*GENWORDS.length)];};
  var r=crypto.getRandomValues(new Uint8Array(5)),suf='';
  for(var i=0;i<5;i++) suf+=(r[i]%36).toString(36);
  return w()+'-'+w()+'-'+w()+'-'+suf;
}
function copyText(s){ if(s&&navigator.clipboard){ navigator.clipboard.writeText(s).then(function(){showToast()}); } }
$('btnGen').onclick=function(){ inPass.value=genPassword(); inPass.focus(); };
$('btnCopyPass').onclick=function(){ copyText(inPass.value); };

// ── Salas recentes (ultimas 5 senhas, no proprio dispositivo) ──
function saveRecent(pass, nk){
  try{
    var list=JSON.parse(localStorage.getItem('hidra_recent')||'[]');
    list=list.filter(function(x){return x.pass!==pass;});
    list.unshift({pass:pass,nick:nk||'',ts:Date.now()});
    localStorage.setItem('hidra_recent', JSON.stringify(list.slice(0,5)));
  }catch(e){}
}
function removeRecent(i){
  try{ var l=JSON.parse(localStorage.getItem('hidra_recent')||'[]'); l.splice(i,1); localStorage.setItem('hidra_recent',JSON.stringify(l)); renderRecent(); }catch(e){}
}
function renderRecent(){
  var list=[];
  try{ list=JSON.parse(localStorage.getItem('hidra_recent')||'[]'); }catch(e){}
  if(!list.length){ $('recentBox').classList.add('hidden'); return; }
  $('recentBox').classList.remove('hidden');
  $('recentList').innerHTML=list.map(function(x,i){
    var label=x.pass.length>24?x.pass.slice(0,24)+'…':x.pass;
    return '<span class="recent-chip" data-i="'+i+'">🔑 '+esc(label)+' <span class="rm" data-rm="'+i+'">✕</span></span>';
  }).join('');
  Array.prototype.forEach.call($('recentList').querySelectorAll('.recent-chip'),function(el){
    el.onclick=function(ev){
      var i=parseInt(el.getAttribute('data-i'),10);
      if(ev.target.hasAttribute('data-rm')){ ev.stopPropagation(); removeRecent(i); return; }
      var item=null; try{ item=JSON.parse(localStorage.getItem('hidra_recent')||'[]')[i]; }catch(e){}
      if(item){ inPass.value=item.pass; if(item.nick&&!inNick.value) inNick.value=item.nick; inNick.focus(); }
    };
  });
}
renderRecent();

// Show the host's shareable LAN address so they can invite friends
(function showMyAddr(){
  fetch('/api/whoami').then(function(r){return r.json()}).then(function(d){
    if(d&&d.lan_ip&&d.lan_ip!=='127.0.0.1'){
      var a=d.lan_ip+':'+(d.port||8081);
      var el=$('myAddrVal');
      el.textContent=a;
      el.onclick=function(){
        if(navigator.clipboard) navigator.clipboard.writeText(a);
        showToast();
      };
      $('myAddr').classList.remove('hidden');
    }
  }).catch(function(){});
})();

// ── WebSocket ──

function connectWS(){
  var host=serverAddr||location.host;
  var proto=(!serverAddr&&location.protocol==='https:')?'wss:':'ws:';
  try{
    ws=new WebSocket(proto+'//'+host+'/ws');
  }catch(e){
    $('connStatus').textContent='Endereço inválido';
    $('connStatus').className='status';
    return;
  }
  ws.onopen=function(){
    reconnAttempts=0;
    $('connStatus').textContent=serverAddr?('Conectado ('+host+')'):'Conectado';
    $('connStatus').className='status on';
    ws.send(JSON.stringify({type:'join',nick:nick,room:roomId}));
  };
  ws.onmessage=function(ev){
    try{handleMsg(JSON.parse(ev.data))}catch(e){}
  };
  ws.onclose=function(){
    $('connStatus').textContent='Desconectado';
    $('connStatus').className='status';
    if(reconnAttempts<MAX_RECONN){
      reconnAttempts++;
      var delay=Math.min(1000*Math.pow(1.5,reconnAttempts),20000);
      setTimeout(connectWS,delay);
    }
  };
  ws.onerror=function(){ws.close()};
}

// ── Message handling ──

function handleMsg(m){
  switch(m.type){
    case 'welcome':
      $('countBadge').textContent=m.count+' online';
      renderUsers(m.users);
      if(m.history&&m.history.length>0){
        m.history.forEach(function(h){if(h.type==='msg') renderChatMsg(h)});
        scrollBottom();
      }
      if(e2e) addSys('🔒 E2E ativo — mensagens criptografadas com AES-256-GCM (PBKDF2 100k)');
      else addSys('Conectado à sala #'+roomId+' — mensagens em texto claro');
      break;
    case 'joined':
      addSys(m.nick+' entrou na sala');
      $('countBadge').textContent=m.count+' online';
      addUser(m.nick,m.color);
      break;
    case 'left':
      addSys(m.nick+' saiu da sala');
      $('countBadge').textContent=m.count+' online';
      removeUser(m.nick);
      clearTyping(m.nick);
      break;
    case 'msg':
      renderChatMsg(m);
      if(m.nick!==nick) beep();
      break;
    case 'typing':
      if(m.nick!==nick) setTyping(m.nick,m.state);
      break;
    case 'error':
      addSys('⚠️ '+m.msg);
      break;
  }
}

async function renderChatMsg(m){
  var isOwn=m.cid?(m.cid===myCid):(m.nick===nick);
  var text;
  if(m.enc){
    text=await decryptMsg(m.enc);
    if(text===null) text=null;
  }else{
    text=m.text||'';
  }

  var el=document.createElement('div');
  el.className='msg '+(isOwn?'own':'other');

  var avatar='';
  if(!isOwn){
    var initials=m.nick.substring(0,2).toUpperCase();
    avatar='<div class="avatar" style="background:'+(m.color||'var(--accent)')+'">'+esc(initials)+'</div>';
  }

  var time=m.time?formatTime(m.time):'';
  var nickHtml=isOwn?'':'<span class="bubble-nick" style="color:'+(m.color||'var(--accent)')+'">'+esc(m.nick)+'</span>';
  var bodyHtml;
  if(text===null){
    bodyHtml='<div class="bubble-text encrypted">🔒 Mensagem criptografada — senha incorreta ou ausente</div>';
  }else{
    bodyHtml='<div class="bubble-text">'+esc(text)+'</div>';
  }

  el.innerHTML=avatar+
    '<div class="bubble">'+
      '<div class="bubble-header">'+nickHtml+'<span class="bubble-time">'+time+'</span></div>'+
      bodyHtml+
    '</div>';
  messagesEl.appendChild(el);
  autoScroll();
}

function addSys(text){
  var el=document.createElement('div');
  el.className='msg sys';
  el.innerHTML='<div class="bubble">'+esc(text)+'</div>';
  messagesEl.appendChild(el);
  autoScroll();
}

// ── User list ──

function renderUsers(list){
  var el=$('userList');el.innerHTML='';
  list.forEach(function(u){addUser(u.nick,u.color)});
}

function addUser(n,color){
  var el=$('userList');
  if(el.querySelector('[data-nick="'+CSS.escape(n)+'"]')) return;
  var d=document.createElement('div');
  d.className='user-item';d.dataset.nick=n;
  d.innerHTML='<span class="user-dot" style="background:'+(color||'var(--accent)')+'"></span><span class="user-nick">'+esc(n)+'</span>';
  el.appendChild(d);
}

function removeUser(n){
  var el=$('userList').querySelector('[data-nick="'+CSS.escape(n)+'"]');
  if(el) el.remove();
}

// ── Typing ──

function setTyping(who,state){
  if(state) typingUsers[who]=Date.now();
  else delete typingUsers[who];
  renderTyping();
}

function clearTyping(who){delete typingUsers[who];renderTyping();}

function renderTyping(){
  var names=Object.keys(typingUsers);
  var bar=$('typingBar');
  if(names.length===0){bar.innerHTML='';return}
  var dots='<span class="dots"><span></span><span></span><span></span></span>';
  if(names.length===1) bar.innerHTML=esc(names[0])+' está digitando'+dots;
  else if(names.length===2) bar.innerHTML=esc(names[0])+' e '+esc(names[1])+' estão digitando'+dots;
  else bar.innerHTML=names.length+' pessoas digitando'+dots;
}

// ── Stale typing cleanup ──
setInterval(function(){
  var now=Date.now(),changed=false;
  Object.keys(typingUsers).forEach(function(k){
    if(now-typingUsers[k]>4000){delete typingUsers[k];changed=true}
  });
  if(changed) renderTyping();
},2000);

// ── Send ──

async function sendMessage(){
  var text=msgInput.value.trim();
  if(!text) return;
  if(mode==='relay'){
    var ts=Date.now();
    relayPublish({k:'msg',nick:nick,color:myColor,text:text,t:ts,cid:myCid});
    renderChatMsg({nick:nick,color:myColor,text:text,time:ts,cid:myCid}); // eco local: aparece na hora
    msgInput.value='';
    sendTypingState(false);
    return;
  }
  if(!ws||ws.readyState!==1) return;
  var payload={type:'msg'};
  if(e2e){
    var enc=await encryptMsg(text);
    if(!enc){addSys('Erro ao criptografar');return}
    payload.enc=enc;
  }else{
    payload.text=text;
  }
  ws.send(JSON.stringify(payload));
  msgInput.value='';
  sendTypingState(false);
}

$('sendBtn').onclick=sendMessage;
msgInput.onkeydown=function(e){
  if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendMessage()}
};

// ── Typing indicator (debounced) ──

msgInput.oninput=function(){
  if(!myTyping){
    myTyping=true;
    sendTypingState(true);
  }
  clearTimeout(typingTimeout);
  typingTimeout=setTimeout(function(){
    myTyping=false;
    sendTypingState(false);
  },2000);
};

function sendTypingState(state){
  if(mode==='relay'){relayPublish({k:'typing',nick:nick,cid:myCid,state:state,t:Date.now()});return}
  if(ws&&ws.readyState===1) ws.send(JSON.stringify({type:'typing',state:state}));
}

// ── Helpers ──

function esc(s){var d=document.createElement('div');d.textContent=s;return d.innerHTML}

function formatTime(ts){
  var d=new Date(ts);
  return d.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'});
}

var scrollLock=false;
function autoScroll(){
  if(scrollLock) return;
  messagesEl.scrollTop=messagesEl.scrollHeight;
}
function scrollBottom(){messagesEl.scrollTop=messagesEl.scrollHeight}

messagesEl.onscroll=function(){
  var diff=messagesEl.scrollHeight-messagesEl.scrollTop-messagesEl.clientHeight;
  scrollLock=diff>80;
};

window.copyRoom=function(){
  var code=$('roomCode').textContent;
  if(navigator.clipboard){
    navigator.clipboard.writeText(code).then(function(){showToast()});
  }else{
    var ta=document.createElement('textarea');ta.value=code;
    document.body.appendChild(ta);ta.select();document.execCommand('copy');
    document.body.removeChild(ta);showToast();
  }
};

$('roomTag').onclick=function(){window.copyRoom()};

function showToast(){
  var t=$('toast');t.classList.add('show');
  setTimeout(function(){t.classList.remove('show')},1500);
}

})();
</script>
</body>
</html>"##;
}
