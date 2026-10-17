//! HidraRelay: the project's own relay for the chat and the forum.
//!
//! The browser's chat and forum pages meet each other through MQTT over
//! WebSocket. Until now the only servers they knew were public brokers run
//! by third parties, which carried the project's encrypted traffic and saw
//! its metadata: which topics exist, who connects when, how much is said.
//! This is a server the project runs itself. It speaks the same MQTT the
//! pages already speak (3.1.1, over WebSocket, subprotocol `mqtt`), so the
//! pages change nothing but the address.
//!
//! What it does that a public broker does not:
//!
//! - keeps only the project's topics (`hidra/...` and `hforum/...`), with
//!   limits on message size, retained messages, subscriptions and rate, so
//!   that one client cannot fill it;
//! - keeps retained messages on disk, in SQLite, so that the forum survives
//!   a restart;
//! - logs counts, never topics, payloads, client ids or addresses;
//! - leaves a place (`Policy`) for the forum's rules to be enforced here,
//!   where a relay run by the project can refuse a post whose signature does
//!   not hold or a claim on a name already taken.
//!
//! It listens on loopback for plain `ws://`; a reverse proxy such as Caddy
//! in front of it gives `wss://` and the certificate. See
//! `hidra-browser/tools/README.md`.
//!
//! Supported: CONNECT (protocol level 4, clean session), PUBLISH at QoS 0
//! and 1 (acknowledged, delivered at QoS 0), retained messages, SUBSCRIBE
//! and UNSUBSCRIBE with `+` and `#`, PINGREQ, DISCONNECT. Not supported, on
//! purpose: QoS 2, wills, persistent sessions, MQTT 5.

// The `hidra-node` binary compiles this module along with the rest of the
// library's `apps` but never calls it: the relay has a binary of its own,
// `hidra-relay`. Without this the binary's `deny(warnings)` would refuse the
// code it does not use.
#![allow(dead_code)]

pub mod forum;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};

use crate::error::{HidraError, Result};
use crate::safelog::sensitive;

// ── Limits ─────────────────────────────────────────────────────────────

/// The topic trees this relay carries. Anything else is refused at
/// publish and at subscribe.
pub const ALLOWED_PREFIXES: &[&str] = &["hidra/", "hforum/"];
/// The largest message on an ordinary topic. A chat message is a few
/// kilobytes; a forum post is bounded by the page at 20 000 characters.
pub const MAX_PAYLOAD: usize = 64 * 1024;
/// The registrar's list may be larger; it is bounded on its side at 512 KB.
pub const MAX_REGISTRY_PAYLOAD: usize = 1024 * 1024;
pub const REGISTRY_TOPIC: &str = "hforum/registry";
pub const MAX_TOPIC_BYTES: usize = 256;
pub const MAX_CLIENTS: usize = 4096;
pub const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 32;
/// What is kept in all. A new subscriber to the forum receives all of it,
/// so this is also the most a page is ever asked to load.
pub const MAX_RETAINED_MESSAGES: usize = 200_000;
pub const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;
/// Packets per second a client may sustain after CONNECT, and the burst
/// it may make. A chat sends a message or a presence beacon every few
/// seconds; the forum, a few messages a minute. Every packet counts, and a
/// subscription counts once per filter.
pub const RATE_PER_SECOND: f64 = 10.0;
pub const RATE_BURST: f64 = 60.0;
/// Frames, and bytes, queued for a client that is not reading. Past either
/// the client is dropped: a slow reader must not hold memory for everyone
/// else.
pub const OUTBOUND_QUEUE: usize = 512;
pub const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// What a filter in a SUBSCRIBE costs in tokens: a new subscription is a
/// pass over everything kept, so it is dearer than a publish. And how many
/// SUBSCRIBE packets one connection may send in its life; the pages send
/// one or two.
pub const SUBSCRIBE_COST: u32 = 5;
pub const MAX_SUBSCRIBES_PER_CONNECTION: u32 = 256;
/// How long the relay waits for room in a client's queue before letting
/// the client go.
pub const WRITE_SECS: u64 = 15;
/// A connection that has not completed the handshake and sent CONNECT
/// within this long of being accepted is closed.
pub const CONNECT_SECS: u64 = 10;
/// Keep-alive used when the client asks for none, and the most a client
/// may ask for: an idle connection is closed at one and a half times it.
pub const DEFAULT_KEEPALIVE_SECS: u64 = 300;
pub const MAX_KEEPALIVE_SECS: u64 = 600;
pub const MAX_PACKET: usize = MAX_REGISTRY_PAYLOAD + MAX_TOPIC_BYTES + 16;
/// Writes waiting for the store's thread, and how many it commits at once.
pub const STORE_QUEUE: usize = 4096;
pub const STORE_BATCH: usize = 256;

// ── MQTT 3.1.1 packets ─────────────────────────────────────────────────

pub mod mqtt {
    //! Just enough of MQTT 3.1.1 for the pages' client, parsed by hand.

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Packet {
        Connect {
            level: u8,
            keepalive: u16,
            client_id: String,
            has_will: bool,
        },
        Publish {
            topic: String,
            qos: u8,
            retain: bool,
            packet_id: Option<u16>,
            payload: Vec<u8>,
        },
        Subscribe {
            packet_id: u16,
            filters: Vec<(String, u8)>,
        },
        Unsubscribe {
            packet_id: u16,
            filters: Vec<String>,
        },
        PingReq,
        Disconnect,
        /// A packet type this relay does not take (PUBREC and friends, or a
        /// server-only packet sent by a client).
        Unsupported(u8),
    }

    /// What `parse` says about the front of a buffer.
    pub enum Parsed {
        /// Not a whole packet yet.
        Incomplete,
        /// The header announces more than the relay accepts.
        TooLarge,
        /// Not MQTT.
        Malformed,
        Ready {
            packet: Packet,
            consumed: usize,
        },
    }

    fn read_u16(b: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
    }

    fn read_str(b: &[u8], at: usize) -> Option<(String, usize)> {
        let len = read_u16(b, at)? as usize;
        let s = b.get(at + 2..at + 2 + len)?;
        let s = std::str::from_utf8(s).ok()?;
        if s.contains('\0') {
            return None;
        }
        Some((s.to_string(), at + 2 + len))
    }

    /// Parses one packet from the front of `buf`, if a whole one is there.
    pub fn parse(buf: &[u8], max_packet: usize) -> Parsed {
        if buf.len() < 2 {
            return Parsed::Incomplete;
        }
        let first = buf[0];
        let kind = first >> 4;
        let flags = first & 0x0f;
        // Remaining length: up to four bytes, seven bits each.
        let mut remaining: usize = 0;
        let mut mult: usize = 1;
        let mut i = 1;
        loop {
            let Some(&b) = buf.get(i) else {
                return Parsed::Incomplete;
            };
            remaining += (b & 0x7f) as usize * mult;
            i += 1;
            if b & 0x80 == 0 {
                break;
            }
            if i > 4 {
                return Parsed::Malformed;
            }
            mult *= 128;
        }
        if remaining > max_packet {
            return Parsed::TooLarge;
        }
        let total = i + remaining;
        if buf.len() < total {
            return Parsed::Incomplete;
        }
        let body = &buf[i..total];
        let packet = match kind {
            1 => {
                let Some((name, at)) = read_str(body, 0) else {
                    return Parsed::Malformed;
                };
                if name != "MQTT" && name != "MQIsdp" {
                    return Parsed::Malformed;
                }
                let Some(&level) = body.get(at) else {
                    return Parsed::Malformed;
                };
                let Some(&cflags) = body.get(at + 1) else {
                    return Parsed::Malformed;
                };
                let Some(keepalive) = read_u16(body, at + 2) else {
                    return Parsed::Malformed;
                };
                let Some((client_id, _)) = read_str(body, at + 4) else {
                    return Parsed::Malformed;
                };
                Packet::Connect {
                    level,
                    keepalive,
                    client_id,
                    has_will: cflags & 0x04 != 0,
                }
            }
            3 => {
                let qos = (flags >> 1) & 0x03;
                if qos == 3 {
                    return Parsed::Malformed;
                }
                let retain = flags & 0x01 != 0;
                let Some((topic, mut at)) = read_str(body, 0) else {
                    return Parsed::Malformed;
                };
                let packet_id = if qos > 0 {
                    let Some(id) = read_u16(body, at) else {
                        return Parsed::Malformed;
                    };
                    at += 2;
                    Some(id)
                } else {
                    None
                };
                Packet::Publish {
                    topic,
                    qos,
                    retain,
                    packet_id,
                    payload: body[at..].to_vec(),
                }
            }
            8 => {
                if flags != 0x02 {
                    return Parsed::Malformed;
                }
                let Some(packet_id) = read_u16(body, 0) else {
                    return Parsed::Malformed;
                };
                let mut at = 2;
                let mut filters = Vec::new();
                while at < body.len() {
                    let Some((f, next)) = read_str(body, at) else {
                        return Parsed::Malformed;
                    };
                    let Some(&q) = body.get(next) else {
                        return Parsed::Malformed;
                    };
                    filters.push((f, q & 0x03));
                    at = next + 1;
                }
                if filters.is_empty() {
                    return Parsed::Malformed;
                }
                Packet::Subscribe { packet_id, filters }
            }
            10 => {
                if flags != 0x02 {
                    return Parsed::Malformed;
                }
                let Some(packet_id) = read_u16(body, 0) else {
                    return Parsed::Malformed;
                };
                let mut at = 2;
                let mut filters = Vec::new();
                while at < body.len() {
                    let Some((f, next)) = read_str(body, at) else {
                        return Parsed::Malformed;
                    };
                    filters.push(f);
                    at = next;
                }
                Packet::Unsubscribe { packet_id, filters }
            }
            12 => Packet::PingReq,
            14 => Packet::Disconnect,
            other => Packet::Unsupported(other),
        };
        Parsed::Ready {
            packet,
            consumed: total,
        }
    }

    fn encode_len(mut n: usize, out: &mut Vec<u8>) {
        loop {
            let mut b = (n % 128) as u8;
            n /= 128;
            if n > 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
    }

    fn packet(first: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + 5);
        out.push(first);
        encode_len(body.len(), &mut out);
        out.extend_from_slice(body);
        out
    }

    pub fn connack(code: u8) -> Vec<u8> {
        vec![0x20, 0x02, 0x00, code]
    }

    pub fn puback(id: u16) -> Vec<u8> {
        let b = id.to_be_bytes();
        vec![0x40, 0x02, b[0], b[1]]
    }

    pub fn suback(id: u16, codes: &[u8]) -> Vec<u8> {
        let mut body = id.to_be_bytes().to_vec();
        body.extend_from_slice(codes);
        packet(0x90, &body)
    }

    pub fn unsuback(id: u16) -> Vec<u8> {
        let b = id.to_be_bytes();
        vec![0xb0, 0x02, b[0], b[1]]
    }

    pub fn pingresp() -> Vec<u8> {
        vec![0xd0, 0x00]
    }

    /// A PUBLISH as delivered to a subscriber: QoS 0, retain flag as given.
    pub fn publish(topic: &str, payload: &[u8], retain: bool) -> Vec<u8> {
        let mut body = (topic.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(payload);
        packet(0x30 | u8::from(retain), &body)
    }

    /// Return code 0x80 in a SUBACK: that filter was refused.
    pub const SUBACK_FAILURE: u8 = 0x80;
    /// CONNACK: unacceptable protocol version.
    pub const CONNACK_BAD_PROTOCOL: u8 = 0x01;
    /// CONNACK: not authorised (used for a will, which this relay refuses).
    pub const CONNACK_NOT_AUTHORISED: u8 = 0x05;
}

// ── Topics and filters ─────────────────────────────────────────────────

pub fn allowed_topic(topic: &str) -> bool {
    !topic.is_empty()
        && topic.len() <= MAX_TOPIC_BYTES
        && !topic.contains(['#', '+', '\0'])
        && ALLOWED_PREFIXES.iter().any(|p| topic.starts_with(p))
}

/// A subscription filter is kept only when every wildcard is where MQTT
/// allows one and the first segment names one of the trees this relay
/// carries; `#` alone, or `+/...`, would subscribe to everything.
pub fn allowed_filter(filter: &str) -> bool {
    if filter.is_empty() || filter.len() > MAX_TOPIC_BYTES || filter.contains('\0') {
        return false;
    }
    let segs: Vec<&str> = filter.split('/').collect();
    let first = segs[0];
    if !ALLOWED_PREFIXES
        .iter()
        .any(|p| p.trim_end_matches('/') == first)
    {
        return false;
    }
    for (i, s) in segs.iter().enumerate() {
        if *s == "#" {
            if i != segs.len() - 1 {
                return false;
            }
        } else if s.contains(['#', '+']) && *s != "+" {
            return false;
        }
    }
    true
}

pub fn matches(filter: &str, topic: &str) -> bool {
    let mut f = filter.split('/');
    let mut t = topic.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => {}
            (Some(a), Some(b)) if a == b => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

// ── Rate limiting ──────────────────────────────────────────────────────

/// A token bucket: `RATE_PER_SECOND` sustained, `RATE_BURST` at once.
pub struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: RATE_BURST,
            last: now,
        }
    }

    pub fn take(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * RATE_PER_SECOND).min(RATE_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ── Policy: where the forum's rules can live ───────────────────────────

/// What a policy established about a publish before the relay's lock was
/// taken; opaque to the relay, read back by the same policy in `admit`.
pub type Prepared = Box<dyn std::any::Any + Send + Sync>;

/// What the relay does with a publish beyond the generic limits. The
/// default lets everything through; the forum policy refuses a claim on a
/// taken name or a post whose signature does not hold.
///
/// Two halves, so that the costly part never holds the lock: `prepare`
/// sees the publish alone and does the parsing and the signature checks;
/// `admit` sees what is kept and does the comparisons.
pub trait Policy: Send + Sync {
    /// `Err(reason)` refuses the publish; the reason is for the log only.
    fn prepare(
        &self,
        _topic: &str,
        _payload: &[u8],
        _retain: bool,
    ) -> std::result::Result<Prepared, &'static str> {
        Ok(Box::new(()))
    }

    /// `Some(reason)` refuses the publish, under the lock, against what is
    /// kept. Called only when the publish also fits the generic caps, so
    /// `None` means it is about to be kept and delivered.
    fn admit(
        &self,
        _prepared: &Prepared,
        _topic: &str,
        _retain: bool,
        _retained: &Retained,
    ) -> Option<&'static str> {
        None
    }
}

pub struct OpenPolicy;
impl Policy for OpenPolicy {}

// ── What is retained ───────────────────────────────────────────────────

/// The last retained message per topic, with the bookkeeping the limits
/// and the policies need: bytes in all, a count per kind of topic, and
/// which topic holds each post id. Payloads are shared, so a subscriber's
/// snapshot of the store costs a pointer per message, not a copy.
#[derive(Default)]
pub struct Retained {
    map: HashMap<String, Arc<[u8]>>,
    bytes: usize,
    counts: HashMap<String, usize>,
    ids: HashMap<String, String>,
}

/// The kind of a topic for counting: its first two segments
/// (`hforum/rep`, `hforum/t`), or the whole topic when it has fewer.
fn class(topic: &str) -> &str {
    match topic.match_indices('/').nth(1) {
        Some((i, _)) => &topic[..i],
        None => topic,
    }
}

/// The post id a forum topic names, if it is a post or reply topic.
fn post_id(topic: &str) -> Option<&str> {
    if let Some(id) = topic.strip_prefix("hforum/t/") {
        return (!id.contains('/')).then_some(id);
    }
    let (_, id) = topic.strip_prefix("hforum/r/")?.split_once('/')?;
    (!id.contains('/')).then_some(id)
}

impl Retained {
    pub fn get(&self, topic: &str) -> Option<&[u8]> {
        self.map.get(topic).map(|p| &p[..])
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// How many topics of this kind (see `class`) are kept.
    pub fn count(&self, class: &str) -> usize {
        self.counts.get(class).copied().unwrap_or(0)
    }

    /// The topic that holds a post id, if any.
    pub fn topic_of_id(&self, id: &str) -> Option<&str> {
        self.ids.get(id).map(String::as_str)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<[u8]>)> {
        self.map.iter().map(|(t, p)| (t.as_str(), p))
    }

    /// Whether a payload of this size fits under the caps, counting what
    /// the topic already holds as replaced.
    pub fn fits(&self, topic: &str, len: usize) -> bool {
        let old = self.map.get(topic).map(|p| p.len()).unwrap_or(0);
        (self.map.contains_key(topic) || self.map.len() < MAX_RETAINED_MESSAGES)
            && self.bytes - old + len <= MAX_RETAINED_BYTES
    }

    pub fn insert(&mut self, topic: &str, payload: Arc<[u8]>) {
        self.remove(topic);
        self.bytes += payload.len();
        *self.counts.entry(class(topic).to_string()).or_insert(0) += 1;
        if let Some(id) = post_id(topic) {
            self.ids.insert(id.to_string(), topic.to_string());
        }
        self.map.insert(topic.to_string(), payload);
    }

    /// Returns whether there was anything to remove.
    pub fn remove(&mut self, topic: &str) -> bool {
        let Some(old) = self.map.remove(topic) else {
            return false;
        };
        self.bytes -= old.len();
        if let Some(n) = self.counts.get_mut(class(topic)) {
            *n = n.saturating_sub(1);
        }
        if let Some(id) = post_id(topic) {
            if self.ids.get(id).is_some_and(|t| t == topic) {
                self.ids.remove(id);
            }
        }
        true
    }
}

// ── Retained store on disk ─────────────────────────────────────────────

enum StoreOp {
    Put(String, Arc<[u8]>),
    Delete(String),
}

/// Retained messages in SQLite, written by one thread in batches so the
/// async side never blocks on disk. The queue to that thread is bounded:
/// when the disk cannot keep up, a write is dropped and counted rather
/// than kept in memory without end.
pub struct Store {
    tx: std::sync::mpsc::SyncSender<StoreOp>,
    dropped: AtomicU64,
}

fn write_batch(
    conn: &mut rusqlite::Connection,
    ops: Vec<StoreOp>,
    now: i64,
) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    for op in ops {
        match op {
            StoreOp::Put(topic, payload) => {
                tx.execute(
                    "INSERT OR REPLACE INTO retained (topic, payload, ts) VALUES (?1, ?2, ?3)",
                    rusqlite::params![topic, &payload[..], now],
                )?;
            }
            StoreOp::Delete(topic) => {
                tx.execute(
                    "DELETE FROM retained WHERE topic = ?1",
                    rusqlite::params![topic],
                )?;
            }
        }
    }
    tx.commit()
}

impl Store {
    pub fn open(path: &std::path::Path) -> Result<(Self, Retained)> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut conn = rusqlite::Connection::open(path)
            .map_err(|e| HidraError::Protocol(format!("relay store: {e}")))?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;\n\
             PRAGMA synchronous=NORMAL;\n\
             CREATE TABLE IF NOT EXISTS retained (\n\
                 topic TEXT PRIMARY KEY,\n\
                 payload BLOB NOT NULL,\n\
                 ts INTEGER NOT NULL\n\
             );",
        )
        .map_err(|e| HidraError::Protocol(format!("relay store schema: {e}")))?;
        let mut loaded = Retained::default();
        {
            let mut stmt = conn
                .prepare("SELECT topic, payload FROM retained")
                .map_err(|e| HidraError::Protocol(format!("relay store read: {e}")))?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|e| HidraError::Protocol(format!("relay store read: {e}")))?;
            for row in rows.flatten() {
                loaded.insert(&row.0, row.1.into());
            }
        }
        let (tx, rx) = std::sync::mpsc::sync_channel::<StoreOp>(STORE_QUEUE);
        std::thread::Builder::new()
            .name("hidra-relay-store".into())
            .spawn(move || {
                while let Ok(first) = rx.recv() {
                    let mut batch = vec![first];
                    while batch.len() < STORE_BATCH {
                        match rx.try_recv() {
                            Ok(op) => batch.push(op),
                            Err(_) => break,
                        }
                    }
                    let now = chrono::Utc::now().timestamp_millis();
                    if let Err(e) = write_batch(&mut conn, batch, now) {
                        warn!(error = %e, "relay store write failed");
                    }
                }
            })
            .map_err(|e| HidraError::Protocol(format!("relay store thread: {e}")))?;
        Ok((
            Self {
                tx,
                dropped: AtomicU64::new(0),
            },
            loaded,
        ))
    }

    fn send(&self, op: StoreOp) {
        if self.tx.try_send(op).is_err() {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if n == 1 || n % 1000 == 0 {
                warn!(
                    dropped = n,
                    "relay store cannot keep up; retained writes were not persisted"
                );
            }
        }
    }

    fn put(&self, topic: &str, payload: &Arc<[u8]>) {
        self.send(StoreOp::Put(topic.to_string(), Arc::clone(payload)));
    }

    fn delete(&self, topic: &str) {
        self.send(StoreOp::Delete(topic.to_string()));
    }
}

// ── The broker ─────────────────────────────────────────────────────────

/// A frame as queued for clients: one copy, shared by every subscriber's
/// queue, so a publish to many costs the relay one frame, not one per
/// client. The copy to the socket is made one frame at a time, when sent.
type Frame = Arc<[u8]>;

/// Everything written to one client: a bounded queue to its writer task,
/// bounded in frames and in bytes. A client that stops reading fills it
/// and is dropped, instead of holding the broker's lock or memory.
#[derive(Clone)]
struct Outbox {
    tx: mpsc::Sender<Frame>,
    queued: Arc<AtomicUsize>,
}

impl Outbox {
    /// For the fan-out under the lock: never waits. Hands the frame back
    /// when there is no room, so the caller can decide what that means.
    fn try_push(&self, frame: Frame) -> std::result::Result<(), Frame> {
        let len = frame.len();
        if self.queued.load(Ordering::Relaxed) + len > MAX_QUEUE_BYTES {
            return Err(frame);
        }
        match self.tx.try_send(frame) {
            Ok(()) => {
                self.queued.fetch_add(len, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(e.into_inner()),
        }
    }

    /// For the connection's own replies: waits for room, but not for ever.
    /// `false` means the client is not reading and is to be let go.
    async fn push(&self, frame: Frame) -> bool {
        let len = frame.len();
        let until = Instant::now() + Duration::from_secs(WRITE_SECS);
        while self.queued.load(Ordering::Relaxed) + len > MAX_QUEUE_BYTES {
            if Instant::now() >= until {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        match tokio::time::timeout_at(until.into(), self.tx.send(frame)).await {
            Ok(Ok(())) => {
                self.queued.fetch_add(len, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }
}

struct ClientEntry {
    outbox: Outbox,
    filters: Vec<String>,
    /// Set while the connection is sending this client the retained
    /// messages of a new subscription; live messages are held in
    /// `deferred` meanwhile so that they follow, not precede, the retained
    /// copies.
    loading: bool,
    deferred: Vec<Frame>,
    deferred_bytes: usize,
    /// Told when the broker drops the client (a slow reader); the
    /// connection task ends on it.
    close: Arc<tokio::sync::Notify>,
}

struct Shared {
    retained: Retained,
    clients: HashMap<u64, ClientEntry>,
    store: Option<Store>,
    /// Counters for the periodic log line.
    published: u64,
    refused: u64,
    dropped_slow: u64,
}

impl Shared {
    fn drop_client(&mut self, id: u64) {
        if let Some(c) = self.clients.remove(&id) {
            c.close.notify_one();
            self.dropped_slow += 1;
        }
    }
}

pub struct RelayConfig {
    pub listen: SocketAddr,
    /// Where retained messages are kept; None keeps them in memory only.
    pub data_dir: Option<PathBuf>,
    pub policy: Arc<dyn Policy>,
}

pub struct Relay {
    listener: TcpListener,
    shared: Arc<Mutex<Shared>>,
    policy: Arc<dyn Policy>,
    next_id: Arc<AtomicU64>,
    clients: Arc<tokio::sync::Semaphore>,
}

impl Relay {
    pub async fn bind(cfg: RelayConfig) -> Result<Self> {
        let (store, retained) = match &cfg.data_dir {
            Some(dir) => {
                let (s, r) = Store::open(&dir.join("retained.sqlite"))?;
                (Some(s), r)
            }
            None => (None, Retained::default()),
        };
        let listener = TcpListener::bind(cfg.listen).await?;
        info!(
            retained = retained.len(),
            retained_bytes = retained.bytes(),
            "HidraRelay listening"
        );
        Ok(Self {
            listener,
            shared: Arc::new(Mutex::new(Shared {
                retained,
                clients: HashMap::new(),
                store,
                published: 0,
                refused: 0,
                dropped_slow: 0,
            })),
            policy: cfg.policy,
            next_id: Arc::new(AtomicU64::new(1)),
            clients: Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn serve(self) -> Result<()> {
        let shared_for_log = Arc::clone(&self.shared);
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(600));
            t.tick().await;
            loop {
                t.tick().await;
                let s = shared_for_log.lock().await;
                info!(
                    clients = s.clients.len(),
                    retained = s.retained.len(),
                    retained_bytes = s.retained.bytes(),
                    published = s.published,
                    refused = s.refused,
                    dropped_slow = s.dropped_slow,
                    "relay"
                );
            }
        });
        loop {
            let (stream, peer) = match self.listener.accept().await {
                Ok(s) => s,
                Err(e) => {
                    warn!(error = %e, "accept error");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&self.clients).try_acquire_owned() else {
                debug!(peer = %sensitive(&peer), "relay full; connection refused");
                drop(stream);
                continue;
            };
            let shared = Arc::clone(&self.shared);
            let policy = Arc::clone(&self.policy);
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle(stream, peer, id, shared, policy).await {
                    debug!(peer = %sensitive(&peer), error = %e, "relay connection ended");
                }
            });
        }
    }
}

/// Accepts the WebSocket handshake. The pages ask for the `mqtt`
/// subprotocol and a browser closes the socket if the server does not
/// answer with it; anything else is a plain WebSocket and is served too.
#[allow(clippy::result_large_err)]
fn accept_handshake(
    req: &Request,
    mut resp: Response,
) -> std::result::Result<Response, ErrorResponse> {
    let wants_mqtt = req
        .headers()
        .get_all("sec-websocket-protocol")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|p| p.trim().eq_ignore_ascii_case("mqtt"));
    if wants_mqtt {
        resp.headers_mut().insert(
            "sec-websocket-protocol",
            http::HeaderValue::from_static("mqtt"),
        );
    }
    Ok(resp)
}

fn protocol(msg: impl Into<String>) -> HidraError {
    HidraError::Protocol(msg.into())
}

async fn handle(
    stream: TcpStream,
    _peer: SocketAddr,
    id: u64,
    shared: Arc<Mutex<Shared>>,
    policy: Arc<dyn Policy>,
) -> Result<()> {
    // The WebSocket layer would otherwise buffer up to 64 MiB a message
    // before the relay saw a byte of it.
    let ws_config = WebSocketConfig {
        max_message_size: Some(MAX_PACKET + 16),
        max_frame_size: Some(MAX_PACKET + 16),
        ..Default::default()
    };
    // One deadline for the handshake and the CONNECT together, fixed at
    // accept: frames that are not CONNECT do not extend it.
    let connect_by = Instant::now() + Duration::from_secs(CONNECT_SECS);
    let ws = tokio::time::timeout_at(
        connect_by.into(),
        tokio_tungstenite::accept_hdr_async_with_config(stream, accept_handshake, Some(ws_config)),
    )
    .await
    .map_err(|_| protocol("handshake timeout"))?
    .map_err(|e| protocol(format!("websocket handshake: {e}")))?;
    let (mut sink, mut source) = ws.split();

    let (tx, mut rx) = mpsc::channel::<Frame>(OUTBOUND_QUEUE);
    let queued = Arc::new(AtomicUsize::new(0));
    let outbox = Outbox {
        tx,
        queued: Arc::clone(&queued),
    };
    let mut writer = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            queued.fetch_sub(bytes.len(), Ordering::Relaxed);
            if sink.send(Message::Binary(bytes.to_vec())).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    let close = Arc::new(tokio::sync::Notify::new());

    let mut buf: Vec<u8> = Vec::new();
    let mut connected = false;
    let mut bucket = Bucket::new(Instant::now());
    let mut idle = Duration::from_secs(CONNECT_SECS);
    let mut subscribes: u32 = 0;

    let outcome: Result<()> = 'conn: loop {
        let next = async {
            if connected {
                tokio::time::timeout(idle, source.next()).await
            } else {
                tokio::time::timeout_at(connect_by.into(), source.next()).await
            }
        };
        let frame = tokio::select! {
            _ = close.notified() => break 'conn Err(protocol("dropped: not reading")),
            r = next => match r {
                Err(_) => break 'conn Ok(()), // silent past the keep-alive
                Ok(None) | Ok(Some(Err(_))) => break 'conn Ok(()),
                Ok(Some(Ok(m))) => m,
            },
        };
        match frame {
            Message::Binary(b) => buf.extend_from_slice(&b),
            Message::Text(t) => buf.extend_from_slice(t.as_bytes()),
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => break 'conn Ok(()),
            Message::Frame(_) => continue,
        }
        if buf.len() > MAX_PACKET + 16 {
            break 'conn Err(protocol("packet over the limit"));
        }
        // Packets are parsed from an offset and the buffer trimmed once per
        // frame, not once per packet.
        let mut off = 0;
        loop {
            let (packet, consumed) = match mqtt::parse(&buf[off..], MAX_PACKET) {
                mqtt::Parsed::Incomplete => break,
                mqtt::Parsed::TooLarge => break 'conn Err(protocol("packet over the limit")),
                mqtt::Parsed::Malformed => break 'conn Err(protocol("not MQTT")),
                mqtt::Parsed::Ready { packet, consumed } => (packet, consumed),
            };
            off += consumed;
            if !connected {
                let mqtt::Packet::Connect {
                    level,
                    keepalive: k,
                    has_will,
                    ..
                } = packet
                else {
                    break 'conn Err(protocol("first packet was not CONNECT"));
                };
                if level != 4 && level != 3 {
                    outbox
                        .push(mqtt::connack(mqtt::CONNACK_BAD_PROTOCOL).into())
                        .await;
                    break 'conn Ok(());
                }
                if has_will {
                    outbox
                        .push(mqtt::connack(mqtt::CONNACK_NOT_AUTHORISED).into())
                        .await;
                    break 'conn Ok(());
                }
                let keepalive = if k == 0 {
                    DEFAULT_KEEPALIVE_SECS
                } else {
                    u64::from(k).min(MAX_KEEPALIVE_SECS)
                };
                idle = Duration::from_secs(keepalive).mul_f32(1.5);
                shared.lock().await.clients.insert(
                    id,
                    ClientEntry {
                        outbox: outbox.clone(),
                        filters: Vec::new(),
                        loading: false,
                        deferred: Vec::new(),
                        deferred_bytes: 0,
                        close: Arc::clone(&close),
                    },
                );
                connected = true;
                if !outbox.push(mqtt::connack(0).into()).await {
                    break 'conn Ok(());
                }
                continue;
            }
            // Every packet after CONNECT costs a token: a flood of pings or
            // subscriptions is a flood.
            if !bucket.take(Instant::now()) {
                break 'conn Err(protocol("rate exceeded"));
            }
            match packet {
                mqtt::Packet::Connect { .. } => break 'conn Err(protocol("second CONNECT")),
                mqtt::Packet::PingReq => {
                    if !outbox.push(mqtt::pingresp().into()).await {
                        break 'conn Ok(());
                    }
                }
                mqtt::Packet::Disconnect => break 'conn Ok(()),
                mqtt::Packet::Unsupported(kind) => {
                    break 'conn Err(protocol(format!("unsupported packet type {kind}")));
                }
                mqtt::Packet::Subscribe { packet_id, filters } => {
                    if filters.len() > MAX_SUBSCRIPTIONS_PER_CLIENT {
                        break 'conn Err(protocol("too many filters in one SUBSCRIBE"));
                    }
                    subscribes += 1;
                    if subscribes > MAX_SUBSCRIBES_PER_CONNECTION {
                        break 'conn Err(protocol("too many SUBSCRIBE packets"));
                    }
                    // A subscription costs a pass over everything kept:
                    // SUBSCRIBE_COST tokens per filter (one was taken above).
                    for _ in 1..(filters.len() as u32 * SUBSCRIBE_COST) {
                        if !bucket.take(Instant::now()) {
                            break 'conn Err(protocol("rate exceeded"));
                        }
                    }
                    let mut codes = Vec::with_capacity(filters.len());
                    let mut snapshot: Vec<(String, Arc<[u8]>)> = Vec::new();
                    {
                        let mut s = shared.lock().await;
                        let Shared {
                            clients, retained, ..
                        } = &mut *s;
                        let Some(c) = clients.get_mut(&id) else {
                            break 'conn Err(protocol("dropped: not reading"));
                        };
                        for (f, _q) in &filters {
                            if !allowed_filter(f) {
                                codes.push(mqtt::SUBACK_FAILURE);
                            } else if c.filters.contains(f) {
                                // Held already: granted again, nothing more
                                // to send. This is also what makes the same
                                // filter repeated in one packet cost one pass.
                                codes.push(0);
                            } else if c.filters.len() >= MAX_SUBSCRIPTIONS_PER_CLIENT {
                                codes.push(mqtt::SUBACK_FAILURE);
                            } else {
                                c.filters.push(f.clone());
                                codes.push(0);
                                for (t, p) in retained.iter() {
                                    if matches(f, t) {
                                        snapshot.push((t.to_string(), Arc::clone(p)));
                                    }
                                }
                            }
                        }
                        if !snapshot.is_empty() {
                            c.loading = true;
                        }
                    }
                    if !outbox.push(mqtt::suback(packet_id, &codes).into()).await {
                        break 'conn Ok(());
                    }
                    for (t, p) in snapshot {
                        if !outbox.push(mqtt::publish(&t, &p, true).into()).await {
                            break 'conn Ok(());
                        }
                    }
                    // What arrived live meanwhile was held back; it goes out
                    // now, under the lock so nothing newer overtakes it, and
                    // whatever the queue cannot take at once is sent with
                    // back-pressure before the next look.
                    loop {
                        let pending = {
                            let mut s = shared.lock().await;
                            let Some(c) = s.clients.get_mut(&id) else {
                                break 'conn Err(protocol("dropped: not reading"));
                            };
                            let held = std::mem::take(&mut c.deferred);
                            c.deferred_bytes = 0;
                            let mut rest = Vec::new();
                            let mut it = held.into_iter();
                            for frame in it.by_ref() {
                                if let Err(frame) = c.outbox.try_push(frame) {
                                    rest.push(frame);
                                    break;
                                }
                            }
                            rest.extend(it);
                            if rest.is_empty() {
                                c.loading = false;
                            }
                            rest
                        };
                        if pending.is_empty() {
                            break;
                        }
                        for frame in pending {
                            if !outbox.push(frame).await {
                                break 'conn Ok(());
                            }
                        }
                    }
                }
                mqtt::Packet::Unsubscribe { packet_id, filters } => {
                    {
                        let mut s = shared.lock().await;
                        if let Some(c) = s.clients.get_mut(&id) {
                            c.filters.retain(|f| !filters.contains(f));
                        }
                    }
                    if !outbox.push(mqtt::unsuback(packet_id).into()).await {
                        break 'conn Ok(());
                    }
                }
                mqtt::Packet::Publish {
                    topic,
                    qos,
                    retain,
                    packet_id,
                    payload,
                } => {
                    if qos == 2 {
                        break 'conn Err(protocol("QoS 2 is not carried"));
                    }
                    let limit = if topic == REGISTRY_TOPIC {
                        MAX_REGISTRY_PAYLOAD
                    } else {
                        MAX_PAYLOAD
                    };
                    if allowed_topic(&topic) && payload.len() <= limit {
                        // The policy's parsing and signature checks run
                        // here, on this connection's task, with no lock held.
                        match policy.prepare(&topic, &payload, retain) {
                            Ok(prepared) => {
                                publish(
                                    &shared,
                                    &*policy,
                                    &topic,
                                    payload.into(),
                                    retain,
                                    &prepared,
                                )
                                .await;
                            }
                            Err(reason) => {
                                shared.lock().await.refused += 1;
                                debug!(reason, "publish refused by policy");
                            }
                        }
                    } else {
                        shared.lock().await.refused += 1;
                    }
                    // Acknowledged either way: a refused publish is simply
                    // not delivered, and the client goes on.
                    if let Some(pid) = packet_id {
                        if !outbox.push(mqtt::puback(pid).into()).await {
                            break 'conn Ok(());
                        }
                    }
                }
            }
        }
        buf.drain(..off);
    };

    shared.lock().await.clients.remove(&id);
    // The writer ends once every sender is gone; the client entry above
    // held one. Then it gets two seconds to flush, and is stopped.
    drop(outbox);
    let _ = tokio::time::timeout(Duration::from_secs(2), &mut writer).await;
    writer.abort();
    outcome
}

async fn publish(
    shared: &Arc<Mutex<Shared>>,
    policy: &dyn Policy,
    topic: &str,
    payload: Arc<[u8]>,
    retain: bool,
    prepared: &Prepared,
) {
    let mut s = shared.lock().await;
    if retain && !payload.is_empty() && !s.retained.fits(topic, payload.len()) {
        s.refused += 1;
        debug!("publish refused: retained store full");
        return;
    }
    if let Some(reason) = policy.admit(prepared, topic, retain, &s.retained) {
        s.refused += 1;
        debug!(reason, "publish refused by policy");
        return;
    }
    let Shared {
        retained,
        clients,
        store,
        published,
        ..
    } = &mut *s;
    if retain {
        if payload.is_empty() {
            if retained.remove(topic) {
                if let Some(st) = store {
                    st.delete(topic);
                }
            }
        } else {
            retained.insert(topic, Arc::clone(&payload));
            if let Some(st) = store {
                st.put(topic, &payload);
            }
        }
    }
    *published += 1;
    let frame: Frame = mqtt::publish(topic, &payload, false).into();
    let mut slow = Vec::new();
    for (cid, c) in clients.iter_mut() {
        if !c.filters.iter().any(|f| matches(f, topic)) {
            continue;
        }
        if c.loading {
            if c.deferred.len() < OUTBOUND_QUEUE
                && c.deferred_bytes + frame.len() <= MAX_QUEUE_BYTES
            {
                c.deferred_bytes += frame.len();
                c.deferred.push(Arc::clone(&frame));
            } else {
                slow.push(*cid);
            }
        } else if c.outbox.try_push(Arc::clone(&frame)).is_err() {
            slow.push(*cid);
        }
    }
    for cid in slow {
        s.drop_client(cid);
    }
}

/// Runs the relay until the process ends.
pub async fn run(cfg: RelayConfig) -> Result<()> {
    Relay::bind(cfg).await?.serve().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    fn connect_packet(client_id: &str, keepalive: u16) -> Vec<u8> {
        let mut body = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02];
        body.extend_from_slice(&keepalive.to_be_bytes());
        body.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        body.extend_from_slice(client_id.as_bytes());
        let mut out = vec![0x10, body.len() as u8];
        out.extend(body);
        out
    }

    fn subscribe_packet(id: u16, filter: &str) -> Vec<u8> {
        let mut body = id.to_be_bytes().to_vec();
        body.extend_from_slice(&(filter.len() as u16).to_be_bytes());
        body.extend_from_slice(filter.as_bytes());
        body.push(1);
        let mut out = vec![0x82, body.len() as u8];
        out.extend(body);
        out
    }

    fn publish_packet(topic: &str, payload: &[u8], qos: u8, retain: bool, id: u16) -> Vec<u8> {
        let mut body = (topic.len() as u16).to_be_bytes().to_vec();
        body.extend_from_slice(topic.as_bytes());
        if qos > 0 {
            body.extend_from_slice(&id.to_be_bytes());
        }
        body.extend_from_slice(payload);
        let mut out = vec![0x30 | (qos << 1) | u8::from(retain)];
        let mut n = body.len();
        loop {
            let mut b = (n % 128) as u8;
            n /= 128;
            if n > 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
        out.extend(body);
        out
    }

    #[test]
    fn packets_parse_and_encode() {
        match mqtt::parse(&connect_packet("abc", 30), MAX_PACKET) {
            mqtt::Parsed::Ready {
                packet:
                    mqtt::Packet::Connect {
                        level,
                        keepalive,
                        client_id,
                        has_will,
                    },
                consumed,
            } => {
                assert_eq!(
                    (level, keepalive, client_id.as_str(), has_will, consumed),
                    (4, 30, "abc", false, 17)
                );
            }
            _ => panic!("connect"),
        }
        let pubp = publish_packet("hidra/x", b"hello", 1, true, 7);
        match mqtt::parse(&pubp, MAX_PACKET) {
            mqtt::Parsed::Ready {
                packet:
                    mqtt::Packet::Publish {
                        topic,
                        qos,
                        retain,
                        packet_id,
                        payload,
                    },
                ..
            } => {
                assert_eq!(
                    (topic.as_str(), qos, retain, packet_id, payload.as_slice()),
                    ("hidra/x", 1, true, Some(7), &b"hello"[..])
                );
            }
            _ => panic!("publish"),
        }
        match mqtt::parse(&subscribe_packet(3, "hforum/t/+"), MAX_PACKET) {
            mqtt::Parsed::Ready {
                packet: mqtt::Packet::Subscribe { packet_id, filters },
                ..
            } => {
                assert_eq!(packet_id, 3);
                assert_eq!(filters, vec![("hforum/t/+".to_string(), 1)]);
            }
            _ => panic!("subscribe"),
        }
        assert!(matches!(
            mqtt::parse(&[0xc0, 0x00], MAX_PACKET),
            mqtt::Parsed::Ready {
                packet: mqtt::Packet::PingReq,
                ..
            }
        ));
        assert!(matches!(
            mqtt::parse(&[0x10], MAX_PACKET),
            mqtt::Parsed::Incomplete
        ));
        assert!(matches!(
            mqtt::parse(&[0x30, 0xff, 0xff, 0xff, 0x7f], MAX_PACKET),
            mqtt::Parsed::TooLarge
        ));
        assert!(matches!(
            mqtt::parse(&[0x82, 0x02, 0x00, 0x01], MAX_PACKET),
            mqtt::Parsed::Malformed
        ));
        // A payload of 300 bytes needs a two-byte remaining length.
        let big = publish_packet("hidra/x", &[1u8; 300], 0, false, 0);
        assert!(
            matches!(mqtt::parse(&big, MAX_PACKET), mqtt::Parsed::Ready { consumed, .. } if consumed == big.len())
        );
        let encoded = mqtt::publish("hidra/x", &[1u8; 300], true);
        assert!(matches!(
            mqtt::parse(&encoded, MAX_PACKET),
            mqtt::Parsed::Ready {
                packet: mqtt::Packet::Publish { retain: true, .. },
                ..
            }
        ));
    }

    #[test]
    fn only_the_projects_topics_pass() {
        assert!(allowed_topic("hidra/abc"));
        assert!(allowed_topic("hforum/u/alice"));
        for bad in [
            "",
            "hidra",
            "other/x",
            "hidra/#",
            "hidra/+/x",
            "$SYS/brokers",
            "hidra/\0",
            &"hidra/".repeat(60),
        ] {
            assert!(!allowed_topic(bad), "{bad:?}");
        }
        for good in [
            "hidra/#",
            "hidra/+",
            "hforum/t/+",
            "hforum/r/+/+",
            "hforum/registry",
            "hforum/#",
        ] {
            assert!(allowed_filter(good), "{good}");
        }
        for bad in [
            "#",
            "+/#",
            "+",
            "hidra#",
            "hidra/a#",
            "hidra/#/x",
            "hidra/a+",
            "other/#",
            "hforumx/#",
        ] {
            assert!(!allowed_filter(bad), "{bad}");
        }
        // A bare tree name matches only a topic no one can publish: harmless.
        assert!(allowed_filter("hidra"));
        assert!(allowed_filter("hforum"));
    }

    #[test]
    fn filters_match_like_mqtt() {
        assert!(matches("hforum/t/+", "hforum/t/abc"));
        assert!(!matches("hforum/t/+", "hforum/t/abc/def"));
        assert!(matches("hforum/r/+/+", "hforum/r/t1/r1"));
        assert!(matches("hidra/#", "hidra/a/b/c"));
        assert!(matches("hidra/#", "hidra"));
        assert!(!matches("hidra/a", "hidra/b"));
        assert!(!matches("hidra/a/b", "hidra/a"));
    }

    #[test]
    fn the_bucket_lets_a_burst_through_and_then_meters() {
        let t0 = Instant::now();
        let mut b = Bucket::new(t0);
        let mut taken = 0;
        while b.take(t0) {
            taken += 1;
        }
        assert_eq!(taken, RATE_BURST as usize);
        assert!(!b.take(t0));
        assert!(b.take(t0 + Duration::from_secs(1)));
    }

    #[test]
    fn retained_messages_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("hidra-relay-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let (store, loaded) = Store::open(&dir.join("retained.sqlite")).unwrap();
            assert!(loaded.is_empty());
            store.put("hforum/t/abc", &b"one"[..].into());
            store.put("hforum/t/def", &b"two"[..].into());
            store.delete("hforum/t/def");
            store.put("hforum/t/abc", &b"three"[..].into());
            std::thread::sleep(Duration::from_millis(300));
        }
        let (_store, loaded) = Store::open(&dir.join("retained.sqlite")).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get("hforum/t/abc"), Some(&b"three"[..]));
        assert_eq!(loaded.bytes(), 5);
        assert_eq!(loaded.count("hforum/t"), 1);
        assert_eq!(loaded.topic_of_id("abc"), Some("hforum/t/abc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Opens a WebSocket to the relay with the `mqtt` subprotocol, as the
    /// pages' client does, and sends CONNECT.
    async fn client(
        addr: SocketAddr,
        id: &str,
    ) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>> {
        let mut req = format!("ws://{addr}/mqtt").into_client_request().unwrap();
        req.headers_mut().insert(
            "sec-websocket-protocol",
            http::HeaderValue::from_static("mqtt"),
        );
        let (mut ws, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok()),
            Some("mqtt")
        );
        ws.send(Message::Binary(connect_packet(id, 30)))
            .await
            .unwrap();
        let ack = ws.next().await.unwrap().unwrap().into_data();
        assert_eq!(ack, vec![0x20, 0x02, 0x00, 0x00]);
        ws
    }

    async fn next_packet(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>,
    ) -> mqtt::Packet {
        let data = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("a packet in time")
            .unwrap()
            .unwrap()
            .into_data();
        match mqtt::parse(&data, MAX_PACKET) {
            mqtt::Parsed::Ready { packet, .. } => packet,
            _ => panic!("not a packet"),
        }
    }

    async fn start() -> SocketAddr {
        let relay = Relay::bind(RelayConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: None,
            policy: Arc::new(OpenPolicy),
        })
        .await
        .unwrap();
        let addr = relay.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = relay.serve().await;
        });
        addr
    }

    #[tokio::test]
    async fn a_message_reaches_the_subscriber_and_retained_ones_reach_a_late_one() {
        let addr = start().await;
        let mut a = client(addr, "a").await;
        let mut b = client(addr, "b").await;
        b.send(Message::Binary(subscribe_packet(1, "hforum/t/+")))
            .await
            .unwrap();
        assert!(matches!(
            next_packet(&mut b).await,
            mqtt::Packet::Unsupported(9)
        )); // SUBACK, a server packet
        a.send(Message::Binary(publish_packet(
            "hforum/t/tabcdefghij",
            b"{\"x\":1}",
            1,
            true,
            5,
        )))
        .await
        .unwrap();
        // The publisher gets its PUBACK (type 4), the subscriber the message.
        assert!(matches!(
            next_packet(&mut a).await,
            mqtt::Packet::Unsupported(4)
        ));
        match next_packet(&mut b).await {
            mqtt::Packet::Publish {
                topic,
                payload,
                retain,
                ..
            } => {
                assert_eq!(topic, "hforum/t/tabcdefghij");
                assert_eq!(payload, b"{\"x\":1}");
                assert!(!retain);
            }
            other => panic!("expected a publish, got {other:?}"),
        }
        // A client arriving later gets the retained copy, flagged retained.
        let mut c = client(addr, "c").await;
        c.send(Message::Binary(subscribe_packet(2, "hforum/#")))
            .await
            .unwrap();
        assert!(matches!(
            next_packet(&mut c).await,
            mqtt::Packet::Unsupported(9)
        ));
        match next_packet(&mut c).await {
            mqtt::Packet::Publish { topic, retain, .. } => {
                assert_eq!(topic, "hforum/t/tabcdefghij");
                assert!(retain);
            }
            other => panic!("expected the retained publish, got {other:?}"),
        }
        // An empty retained publish deletes it.
        a.send(Message::Binary(publish_packet(
            "hforum/t/tabcdefghij",
            b"",
            0,
            true,
            0,
        )))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut d = client(addr, "d").await;
        d.send(Message::Binary(subscribe_packet(3, "hforum/#")))
            .await
            .unwrap();
        assert!(matches!(
            next_packet(&mut d).await,
            mqtt::Packet::Unsupported(9)
        ));
        d.send(Message::Binary(vec![0xc0, 0x00])).await.unwrap();
        assert!(
            matches!(next_packet(&mut d).await, mqtt::Packet::Unsupported(13)),
            "nothing retained came before the ping reply"
        );
    }

    #[tokio::test]
    async fn what_is_outside_the_projects_trees_or_too_large_is_not_delivered() {
        let addr = start().await;
        let mut a = client(addr, "a").await;
        let mut b = client(addr, "b").await;
        b.send(Message::Binary(subscribe_packet(1, "hidra/#")))
            .await
            .unwrap();
        assert!(matches!(
            next_packet(&mut b).await,
            mqtt::Packet::Unsupported(9)
        ));
        // A filter outside the trees is refused in the SUBACK.
        b.send(Message::Binary(subscribe_packet(2, "#")))
            .await
            .unwrap();
        let data = tokio::time::timeout(Duration::from_secs(3), b.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data();
        assert_eq!(data, vec![0x90, 0x03, 0x00, 0x02, 0x80]);
        // A publish on another tree is acknowledged and dropped.
        a.send(Message::Binary(publish_packet(
            "other/x", b"nope", 1, false, 1,
        )))
        .await
        .unwrap();
        assert!(matches!(
            next_packet(&mut a).await,
            mqtt::Packet::Unsupported(4)
        ));
        // One over the size limit too.
        a.send(Message::Binary(publish_packet(
            "hidra/x",
            &vec![0u8; MAX_PAYLOAD + 1],
            1,
            false,
            2,
        )))
        .await
        .unwrap();
        assert!(matches!(
            next_packet(&mut a).await,
            mqtt::Packet::Unsupported(4)
        ));
        // A good one still arrives, and it is the first thing b sees.
        a.send(Message::Binary(publish_packet(
            "hidra/x", b"yes", 0, false, 0,
        )))
        .await
        .unwrap();
        match next_packet(&mut b).await {
            mqtt::Packet::Publish { topic, payload, .. } => {
                assert_eq!(topic, "hidra/x");
                assert_eq!(payload, b"yes");
            }
            other => panic!("expected the good publish, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_client_that_floods_is_disconnected() {
        let addr = start().await;
        let mut a = client(addr, "a").await;
        for i in 0..(RATE_BURST as usize + 5) {
            let _ = a
                .send(Message::Binary(publish_packet(
                    "hidra/x", b"m", 0, false, i as u16,
                )))
                .await;
        }
        // The relay closes the connection; the next read ends.
        let mut closed = false;
        for _ in 0..20 {
            match tokio::time::timeout(Duration::from_secs(2), a.next()).await {
                Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => {
                    closed = true;
                    break;
                }
                Ok(Some(Ok(_))) => continue,
                Err(_) => break,
            }
        }
        assert!(closed, "the flooding client was not disconnected");
    }

    #[tokio::test]
    async fn a_first_packet_other_than_connect_ends_the_connection() {
        let addr = start().await;
        let req = format!("ws://{addr}/mqtt").into_client_request().unwrap();
        let (mut ws, _) = tokio_tungstenite::connect_async(req).await.unwrap();
        ws.send(Message::Binary(subscribe_packet(1, "hidra/#")))
            .await
            .unwrap();
        let r = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .unwrap();
        assert!(matches!(
            r,
            None | Some(Err(_)) | Some(Ok(Message::Close(_)))
        ));
    }

    fn subscribe_many(id: u16, filters: &[&str]) -> Vec<u8> {
        let mut body = id.to_be_bytes().to_vec();
        for f in filters {
            body.extend_from_slice(&(f.len() as u16).to_be_bytes());
            body.extend_from_slice(f.as_bytes());
            body.push(1);
        }
        let mut out = vec![0x82];
        let mut n = body.len();
        loop {
            let mut b = (n % 128) as u8;
            n /= 128;
            if n > 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
        out.extend(body);
        out
    }

    #[tokio::test]
    async fn a_filter_repeated_in_one_subscribe_costs_one_pass_over_the_store() {
        let addr = start().await;
        let mut a = client(addr, "a").await;
        for i in 0..3u8 {
            a.send(Message::Binary(publish_packet(
                &format!("hforum/t/t{i}"),
                b"post",
                1,
                true,
                i as u16 + 1,
            )))
            .await
            .unwrap();
            next_packet(&mut a).await;
        }
        let mut b = client(addr, "b").await;
        // Ten copies: within the burst at SUBSCRIBE_COST tokens each.
        let same = ["hforum/#"; 10];
        b.send(Message::Binary(subscribe_many(1, &same)))
            .await
            .unwrap();
        // SUBACK: ten codes, all granted.
        let suback = tokio::time::timeout(Duration::from_secs(3), b.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data();
        assert_eq!(suback, mqtt::suback(1, &[0; 10]));
        let mut retained = 0;
        for _ in 0..3 {
            match next_packet(&mut b).await {
                mqtt::Packet::Publish { retain: true, .. } => retained += 1,
                other => panic!("expected a retained publish, got {other:?}"),
            }
        }
        b.send(Message::Binary(vec![0xc0, 0x00])).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(3), b.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data();
        assert_eq!(
            reply,
            mqtt::pingresp(),
            "exactly three retained messages came before the ping reply, not thirty"
        );
        assert_eq!(retained, 3);
        // More filters than a client may hold, in one packet, ends it.
        let mut c = client(addr, "c").await;
        let many: Vec<String> = (0..MAX_SUBSCRIPTIONS_PER_CLIENT + 1)
            .map(|i| format!("hforum/t/{i}"))
            .collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        c.send(Message::Binary(subscribe_many(2, &refs)))
            .await
            .unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match c.next().await {
                    None | Some(Err(_)) => break true,
                    Some(Ok(Message::Close(_))) => break true,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(
            closed,
            "too many filters in one SUBSCRIBE ends the connection"
        );
    }

    #[tokio::test]
    async fn a_ping_flood_is_disconnected() {
        let addr = start().await;
        let mut a = client(addr, "a").await;
        // One frame full of PINGREQs: each costs a token like any packet.
        let frame: Vec<u8> = std::iter::repeat_n([0xc0u8, 0x00], RATE_BURST as usize + 5)
            .flatten()
            .collect();
        a.send(Message::Binary(frame)).await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                match a.next().await {
                    None | Some(Err(_)) => break true,
                    Some(Ok(Message::Close(_))) => break true,
                    Some(Ok(_)) => {}
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(closed);
    }

    #[test]
    fn the_retained_bookkeeping_follows_inserts_and_removals() {
        let mut r = Retained::default();
        r.insert("hforum/t/tabcdefghij", b"post"[..].into());
        r.insert("hforum/r/tabcdefghij/rabcdefghij", b"reply"[..].into());
        r.insert("hforum/rep/tabcdefghij/e27a", b"1"[..].into());
        r.insert("hidra/presence/v1", b"x"[..].into());
        assert_eq!(r.len(), 4);
        assert_eq!(r.bytes(), 11);
        assert_eq!(r.count("hforum/t"), 1);
        assert_eq!(r.count("hforum/r"), 1);
        assert_eq!(r.count("hforum/rep"), 1);
        assert_eq!(r.count("hidra/presence"), 1);
        assert_eq!(
            r.topic_of_id("rabcdefghij"),
            Some("hforum/r/tabcdefghij/rabcdefghij")
        );
        assert_eq!(r.topic_of_id("tabcdefghij"), Some("hforum/t/tabcdefghij"));
        r.insert("hforum/t/tabcdefghij", b"replaced"[..].into());
        assert_eq!(r.len(), 4);
        assert_eq!(r.bytes(), 15);
        assert_eq!(r.count("hforum/t"), 1);
        assert!(r.remove("hforum/r/tabcdefghij/rabcdefghij"));
        assert!(!r.remove("hforum/r/tabcdefghij/rabcdefghij"));
        assert_eq!(r.topic_of_id("rabcdefghij"), None);
        assert_eq!(r.count("hforum/r"), 0);
        assert_eq!(r.bytes(), 10);
        assert!(r.fits("hforum/t/tabcdefghij", MAX_RETAINED_BYTES - 2));
        assert!(!r.fits("hforum/t/tnew", MAX_RETAINED_BYTES - 2));
    }
}
