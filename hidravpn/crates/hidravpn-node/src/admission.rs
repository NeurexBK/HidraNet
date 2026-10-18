//! The node's admission service: the small HTTP listener beside the
//! WireGuard port that lets a stranger be admitted without meeting the
//! operator — when the operator chose `admission = "open"`.
//!
//! `GET /` describes the node (its record, as a signed list would carry it).
//! `POST /admit` with `{"public_key": ..., "name": ...}` admits that key and
//! answers with its invite, unless admission is by hand (403), the source
//! address asked too often (429), or the node is full (503). The request is
//! handed to the node's main loop, which owns the leases and the device, over
//! a channel; this module never touches either.
//!
//! Limits are deliberate: a few admissions per address per ten minutes and a
//! modest number overall, a short timeout per connection and a cap on
//! concurrent ones, overall and per address. A script with enough addresses
//! can still fill a node in hours, or hold its door shut while it keeps
//! hundreds of connections open; what it cannot do is keep the node full, or
//! touch the tunnel, because a lease that never
//! completes a handshake lapses within a quarter of an hour (`leases.rs`),
//! so filling a node costs real tunnels, not requests.
//! Nothing here logs an address or a key: counts only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hidravpn_core::admission::{
    http_response, read_request, refusal, refusal_wanting_work, work, AdmissionRequest,
};
use hidravpn_core::pass::Redemption;
use hidravpn_core::Invite;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot, Mutex, Semaphore};
use tracing::{info, warn};

use crate::config::NodeConfig;

/// One admission the main loop is asked to make.
pub struct Admit {
    pub public_key: String,
    pub name: String,
    /// A key made for one connection: its lease lapses with the connection.
    pub session: bool,
    /// Set when the admission is a redeemed pass: what to write down as
    /// spent, and until when. The main loop refuses a tag it already holds.
    pub pass: Option<SpentPass>,
    /// The invite, or the HTTP status and reason for refusing.
    pub reply: oneshot::Sender<std::result::Result<Invite, (u16, String)>>,
}

const PER_IP: usize = 3;
const PER_IP_WINDOW: Duration = Duration::from_secs(600);
const GLOBAL: usize = 120;
const GLOBAL_WINDOW: Duration = Duration::from_secs(600);
/// Session admissions (a fresh key per connection) are paid for with a
/// proof of work instead of being counted per address: they come from the
/// client's own address for a first hop and from the entry's for an exit,
/// and counting the entry's address would throttle all its clients
/// together. They have a node-wide ceiling of their own.
const SESSION_GLOBAL: usize = 600;
/// Connections served at once. An idle one costs a task and a small
/// buffer, so the cap is generous: what keeps one source from holding them
/// all is the cap per address below, and the timeout.
const CONNECTIONS: usize = 256;
/// Connections one address may hold open at once; past it, a connection is
/// closed at once. A few, for clients behind one address (a household, a
/// carrier's NAT).
const CONNECTIONS_PER_IP: usize = 8;
const PER_CONNECTION: Duration = Duration::from_secs(5);

/// Sliding windows: per source address and overall for lasting leases,
/// overall only for session leases.
#[derive(Default)]
pub struct RateLimiter {
    per_ip: HashMap<IpAddr, VecDeque<Instant>>,
    global: VecDeque<Instant>,
    /// Session admissions in the window, oldest first, by key: a key is
    /// counted once, so replaying its request (the proof holds for a few
    /// minutes) takes no further room.
    sessions: VecDeque<(Instant, [u8; 32])>,
    session_keys: HashSet<[u8; 32]>,
}

/// Drops what has slid out of the window; true if there is room for one more.
fn room(q: &mut VecDeque<Instant>, now: Instant, window: Duration, limit: usize) -> bool {
    while q.front().is_some_and(|t| now.duration_since(*t) > window) {
        q.pop_front();
    }
    q.len() < limit
}

impl RateLimiter {
    /// Whether one more lasting admission from `ip` is allowed now; records
    /// it if so.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if !room(&mut self.global, now, GLOBAL_WINDOW, GLOBAL) {
            return false;
        }
        let q = self.per_ip.entry(ip).or_default();
        if !room(q, now, PER_IP_WINDOW, PER_IP) {
            return false;
        }
        q.push_back(now);
        self.global.push_back(now);
        // Forget addresses that have gone quiet, so the map cannot grow forever.
        if self.per_ip.len() > 10_000 {
            self.per_ip.retain(|_, q| {
                q.back()
                    .is_some_and(|t| now.duration_since(*t) <= PER_IP_WINDOW)
            });
        }
        true
    }

    /// Forgets the session admissions that have slid out of the window.
    fn slide_sessions(&mut self, now: Instant) {
        while let Some((t, _)) = self.sessions.front() {
            if now.duration_since(*t) <= GLOBAL_WINDOW {
                break;
            }
            if let Some((_, key)) = self.sessions.pop_front() {
                self.session_keys.remove(&key);
            }
        }
    }

    /// The work a session admission costs now: `base` while the window is
    /// at most half full, then two bits more (four times the work) for each
    /// step closer to the ceiling, up to what a client agrees to do. A
    /// person connecting pays about a second; whoever tries to fill the
    /// window pays the most for the last places.
    pub fn session_bits(&mut self, base: u8, now: Instant) -> u8 {
        self.slide_sessions(now);
        let used = self.sessions.len();
        let extra = if used < SESSION_GLOBAL / 2 {
            0
        } else if used < SESSION_GLOBAL * 3 / 4 {
            2
        } else if used < SESSION_GLOBAL * 7 / 8 {
            4
        } else {
            6
        };
        base.saturating_add(extra).min(work::MAX_BITS.max(base))
    }

    /// Whether a session admission for `key` is allowed now, whoever asks;
    /// records it if so. The proof of work is checked before this. A key
    /// already admitted in the window is allowed again without taking more
    /// room: the node answers with the lease it already holds.
    pub fn allow_session(&mut self, key: [u8; 32], now: Instant) -> bool {
        self.slide_sessions(now);
        if self.session_keys.contains(&key) {
            return true;
        }
        if self.sessions.len() >= SESSION_GLOBAL {
            return false;
        }
        self.sessions.push_back((now, key));
        self.session_keys.insert(key);
        true
    }
}

/// A pass to write down as spent, once the main loop has checked it is not.
pub struct SpentPass {
    pub tag: String,
    pub valid_until: i64,
}

/// A lease name the operator can read in `status`: the client's wish if it
/// is one, else a number.
pub fn lease_name(wanted: &str, counter: u64) -> String {
    let w = wanted.trim();
    if !w.is_empty()
        && w.len() <= 32
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        w.to_string()
    } else {
        format!("open-{counter}")
    }
}

/// Serves until the task is dropped.
pub async fn serve(
    listen: SocketAddr,
    cfg: Arc<NodeConfig>,
    tx: mpsc::Sender<Admit>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding the admission port {}", listen.port()))?;
    info!(
        "admission service on TCP {} ({})",
        listen.port(),
        if cfg.admission_is_open() {
            "open: any client may ask"
        } else if cfg.admits_with_passes() {
            "with a pass: a client redeems one"
        } else {
            "by hand: describes the node only"
        }
    );
    if listen.port() != hidravpn_core::admission::DEFAULT_ADMISSION_PORT
        && !cfg.role.eq_ignore_ascii_case("entry")
        && (cfg.admission_is_open() || cfg.admits_with_passes())
    {
        warn!(
            "entries relay admission requests only to TCP {}: on another port this node is used as the only hop, never as the exit of two hops",
            hidravpn_core::admission::DEFAULT_ADMISSION_PORT
        );
    }
    if cfg.public_endpoint.port() != hidravpn_core::admission::DEFAULT_WIREGUARD_PORT
        && !cfg.role.eq_ignore_ascii_case("entry")
    {
        warn!(
            "entries forward WireGuard only to UDP {}: on another port this node is used as the only hop, never as the exit of two hops",
            hidravpn_core::admission::DEFAULT_WIREGUARD_PORT
        );
    }
    let limiter = Arc::new(Mutex::new(RateLimiter::default()));
    let slots = Arc::new(Semaphore::new(CONNECTIONS));
    let open = Arc::new(std::sync::Mutex::new(OpenPerIp::default()));
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
    loop {
        let Ok(slot) = slots.clone().acquire_owned().await else {
            // The semaphore is never closed; if it ever were, waiting beats dying.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            continue;
        };
        // An accept error (out of descriptors, out of buffers) is a condition
        // to wait out, never a reason for the node to stop serving its
        // tunnel: a client that could provoke one would take the node down.
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!("admission accept: {e}; waiting");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        // Over its share, the connection is closed unread: it is not worth
        // a slot, and an answer would be one more thing to wait on.
        let Some(_held) = OpenPerIp::take(&open, peer.ip()) else {
            drop(stream);
            continue;
        };
        let (cfg, tx, limiter, counter) =
            (cfg.clone(), tx.clone(), limiter.clone(), counter.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let _held = _held;
            let r = tokio::time::timeout(
                PER_CONNECTION,
                handle(stream, peer.ip(), cfg, tx, limiter, counter),
            )
            .await;
            if let Ok(Err(e)) = r {
                warn!("admission connection: {e}");
            }
        });
    }
}

/// How many connections each address holds open now.
#[derive(Default)]
struct OpenPerIp(HashMap<IpAddr, usize>);

impl OpenPerIp {
    /// One more connection for `ip`, or None when it holds its share. The
    /// count goes down when the returned guard is dropped.
    fn take(this: &Arc<std::sync::Mutex<Self>>, ip: IpAddr) -> Option<OpenGuard> {
        let mut m = this.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.0.entry(ip).or_insert(0);
        if *n >= CONNECTIONS_PER_IP {
            return None;
        }
        *n += 1;
        Some(OpenGuard {
            map: this.clone(),
            ip,
        })
    }
}

struct OpenGuard {
    map: Arc<std::sync::Mutex<OpenPerIp>>,
    ip: IpAddr,
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = m.0.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                m.0.remove(&self.ip);
            }
        }
    }
}

async fn handle(
    mut stream: tokio::net::TcpStream,
    ip: IpAddr,
    cfg: Arc<NodeConfig>,
    tx: mpsc::Sender<Admit>,
    limiter: Arc<Mutex<RateLimiter>>,
    counter: Arc<std::sync::atomic::AtomicU64>,
) -> Result<()> {
    let answer = match read_request(&mut stream).await {
        Err(_) => http_response(400, &refusal("not a request this service reads")),
        Ok(req) => match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") | ("GET", "/node") => match cfg.record() {
                Ok(rec) => http_response(200, &serde_json::to_string(&rec)?),
                Err(e) => http_response(500, &refusal(format!("{e:#}"))),
            },
            ("POST", "/admit") => admit(&req.body, ip, &cfg, &tx, &limiter, &counter).await,
            ("POST", "/redeem") => redeem(&req.body, &cfg, &tx, &counter).await,
            ("POST", _) | ("GET", _) => http_response(404, &refusal("no such path")),
            _ => http_response(405, &refusal("GET or POST")),
        },
    };
    stream.write_all(&answer).await?;
    stream.flush().await?;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn admit(
    body: &[u8],
    ip: IpAddr,
    cfg: &NodeConfig,
    tx: &mpsc::Sender<Admit>,
    limiter: &Mutex<RateLimiter>,
    counter: &std::sync::atomic::AtomicU64,
) -> Vec<u8> {
    if cfg.admits_with_passes() {
        return http_response(
            403,
            &refusal("this node admits with a pass: get passes from the issuer the node list names (`hidravpn passes get`)"),
        );
    }
    if !cfg.admission_is_open() {
        return http_response(
            403,
            &refusal("this node admits clients by hand: ask its operator (see its contact in the node list)"),
        );
    }
    let req: AdmissionRequest = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => {
            return http_response(
                400,
                &refusal("the request is not {\"public_key\": ..., \"name\": ...}"),
            )
        }
    };
    // A key that is not a key is refused before it counts against anyone.
    let client = match hidravpn_core::keys::public_key_from_base64(&req.public_key) {
        Ok(k) => *k.as_bytes(),
        Err(_) => {
            return http_response(
                400,
                &refusal("public_key is not a WireGuard public key (32 bytes, base64)"),
            );
        }
    };
    if req.session {
        // A session key is paid for with work, bound to this node and this
        // key, not counted against an address.
        let bits = limiter
            .lock()
            .await
            .session_bits(cfg.admission_work_bits, Instant::now());
        let paid = match (
            req.work,
            hidravpn_core::keys::public_key_from_base64(&cfg.public_key().unwrap_or_default()),
        ) {
            (Some(w), Ok(node)) => {
                work::verify(node.as_bytes(), &client, w, bits, work::now_minute())
            }
            _ => false,
        };
        if !paid {
            return http_response(428, &refusal_wanting_work(bits));
        }
        if !limiter.lock().await.allow_session(client, Instant::now()) {
            return http_response(
                429,
                &refusal("this node is admitting too many sessions right now; try another"),
            );
        }
    } else if !limiter.lock().await.allow(ip, Instant::now()) {
        return http_response(
            429,
            &refusal("too many admissions from this address; try again later"),
        );
    }
    let name = lease_name(
        &req.name,
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    );
    let (reply, rx) = oneshot::channel();
    if tx
        .send(Admit {
            public_key: req.public_key,
            session: req.session,
            name,
            pass: None,
            reply,
        })
        .await
        .is_err()
    {
        return http_response(503, &refusal("the node is stopping"));
    }
    match tokio::time::timeout(Duration::from_secs(4), rx).await {
        Ok(Ok(Ok(invite))) => http_response(200, &invite.to_json()),
        Ok(Ok(Err((status, why)))) => http_response(status, &refusal(why)),
        _ => http_response(503, &refusal("the node did not answer in time")),
    }
}

/// `POST /redeem`: a pass, checked here (a current issuer key this node
/// trusts, made for this node, a signature that holds) and then by the main
/// loop (never spent here before). No rate limit by address: a valid pass
/// was paid for with an account's quota, and an invalid one costs a
/// signature check and nothing else.
async fn redeem(
    body: &[u8],
    cfg: &NodeConfig,
    tx: &mpsc::Sender<Admit>,
    counter: &std::sync::atomic::AtomicU64,
) -> Vec<u8> {
    if !cfg.admits_with_passes() {
        return http_response(403, &refusal("this node does not admit with passes"));
    }
    let r: Redemption = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) => return http_response(400, &refusal("the request is not a pass")),
    };
    let me = match cfg.public_key() {
        Ok(k) => k,
        Err(_) => return http_response(500, &refusal("this node cannot read its own key")),
    };
    let now = hidravpn_core::timefmt::now_unix();
    if let Err(e) = r.verify(&cfg.pass_keys, &me, now) {
        return http_response(403, &refusal(format!("the pass is refused: {e}")));
    }
    let valid_until = cfg
        .pass_keys
        .iter()
        .find(|k| k.id.trim().eq_ignore_ascii_case(r.key_id.trim()))
        .and_then(|k| hidravpn_core::timefmt::rfc3339_to_unix(&k.not_after).ok())
        .unwrap_or(now);
    let name = format!(
        "pass-{}",
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let (reply, rx) = oneshot::channel();
    if tx
        .send(Admit {
            public_key: r.client_public_key.clone(),
            name,
            session: false,
            pass: Some(SpentPass {
                tag: r.spent_tag(),
                valid_until,
            }),
            reply,
        })
        .await
        .is_err()
    {
        return http_response(503, &refusal("the node is stopping"));
    }
    match tokio::time::timeout(Duration::from_secs(4), rx).await {
        Ok(Ok(Ok(invite))) => http_response(200, &invite.to_json()),
        Ok(Ok(Err((status, why)))) => http_response(status, &refusal(why)),
        _ => http_response(503, &refusal("the node did not answer in time")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_holds_a_few_connections_at_most_and_gets_them_back() {
        let open = Arc::new(std::sync::Mutex::new(OpenPerIp::default()));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let held: Vec<_> = (0..CONNECTIONS_PER_IP)
            .map(|_| OpenPerIp::take(&open, ip).expect("within its share"))
            .collect();
        assert!(OpenPerIp::take(&open, ip).is_none(), "one more is closed");
        let other: IpAddr = "203.0.113.6".parse().unwrap();
        assert!(
            OpenPerIp::take(&open, other).is_some(),
            "another address is not affected"
        );
        drop(held);
        assert!(
            OpenPerIp::take(&open, ip).is_some(),
            "closed connections are given back"
        );
        assert_eq!(
            open.lock().unwrap().0.len(),
            0,
            "nothing is kept for an address with none open"
        );
    }

    #[test]
    fn a_source_gets_a_few_tries_per_window_and_the_window_slides() {
        let mut l = RateLimiter::default();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..PER_IP {
            assert!(l.allow(ip, t0));
        }
        assert!(!l.allow(ip, t0), "one more is refused");
        let other: IpAddr = "203.0.113.6".parse().unwrap();
        assert!(l.allow(other, t0), "another address is not affected");
        assert!(
            l.allow(ip, t0 + PER_IP_WINDOW + Duration::from_secs(1)),
            "after the window it may ask again"
        );
    }

    #[test]
    fn session_admissions_are_not_counted_per_address_but_have_a_ceiling() {
        let mut l = RateLimiter::default();
        let entry: IpAddr = "203.0.113.7".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..PER_IP {
            assert!(l.allow(entry, t0));
        }
        assert!(!l.allow(entry, t0), "lasting leases: a few per address");
        let mut sessions = 0;
        while l.allow_session(key(sessions), t0) {
            sessions += 1;
        }
        assert_eq!(
            sessions, SESSION_GLOBAL as u32,
            "sessions: the node-wide ceiling only"
        );
        assert!(l.allow_session(key(sessions), t0 + GLOBAL_WINDOW + Duration::from_secs(1)));
    }

    fn key(n: u32) -> [u8; 32] {
        let mut k = [7u8; 32];
        k[..4].copy_from_slice(&n.to_be_bytes());
        k
    }

    #[test]
    fn a_replayed_session_request_takes_no_more_room() {
        let mut l = RateLimiter::default();
        let t0 = Instant::now();
        for _ in 0..(SESSION_GLOBAL * 2) {
            assert!(l.allow_session(key(1), t0), "the same key, again and again");
        }
        assert_eq!(l.sessions.len(), 1, "counted once");
        for n in 2..=SESSION_GLOBAL as u32 {
            assert!(l.allow_session(key(n), t0));
        }
        assert!(
            !l.allow_session(key(0), t0),
            "the window is full of different keys"
        );
        assert!(
            l.allow_session(key(1), t0),
            "a key already in it still has its lease"
        );
        // Once it slides out, the key is forgotten with it.
        let later = t0 + GLOBAL_WINDOW + Duration::from_secs(1);
        assert!(l.allow_session(key(0), later));
        assert!(!l.session_keys.contains(&key(1)));
        assert_eq!(l.sessions.len(), 1);
    }

    #[test]
    fn the_work_asked_rises_as_the_session_window_fills() {
        let mut l = RateLimiter::default();
        let t0 = Instant::now();
        let mut seen = Vec::new();
        for n in 0..SESSION_GLOBAL as u32 {
            let b = l.session_bits(20, t0);
            if seen.last() != Some(&b) {
                seen.push(b);
            }
            assert!(l.allow_session(key(n), t0));
        }
        assert_eq!(
            seen,
            vec![20, 22, 24, 26],
            "two bits a step, from half full"
        );
        assert_eq!(l.session_bits(20, t0), 26, "never past what a client does");
        assert_eq!(l.session_bits(25, t0), 26);
        assert_eq!(
            l.session_bits(28, t0),
            28,
            "an operator's own choice stands"
        );
        let later = t0 + GLOBAL_WINDOW + Duration::from_secs(1);
        assert_eq!(
            l.session_bits(20, later),
            20,
            "back down once the window empties"
        );
    }

    #[test]
    fn the_whole_node_has_a_ceiling_too() {
        let mut l = RateLimiter::default();
        let t0 = Instant::now();
        let mut allowed = 0;
        for i in 0..(GLOBAL + 50) {
            let ip: IpAddr = format!("198.51.100.{}", i % 250).parse().unwrap();
            if l.allow(ip, t0) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, GLOBAL);
    }

    #[test]
    fn a_lease_name_is_the_wish_or_a_number() {
        assert_eq!(lease_name("laptop", 7), "laptop");
        assert_eq!(lease_name("", 7), "open-7");
        assert_eq!(lease_name("has space", 8), "open-8");
        assert_eq!(lease_name(&"x".repeat(40), 9), "open-9");
    }
}
