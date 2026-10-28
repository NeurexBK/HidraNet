//! The node's admission service: the small HTTP listener beside the
//! WireGuard port that lets a stranger be admitted without meeting the
//! operator — when the operator chose `admission = "open"`.
//!
//! `GET /` describes the node (its record, as a signed list would carry it).
//! `POST /admit` with `{"public_key": ..., "name": ...}` admits that key and
//! answers with its invite, unless admission is by hand, or the node is an
//! entry and the request is not for a session (403), the source address
//! asked too often (429), or the node is full (503). The request is
//! handed to the node's main loop, which owns the leases and the device, over
//! a channel; this module never touches either.
//!
//! Limits are deliberate. A lasting lease (`nodes join`) costs no work: it
//! is counted per address (a few every ten minutes) and overall, the node
//! keeps at most a quarter of its places for such leases, and an entry,
//! which a client only ever asks for a key for one connection, gives none.
//! A session costs a proof of work, more as the window of recent sessions
//! or the node's table of leases fills, whichever is fuller, so the last
//! places cost the most. A connection is accepted, then closed at once when
//! the service holds all the connections it serves or the address holds
//! its share; one that sends nothing for two seconds, or not a whole request
//! in three, is closed. A lease that never completes a handshake lapses
//! within a quarter of an hour (`leases.rs`), so filling a node costs real
//! tunnels, not requests. What this does not stop: one handshake every few
//! minutes keeps a session alive, so someone with enough processor time can
//! still fill an open node with sessions and hold it while they keep them
//! alive, and someone with hundreds of addresses can keep the door busy.
//! Nodes that admit with a pass are the answer to that.
//! Nothing here logs an address or a key: counts only.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
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

/// How many connections the service holds open, and for how long.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Connections served at once; past it a new one is closed at once.
    connections: usize,
    /// Connections one address may hold open at once; past it, too. A few,
    /// for clients behind one address (a household, a carrier's NAT).
    per_ip: usize,
    /// The same for an address in `admission_relays`: an entry, every
    /// two-hop client of which comes from its address.
    per_relay: usize,
    /// A connection that has sent nothing by then is closed.
    first_byte: Duration,
    /// The whole request, headers and body, must be in by then.
    request: Duration,
    /// The whole exchange, the answer included.
    per_connection: Duration,
}

/// An idle connection costs a task and a small buffer, and the node's unit
/// allows 65536 descriptors, so the overall cap is generous: one address's
/// share is a small fraction of it, and a connection that sends nothing
/// holds its place for two seconds.
const LIMITS: Limits = Limits {
    connections: 4096,
    per_ip: 8,
    per_relay: 1024,
    first_byte: Duration::from_secs(2),
    request: Duration::from_secs(3),
    per_connection: Duration::from_secs(5),
};

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

/// The bits of work added as `used` nears `ceiling`: two from half full,
/// four from three quarters, six from seven eighths.
fn extra_bits(used: usize, ceiling: usize) -> u8 {
    if used * 2 < ceiling {
        0
    } else if used * 4 < ceiling * 3 {
        2
    } else if used * 8 < ceiling * 7 {
        4
    } else {
        6
    }
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

    /// The work a session admission costs now: `base` while the window and
    /// the node's table of leases (`held` of `max_clients`) are at most
    /// half full, then two bits more (four times the work) for each step
    /// the fuller of them is closer to its ceiling, up to what a client
    /// agrees to do. A person connecting pays about a second; whoever tries
    /// to fill the node pays the most for the last places, however slowly
    /// they came.
    pub fn session_bits(&mut self, base: u8, now: Instant, held: usize, max_clients: usize) -> u8 {
        self.slide_sessions(now);
        let extra =
            extra_bits(self.sessions.len(), SESSION_GLOBAL).max(extra_bits(held, max_clients));
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

/// Serves until the task is dropped. `held` is how many leases the node
/// holds now, which the main loop keeps up to date.
pub async fn serve(
    listen: SocketAddr,
    cfg: Arc<NodeConfig>,
    tx: mpsc::Sender<Admit>,
    held: Arc<AtomicUsize>,
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
        && !cfg.is_entry()
        && (cfg.admission_is_open() || cfg.admits_with_passes())
    {
        warn!(
            "entries relay admission requests only to TCP {}: on another port this node is used as the only hop, never as the exit of two hops",
            hidravpn_core::admission::DEFAULT_ADMISSION_PORT
        );
    }
    if cfg.public_endpoint.port() != hidravpn_core::admission::DEFAULT_WIREGUARD_PORT
        && !cfg.is_entry()
    {
        warn!(
            "entries forward WireGuard only to UDP {}: on another port this node is used as the only hop, never as the exit of two hops",
            hidravpn_core::admission::DEFAULT_WIREGUARD_PORT
        );
    }
    if !cfg.admission_relays.is_empty() {
        // How many, not which: no address goes into a log.
        info!(
            "{} entry address(es) relay admission requests here, each with a larger share of connections",
            cfg.admission_relays.len()
        );
    }
    serve_on(listener, cfg, tx, held, LIMITS).await
}

async fn serve_on(
    listener: tokio::net::TcpListener,
    cfg: Arc<NodeConfig>,
    tx: mpsc::Sender<Admit>,
    held: Arc<AtomicUsize>,
    limits: Limits,
) -> Result<()> {
    let limiter = Arc::new(Mutex::new(RateLimiter::default()));
    let slots = Arc::new(Semaphore::new(limits.connections));
    let open = Arc::new(std::sync::Mutex::new(OpenPerIp::default()));
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(1));
    loop {
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
        // Accepted first, then given a slot or closed at once: a full
        // service never stops accepting, so connections never wait in the
        // kernel's queue past the client's patience while the ones it
        // serves run out their time.
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        // Over its share, the connection is closed unread: it is not worth
        // a slot, and an answer would be one more thing to wait on.
        let share = if cfg.admission_relays.contains(&peer.ip()) {
            limits.per_relay
        } else {
            limits.per_ip
        };
        let Some(open_here) = OpenPerIp::take(&open, peer.ip(), share) else {
            drop(stream);
            continue;
        };
        let (cfg, tx, limiter, counter, held) = (
            cfg.clone(),
            tx.clone(),
            limiter.clone(),
            counter.clone(),
            held.clone(),
        );
        tokio::spawn(async move {
            let _slot = slot;
            let _open_here = open_here;
            let r = tokio::time::timeout(
                limits.per_connection,
                handle(stream, peer.ip(), cfg, tx, limiter, counter, held, limits),
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
    /// One more connection for `ip`, or None when it holds its `share`.
    /// The count goes down when the returned guard is dropped.
    fn take(this: &Arc<std::sync::Mutex<Self>>, ip: IpAddr, share: usize) -> Option<OpenGuard> {
        let mut m = this.lock().unwrap_or_else(|e| e.into_inner());
        let n = m.0.entry(ip).or_insert(0);
        if *n >= share {
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

#[allow(clippy::too_many_arguments)]
async fn handle(
    mut stream: tokio::net::TcpStream,
    ip: IpAddr,
    cfg: Arc<NodeConfig>,
    tx: mpsc::Sender<Admit>,
    limiter: Arc<Mutex<RateLimiter>>,
    counter: Arc<std::sync::atomic::AtomicU64>,
    held: Arc<AtomicUsize>,
    limits: Limits,
) -> Result<()> {
    let accepted = tokio::time::Instant::now();
    // A client sends its request as soon as it is connected. A connection
    // that sends nothing, or not a whole request, in time is closed
    // unanswered: it would hold its place for nothing.
    let mut first = [0u8; 1];
    match tokio::time::timeout(limits.first_byte, stream.peek(&mut first)).await {
        Ok(Ok(n)) if n > 0 => {}
        _ => return Ok(()),
    }
    let Ok(read) =
        tokio::time::timeout_at(accepted + limits.request, read_request(&mut stream)).await
    else {
        return Ok(());
    };
    let answer = match read {
        Err(_) => http_response(400, &refusal("not a request this service reads")),
        Ok(req) => match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") | ("GET", "/node") => match cfg.record() {
                Ok(rec) => http_response(200, &serde_json::to_string(&rec)?),
                Err(e) => http_response(500, &refusal(format!("{e:#}"))),
            },
            ("POST", "/admit") => admit(&req.body, ip, &cfg, &tx, &limiter, &counter, &held).await,
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
    held: &AtomicUsize,
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
    // A client asks an entry only for a key for one connection, as it
    // connects. A lasting lease there would cost no work and hold a place
    // for weeks after one handshake, for nothing a client does.
    if !req.session && cfg.is_entry() {
        return http_response(
            403,
            &refusal("this node is an entry: it admits a key for one connection, which a client asks for as it connects; there is nothing to join here"),
        );
    }
    if req.session {
        // A session key is paid for with work, bound to this node and this
        // key, not counted against an address.
        let bits = limiter.lock().await.session_bits(
            cfg.admission_work_bits,
            Instant::now(),
            held.load(Ordering::Relaxed),
            cfg.max_clients as usize,
        );
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
        let share = LIMITS.per_ip;
        let held: Vec<_> = (0..share)
            .map(|_| OpenPerIp::take(&open, ip, share).expect("within its share"))
            .collect();
        assert!(
            OpenPerIp::take(&open, ip, share).is_none(),
            "one more is closed"
        );
        let other: IpAddr = "203.0.113.6".parse().unwrap();
        assert!(
            OpenPerIp::take(&open, other, share).is_some(),
            "another address is not affected"
        );
        drop(held);
        assert!(
            OpenPerIp::take(&open, ip, share).is_some(),
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
            let b = l.session_bits(20, t0, 0, 4000);
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
        assert_eq!(
            l.session_bits(20, t0, 0, 4000),
            26,
            "never past what a client does"
        );
        assert_eq!(l.session_bits(25, t0, 0, 4000), 26);
        assert_eq!(
            l.session_bits(28, t0, 0, 4000),
            28,
            "an operator's own choice stands"
        );
        let later = t0 + GLOBAL_WINDOW + Duration::from_secs(1);
        assert_eq!(
            l.session_bits(20, later, 0, 4000),
            20,
            "back down once the window empties"
        );
    }

    #[test]
    fn the_work_asked_rises_as_the_table_of_leases_fills_however_slowly() {
        // Sessions that came one at a time, never many in a window, still
        // make the last places cost the most.
        let mut l = RateLimiter::default();
        let t0 = Instant::now();
        let max = 4000;
        let bits: Vec<u8> = [0, 1999, 2000, 2999, 3000, 3499, 3500, 4000]
            .iter()
            .map(|held| l.session_bits(20, t0, *held, max))
            .collect();
        assert_eq!(bits, vec![20, 20, 22, 22, 24, 24, 26, 26]);
        assert_eq!(l.session_bits(20, t0, 0, 0), 26, "no places: the most");
        // The fuller of the window and the table decides.
        for n in 0..(SESSION_GLOBAL as u32 * 3 / 4) {
            assert!(l.allow_session(key(n), t0));
        }
        assert_eq!(l.session_bits(20, t0, 0, max), 24);
        assert_eq!(l.session_bits(20, t0, 3600, max), 26);
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

    fn node(role: &str) -> NodeConfig {
        let mut cfg = NodeConfig::fresh(
            "n".into(),
            "192.0.2.4:51820".parse().unwrap(),
            51820,
            "10.77.0.0/16",
            NodeConfig::default_dns(),
            None,
        )
        .unwrap();
        cfg.set_role(role).unwrap();
        cfg.admission = "open".into();
        cfg
    }

    #[tokio::test]
    async fn an_entry_refuses_a_lasting_lease_and_says_why() {
        let (tx, mut rx) = mpsc::channel(4);
        let limiter = Mutex::new(RateLimiter::default());
        let counter = std::sync::atomic::AtomicU64::new(1);
        let held = AtomicUsize::new(0);
        let key = wireguard_control::Key::generate_private()
            .get_public()
            .to_base64();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for body in [
            format!(r#"{{"public_key":"{key}","name":"x"}}"#),
            format!(r#"{{"public_key":"{key}","name":"x","session":false}}"#),
        ] {
            let answer = admit(
                body.as_bytes(),
                ip,
                &node("entry"),
                &tx,
                &limiter,
                &counter,
                &held,
            )
            .await;
            let text = String::from_utf8_lossy(&answer);
            assert!(text.starts_with("HTTP/1.1 403"), "{text}");
            assert!(text.contains("entry"), "{text}");
        }
        assert!(rx.try_recv().is_err(), "nothing reached the main loop");
        // A session there is asked for its work, as on any node.
        let body = format!(r#"{{"public_key":"{key}","name":"x","session":true}}"#);
        let answer = admit(
            body.as_bytes(),
            ip,
            &node("entry"),
            &tx,
            &limiter,
            &counter,
            &held,
        )
        .await;
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 428"));
        // An exit still gives a lasting lease (the main loop is asked).
        let exit = node("exit");
        let body = format!(r#"{{"public_key":"{key}","name":"x"}}"#);
        let asked = tokio::spawn({
            let tx = tx.clone();
            async move {
                let limiter = Mutex::new(RateLimiter::default());
                let counter = std::sync::atomic::AtomicU64::new(1);
                let held = AtomicUsize::new(0);
                admit(body.as_bytes(), ip, &exit, &tx, &limiter, &counter, &held).await
            }
        });
        let req = rx.recv().await.expect("the exit asks the main loop");
        assert!(!req.session);
        let _ = req.reply.send(Err((503, "full".into())));
        let answer = asked.await.unwrap();
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 503"));
    }

    const QUICK: Limits = Limits {
        connections: 4,
        per_ip: 2,
        per_relay: 6,
        first_byte: Duration::from_millis(300),
        request: Duration::from_millis(700),
        per_connection: Duration::from_secs(3),
    };

    /// A service on a loopback port with `limits`; its main loop never
    /// answers (nothing here is admitted).
    async fn service(cfg: NodeConfig, limits: Limits) -> (SocketAddr, mpsc::Receiver<Admit>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(serve_on(
            listener,
            Arc::new(cfg),
            tx,
            Arc::new(AtomicUsize::new(0)),
            limits,
        ));
        (addr, rx)
    }

    async fn connect_from(from: &str, to: SocketAddr) -> tokio::net::TcpStream {
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        s.bind(format!("{from}:0").parse().unwrap()).unwrap();
        s.connect(to).await.unwrap()
    }

    /// Whether the service closed `s` within `wait`: end of stream or a
    /// reset, not silence.
    async fn closed_within(s: &mut tokio::net::TcpStream, wait: Duration) -> bool {
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 64];
        matches!(
            tokio::time::timeout(wait, s.read(&mut buf)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    async fn get_record(from: &str, to: SocketAddr) -> String {
        use tokio::io::AsyncReadExt;
        let mut s = connect_from(from, to).await;
        s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn a_connection_that_sends_nothing_or_too_little_is_closed_soon() {
        let (addr, _rx) = service(node("exit"), QUICK).await;
        let t0 = Instant::now();
        let mut idle = connect_from("127.0.0.1", addr).await;
        assert!(closed_within(&mut idle, Duration::from_secs(2)).await);
        let idle_for = t0.elapsed();
        assert!(
            idle_for >= QUICK.first_byte && idle_for < QUICK.request,
            "closed after {idle_for:?}, at the first-byte deadline"
        );
        let t0 = Instant::now();
        let mut slow = connect_from("127.0.0.1", addr).await;
        slow.write_all(b"POST /admit HTTP/1.1\r\nContent-Le")
            .await
            .unwrap();
        assert!(closed_within(&mut slow, Duration::from_secs(2)).await);
        let slow_for = t0.elapsed();
        assert!(
            slow_for >= QUICK.request && slow_for < QUICK.per_connection,
            "closed after {slow_for:?}, at the request deadline"
        );
        assert!(get_record("127.0.0.1", addr)
            .await
            .starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn a_full_service_closes_a_new_connection_at_once_and_serves_once_there_is_room() {
        let limits = Limits {
            per_ip: QUICK.connections,
            first_byte: Duration::from_secs(10),
            request: Duration::from_secs(10),
            per_connection: Duration::from_secs(10),
            ..QUICK
        };
        let (addr, _rx) = service(node("exit"), limits).await;
        let mut held = Vec::new();
        for _ in 0..limits.connections {
            held.push(connect_from("127.0.0.1", addr).await);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for s in held.iter_mut() {
            assert!(
                !closed_within(s, Duration::from_millis(50)).await,
                "within the cap: kept"
            );
        }
        let mut late = connect_from("127.0.0.1", addr).await;
        assert!(
            closed_within(&mut late, Duration::from_millis(500)).await,
            "one past the cap is closed at once, not left waiting"
        );
        drop(held);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(get_record("127.0.0.1", addr)
            .await
            .starts_with("HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn an_entry_listed_as_a_relay_holds_more_connections_than_another_address() {
        let mut cfg = node("exit");
        cfg.admission_relays = vec!["127.0.0.1".parse().unwrap()];
        let limits = Limits {
            connections: 16,
            first_byte: Duration::from_secs(10),
            request: Duration::from_secs(10),
            per_connection: Duration::from_secs(10),
            ..QUICK
        };
        let (addr, _rx) = service(cfg, limits).await;
        // The relay: every two-hop client of that entry comes from it.
        let mut relayed = Vec::new();
        for _ in 0..limits.per_relay {
            relayed.push(connect_from("127.0.0.1", addr).await);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for s in relayed.iter_mut() {
            assert!(!closed_within(s, Duration::from_millis(50)).await);
        }
        let mut one_more = connect_from("127.0.0.1", addr).await;
        assert!(closed_within(&mut one_more, Duration::from_millis(500)).await);
        // Any other address keeps the ordinary share.
        let mut other = Vec::new();
        for _ in 0..limits.per_ip {
            other.push(connect_from("127.0.0.2", addr).await);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for s in other.iter_mut() {
            assert!(!closed_within(s, Duration::from_millis(50)).await);
        }
        let mut past = connect_from("127.0.0.2", addr).await;
        assert!(closed_within(&mut past, Duration::from_millis(500)).await);
    }

    #[test]
    fn a_lease_name_is_the_wish_or_a_number() {
        assert_eq!(lease_name("laptop", 7), "laptop");
        assert_eq!(lease_name("", 7), "open-7");
        assert_eq!(lease_name("has space", 8), "open-8");
        assert_eq!(lease_name(&"x".repeat(40), 9), "open-9");
    }
}
