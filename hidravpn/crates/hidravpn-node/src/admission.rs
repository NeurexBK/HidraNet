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
//! concurrent ones. A script with enough addresses can still fill a node in
//! hours; what it cannot do is keep it full, because a lease that never
//! completes a handshake lapses within a quarter of an hour (`leases.rs`),
//! so filling a node costs real tunnels, not requests.
//! Nothing here logs an address or a key: counts only.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use hidravpn_core::admission::{http_response, read_request, refusal, AdmissionRequest};
use hidravpn_core::Invite;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot, Mutex, Semaphore};
use tracing::{info, warn};

use crate::config::NodeConfig;

/// One admission the main loop is asked to make.
pub struct Admit {
    pub public_key: String,
    pub name: String,
    /// The client's ML-KEM public key, when it sent one; the main loop
    /// answers it with a ciphertext and sets the agreed pre-shared key.
    pub kem_public_key: Option<String>,
    /// The invite, or the HTTP status and reason for refusing.
    pub reply: oneshot::Sender<std::result::Result<Invite, (u16, String)>>,
}

const PER_IP: usize = 3;
const PER_IP_WINDOW: Duration = Duration::from_secs(600);
const GLOBAL: usize = 120;
const GLOBAL_WINDOW: Duration = Duration::from_secs(600);
const CONNECTIONS: usize = 32;
const PER_CONNECTION: Duration = Duration::from_secs(5);

/// A sliding-window count per source address and overall.
#[derive(Default)]
pub struct RateLimiter {
    per_ip: HashMap<IpAddr, VecDeque<Instant>>,
    global: VecDeque<Instant>,
}

impl RateLimiter {
    /// Whether one more admission from `ip` is allowed now; records it if so.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        while self
            .global
            .front()
            .is_some_and(|t| now.duration_since(*t) > GLOBAL_WINDOW)
        {
            self.global.pop_front();
        }
        if self.global.len() >= GLOBAL {
            return false;
        }
        let q = self.per_ip.entry(ip).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > PER_IP_WINDOW)
        {
            q.pop_front();
        }
        if q.len() >= PER_IP {
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
        .with_context(|| format!("binding the admission port {listen}"))?;
    info!(
        "admission service on TCP {} ({})",
        listen.port(),
        if cfg.admission_is_open() {
            "open: any client may ask"
        } else {
            "by hand: describes the node only"
        }
    );
    let limiter = Arc::new(Mutex::new(RateLimiter::default()));
    let slots = Arc::new(Semaphore::new(CONNECTIONS));
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
        let (cfg, tx, limiter, counter) =
            (cfg.clone(), tx.clone(), limiter.clone(), counter.clone());
        tokio::spawn(async move {
            let _slot = slot;
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
    if hidravpn_core::keys::public_key_from_base64(&req.public_key).is_err() {
        return http_response(
            400,
            &refusal("public_key is not a WireGuard public key (32 bytes, base64)"),
        );
    }
    // Likewise a KEM key that is not one, before it costs anyone a slot.
    if let Some(ek) = &req.kem_public_key {
        if hidravpn_core::psk::answer(ek, "probe", "probe").is_err() {
            return http_response(
                400,
                &refusal("kem_public_key is not an ML-KEM-1024 public key (1568 bytes, base64)"),
            );
        }
    }
    if !limiter.lock().await.allow(ip, Instant::now()) {
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
            name,
            kem_public_key: req.kem_public_key,
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
