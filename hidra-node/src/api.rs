//! The status server the browser reads to draw its connection panel.
//!
//! It listens on loopback, which keeps other machines out but not web pages:
//! anything open in any browser on this machine can issue requests to
//! 127.0.0.1. [`crate::local_guard`] screens those by `Host` and `Origin`,
//! and that screening is the first line here.
//!
//! It is not the only one, because of what this endpoint used to return.
//! `/api/circuit` answered with the IP addresses of the guard, middle and
//! exit relays of the live circuit. The entry guard is the single address
//! that identifies a user to anyone watching the network, so one mistake in
//! the screening — a header parsed slightly differently from the way a
//! browser sends it, a redirect, some future `fetch` mode nobody thought
//! about — turns directly into a deanonymisation. Screening that has to be
//! perfect is not a good place to put the only defence.
//!
//! So two things changed. The addresses are gone: a caller gets an opaque
//! per-run fingerprint, enough to show three distinct hops and to notice when
//! they change, and nothing that names a machine. And `/api/circuit` now
//! needs a token the engine writes to a file only the user can read — a web
//! page cannot read a local file no matter how the screening fails.
//!
//! `/api/status` carries no fingerprint and no address, so it stays open to
//! anything local that passes the screen.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};


pub struct ApiState {
    pub start_time: Instant,
    pub relay_count: usize,
    pub relay_addrs: Vec<SocketAddr>,
    pub hops: usize,
    /// Proves the caller can read a file on this machine. Empty disables the
    /// check, which only happens when the token file could not be written —
    /// and then the circuit endpoint refuses rather than answering freely.
    pub token: String,
    /// Keyed per run, so a fingerprint means nothing outside this process and
    /// two runs cannot be lined up against each other.
    fingerprint_key: [u8; 32],
}

impl ApiState {
    pub fn new(
        start_time: Instant,
        relay_count: usize,
        relay_addrs: Vec<SocketAddr>,
        hops: usize,
        token: String,
    ) -> Self {
        let mut fingerprint_key = [0u8; 32];
        OsRng.fill_bytes(&mut fingerprint_key);
        Self {
            start_time,
            relay_count,
            relay_addrs,
            hops,
            token,
            fingerprint_key,
        }
    }

    /// A short, stable, meaningless name for a relay.
    ///
    /// Stable within a run, so the panel can show that the circuit has not
    /// changed. Meaningless outside it: the key is random per process and
    /// never leaves memory, which matters because an IPv4 address is only 32
    /// bits — an unkeyed hash of one is recovered by trying all of them.
    fn fingerprint(&self, addr: &SocketAddr) -> String {
        let hash = blake3::keyed_hash(&self.fingerprint_key, addr.to_string().as_bytes());
        hash.as_bytes()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Generate the token and write it where only this user can read it.
///
/// Returns an empty string if it could not be written, which leaves
/// `/api/circuit` refusing every request. That is the right failure: the
/// endpoint is a convenience, and answering without the check is the thing
/// the check exists to prevent.
pub fn issue_token(keys_dir: &Path) -> String {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    let path = keys_dir.join("api_token");
    if let Err(e) = crate::crypto::keys::write_private_file(&path, token.as_bytes()) {
        warn!(
            error = %e,
            "could not write the status API token; /api/circuit will refuse \
             every request rather than answer without it"
        );
        return String::new();
    }
    info!("status API token written to the keys directory");
    token
}

pub async fn run_api_server(addr: SocketAddr, state: Arc<ApiState>) {
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(error = %e, addr = %addr, "status API server failed to bind");
            return;
        }
    };

    info!(addr = %addr, "status API server listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            handle_request(stream, &state).await;
        });
    }
}

/// The bearer token on a request, from the header or the query string.
fn presented_token(request: &str) -> Option<&str> {
    let head = request.split("\r\n\r\n").next().unwrap_or(request);

    for line in head.split("\r\n").skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((_, value)) = line
            .split_once(':')
            .filter(|(key, _)| key.trim().eq_ignore_ascii_case("authorization"))
        {
            return value.trim().strip_prefix("Bearer ").map(str::trim);
        }
    }

    // ?token=… on the request line, for callers that cannot set headers.
    let request_line = head.split("\r\n").next()?;
    let target = request_line.split(' ').nth(1)?;
    let query = target.split_once('?')?.1;
    query.split('&').find_map(|p| p.strip_prefix("token="))
}

/// Compare in constant time: a token checked with `==` leaks its prefix to
/// anything that can time the reply, and something that can reach this
/// endpoint can time the reply.
fn token_ok(expected: &str, presented: Option<&str>) -> bool {
    if expected.is_empty() {
        return false;
    }
    let Some(presented) = presented else {
        return false;
    };
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

async fn handle_request(mut stream: tokio::net::TcpStream, state: &ApiState) {
    let mut buf = [0u8; 2048];
    // A peer that opens a connection and never sends used to hold a task
    // open indefinitely; enough of them and the server stops answering.
    let n = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
        Ok(Ok(n)) => n,
    };

    let request = String::from_utf8_lossy(&buf[..n]);

    let allowed_origin = match crate::local_guard::screen(&request) {
        crate::local_guard::Access::Allow(origin) => origin,
        crate::local_guard::Access::Deny => {
            let (code, text) = crate::local_guard::DENIED_STATUS;
            let body = crate::local_guard::DENIED_BODY;
            let response = format!(
                "HTTP/1.1 {code} {text}\r\n\
                 Content-Type: application/json\r\n\
                 {}\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                crate::local_guard::response_headers(None),
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            return;
        }
    };

    let (status_code, status_text, body) = if request.starts_with("GET /api/status") {
        let uptime = state.start_time.elapsed().as_secs();
        // "latency" was the literal 42. Nothing here measures a round
        // trip, so it reports null and a caller can show "—" rather than a
        // number that was never true.
        let body = format!(
            r#"{{"connected":true,"relays":{},"latency":null,"uptime":{},"hops":{}}}"#,
            state.relay_count, uptime, state.hops
        );
        (200, "OK", body)
    } else if request.starts_with("GET /api/circuit") {
        if !token_ok(&state.token, presented_token(&request)) {
            (
                403,
                "Forbidden",
                r#"{"error":"the circuit view needs the token from the keys directory"}"#
                    .to_string(),
            )
        } else {
            let hops: Vec<String> = state
                .relay_addrs
                .iter()
                .enumerate()
                .map(|(i, addr)| {
                    let role = match i {
                        0 => "Guard",
                        1 => "Middle",
                        _ => "Exit",
                    };
                    // A fingerprint, never the address. The panel wants to
                    // show three hops and notice when they change; it has
                    // never wanted to name a machine, and naming the guard
                    // is what would identify the user.
                    format!(
                        r#"{{"fingerprint":"{}","role":"{role}"}}"#,
                        state.fingerprint(addr)
                    )
                })
                .collect();
            let body = format!(r#"{{"hops":[{}]}}"#, hops.join(","));
            (200, "OK", body)
        }
    } else if request.starts_with("OPTIONS") {
        (204, "No Content", String::new())
    } else {
        (404, "Not Found", r#"{"error":"not found"}"#.to_string())
    };

    let response = format!(
        "HTTP/1.1 {status_code} {status_text}\r\n\
         Content-Type: application/json\r\n\
         {}\
         Access-Control-Allow-Methods: GET, OPTIONS\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {body}",
        crate::local_guard::response_headers(allowed_origin.as_deref()),
        body.len()
    );

    let _ = stream.write_all(response.as_bytes()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with(token: &str) -> ApiState {
        ApiState::new(
            Instant::now(),
            3,
            vec![
                "198.51.100.1:9150".parse().unwrap(),
                "198.51.100.2:9150".parse().unwrap(),
                "198.51.100.3:9150".parse().unwrap(),
            ],
            3,
            token.to_string(),
        )
    }

    #[test]
    fn a_fingerprint_does_not_contain_the_address() {
        let state = state_with("t");
        let addr: SocketAddr = "198.51.100.1:9150".parse().unwrap();
        let fp = state.fingerprint(&addr);
        assert!(!fp.contains("198"), "{fp}");
        assert!(!fp.contains("9150"), "{fp}");
        assert_eq!(fp.len(), 8);
    }

    #[test]
    fn the_same_relay_fingerprints_the_same_way_within_a_run() {
        let state = state_with("t");
        let addr: SocketAddr = "198.51.100.1:9150".parse().unwrap();
        assert_eq!(state.fingerprint(&addr), state.fingerprint(&addr));
    }

    #[test]
    fn two_runs_do_not_share_fingerprints() {
        let addr: SocketAddr = "198.51.100.1:9150".parse().unwrap();
        let a = state_with("t").fingerprint(&addr);
        let b = state_with("t").fingerprint(&addr);
        assert_ne!(a, b, "a fingerprint must not survive a restart");
    }

    #[test]
    fn the_fingerprint_is_not_a_plain_hash_of_the_address() {
        // Unkeyed, 32 bits of address space is enumerable in seconds.
        let addr: SocketAddr = "198.51.100.1:9150".parse().unwrap();
        let unkeyed: String = blake3::hash(addr.to_string().as_bytes()).as_bytes()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(state_with("t").fingerprint(&addr), unkeyed);
    }

    #[test]
    fn a_token_is_read_from_the_header_and_the_query() {
        assert_eq!(
            presented_token("GET /api/circuit HTTP/1.1\r\nAuthorization: Bearer abc123\r\n\r\n"),
            Some("abc123")
        );
        assert_eq!(
            presented_token("GET /api/circuit?token=abc123 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some("abc123")
        );
        assert_eq!(
            presented_token("GET /api/circuit HTTP/1.1\r\nHost: x\r\n\r\n"),
            None
        );
    }

    #[test]
    fn a_token_in_the_body_is_not_accepted() {
        // The body is attacker-controlled on a cross-origin POST.
        assert_eq!(
            presented_token(
                "POST /api/circuit HTTP/1.1\r\nHost: x\r\n\r\nAuthorization: Bearer abc123"
            ),
            None
        );
    }

    #[test]
    fn the_wrong_token_is_refused() {
        assert!(!token_ok("abc123", Some("abc124")));
        assert!(!token_ok("abc123", Some("abc12")));
        assert!(!token_ok("abc123", Some("")));
        assert!(!token_ok("abc123", None));
        assert!(token_ok("abc123", Some("abc123")));
    }

    #[test]
    fn no_token_at_all_refuses_everything() {
        // The file could not be written. Refusing is correct: answering
        // without the check defeats the reason for having it.
        assert!(!token_ok("", Some("")));
        assert!(!token_ok("", None));
        assert!(!token_ok("", Some("anything")));
    }
}
