//! Open admission: how a client gets admitted on a node without meeting its
//! operator, and the one reason a stranger can connect at all.
//!
//! A node that runs with `admission = "open"` answers a small HTTP service
//! beside its WireGuard port (TCP 51821 by default). A client that knows the
//! node from a signed list sends the key it will show that node and gets its
//! invite back; the node has admitted it, rate-limited by source address and
//! capped in number, and the client checks that the invite names the node
//! the list named — the same public key, the same endpoint — before it trusts
//! a byte of it. So the exchange needs no secrecy: an invite carries nothing
//! secret, and a man in the middle who swapped it for another node's would be
//! caught by the key.
//!
//! The HTTP is the smallest useful subset, written here rather than pulled
//! in: one request, one answer, `Connection: close`, strict limits.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::config::Invite;
use crate::directory::NodeRecord;

/// Where a node answers admission requests, unless its record says otherwise.
pub const DEFAULT_ADMISSION_PORT: u16 = 51821;
/// How long the whole exchange may take.
pub const TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HEADERS: usize = 8 * 1024;
const MAX_BODY: usize = 16 * 1024;
const MAX_ANSWER: usize = 64 * 1024;

/// What a client sends to `POST /admit`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionRequest {
    /// The key the client will show this node (derived for it; never the
    /// master key).
    pub public_key: String,
    /// A name for the lease, for the operator's `status`; optional.
    #[serde(default)]
    pub name: String,
    /// A key made for one connection, asked for through an entry: the node
    /// keeps its lease only while the connection lives (a short idle window,
    /// not days), so it holds nothing about the client once it is over.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub session: bool,
    /// The proof of work a session admission carries (`work`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<Work>,
}

/// A proof of work: a nonce that makes the digest of this node, this key and
/// this minute start with enough zero bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Work {
    pub minute: u64,
    pub nonce: u64,
}

/// What a session admission costs the client, instead of who it is.
///
/// A node that admits a fresh key for every connection cannot count requests
/// per client — it does not know who the client is, by design — and counting
/// per source address would throttle every client of a busy entry together.
/// So each such request carries a proof of work bound to the node, the key
/// it asks for and the current minute: about a second of one core for a
/// person connecting, and the same second again for every lease a script
/// would take. It is not proof against someone with many machines; passes
/// (phase 5) are. A key's lease is only granted once, so replaying a proof
/// buys nothing, and the minute stops proofs being stockpiled.
pub mod work {
    use sha2::{Digest, Sha256};

    /// What a client does when the node has not said otherwise.
    pub const DEFAULT_BITS: u8 = 20;
    /// What a client agrees to do at most when a node asks for more.
    pub const MAX_BITS: u8 = 26;
    /// How far, in minutes, a proof's minute may be from the node's clock.
    pub const SLACK_MINUTES: u64 = 2;
    const DOMAIN: &[u8] = b"HidraVPN admission work v1";

    pub fn now_minute() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() / 60)
            .unwrap_or(0)
    }

    fn digest(node: &[u8; 32], client: &[u8; 32], minute: u64, nonce: u64) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DOMAIN);
        h.update(node);
        h.update(client);
        h.update(minute.to_be_bytes());
        h.update(nonce.to_be_bytes());
        h.finalize().into()
    }

    fn zero_bits(d: &[u8; 32]) -> u32 {
        let mut n = 0;
        for b in d {
            if *b == 0 {
                n += 8;
            } else {
                return n + b.leading_zeros();
            }
        }
        n
    }

    /// The first nonce that makes the digest start with `bits` zero bits.
    pub fn solve(node: &[u8; 32], client: &[u8; 32], minute: u64, bits: u8) -> super::Work {
        let mut nonce = 0u64;
        while zero_bits(&digest(node, client, minute, nonce)) < u32::from(bits) {
            nonce += 1;
        }
        super::Work { minute, nonce }
    }

    /// Whether `w` proves `bits` of work for this node and key, made within
    /// `SLACK_MINUTES` of `now_minute`.
    pub fn verify(
        node: &[u8; 32],
        client: &[u8; 32],
        w: super::Work,
        bits: u8,
        now_minute: u64,
    ) -> bool {
        now_minute.abs_diff(w.minute) <= SLACK_MINUTES
            && zero_bits(&digest(node, client, w.minute, w.nonce)) >= u32::from(bits)
    }
}

/// What a node answers when it does not admit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refusal {
    pub error: String,
    /// A node that wants more work than a request carried says how much.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_bits: Option<u8>,
}

// ---- the client ----------------------------------------------------------

/// The node's own record, as it describes itself on `GET /`.
pub async fn fetch_record(ip: IpAddr, port: u16) -> Result<NodeRecord> {
    let (status, body) = http_call(SocketAddr::new(ip, port), "GET", "/", "").await?;
    if status != 200 {
        return Err(anyhow!(
            "the node answered {status}: {}",
            refusal_text(&body)
        ));
    }
    let rec: NodeRecord = serde_json::from_str(&body).context("the node's record is unreadable")?;
    rec.validate()?;
    Ok(rec)
}

/// Asks the node to admit `client_public_key` and returns the invite, checked
/// against what the list said the node is.
pub async fn request_admission(
    record: &NodeRecord,
    client_public_key: &str,
    name: &str,
    session: bool,
) -> Result<Invite> {
    let endpoint: SocketAddr = record
        .endpoint
        .parse()
        .context("the node's endpoint is not ip:port")?;
    let port = record.admission_port.unwrap_or(DEFAULT_ADMISSION_PORT);
    let mut bits = work::DEFAULT_BITS;
    let (status, answer) = loop {
        let proof = if session {
            let node = *crate::keys::public_key_from_base64(&record.node_public_key)?.as_bytes();
            let client = *crate::keys::public_key_from_base64(client_public_key)?.as_bytes();
            let minute = work::now_minute();
            Some(
                tokio::task::spawn_blocking(move || work::solve(&node, &client, minute, bits))
                    .await
                    .context("working out the proof of work")?,
            )
        } else {
            None
        };
        let body = serde_json::to_string(&AdmissionRequest {
            public_key: client_public_key.to_string(),
            name: name.to_string(),
            session,
            work: proof,
        })?;
        let (status, answer) = http_call(
            SocketAddr::new(endpoint.ip(), port),
            "POST",
            "/admit",
            &body,
        )
        .await?;
        // A node that wants more work says how much, once; within reason.
        match serde_json::from_str::<Refusal>(&answer)
            .ok()
            .and_then(|r| r.work_bits)
        {
            Some(want) if status == 428 && session && want > bits && want <= work::MAX_BITS => {
                bits = want;
            }
            _ => break (status, answer),
        }
    };
    if status != 200 {
        return Err(anyhow!(
            "{} did not admit this machine ({status}): {}",
            record.node_name,
            refusal_text(&answer)
        ));
    }
    checked_invite(record, &answer)
}

/// A node looked at a pass and said no (spent, expired, not for it, not
/// signed right): the pass is worth nothing there, unlike a pass that never
/// reached the node, which is kept.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PassRefused(pub String);

/// Redeems a pass on the node the record names and returns the invite,
/// checked the same way: the node's key and endpoint as the list has them.
/// The invite remembers the pass's fresh key, which the tunnel then shows.
pub async fn redeem_pass(record: &NodeRecord, pass: &crate::pass::Pass) -> Result<Invite> {
    if pass.node_public_key.trim() != record.node_public_key.trim() {
        return Err(anyhow!(
            "that pass was made for another node than {}",
            record.node_name
        ));
    }
    let endpoint: SocketAddr = record
        .endpoint
        .parse()
        .context("the node's endpoint is not ip:port")?;
    let port = record.admission_port.unwrap_or(DEFAULT_ADMISSION_PORT);
    let body = serde_json::to_string(&pass.redemption()?)?;
    let (status, answer) = http_call(
        SocketAddr::new(endpoint.ip(), port),
        "POST",
        "/redeem",
        &body,
    )
    .await?;
    if status != 200 {
        let why = format!(
            "{} did not take the pass ({status}): {}",
            record.node_name,
            refusal_text(&answer)
        );
        // 503 (full, stopping) and 5xx say nothing about the pass itself.
        if status >= 500 {
            return Err(anyhow!(why));
        }
        return Err(PassRefused(why).into());
    }
    // The node took the pass (200): whatever is wrong with its answer now,
    // the pass is spent there and must not be kept for another try.
    let mut invite = checked_invite(record, &answer).map_err(|e| PassRefused(format!("{e:#}")))?;
    invite.pass = Some(crate::config::PassBinding {
        client_secret: pass.client_secret.clone(),
        admission_port: record.admission_port,
        redeemed_at: crate::timefmt::now_unix().max(0) as u64,
        used_at: 0,
    });
    Ok(invite)
}

/// An invite from a node, held against the record the signed list carried.
fn checked_invite(record: &NodeRecord, answer: &str) -> Result<Invite> {
    let endpoint: SocketAddr = record
        .endpoint
        .parse()
        .context("the node's endpoint is not ip:port")?;
    let mut invite = Invite::from_json(answer).context("the invite the node sent is not valid")?;
    if invite.node_public_key.trim() != record.node_public_key.trim() {
        return Err(anyhow!(
            "the invite names another key than the list does for {}: not the node the list named; refusing it",
            record.node_name
        ));
    }
    if invite.endpoint_addr()? != endpoint {
        return Err(anyhow!(
            "the invite names another endpoint than the list does for {}; refusing it",
            record.node_name
        ));
    }
    // What the pocket remembers about the node is what the signed list said,
    // not what the node claims for itself: its name, who runs it, its role,
    // its country (none when the list names none).
    // And a node never chooses the key this client shows it.
    invite.node_name = record.node_name.clone();
    invite.operator = record.operator.clone();
    invite.role = record.role.clone();
    invite.country = record.country.clone();
    invite.admission = record.admission.clone();
    invite.admission_port = record.admission_port;
    invite.features = record.features.clone();
    invite.pass = None;
    Ok(invite)
}

fn refusal_text(body: &str) -> String {
    serde_json::from_str::<Refusal>(body)
        .map(|r| r.error)
        .unwrap_or_else(|_| body.trim().chars().take(200).collect())
}

async fn http_call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(u16, String)> {
    let io = async {
        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to the node's admission port {addr}"))?;
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            addr.ip(),
            body.len()
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;
        let mut raw = Vec::new();
        let mut limited = stream.take(MAX_ANSWER as u64);
        limited.read_to_end(&mut raw).await?;
        parse_response(&raw)
    };
    tokio::time::timeout(TIMEOUT, io)
        .await
        .map_err(|_| anyhow!("the node did not answer within {TIMEOUT:?}"))?
}

// The node's answer, read the way every answer this client gets is read:
// cut short against its length, or not text, it is refused.
use crate::http::parse_response;

// ---- the server's half, shared so the node parses exactly what the client sends ----

/// One request, as the node reads it.
#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Reads one HTTP/1.1 request with strict limits; anything odd is an error
/// the caller answers with 400.
pub async fn read_request<R: tokio::io::AsyncRead + Unpin>(r: R) -> Result<HttpRequest> {
    let mut reader = BufReader::new(r.take((MAX_HEADERS + MAX_BODY) as u64));
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || !path.starts_with('/') {
        return Err(anyhow!("not an HTTP request"));
    }
    let mut content_length = 0usize;
    let mut total = line.len();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        total += n;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if total > MAX_HEADERS {
            return Err(anyhow!("headers too long"));
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v
                    .trim()
                    .parse()
                    .map_err(|_| anyhow!("bad content-length"))?;
            }
        }
    }
    if content_length > MAX_BODY {
        return Err(anyhow!("body too long"));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }
    Ok(HttpRequest { method, path, body })
}

/// One answer: a status, a JSON body, and the connection closes.
pub fn http_response(status: u16, body: &str) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        428 => "Precondition Required",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A refusal body.
pub fn refusal(msg: impl Into<String>) -> String {
    serde_json::to_string(&Refusal {
        error: msg.into(),
        work_bits: None,
    })
    .expect("a refusal serialises")
}

/// A refusal that says how much work the node wants (status 428).
pub fn refusal_wanting_work(bits: u8) -> String {
    serde_json::to_string(&Refusal {
        error: format!("a session admission here needs a proof of {bits} bits of work"),
        work_bits: Some(bits),
    })
    .expect("a refusal serialises")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_is_bound_to_the_node_the_key_and_the_minute() {
        let node = [7u8; 32];
        let client = [9u8; 32];
        let w = work::solve(&node, &client, 1000, 12);
        assert!(work::verify(&node, &client, w, 12, 1000));
        assert!(
            work::verify(&node, &client, w, 12, 1002),
            "a little clock skew is fine"
        );
        assert!(
            !work::verify(&node, &client, w, 12, 1003),
            "an old proof is not"
        );
        assert!(
            !work::verify(&[8u8; 32], &client, w, 12, 1000),
            "another node"
        );
        assert!(!work::verify(&node, &[1u8; 32], w, 12, 1000), "another key");
        // More bits than were worked for: almost never enough by luck.
        let hard = (0..64)
            .filter(|m| work::verify(&node, &client, work::solve(&node, &client, *m, 4), 20, *m))
            .count();
        assert!(hard < 2, "{hard}");
    }

    #[tokio::test]
    async fn a_request_is_read_with_its_body_and_limits_hold() {
        let raw = b"POST /admit HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello";
        let r = read_request(&raw[..]).await.unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/admit"));
        assert_eq!(r.body, b"hello");
        let r = read_request(&b"GET / HTTP/1.1\r\n\r\n"[..]).await.unwrap();
        assert!(r.body.is_empty());
        assert!(read_request(&b"nonsense\r\n\r\n"[..]).await.is_err());
        let big = format!(
            "POST /admit HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(read_request(big.as_bytes()).await.is_err());
        let long = format!("GET / HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(MAX_HEADERS));
        assert!(read_request(long.as_bytes()).await.is_err());
    }

    #[test]
    fn an_answer_is_parsed_and_a_refusal_is_read_back() {
        let resp = http_response(429, &refusal("slow down"));
        let (status, body) = parse_response(&resp).unwrap();
        assert_eq!(status, 429);
        assert_eq!(refusal_text(&body), "slow down");
        assert!(parse_response(b"garbage").is_err());
        assert_eq!(refusal_text("not json"), "not json");
    }

    #[tokio::test]
    async fn the_client_checks_the_invite_against_the_record() {
        // A stand-in node that admits, but with another key than the list has.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let other = crate::keys::ClientKey::generate().unwrap().public_base64();
        let invite_json = serde_json::json!({
            "node_name": "n", "node_public_key": other, "endpoint": format!("127.0.0.1:{port}"),
            "client_address": "10.77.0.2/16", "dns": "10.77.0.1"
        })
        .to_string();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut s).await;
            let _ = s.write_all(&http_response(200, &invite_json)).await;
        });
        let record = NodeRecord {
            node_name: "n".into(),
            node_public_key: crate::keys::ClientKey::generate().unwrap().public_base64(),
            endpoint: format!("127.0.0.1:{port}"),
            operator: None,
            contact: None,
            role: None,
            admission: Some("open".into()),
            admission_port: Some(port),
            country: None,
            features: Vec::new(),
        };
        let e = request_admission(&record, "k", "laptop", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("another key"), "{e}");
    }

    #[tokio::test]
    async fn the_client_checks_the_invite_endpoint_against_the_record() {
        // The right key, but an invite that would send the tunnel elsewhere.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let node_key = crate::keys::ClientKey::generate().unwrap().public_base64();
        let invite_json = serde_json::json!({
            "node_name": "n", "node_public_key": node_key, "endpoint": "127.0.0.2:51820",
            "client_address": "10.77.0.2/16", "dns": "10.77.0.1"
        })
        .to_string();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut s).await;
            let _ = s.write_all(&http_response(200, &invite_json)).await;
        });
        let record = NodeRecord {
            node_name: "n".into(),
            node_public_key: node_key.clone(),
            endpoint: format!("127.0.0.1:{port}"),
            operator: None,
            contact: None,
            role: None,
            admission: Some("open".into()),
            admission_port: Some(port),
            country: None,
            features: Vec::new(),
        };
        let e = request_admission(&record, "k", "laptop", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("another endpoint"), "{e}");
    }

    #[tokio::test]
    async fn a_refusal_from_the_node_is_reported_in_its_words() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read_request(&mut s).await;
            let _ = s
                .write_all(&http_response(403, &refusal("admission here is by hand")))
                .await;
        });
        let record = NodeRecord {
            node_name: "n".into(),
            node_public_key: crate::keys::ClientKey::generate().unwrap().public_base64(),
            endpoint: format!("127.0.0.1:{port}"),
            operator: None,
            contact: None,
            role: None,
            admission: Some("manual".into()),
            admission_port: Some(port),
            country: None,
            features: Vec::new(),
        };
        let e = request_admission(&record, "k", "laptop", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("403") && e.contains("by hand"), "{e}");
    }
}
