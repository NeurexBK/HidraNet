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
}

/// What a node answers when it does not admit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refusal {
    pub error: String,
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
) -> Result<Invite> {
    let endpoint: SocketAddr = record
        .endpoint
        .parse()
        .context("the node's endpoint is not ip:port")?;
    let port = record.admission_port.unwrap_or(DEFAULT_ADMISSION_PORT);
    let body = serde_json::to_string(&AdmissionRequest {
        public_key: client_public_key.to_string(),
        name: name.to_string(),
    })?;
    let (status, answer) = http_call(
        SocketAddr::new(endpoint.ip(), port),
        "POST",
        "/admit",
        &body,
    )
    .await?;
    if status != 200 {
        return Err(anyhow!(
            "{} did not admit this machine ({status}): {}",
            record.node_name,
            refusal_text(&answer)
        ));
    }
    let mut invite = Invite::from_json(&answer).context("the invite the node sent is not valid")?;
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
    // not what the node claims for itself: its name, who runs it, its role.
    invite.node_name = record.node_name.clone();
    invite.operator = record.operator.clone();
    invite.role = record.role.clone();
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

fn parse_response(raw: &[u8]) -> Result<(u16, String)> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("the node's answer has no headers"))?;
    let status_line = head.lines().next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("the node's answer has no status: {status_line}"))?;
    Ok((status, body.to_string()))
}

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
    serde_json::to_string(&Refusal { error: msg.into() }).expect("a refusal serialises")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let e = request_admission(&record, "k", "laptop")
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
        };
        let e = request_admission(&record, "k", "laptop")
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
        };
        let e = request_admission(&record, "k", "laptop")
            .await
            .unwrap_err()
            .to_string();
        assert!(e.contains("403") && e.contains("by hand"), "{e}");
    }
}
