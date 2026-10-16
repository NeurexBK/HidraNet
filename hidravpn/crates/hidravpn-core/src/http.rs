//! The smallest HTTP(S) client that the pass issuer needs: one request, one
//! answer, `Connection: close`, strict limits. HTTPS through rustls with the
//! Mozilla roots built in, so no system store is trusted.
//!
//! Plain HTTP is refused unless the host is an address that never leaves a
//! private network (loopback, RFC 1918, carrier-grade NAT), because what goes
//! to the issuer is an account token: on the open internet it travels
//! encrypted or not at all.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long one exchange may take, connecting included.
pub const TIMEOUT: Duration = Duration::from_secs(15);
/// The most an answer may be.
pub const MAX_ANSWER: usize = 256 * 1024;

/// A URL this client can follow.
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(s: &str) -> Result<Url> {
        let s = s.trim();
        let (https, rest) = if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(anyhow!("{s:?} is not an http:// or https:// address"));
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, "/".to_string()),
        };
        if authority.is_empty() || authority.contains('@') {
            return Err(anyhow!("{s:?} has no usable host"));
        }
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(r) = authority.strip_prefix('[') {
            let (h, after) = r
                .split_once(']')
                .ok_or_else(|| anyhow!("{s:?}: an IPv6 host needs its closing ]"))?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse().context("the port is not a number")?,
                None => default_port,
            };
            (h.to_string(), port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse().context("the port is not a number")?,
                ),
                None => (authority.to_string(), default_port),
            }
        };
        if host.is_empty()
            || !host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
        {
            return Err(anyhow!("{s:?} has no usable host"));
        }
        if !https && !stays_private(&host) {
            return Err(anyhow!(
                "{s:?} is plain HTTP to an address on the open internet; an account token only travels over https://"
            ));
        }
        Ok(Url {
            https,
            host,
            port,
            path,
        })
    }

    /// The same host and port, with `path` under the URL's own path: an
    /// issuer at "https://example.org/passes/" is asked at "/passes/issue".
    pub fn with_path(&self, path: &str) -> Url {
        let mut u = self.clone();
        u.path = format!(
            "{}/{}",
            self.path.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        u
    }

    /// Whether an account token may be sent here: over https://, or plain
    /// HTTP to this machine itself. A private address is not enough: the
    /// network a laptop sits on is whoever runs the café's router.
    /// `HIDRAVPN_PLAIN_HTTP_ISSUER=1` lifts this for a test network.
    pub fn check_for_token(&self) -> Result<()> {
        if self.https || loopback(&self.host) {
            return Ok(());
        }
        if std::env::var("HIDRAVPN_PLAIN_HTTP_ISSUER").as_deref() == Ok("1") {
            return Ok(());
        }
        Err(anyhow!(
            "the pass issuer at {} speaks plain HTTP; an account token only travels over https:// (or to this machine itself)",
            self.host
        ))
    }
}

fn loopback(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(a) => a.is_loopback(),
        Err(_) => host == "localhost",
    }
}

fn stays_private(host: &str) -> bool {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            let o = a.octets();
            a.is_loopback() || a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        Ok(IpAddr::V6(a)) => a.is_loopback(),
        Err(_) => host == "localhost",
    }
}

/// Sends one request and returns the status and the body.
pub async fn call(url: &Url, method: &str, body: &str) -> Result<(u16, String)> {
    let io = async {
        let addr = resolve(url).await?;
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .with_context(|| format!("connecting to {}", url.host))?;
        if url.https {
            let mut roots = tokio_rustls::rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let config = tokio_rustls::rustls::ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| anyhow!("TLS setup: {e}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
            let name = tokio_rustls::rustls::pki_types::ServerName::try_from(url.host.clone())
                .map_err(|_| anyhow!("{} is not a name TLS can check", url.host))?;
            let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, tcp)
                .await
                .with_context(|| format!("TLS with {}", url.host))?;
            exchange(tls, url, method, body).await
        } else {
            exchange(tcp, url, method, body).await
        }
    };
    tokio::time::timeout(TIMEOUT, io)
        .await
        .map_err(|_| anyhow!("{} did not answer within {TIMEOUT:?}", url.host))?
}

async fn resolve(url: &Url) -> Result<SocketAddr> {
    if let Ok(ip) = url.host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, url.port));
    }
    tokio::net::lookup_host((url.host.as_str(), url.port))
        .await
        .with_context(|| format!("looking up {}", url.host))?
        .next()
        .ok_or_else(|| anyhow!("{} has no address", url.host))
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    url: &Url,
    method: &str,
    body: &str,
) -> Result<(u16, String)> {
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    let req = format!(
        "{method} {} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        url.path,
        body.len()
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    // A TLS peer that closes without close_notify is an error to rustls;
    // what was read by then is still the answer.
    let _ = (&mut stream)
        .take(MAX_ANSWER as u64)
        .read_to_end(&mut raw)
        .await;
    parse_response(&raw)
}

pub(crate) fn parse_response(raw: &[u8]) -> Result<(u16, String)> {
    if raw.len() >= MAX_ANSWER {
        return Err(anyhow!("the answer is larger than any this client reads"));
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("the answer has no headers"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("the answer has no status"))?;
    let header = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_string())
        })
    };
    let chunked =
        header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked {
        dechunk(body)?
    } else if let Some(len) = header("content-length") {
        // A connection that ended early must not pass for a short answer.
        let len: usize = len
            .parse()
            .map_err(|_| anyhow!("the answer has a bad Content-Length"))?;
        if body.len() < len {
            return Err(anyhow!("the answer was cut short"));
        }
        body[..len].to_vec()
    } else {
        body.to_vec()
    };
    let body = String::from_utf8(body).map_err(|_| anyhow!("the answer is not text"))?;
    Ok((status, body))
}

/// The body of a `Transfer-Encoding: chunked` answer, joined (what a TLS
/// proxy in front of the issuer may send). Counted in bytes, as the sizes
/// are.
fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("a chunked answer ends mid-chunk"))?;
        let size_line = String::from_utf8_lossy(&rest[..eol]);
        let after = &rest[eol + 2..];
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| anyhow!("a chunked answer has a bad chunk size"))?;
        if size == 0 {
            return Ok(out);
        }
        // The size comes from the other end: compared without adding to it,
        // so a size near usize::MAX is refused, not wrapped or overflowed.
        if size > after.len() || after.len() - size < 2 {
            return Err(anyhow!("a chunked answer ends mid-chunk"));
        }
        out.extend_from_slice(&after[..size]);
        rest = after[size..]
            .strip_prefix(b"\r\n")
            .ok_or_else(|| anyhow!("a chunk is not followed by its line end"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse_and_plain_http_stays_on_private_networks() {
        let u = Url::parse("https://passes.example.org/issue").unwrap();
        assert_eq!(
            (u.https, u.host.as_str(), u.port, u.path.as_str()),
            (true, "passes.example.org", 443, "/issue")
        );
        let u = Url::parse("https://passes.example.org:8443").unwrap();
        assert_eq!((u.port, u.path.as_str()), (8443, "/"));
        assert_eq!(u.with_path("/issue").path, "/issue");
        let under = Url::parse("https://example.org/passes/").unwrap();
        assert_eq!(under.with_path("/issue").path, "/passes/issue");
        let u = Url::parse("http://10.201.0.2:8080/x").unwrap();
        assert_eq!((u.https, u.port), (false, 8080));
        Url::parse("http://127.0.0.1/").unwrap();
        Url::parse("http://[::1]:9/").unwrap();
        for bad in [
            "http://198.51.100.7/issue",
            "http://passes.example.org/",
            "ftp://x/",
            "https://",
            "https://user@host/",
            "https://bad host/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_answer_is_read_back() {
        let (s, b) = parse_response(b"HTTP/1.1 429 Too Many\r\nX: y\r\n\r\n{\"e\":1}").unwrap();
        assert_eq!((s, b.as_str()), (429, "{\"e\":1}"));
        assert!(parse_response(b"garbage").is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n5\r\n:1}\r\n\r\n0\r\n\r\n";
        let (s, b) = parse_response(chunked).unwrap();
        assert_eq!((s, b.as_str()), (200, "{\"a\":1}\r\n"));
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n").is_err()
        );
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nab")
                .is_err()
        ); // Cut short against its Content-Length; exactly long, or longer.
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n{\"a\":").is_err());
        let (_, b) =
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}xx").unwrap();
        assert_eq!(b, "{\"a\":1}");
        // Chunk sizes count bytes, even of text that is not ASCII.
        let (_, b) = parse_response(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n\"é\"\r\n0\r\n\r\n"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(b, "\"é\"");
        assert!(parse_response(&vec![b'a'; MAX_ANSWER]).is_err());
        // A chunk size the far end cannot mean: refused, never a panic.
        for size in ["ffffffffffffffff", "fffffffffffffffe", "10000000000000000"] {
            let raw = format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{size}\r\nab\r\n0\r\n\r\n"
            );
            assert!(parse_response(raw.as_bytes()).is_err(), "{size}");
        }
    }

    #[test]
    fn a_token_goes_over_https_or_to_this_machine_only() {
        assert!(Url::parse("https://passes.example.org/")
            .unwrap()
            .check_for_token()
            .is_ok());
        assert!(Url::parse("http://127.0.0.1:8730/")
            .unwrap()
            .check_for_token()
            .is_ok());
        if std::env::var("HIDRAVPN_PLAIN_HTTP_ISSUER").is_err() {
            assert!(Url::parse("http://10.201.0.2:8730/")
                .unwrap()
                .check_for_token()
                .is_err());
        }
    }

    #[tokio::test]
    async fn a_plain_exchange_on_loopback_works() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let req = crate::admission::read_request(&mut s).await.unwrap();
            assert_eq!((req.method.as_str(), req.path.as_str()), ("POST", "/issue"));
            assert_eq!(req.body, b"{}");
            s.write_all(&crate::admission::http_response(200, "{\"ok\":true}"))
                .await
                .unwrap();
        });
        let u = Url::parse(&format!("http://127.0.0.1:{port}/issue")).unwrap();
        let (status, body) = call(&u, "POST", "{}").await.unwrap();
        assert_eq!((status, body.as_str()), (200, "{\"ok\":true}"));
    }
}
