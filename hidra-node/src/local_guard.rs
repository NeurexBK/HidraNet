//! Screening for the HTTP servers that listen on loopback.
//!
//! Binding to 127.0.0.1 keeps other machines out; it does not keep *web pages*
//! out. A page open in any browser on this machine can issue requests to
//! 127.0.0.1, and these servers answered them: every one sent
//! `Access-Control-Allow-Origin: *`, so the reply was readable cross-origin.
//! For the status API that meant any site the user visited could read back the
//! guard, middle and exit relays of the live circuit — the entry guard is the
//! one address that identifies a user to a network observer.
//!
//! A loopback bind is also no defence against DNS rebinding: an attacker points
//! a hostname they control at 127.0.0.1, the browser treats the result as
//! same-origin with their page, and the request arrives carrying their
//! `Host`. Checking that `Host` names this machine is what closes that, and it
//! is why the check is on `Host` rather than on the peer address, which always
//! reads as loopback in both cases.

/// What to do with a request that reached one of the loopback servers.
pub enum Access {
    /// Answer it. Carries the `Origin` to echo back, when the request had one.
    Allow(Option<String>),
    /// Refuse it: the `Host` or the `Origin` does not belong to this machine.
    Deny,
}

/// First value of a header, case-insensitively, from a raw request head.
fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request
        .split("\r\n")
        .skip(1) // the request line
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
        })
}

/// Host part of an authority, with any port and IPv6 brackets removed.
fn host_of(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // [::1]:9051
        return rest.split(']').next().unwrap_or("");
    }
    authority.split(':').next().unwrap_or("")
}

/// True when the authority names this machine. The whole 127.0.0.0/8 block
/// counts, not just 127.0.0.1, because a server may be reached on any of it.
fn is_loopback_authority(authority: &str) -> bool {
    let host = host_of(authority);
    host == "localhost"
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

/// Screen a raw HTTP request head.
///
/// A request with no `Origin` is allowed: that is a non-browser client such as
/// the browser's own main process or curl, and a page cannot suppress the
/// header on a cross-origin request. A request that carries one must prove it
/// came from this machine — `Origin: null`, which is what a sandboxed iframe
/// or a `file://` page sends, is refused along with everything else remote.
pub fn screen(request: &str) -> Access {
    match header(request, "host") {
        Some(host) if is_loopback_authority(host) => {}
        // No Host at all is HTTP/1.0 or a hand-rolled client; it cannot be the
        // rebinding case, which depends on the browser filling it in.
        None => {}
        Some(_) => return Access::Deny,
    }

    match header(request, "origin") {
        None => Access::Allow(None),
        Some(origin) => {
            let authority = origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
                .unwrap_or("");
            if !authority.is_empty() && is_loopback_authority(authority) {
                Access::Allow(Some(origin.to_string()))
            } else {
                Access::Deny
            }
        }
    }
}

/// The CORS and framing headers to send with an allowed response.
///
/// `Access-Control-Allow-Origin` echoes the one origin that was allowed
/// instead of `*`, and no `Allow-Credentials` is sent. The rest stop the
/// reply being framed, sniffed into another content type, or sent anywhere
/// as a referrer.
pub fn response_headers(allowed_origin: Option<&str>) -> String {
    let cors = match allowed_origin {
        Some(origin) => format!(
            "Access-Control-Allow-Origin: {origin}\r\n\
             Vary: Origin\r\n"
        ),
        None => String::new(),
    };
    format!(
        "{cors}\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n"
    )
}

/// Body and status for a refused request.
pub const DENIED_STATUS: (u16, &str) = (403, "Forbidden");
pub const DENIED_BODY: &str = r#"{"error":"request did not come from this machine"}"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &str) -> String {
        format!("GET /api/status HTTP/1.1\r\n{headers}\r\n")
    }

    fn allowed(request: &str) -> bool {
        matches!(screen(request), Access::Allow(_))
    }

    #[test]
    fn plain_loopback_request_is_allowed() {
        assert!(allowed(&req("Host: 127.0.0.1:9051\r\n")));
        assert!(allowed(&req("Host: localhost:9051\r\n")));
        assert!(allowed(&req("Host: [::1]:9051\r\n")));
        assert!(allowed(&req("Host: 127.0.0.53\r\n")));
    }

    #[test]
    fn rebound_hostname_is_refused() {
        // The attack: evil.com resolves to 127.0.0.1, so the socket is
        // loopback but the browser sends the attacker's Host.
        assert!(!allowed(&req("Host: rebind.evil.com:9051\r\n")));
        assert!(!allowed(&req("Host: 203.0.113.9\r\n")));
    }

    #[test]
    fn cross_origin_page_is_refused() {
        assert!(!allowed(&req(
            "Host: 127.0.0.1:9051\r\nOrigin: https://evil.com\r\n"
        )));
        // file:// and sandboxed iframes send this.
        assert!(!allowed(&req("Host: 127.0.0.1:9051\r\nOrigin: null\r\n")));
    }

    #[test]
    fn local_page_origin_is_echoed_not_wildcarded() {
        match screen(&req(
            "Host: 127.0.0.1:9051\r\nOrigin: http://127.0.0.1:8084\r\n",
        )) {
            Access::Allow(Some(origin)) => assert_eq!(origin, "http://127.0.0.1:8084"),
            _ => panic!("a local page should be allowed, by name"),
        }
    }

    #[test]
    fn header_matching_ignores_case_and_spacing() {
        assert!(allowed(&req("HOST:127.0.0.1:9051\r\n")));
        assert!(!allowed(&req("hOsT:  evil.com\r\n")));
    }

    #[test]
    fn a_header_in_the_body_is_not_read_as_a_header() {
        let request = "POST /api/send HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\nOrigin: https://evil.com";
        match screen(request) {
            Access::Allow(None) => {}
            _ => panic!("the body must not be parsed as headers"),
        }
    }

    #[test]
    fn no_wildcard_is_ever_emitted() {
        assert!(!response_headers(Some("http://127.0.0.1:8084")).contains('*'));
        assert!(!response_headers(None).contains("Access-Control-Allow-Origin"));
    }
}
