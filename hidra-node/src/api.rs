use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub struct ApiState {
    pub start_time: Instant,
    pub relay_count: usize,
    pub relay_addrs: Vec<SocketAddr>,
    pub hops: usize,
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

    // This reply names the guard, middle and exit relays of the live circuit.
    // With `Access-Control-Allow-Origin: *` on it, any site the user visited
    // could read that back, and the entry guard is the one address that
    // identifies a user to a network observer.
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
        let body = format!(
            r#"{{"connected":true,"relays":{},"latency":42,"uptime":{},"hops":{}}}"#,
            state.relay_count, uptime, state.hops
        );
        (200, "OK", body)
    } else if request.starts_with("GET /api/circuit") {
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
                format!(r#"{{"ip":"{addr}","role":"{role}"}}"#)
            })
            .collect();
        let body = format!(r#"{{"hops":[{}]}}"#, hops.join(","));
        (200, "OK", body)
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
