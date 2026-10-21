use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::client::circuit_pool::CircuitPool;
use crate::client::streaming::StreamingCircuit;
use crate::error::{HidraError, Result};
use crate::p2p::dht::DhtNode;
use crate::proxy::resolver;
use crate::proxy::socks5::{self, TargetAddr};
use crate::safelog::sensitive;

const MAX_RETRIES: usize = 3;
const INITIAL_BACKOFF_MS: u64 = 100;

pub async fn handle_socks5_connection(
    mut browser_stream: TcpStream,
    pool: Arc<CircuitPool>,
    dht: Arc<DhtNode>,
    client_addr: SocketAddr,
) {
    if let Err(e) =
        handle_inner(&mut browser_stream, &pool, &dht, client_addr).await
    {
        warn!(
            client_ip = %sensitive(&client_addr),
            error = %e,
            "SOCKS5 session failed"
        );
        let _ = socks5::send_failure(&mut browser_stream).await;
    }
}

fn parse_hidra_address(host: &str) -> Option<[u8; 20]> {
    let stripped = host.strip_suffix(".hidra")?;
    if stripped.len() != 40 {
        return None;
    }
    let mut hash = [0u8; 20];
    for (i, chunk) in stripped.as_bytes().chunks(2).enumerate() {
        let hi = match chunk[0] {
            b'0'..=b'9' => chunk[0] - b'0',
            b'a'..=b'f' => chunk[0] - b'a' + 10,
            b'A'..=b'F' => chunk[0] - b'A' + 10,
            _ => return None,
        };
        let lo = match chunk[1] {
            b'0'..=b'9' => chunk[1] - b'0',
            b'a'..=b'f' => chunk[1] - b'a' + 10,
            b'A'..=b'F' => chunk[1] - b'A' + 10,
            _ => return None,
        };
        hash[i] = (hi << 4) | lo;
    }
    Some(hash)
}

async fn handle_inner(
    browser: &mut TcpStream,
    pool: &CircuitPool,
    dht: &DhtNode,
    client_addr: SocketAddr,
) -> Result<()> {
    socks5::handshake(browser).await?;
    let target = socks5::read_request(browser).await?;
    let (host, port) = match &target {
        TargetAddr::Ip(addr) => {
            (addr.ip().to_string(), addr.port())
        }
        TargetAddr::Domain(h, p) => (h.clone(), *p),
    };
    let target_domain = format!("{target}");
    info!(
        client_ip = %sensitive(&client_addr),
        target_domain = %sensitive(&target_domain),
        "SOCKS5 CONNECT request"
    );

    // Where a name is resolved is the whole DNS-leak question, so the answer
    // comes from resolver::target_host — one tested place that states the
    // policy — rather than from an ad-hoc check here. An internet name is
    // never looked up locally: it travels the circuit as a name and the exit
    // resolves it.
    let routing = resolver::target_host(&host);
    debug_assert!(
        !matches!(routing, resolver::TargetResolution::RemoteDns)
            || parse_hidra_address(&host).is_none(),
        "a .hidra name must never be classified for remote DNS"
    );

    if matches!(routing, resolver::TargetResolution::HidraInternal) {
        let service_hash = parse_hidra_address(&host).ok_or_else(|| {
            HidraError::Protocol(format!(
                "{} ends in .hidra but is not a service address",
                sensitive(&host)
            ))
        })?;
        info!(
            client_ip = %sensitive(&client_addr),
            address = %sensitive(&host),
            "resolving .hidra hidden service via DHT"
        );
        let descriptor = dht.lookup_service(&service_hash).await?
            .ok_or_else(|| HidraError::Circuit(
                format!("hidden service not found: {}", sensitive(&host))
            ))?;
        let (intro_points, service_pubkey) = descriptor;
        info!(
            intro_points = intro_points.len(),
            "found hidden service descriptor"
        );
        let mut circuit = connect_service_with_failover(
            pool,
            &intro_points,
            &service_pubkey,
            &target_domain,
            client_addr,
        )
        .await?;
        let circuit_id = circuit.circuit_id();
        let hop_count = circuit.hop_count();
        let relay_chain = circuit.relay_chain_display();
        info!(
            client_ip = %sensitive(&client_addr),
            target_domain = %sensitive(&target_domain),
            circuit_id, hop_count,
            relay_chain = %sensitive(&relay_chain),
            "circuit connected to hidden service"
        );
        socks5::send_success(browser).await?;
        let mut bytes_sent: u64 = 0;
        let mut bytes_received: u64 = 0;
        stream_bidirectional(
            browser,
            &mut circuit,
            &mut bytes_sent,
            &mut bytes_received,
        )
        .await;
        info!(
            client_ip = %sensitive(&client_addr),
            target_domain = %sensitive(&target_domain),
            circuit_id, hop_count,
            relay_chain = %sensitive(&relay_chain),
            bytes_sent, bytes_received,
            "hidden service session completed"
        );
        return Ok(());
    }

    let mut circuit = connect_with_failover(
        pool,
        &host,
        port,
        &target_domain,
        client_addr,
    )
    .await?;
    let circuit_id = circuit.circuit_id();
    let hop_count = circuit.hop_count();
    let relay_chain = circuit.relay_chain_display();
    info!(
        client_ip = %sensitive(&client_addr),
        target_domain = %sensitive(&target_domain),
        circuit_id, hop_count,
        relay_chain = %sensitive(&relay_chain),
        "circuit connected to target"
    );
    socks5::send_success(browser).await?;
    let mut bytes_sent: u64 = 0;
    let mut bytes_received: u64 = 0;
    stream_bidirectional(
        browser,
        &mut circuit,
        &mut bytes_sent,
        &mut bytes_received,
    )
    .await;
    info!(
        client_ip = %sensitive(&client_addr),
        target_domain = %sensitive(&target_domain),
        circuit_id, hop_count,
        relay_chain = %sensitive(&relay_chain),
        bytes_sent, bytes_received,
        "SOCKS5 session completed"
    );
    Ok(())
}

async fn connect_with_failover(
    pool: &CircuitPool,
    host: &str,
    port: u16,
    target_domain: &str,
    client_addr: SocketAddr,
) -> Result<StreamingCircuit> {
    let mut backoff = Duration::from_millis(INITIAL_BACKOFF_MS);
    let mut last_error = None;
    for attempt in 0..MAX_RETRIES {
        let mut circuit = match pool.get_circuit().await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    attempt,
                    client_ip = %sensitive(&client_addr),
                    target_domain = %sensitive(&target_domain),
                    error = %e,
                    "failed to obtain circuit"
                );
                last_error = Some(e);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                continue;
            }
        };
        match circuit.connect(host, port).await {
            Ok(()) => return Ok(circuit),
            Err(e) => {
                warn!(
                    attempt,
                    circuit_id = circuit.circuit_id(),
                    client_ip = %sensitive(&client_addr),
                    target_domain = %sensitive(&target_domain),
                    error = %e,
                    "circuit connect failed, retrying"
                );
                last_error = Some(e);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        HidraError::Circuit(
            "all circuit retry attempts exhausted".into(),
        )
    }))
}

/// Reaches a hidden service through one of its introduction points and has
/// it prove, with the key from its signed descriptor, that it is the service
/// the address names. A relay that hands the circuit to anyone else fails the
/// proof, and the next introduction point is tried.
async fn connect_service_with_failover(
    pool: &CircuitPool,
    intro_points: &[SocketAddr],
    service_pubkey: &[u8; 32],
    target_domain: &str,
    client_addr: SocketAddr,
) -> Result<StreamingCircuit> {
    if intro_points.is_empty() {
        return Err(HidraError::Circuit("the service names no introduction point".into()));
    }
    let mut backoff = Duration::from_millis(INITIAL_BACKOFF_MS);
    let mut last_error = None;
    for attempt in 0..MAX_RETRIES {
        let intro = intro_points[attempt % intro_points.len()];
        let mut circuit = match pool.build_circuit_via(intro).await {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    attempt,
                    client_ip = %sensitive(&client_addr),
                    target_domain = %sensitive(&target_domain),
                    error = %e,
                    "failed to obtain circuit for service"
                );
                last_error = Some(e);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
                continue;
            }
        };
        match circuit.connect_service_authenticated(service_pubkey).await {
            Ok(()) => return Ok(circuit),
            Err(e) => {
                warn!(
                    attempt,
                    circuit_id = circuit.circuit_id(),
                    client_ip = %sensitive(&client_addr),
                    target_domain = %sensitive(&target_domain),
                    error = %e,
                    "service connect failed, retrying"
                );
                last_error = Some(e);
                tokio::time::sleep(backoff).await;
                backoff *= 2;
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        HidraError::Circuit(
            "all service circuit retry attempts exhausted".into(),
        )
    }))
}

async fn stream_bidirectional(
    browser: &mut TcpStream,
    circuit: &mut StreamingCircuit,
    bytes_sent: &mut u64,
    bytes_received: &mut u64,
) {
    let mut browser_buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            n = browser.read(&mut browser_buf) => {
                match n {
                    Ok(0) => {
                        debug!("browser closed connection");
                        let _ = circuit.send_end().await;
                        break;
                    }
                    Ok(n) => {
                        *bytes_sent += n as u64;
                        if circuit.send_data(&browser_buf[..n]).await.is_err() { break; }
                    }
                    Err(e) => {
                        debug!(error = %e, "browser read error");
                        let _ = circuit.send_end().await;
                        break;
                    }
                }
            }
            data_result = circuit.recv_data() => {
                match data_result {
                    Ok(Some(data)) => {
                        *bytes_received += data.len() as u64;
                        if browser.write_all(&data).await.is_err() { break; }
                    }
                    Ok(None) => {
                        debug!("circuit stream ended");
                        break;
                    }
                    Err(e) => {
                        debug!(error = %e, "circuit recv error");
                        break;
                    }
                }
            }
        }
    }
}
