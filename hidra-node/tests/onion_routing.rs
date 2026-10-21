use std::net::SocketAddr;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::circuit_pool::CircuitPool;
use hidra_node::client::session::run_client_session;
use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::p2p::dht::descriptor::VerifiedRelay;

async fn start_echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    addr
}

/// Three relays on loopback, each pinned to the key it really holds.
async fn start_three_relays() -> Vec<VerifiedRelay> {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut relays = Vec::new();
    for _ in 0..3 {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = PublicKey::from(&secret).to_bytes();
        let l = NodeListener::bind(addr, secret).await.unwrap();
        relays.push(VerifiedRelay::pinned(l.local_addr().unwrap(), key));
        tokio::spawn(async move { l.accept_loop().await });
    }
    relays
}

/// A DHT the SOCKS handler can hold but will never consult.
///
/// `handle_socks5_connection` takes one because a `.hidra` target is resolved
/// through it. These tests only ask for host:port, which never reaches that
/// path, so an isolated node with an empty routing table is the honest stand-in
/// — it is a real DhtNode, not a mock, and a test that did take the service
/// path would fail rather than quietly pass.
async fn idle_dht() -> std::sync::Arc<hidra_node::p2p::dht::DhtNode> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    // A low ID difficulty: this node never meets another, and the public
    // network's 24 bits would cost seconds in a debug build for nothing.
    let node = hidra_node::p2p::dht::DhtNode::with_id_bits(
        "127.0.0.1:0".parse().unwrap(),
        signing_key,
        None,
        8,
    )
    .await
    .unwrap();
    std::sync::Arc::new(node)
}

#[tokio::test]
async fn three_relay_onion_circuit() {
    let relays = start_three_relays().await;

    let response = run_client_session(&relays, "Hello, hidden world")
        .await
        .unwrap();

    assert_eq!(response, "Received, agent");
}

#[tokio::test]
async fn streaming_circuit_echo_through_three_relays() {
    let relays = start_three_relays().await;
    let echo_addr = start_echo_server().await;

    let mut circuit = StreamingCircuit::build(&relays).await.unwrap();

    circuit
        .connect(&echo_addr.ip().to_string(), echo_addr.port())
        .await
        .unwrap();

    let test_data = b"Hello through the onion circuit!";
    circuit.send_data(test_data).await.unwrap();

    let received = circuit.recv_data().await.unwrap().unwrap();
    assert_eq!(received, test_data);

    let large_data: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();
    circuit.send_data(&large_data).await.unwrap();

    // A stream, not messages: the echo server writes back in 4096-byte reads,
    // so the bytes may come in more than one piece.
    let mut received_large = Vec::new();
    while received_large.len() < large_data.len() {
        received_large.extend(circuit.recv_data().await.unwrap().unwrap());
    }
    assert_eq!(received_large, large_data);

    circuit.send_end().await.unwrap();
}

#[tokio::test]
async fn streaming_circuit_connect_refused() {
    let relays = start_three_relays().await;

    let mut circuit = StreamingCircuit::build(&relays).await.unwrap();

    let result = circuit.connect("127.0.0.1", 1).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("connect failed"), "error was: {err_msg}");
}

#[tokio::test]
async fn socks5_proxy_end_to_end() {
    let relays = start_three_relays().await;
    let echo_addr = start_echo_server().await;

    let pool = CircuitPool::new(relays);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let pool_clone = std::sync::Arc::clone(&pool);
    let dht = idle_dht().await;
    tokio::spawn(async move {
        let (stream, remote_addr) = proxy_listener.accept().await.unwrap();
        hidra_node::proxy::stream_handler::handle_socks5_connection(
            stream,
            pool_clone,
            dht,
            remote_addr,
        )
        .await;
    });

    let mut browser = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    browser.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    browser.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    let echo_ip = match echo_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("expected IPv4"),
    };
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
    connect_req.extend_from_slice(&echo_ip.octets());
    connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    browser.write_all(&connect_req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    browser.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[0], 0x05);
    assert_eq!(connect_resp[1], 0x00);
    assert_eq!(connect_resp[3], 0x01);

    let payload = b"Data through SOCKS5 + onion circuit!";
    browser.write_all(payload).await.unwrap();

    let mut echo_buf = vec![0u8; payload.len()];
    browser.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, payload);
}

#[tokio::test]
async fn socks5_proxy_domain_name_no_local_dns() {
    let relays = start_three_relays().await;
    let echo_addr = start_echo_server().await;

    let pool = CircuitPool::new(relays);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let pool_clone = std::sync::Arc::clone(&pool);
    let dht = idle_dht().await;
    tokio::spawn(async move {
        let (stream, remote_addr) = proxy_listener.accept().await.unwrap();
        hidra_node::proxy::stream_handler::handle_socks5_connection(
            stream,
            pool_clone,
            dht,
            remote_addr,
        )
        .await;
    });

    let mut browser = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    // SOCKS5 handshake
    browser.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    browser.read_exact(&mut resp).await.unwrap();
    assert_eq!(resp, [0x05, 0x00]);

    // SOCKS5 CONNECT with domain name (ATYP=0x03)
    // Domain = "localhost" pointing at the echo server port
    let domain = b"localhost";
    let mut connect_req = vec![
        0x05, // version
        0x01, // CONNECT
        0x00, // reserved
        0x03, // domain
        domain.len() as u8,
    ];
    connect_req.extend_from_slice(domain);
    connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    browser.write_all(&connect_req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    browser.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[0], 0x05);
    assert_eq!(connect_resp[1], 0x00);

    // Data through SOCKS5 tunnel with domain-based CONNECT
    let payload = b"Domain-based SOCKS5 connection!";
    browser.write_all(payload).await.unwrap();

    let mut echo_buf = vec![0u8; payload.len()];
    browser.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, payload);
}

#[tokio::test]
async fn circuit_pool_reuses_prebuilt_circuits() {
    let relays = start_three_relays().await;
    let pool = CircuitPool::new(relays);

    // Pre-build circuits
    pool.maintain().await;
    let initial_size = pool.pool_size().await;
    assert!(initial_size > 0, "pool should have pre-built circuits");

    // Take a circuit
    let circuit = pool.get_circuit().await.unwrap();
    assert!(circuit.circuit_id() > 0);

    let after_take = pool.pool_size().await;
    assert_eq!(after_take, initial_size - 1);
}

#[tokio::test]
async fn failover_retries_on_connect_failure() {
    let relays = start_three_relays().await;
    let pool = CircuitPool::new(relays);

    let echo_addr = start_echo_server().await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let pool_clone = std::sync::Arc::clone(&pool);
    let dht = idle_dht().await;
    tokio::spawn(async move {
        let (stream, remote_addr) = proxy_listener.accept().await.unwrap();
        hidra_node::proxy::stream_handler::handle_socks5_connection(
            stream,
            pool_clone,
            dht,
            remote_addr,
        )
        .await;
    });

    let mut browser = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();

    browser.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    browser.read_exact(&mut resp).await.unwrap();

    // Connect to echo server — should succeed (failover works even with working relays)
    let echo_ip = match echo_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("expected IPv4"),
    };
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x01];
    connect_req.extend_from_slice(&echo_ip.octets());
    connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    browser.write_all(&connect_req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    browser.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[1], 0x00);

    let payload = b"Failover test data";
    browser.write_all(payload).await.unwrap();

    let mut echo_buf = vec![0u8; payload.len()];
    browser.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, payload);
}
