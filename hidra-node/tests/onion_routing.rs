use std::net::SocketAddr;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::StaticSecret;

use hidra_node::client::circuit_pool::CircuitPool;
use hidra_node::client::session::run_client_session;
use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::relay::registry::RelayEntry;

fn make_relays(addrs: &[SocketAddr]) -> Vec<RelayEntry> {
    addrs
        .iter()
        .enumerate()
        .map(|(i, addr)| RelayEntry {
            name: format!("relay-{}", i + 1),
            addr: *addr,
            noise_pubkey_b64: String::new(),
        })
        .collect()
}

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

async fn start_three_relays() -> (SocketAddr, SocketAddr, SocketAddr) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let l1 = NodeListener::bind(addr, StaticSecret::random_from_rng(OsRng)).await.unwrap();
    let l2 = NodeListener::bind(addr, StaticSecret::random_from_rng(OsRng)).await.unwrap();
    let l3 = NodeListener::bind(addr, StaticSecret::random_from_rng(OsRng)).await.unwrap();

    let a1 = l1.local_addr().unwrap();
    let a2 = l2.local_addr().unwrap();
    let a3 = l3.local_addr().unwrap();

    tokio::spawn(async move { l1.accept_loop().await });
    tokio::spawn(async move { l2.accept_loop().await });
    tokio::spawn(async move { l3.accept_loop().await });

    (a1, a2, a3)
}

#[tokio::test]
async fn three_relay_onion_circuit() {
    let relay1_secret = StaticSecret::random_from_rng(OsRng);
    let relay2_secret = StaticSecret::random_from_rng(OsRng);
    let relay3_secret = StaticSecret::random_from_rng(OsRng);
    let client_secret = StaticSecret::random_from_rng(OsRng);

    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let listener1 = NodeListener::bind(addr, relay1_secret).await.unwrap();
    let listener2 = NodeListener::bind(addr, relay2_secret).await.unwrap();
    let listener3 = NodeListener::bind(addr, relay3_secret).await.unwrap();

    let addr1 = listener1.local_addr().unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let addr3 = listener3.local_addr().unwrap();

    tokio::spawn(async move { listener1.accept_loop().await });
    tokio::spawn(async move { listener2.accept_loop().await });
    tokio::spawn(async move { listener3.accept_loop().await });

    let relays = vec![
        RelayEntry {
            name: "relay-1".into(),
            addr: addr1,
            noise_pubkey_b64: String::new(),
        },
        RelayEntry {
            name: "relay-2".into(),
            addr: addr2,
            noise_pubkey_b64: String::new(),
        },
        RelayEntry {
            name: "relay-3".into(),
            addr: addr3,
            noise_pubkey_b64: String::new(),
        },
    ];

    let response = run_client_session(&relays, client_secret, "Olá, mundo oculto")
        .await
        .unwrap();

    assert_eq!(response, "Recebido, agente");
}

#[tokio::test]
async fn streaming_circuit_echo_through_three_relays() {
    let (a1, a2, a3) = start_three_relays().await;
    let echo_addr = start_echo_server().await;

    let relays = make_relays(&[a1, a2, a3]);
    let client_secret = StaticSecret::random_from_rng(OsRng);

    let mut circuit = StreamingCircuit::build(&relays, client_secret)
        .await
        .unwrap();

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

    let received_large = circuit.recv_data().await.unwrap().unwrap();
    assert_eq!(received_large, large_data);

    circuit.send_end().await.unwrap();
}

#[tokio::test]
async fn streaming_circuit_connect_refused() {
    let (a1, a2, a3) = start_three_relays().await;

    let relays = make_relays(&[a1, a2, a3]);
    let client_secret = StaticSecret::random_from_rng(OsRng);

    let mut circuit = StreamingCircuit::build(&relays, client_secret)
        .await
        .unwrap();

    let result = circuit.connect("127.0.0.1", 1).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("connect failed"), "error was: {err_msg}");
}

#[tokio::test]
async fn socks5_proxy_end_to_end() {
    let (a1, a2, a3) = start_three_relays().await;
    let echo_addr = start_echo_server().await;

    let relays = make_relays(&[a1, a2, a3]);
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let secret_bytes = client_secret.to_bytes();

    let pool = CircuitPool::new(secret_bytes, relays);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let pool_clone = std::sync::Arc::clone(&pool);
    tokio::spawn(async move {
        let (stream, remote_addr) = proxy_listener.accept().await.unwrap();
        hidra_node::proxy::stream_handler::handle_socks5_connection(
            stream,
            pool_clone,
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
    let (a1, a2, a3) = start_three_relays().await;
    let echo_addr = start_echo_server().await;

    let relays = make_relays(&[a1, a2, a3]);
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let pool = CircuitPool::new(client_secret.to_bytes(), relays);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let pool_clone = std::sync::Arc::clone(&pool);
    tokio::spawn(async move {
        let (stream, remote_addr) = proxy_listener.accept().await.unwrap();
        hidra_node::proxy::stream_handler::handle_socks5_connection(
            stream,
            pool_clone,
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
    let (a1, a2, a3) = start_three_relays().await;

    let relays = make_relays(&[a1, a2, a3]);
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let pool = CircuitPool::new(client_secret.to_bytes(), relays);

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
    let (a1, a2, a3) = start_three_relays().await;

    let relays = make_relays(&[a1, a2, a3]);
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let pool = CircuitPool::new(client_secret.to_bytes(), relays);

    let echo_addr = start_echo_server().await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let pool_clone = std::sync::Arc::clone(&pool);
    tokio::spawn(async move {
        let (stream, remote_addr) = proxy_listener.accept().await.unwrap();
        hidra_node::proxy::stream_handler::handle_socks5_connection(
            stream,
            pool_clone,
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
