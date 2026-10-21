use std::net::SocketAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::circuit_pool::CircuitPool;
use hidra_node::client::session::run_client_session;
use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::relay::exit_policy::ExitPolicy;
use hidra_node::relay::registry::RelayEntry;

fn pubkey_b64(secret: &StaticSecret) -> String {
    BASE64.encode(PublicKey::from(secret).to_bytes())
}

/// Starts a relay on an ephemeral port and returns a `RelayEntry` carrying its
/// real identity key, so the client can pin it (circuits refuse unkeyed hops).
async fn start_relay(name: &str) -> RelayEntry {
    let secret = StaticSecret::random_from_rng(OsRng);
    let key = pubkey_b64(&secret);
    let listener = NodeListener::bind("127.0.0.1:0".parse().unwrap(), secret)
        .await
        .unwrap()
        .with_exit_policy(ExitPolicy::ALLOW_PRIVATE);
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { listener.accept_loop().await });
    RelayEntry {
        name: name.into(),
        addr,
        noise_pubkey_b64: key,
    }
}

async fn three_relays() -> Vec<RelayEntry> {
    vec![
        start_relay("relay-1").await,
        start_relay("relay-2").await,
        start_relay("relay-3").await,
    ]
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

/// A DHT the SOCKS handler can hold but will never consult.
async fn idle_dht() -> std::sync::Arc<hidra_node::p2p::dht::DhtNode> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
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
    let relays = three_relays().await;
    let client_secret = StaticSecret::random_from_rng(OsRng);

    let response = run_client_session(&relays, client_secret, "Hello, hidden world")
        .await
        .unwrap();

    assert_eq!(response, "Received, agent");
}

#[tokio::test]
async fn streaming_circuit_echo_through_three_relays() {
    let relays = three_relays().await;
    let echo_addr = start_echo_server().await;
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
    let relays = three_relays().await;
    let client_secret = StaticSecret::random_from_rng(OsRng);

    let mut circuit = StreamingCircuit::build(&relays, client_secret)
        .await
        .unwrap();

    let result = circuit.connect("127.0.0.1", 1).await;
    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("connect failed"), "error was: {err_msg}");
}

/// A circuit refuses to build through a relay whose identity key is not the one
/// on record: this is what stops a relay carrying another hop's handshake from
/// impersonating it.
#[tokio::test]
async fn circuit_refuses_a_relay_with_the_wrong_key() {
    let mut relays = three_relays().await;
    // Swap the middle relay's recorded key for an unrelated one; the real relay
    // still answers, but it can no longer prove the key the client expects.
    let wrong = pubkey_b64(&StaticSecret::random_from_rng(OsRng));
    relays[1].noise_pubkey_b64 = wrong;
    let client_secret = StaticSecret::random_from_rng(OsRng);

    let msg = match StreamingCircuit::build(&relays, client_secret).await {
        Err(e) => format!("{e}"),
        Ok(_) => panic!("a circuit must not build through a relay with the wrong identity key"),
    };
    assert!(
        msg.contains("does not match") || msg.contains("identity"),
        "error was: {msg}"
    );
}

/// A relay with no identity key on record cannot be a hop.
#[tokio::test]
async fn circuit_refuses_an_unkeyed_relay() {
    let mut relays = three_relays().await;
    relays[2].noise_pubkey_b64 = String::new();
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let result = StreamingCircuit::build(&relays, client_secret).await;
    assert!(
        result.is_err(),
        "an unkeyed relay must not be used as a hop"
    );
}

#[tokio::test]
async fn socks5_proxy_end_to_end() {
    let relays = three_relays().await;
    let echo_addr = start_echo_server().await;

    let client_secret = StaticSecret::random_from_rng(OsRng);
    let secret_bytes = client_secret.to_bytes();

    let pool = CircuitPool::new(secret_bytes, relays);

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
    let relays = three_relays().await;
    let echo_addr = start_echo_server().await;

    let client_secret = StaticSecret::random_from_rng(OsRng);
    let pool = CircuitPool::new(client_secret.to_bytes(), relays);

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

    let domain = b"localhost";
    let mut connect_req = vec![0x05, 0x01, 0x00, 0x03, domain.len() as u8];
    connect_req.extend_from_slice(domain);
    connect_req.extend_from_slice(&echo_addr.port().to_be_bytes());
    browser.write_all(&connect_req).await.unwrap();

    let mut connect_resp = [0u8; 10];
    browser.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[0], 0x05);
    assert_eq!(connect_resp[1], 0x00);

    let payload = b"Domain-based SOCKS5 connection!";
    browser.write_all(payload).await.unwrap();

    let mut echo_buf = vec![0u8; payload.len()];
    browser.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, payload);
}

#[tokio::test]
async fn circuit_pool_reuses_prebuilt_circuits() {
    let relays = three_relays().await;
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let pool = CircuitPool::new(client_secret.to_bytes(), relays);

    pool.maintain().await;
    let initial_size = pool.pool_size().await;
    assert!(initial_size > 0, "pool should have pre-built circuits");

    let circuit = pool.get_circuit().await.unwrap();
    assert!(circuit.circuit_id() > 0);

    let after_take = pool.pool_size().await;
    assert_eq!(after_take, initial_size - 1);
}

#[tokio::test]
async fn failover_retries_on_connect_failure() {
    let relays = three_relays().await;
    let client_secret = StaticSecret::random_from_rng(OsRng);
    let pool = CircuitPool::new(client_secret.to_bytes(), relays);

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

/// A target that streams `down` bytes to whoever connects while reading the
/// `up` bytes they send, and reports whether those arrived intact.
async fn start_two_way_server(
    down: usize,
    up: usize,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut rd, mut wr) = stream.into_split();
        let writer = tokio::spawn(async move {
            let data: Vec<u8> = (0..down).map(|i| (i % 251) as u8).collect();
            for (n, chunk) in data.chunks(4000).enumerate() {
                if wr.write_all(chunk).await.is_err() {
                    return;
                }
                if n % 8 == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
            let _ = wr.flush().await;
            // Keep the write half open: a stream ends for both directions
            // when either side closes, so closing early would cut the upload.
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        });
        let mut got = Vec::with_capacity(up);
        let mut buf = vec![0u8; 8192];
        while got.len() < up {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        let intact = got.len() == up && got.iter().enumerate().all(|(i, b)| *b == (i % 241) as u8);
        let _ = done_tx.send(intact);
        let _ = writer.await;
    });
    (addr, done_rx)
}

/// Data flowing both ways at once through the SOCKS proxy and three relays.
///
/// Every hop races a read from one side against a read from the other. Those
/// reads used to lose the bytes of a frame they had started when the other
/// side won the race, and the stream broke. Uploading while downloading — a
/// page sending a request while another is still arriving — is where that
/// happened.
#[tokio::test]
async fn socks5_stream_carries_both_directions_at_once() {
    const DOWN: usize = 600_000;
    const UP: usize = 300_000;
    let relays = three_relays().await;
    let (target, target_done) = start_two_way_server(DOWN, UP).await;

    let client_secret = StaticSecret::random_from_rng(OsRng);
    let pool = CircuitPool::new(client_secret.to_bytes(), relays);
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();
    let dht = idle_dht().await;
    tokio::spawn(async move {
        let (stream, remote_addr) = proxy_listener.accept().await.unwrap();
        hidra_node::proxy::stream_handler::handle_socks5_connection(stream, pool, dht, remote_addr)
            .await;
    });

    let mut browser = tokio::net::TcpStream::connect(proxy_addr).await.unwrap();
    browser.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut resp = [0u8; 2];
    browser.read_exact(&mut resp).await.unwrap();
    let ip = match target.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("expected IPv4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&ip.octets());
    req.extend_from_slice(&target.port().to_be_bytes());
    browser.write_all(&req).await.unwrap();
    let mut connect_resp = [0u8; 10];
    browser.read_exact(&mut connect_resp).await.unwrap();
    assert_eq!(connect_resp[1], 0x00, "the circuit did not connect");

    let (mut rd, mut wr) = browser.into_split();
    let upload = tokio::spawn(async move {
        let data: Vec<u8> = (0..UP).map(|i| (i % 241) as u8).collect();
        for (n, chunk) in data.chunks(3000).enumerate() {
            wr.write_all(chunk).await.unwrap();
            if n % 8 == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
        wr
    });
    let download = async {
        let mut got = Vec::with_capacity(DOWN);
        let mut buf = vec![0u8; 16384];
        while got.len() < DOWN {
            match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        got
    };
    let got = tokio::time::timeout(std::time::Duration::from_secs(60), download)
        .await
        .expect("the download stalled");
    let _wr = upload.await.unwrap();

    assert_eq!(got.len(), DOWN, "the download broke off after {} of {} bytes", got.len(), DOWN);
    assert!(got.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8), "the download arrived corrupted");
    let intact = tokio::time::timeout(std::time::Duration::from_secs(30), target_done)
        .await
        .expect("the upload never finished")
        .unwrap();
    assert!(intact, "the upload arrived short or corrupted");
}
