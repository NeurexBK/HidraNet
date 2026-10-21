//! A circuit must not let the client open a connection to any hop but the
//! guard (the first relay). If it does, that hop learns the client's real
//! address, which defeats the point of multiple hops.
//!
//! Each relay runs on its own loopback address and is told to make its
//! outbound hop connections from that address. A transparent sniffer in front
//! of each relay records the source address of every connection it accepts.
//! The client makes its one connection unbound, so it is seen as 127.0.0.1;
//! every relay-to-relay connection is seen as that relay's own address. So the
//! client (127.0.0.1) must appear only at the guard, never at the middle or
//! the exit.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::relay::exit_policy::ExitPolicy;
use hidra_node::relay::registry::RelayEntry;

const CLIENT: &str = "127.0.0.1";

#[derive(Clone, Default)]
struct SrcLog(Arc<Mutex<Vec<String>>>);

impl SrcLog {
    fn sources(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }
    fn from_client(&self) -> usize {
        self.sources().iter().filter(|s| *s == CLIENT).count()
    }
}

/// A transparent relay in front of `node`: it records the source address of
/// every accepted connection, then splices it straight through unchanged.
async fn sniffer_in_front_of(node: SocketAddr) -> (SocketAddr, SrcLog) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let log = SrcLog::default();
    let log_for_task = log.clone();
    tokio::spawn(async move {
        loop {
            let (mut inbound, src) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            log_for_task.0.lock().unwrap().push(src.ip().to_string());
            tokio::spawn(async move {
                let mut outbound = match TcpStream::connect(node).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    (addr, log)
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

/// A relay on its own loopback address, dialing the next hop from that same
/// address, so the sniffer in front of the next hop sees this relay as the
/// source.
async fn start_relay(ip: &str) -> (SocketAddr, String) {
    let bind: SocketAddr = format!("{ip}:0").parse().unwrap();
    let source: IpAddr = ip.parse().unwrap();
    let secret = StaticSecret::random_from_rng(OsRng);
    let key = BASE64.encode(PublicKey::from(&secret).to_bytes());
    let listener = NodeListener::bind(bind, secret)
        .await
        .unwrap()
        .with_exit_policy(ExitPolicy::ALLOW_PRIVATE)
        .with_dial_source(source);
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { listener.accept_loop().await });
    (addr, key)
}

#[tokio::test]
async fn only_the_guard_is_contacted_by_the_client() {
    // Guard, middle and exit, each on its own loopback address, each behind a
    // sniffer. The circuit is built from the sniffer addresses, so every
    // connection to a relay passes its sniffer, whoever made it.
    let (guard, guard_key) = start_relay("127.0.0.2").await;
    let (middle, middle_key) = start_relay("127.0.0.3").await;
    let (exit, exit_key) = start_relay("127.0.0.4").await;
    let (s_guard, log_guard) = sniffer_in_front_of(guard).await;
    let (s_middle, log_middle) = sniffer_in_front_of(middle).await;
    let (s_exit, log_exit) = sniffer_in_front_of(exit).await;
    let echo = start_echo_server().await;

    let relays = vec![
        RelayEntry {
            name: "guard".into(),
            addr: s_guard,
            noise_pubkey_b64: guard_key,
        },
        RelayEntry {
            name: "middle".into(),
            addr: s_middle,
            noise_pubkey_b64: middle_key,
        },
        RelayEntry {
            name: "exit".into(),
            addr: s_exit,
            noise_pubkey_b64: exit_key,
        },
    ];

    let client_secret = StaticSecret::random_from_rng(OsRng);
    let mut circuit = StreamingCircuit::build(&relays, client_secret)
        .await
        .unwrap();
    circuit
        .connect(&echo.ip().to_string(), echo.port())
        .await
        .unwrap();
    let payload = b"through the circuit";
    circuit.send_data(payload).await.unwrap();
    let echoed = circuit.recv_data().await.unwrap().unwrap();
    assert_eq!(
        echoed, payload,
        "the circuit must still carry data end to end"
    );
    circuit.send_end().await.unwrap();

    // Let every forwarded connection be accepted and recorded.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The client reached the guard, and only the guard.
    assert_eq!(
        log_guard.from_client(),
        1,
        "the client should reach the guard exactly once; guard saw {:?}",
        log_guard.sources()
    );
    assert!(
        !log_middle.sources().is_empty(),
        "the middle should have been reached by the guard"
    );
    assert_eq!(
        log_middle.from_client(),
        0,
        "the client reached the middle relay directly; middle saw {:?}",
        log_middle.sources()
    );
    assert!(
        !log_exit.sources().is_empty(),
        "the exit should have been reached by the middle"
    );
    assert_eq!(
        log_exit.from_client(),
        0,
        "the client reached the exit relay directly; exit saw {:?}",
        log_exit.sources()
    );
}
