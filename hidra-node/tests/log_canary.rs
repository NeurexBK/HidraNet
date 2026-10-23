//! What the running node writes to its log, checked with a canary.
//!
//! `no_addresses_in_logs.rs` reads the source for log calls that could print
//! an address. This test runs the code instead: it sends a payload and a
//! hostname nobody else could produce through real circuits, through the SOCKS
//! handler, and down the failure paths (a wrong relay key, an extension to a
//! relay that is down, a hostname that does not resolve), with every
//! component logging at DEBUG, and then searches everything that was written.
//!
//! Neither canary may appear, nor the client's address. Everything here runs
//! on loopback, so relays, target and proxy listen on 127.0.0.2 and up, and
//! 127.0.0.1 is only ever the source address of a connection: of the client,
//! and of a relay dialling the next hop, which a log must not name either.
//!
//! One test in this file, on purpose: it installs the process-wide log
//! subscriber, which every task of every component writes through.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rand::RngCore;
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::circuit_pool::CircuitPool;
use hidra_node::client::session::run_client_session;
use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::p2p::dht::descriptor::VerifiedRelay;

/// Everything every component logs, in one buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// The client's address. Nothing listens on it.
const CLIENT_IP: &str = "127.0.0.1";

async fn relay_at(ip: &str) -> VerifiedRelay {
    let secret = StaticSecret::random_from_rng(OsRng);
    let key = PublicKey::from(&secret).to_bytes();
    let l = NodeListener::bind(format!("{ip}:0").parse().unwrap(), secret)
        .await
        .unwrap();
    let r = VerifiedRelay::pinned(l.local_addr().unwrap(), key);
    tokio::spawn(async move { l.accept_loop().await });
    r
}

async fn echo_at(ip: &str) -> SocketAddr {
    let l = TcpListener::bind(format!("{ip}:0")).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A SOCKS5 CONNECT through the proxy at `proxy`, to a domain name. Returns
/// the reply code and the open stream.
async fn socks_connect(proxy: SocketAddr, host: &str, port: u16) -> (u8, TcpStream) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut reply = [0u8; 10];
    let _ = s.read_exact(&mut reply).await;
    (reply[1], s)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn neither_the_canary_nor_the_client_address_reaches_any_log() {
    let log = Captured::default();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .with_writer(log.clone())
        .init();
    assert!(
        !hidra_node::safelog::unsafe_logging(),
        "the default must scrub"
    );

    let mut tag = [0u8; 8];
    OsRng.fill_bytes(&mut tag);
    let tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    let payload_canary = format!("payload-canary-{tag}");
    let host_canary = format!("host-canary-{tag}.invalid");

    let relays = vec![
        relay_at("127.0.0.2").await,
        relay_at("127.0.0.3").await,
        relay_at("127.0.0.4").await,
    ];
    let target = echo_at("127.0.0.5").await;

    // 1. A circuit carries the payload canary to the target and back.
    let mut c = StreamingCircuit::build(&relays).await.unwrap();
    c.connect(&target.ip().to_string(), target.port())
        .await
        .unwrap();
    c.send_data(payload_canary.as_bytes()).await.unwrap();
    let mut back = Vec::new();
    while back.len() < payload_canary.len() {
        back.extend(c.recv_data().await.unwrap().unwrap());
    }
    assert_eq!(back, payload_canary.as_bytes());
    c.destroy().await;

    // 2. The exit is asked for the hostname canary, which does not resolve.
    let mut c = StreamingCircuit::build(&relays).await.unwrap();
    assert!(c.connect(&host_canary, 443).await.is_err());
    c.destroy().await;

    // 3. The probe the command line sends, carrying the payload canary.
    assert_eq!(
        run_client_session(&relays, &payload_canary).await.unwrap(),
        "Received, agent"
    );

    // 4. A wrong key at each hop, and a middle relay that is down.
    for i in 0..3 {
        let mut path = relays.clone();
        let wrong = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
        path[i] = VerifiedRelay::pinned(relays[i].addr(), wrong);
        assert!(StreamingCircuit::build(&path).await.is_err());
    }
    let dead = {
        let l = TcpListener::bind("127.0.0.6:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let dead_relay = VerifiedRelay::pinned(dead, [7; 32]);
    let path = vec![relays[0].clone(), dead_relay, relays[2].clone()];
    assert!(StreamingCircuit::build(&path).await.is_err());

    // 5. The production path: the SOCKS handler, the browser on 127.0.0.1,
    //    once to the hostname canary (fails at the exit) and once to the
    //    target with the payload canary.
    let pool = CircuitPool::new(relays.clone());
    let dht = {
        let node = hidra_node::p2p::dht::DhtNode::with_id_bits(
            "127.0.0.7:0".parse().unwrap(),
            ed25519_dalek::SigningKey::generate(&mut OsRng),
            None,
            8,
        )
        .await
        .unwrap();
        Arc::new(node)
    };
    let proxy = TcpListener::bind("127.0.0.8:0").await.unwrap();
    let proxy_addr = proxy.local_addr().unwrap();
    {
        let pool = Arc::clone(&pool);
        let dht = Arc::clone(&dht);
        tokio::spawn(async move {
            while let Ok((stream, from)) = proxy.accept().await {
                let pool = Arc::clone(&pool);
                let dht = Arc::clone(&dht);
                tokio::spawn(async move {
                    hidra_node::proxy::stream_handler::handle_socks5_connection(
                        stream, pool, dht, from,
                    )
                    .await;
                });
            }
        });
    }
    let (code, _) = socks_connect(proxy_addr, &host_canary, 443).await;
    assert_ne!(
        code, 0x00,
        "a hostname that does not resolve cannot succeed"
    );
    let (code, mut s) = socks_connect(proxy_addr, "127.0.0.5", target.port()).await;
    assert_eq!(code, 0x00);
    s.write_all(payload_canary.as_bytes()).await.unwrap();
    let mut echoed = vec![0u8; payload_canary.len()];
    s.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, payload_canary.as_bytes());
    drop(s);

    // Let teardown and failure paths finish writing.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let text = String::from_utf8_lossy(&log.0.lock().unwrap()).into_owned();
    // The capture saw the relays and the failure paths, at DEBUG; otherwise
    // an empty log would pass.
    for expected in [
        "circuit created",
        "circuit extended",
        "extend failed",
        "circuit closed",
        "SOCKS5",
    ] {
        assert!(
            text.contains(expected),
            "the log has no {expected:?}: the capture missed something"
        );
    }
    let leaks: Vec<&str> = text
        .lines()
        .filter(|l| {
            l.contains(&payload_canary)
                || l.contains(&host_canary)
                || l.contains(&tag)
                || l.contains(CLIENT_IP)
        })
        .collect();
    assert!(
        leaks.is_empty(),
        "{} log line(s) carry the canary or the client's address:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
}
