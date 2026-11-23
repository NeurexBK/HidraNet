//! Driver for scripts/test-anonymity-netns.sh. Not part of the node.
//!
//!   netns_harness relay  <listen> <descriptor-out> [--lie] [--dht <udp-listen> [--bootstrap <udp>]]
//!   netns_harness echo   <listen>
//!   netns_harness pin    <descriptor>        (prints the transport key, base64)
//!   netns_harness service <entry.json> <middle.json> <exit.json> <dht-listen> <bootstrap> <name-out>
//!   netns_harness socks  <proxy> <host> <port>
//!   netns_harness tamper <descriptor-in> <descriptor-out>
//!   netns_harness client <entry.json> <middle.json> <exit.json> <target> [expect-fail]
//!
//! A relay writes the descriptor it signed to a file; the client reads the
//! three files, verifies them, and builds circuits through them in order.
//! `--lie` makes a relay sign a descriptor for a key it does not hold: the
//! signature is good, the key is wrong. `tamper` changes the key in a
//! descriptor after it was signed. With `expect-fail` the client exits 0 only
//! if no circuit could be built.
//!
//! `--dht` also runs the relay's DHT node, announcing a descriptor for the
//! relay, as `hidra-node` in relay mode does. `service` registers a hidden
//! service at the exit of a circuit, announces it in the DHT, writes its
//! `.hidra` name to a file, and echoes whatever reaches it. `socks` connects
//! through a SOCKS5 proxy (retrying while the proxy starts) and checks that
//! 4 KiB beginning with HIDRA_CANARY come back.

use std::net::SocketAddr;
use std::process::exit;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::p2p::dht::descriptor::{RelayDescriptor, VerifiedRelay};

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// A DHT node for this relay, as `hidra-node` in relay mode runs, joined
/// through `bootstrap` (retried while that node is still solving its ID).
async fn relay_dht(
    identity: SigningKey,
    dht_listen: SocketAddr,
    relay_addr: SocketAddr,
    transport_key: [u8; 32],
    bootstrap: Option<SocketAddr>,
) -> std::sync::Arc<hidra_node::p2p::dht::DhtNode> {
    use hidra_node::p2p::dht::{DhtNode, node::ID_PUZZLE_BITS};
    let mut dht = DhtNode::relay(
        dht_listen,
        identity,
        relay_addr,
        transport_key,
        ID_PUZZLE_BITS,
    )
    .await
    .unwrap();
    dht.start().await;
    if let Some(b) = bootstrap {
        for _ in 0..30 {
            if hidra_node::p2p::bootstrap::bootstrap(&dht, &[b])
                .await
                .unwrap_or(0)
                > 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    let _ = dht.announce_relay().await;
    std::sync::Arc::new(dht)
}

fn read_descriptor(path: &str) -> RelayDescriptor {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn write_descriptor(path: &str, d: &RelayDescriptor) {
    std::fs::write(path, serde_json::to_string(d).unwrap()).unwrap();
}

/// Connects to the target, by the name in HIDRA_CANARY_HOST if set, and
/// echoes 64 KiB that start with HIDRA_CANARY if set: the script then looks
/// for both in every log.
async fn round_trip(c: &mut StreamingCircuit, target: SocketAddr) -> Result<usize, String> {
    let host = std::env::var("HIDRA_CANARY_HOST").unwrap_or_else(|_| target.ip().to_string());
    c.connect(&host, target.port())
        .await
        .map_err(|e| e.to_string())?;
    let mut data: Vec<u8> = std::env::var("HIDRA_CANARY")
        .unwrap_or_default()
        .into_bytes();
    data.extend((0..65536u32).map(|i| (i % 251) as u8));
    data.truncate(65536);
    for chunk in data.chunks(8192) {
        c.send_data(chunk).await.map_err(|e| e.to_string())?;
    }
    let mut got = Vec::new();
    while got.len() < data.len() {
        match c.recv_data().await.map_err(|e| e.to_string())? {
            Some(d) => got.extend(d),
            None => return Err("stream closed early".into()),
        }
    }
    if got != data {
        return Err("echoed data differs".into());
    }
    c.send_end().await.map_err(|e| e.to_string())?;
    Ok(got.len())
}

async fn socks_round_trip(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    data: &[u8],
) -> Result<(), String> {
    let mut s = tokio::net::TcpStream::connect(proxy)
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| e.to_string())?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.map_err(|e| e.to_string())?;
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(|e| e.to_string())?;
    let mut reply = [0u8; 10];
    s.read_exact(&mut reply).await.map_err(|e| e.to_string())?;
    if reply[1] != 0 {
        return Err(format!("SOCKS reply {}", reply[1]));
    }
    s.write_all(data).await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; data.len()];
    tokio::time::timeout(std::time::Duration::from_secs(20), s.read_exact(&mut got))
        .await
        .map_err(|_| "echo timed out".to_string())?
        .map_err(|e| e.to_string())?;
    if got != data {
        return Err("echoed data differs".into());
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    hidra_node::logging::init_logging("debug", "pretty");
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("relay") => {
            let addr: SocketAddr = args[2].parse().unwrap();
            let secret = StaticSecret::random_from_rng(OsRng);
            let identity = SigningKey::generate(&mut OsRng);
            let claimed = if args.get(4).map(String::as_str) == Some("--lie") {
                PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes()
            } else {
                PublicKey::from(&secret).to_bytes()
            };
            let descriptor = RelayDescriptor::sign_now(&identity, addr, claimed);
            let mut l = NodeListener::bind(addr, secret).await.unwrap();
            let dht = match flag(&args, "--dht") {
                Some(d) => {
                    let bootstrap = flag(&args, "--bootstrap").map(|b| b.parse().unwrap());
                    let dht =
                        relay_dht(identity, d.parse().unwrap(), addr, claimed, bootstrap).await;
                    l = l.with_dht(std::sync::Arc::clone(&dht));
                    Some(dht)
                }
                None => None,
            };
            tokio::spawn(async move { l.accept_loop().await.unwrap() });
            // Written once the relay is listening: the script waits for it.
            write_descriptor(&args[3], &descriptor);
            // The DHT's maintenance loop is not Send, so it runs here.
            match dht {
                Some(dht) => hidra_node::p2p::discovery::run_maintenance_loop(&dht).await,
                None => std::future::pending().await,
            }
        }
        Some("echo") => {
            let addr: SocketAddr = args[2].parse().unwrap();
            let l = TcpListener::bind(addr).await.unwrap();
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16384];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
        Some("pin") => {
            use base64::Engine as _;
            let d = read_descriptor(&args[2]);
            println!(
                "{}",
                base64::engine::general_purpose::STANDARD.encode(d.transport_key)
            );
        }
        Some("service") => {
            use hidra_node::p2p::dht::DhtNode;
            let relays: Vec<VerifiedRelay> = args[2..5]
                .iter()
                .map(|p| read_descriptor(p).verify().unwrap())
                .collect();
            let keys = hidra_node::crypto::keys::ServiceKeys::generate();
            let mut circuit = StreamingCircuit::build(&relays).await.unwrap();
            circuit
                .register_service(keys.address_hash.to_vec())
                .await
                .unwrap();
            let mut dht = DhtNode::new(
                args[5].parse().unwrap(),
                SigningKey::generate(&mut OsRng),
                None,
            )
            .await
            .unwrap();
            dht.start().await;
            let bootstrap: SocketAddr = args[6].parse().unwrap();
            for _ in 0..30 {
                if hidra_node::p2p::bootstrap::bootstrap(&dht, &[bootstrap])
                    .await
                    .unwrap_or(0)
                    > 0
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            dht.announce_signed_service(&keys.signing_key, vec![relays[2].addr()])
                .await
                .unwrap();
            std::fs::write(&args[7], &keys.address).unwrap();
            println!("RESULT service registered and announced");
            while let Ok(Some(data)) = circuit.recv_data().await {
                if circuit.send_data(&data).await.is_err() {
                    break;
                }
            }
        }
        Some("socks") => {
            let proxy: SocketAddr = args[2].parse().unwrap();
            let host = &args[3];
            let port: u16 = args[4].parse().unwrap();
            let mut data: Vec<u8> = std::env::var("HIDRA_CANARY")
                .unwrap_or_default()
                .into_bytes();
            data.extend((0..4096u32).map(|i| (i % 251) as u8));
            data.truncate(4096);
            let mut last = String::from("never tried");
            for _ in 0..20 {
                match socks_round_trip(proxy, host, port, &data).await {
                    Ok(()) => {
                        println!("RESULT socks ok: 4096 bytes echoed through the proxy");
                        exit(0);
                    }
                    Err(e) => last = e,
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
            println!("RESULT socks failed: {last}");
            exit(1);
        }
        Some("tamper") => {
            let mut d = read_descriptor(&args[2]);
            d.transport_key[0] ^= 1;
            write_descriptor(&args[3], &d);
        }
        Some("client") => {
            let mut relays: Vec<VerifiedRelay> = Vec::new();
            for path in &args[2..5] {
                match read_descriptor(path).verify() {
                    Ok(r) => relays.push(r),
                    Err(e) => {
                        println!("RESULT descriptor refused: {e}");
                        exit(if args.get(6).map(String::as_str) == Some("expect-fail") {
                            0
                        } else {
                            1
                        });
                    }
                }
            }
            let target: SocketAddr = args[5].parse().unwrap();
            let expect_fail = args.get(6).map(String::as_str) == Some("expect-fail");
            for round in 0..2 {
                let mut c = match StreamingCircuit::build(&relays).await {
                    Ok(c) => c,
                    Err(e) => {
                        println!("RESULT round {round}: circuit build failed: {e}");
                        exit(if expect_fail { 0 } else { 1 });
                    }
                };
                if expect_fail {
                    println!(
                        "RESULT a circuit was built through a path that should have refused it"
                    );
                    exit(1);
                }
                match round_trip(&mut c, target).await {
                    Ok(n) => println!(
                        "RESULT round {round}: {n} bytes echoed intact, circuit {} hops",
                        c.hop_count()
                    ),
                    Err(e) => {
                        println!("RESULT round {round}: {e}");
                        exit(1);
                    }
                }
                c.destroy().await;
            }
            println!("RESULT client ok");
        }
        _ => {
            eprintln!("usage: see the top of examples/netns_harness.rs");
            exit(2);
        }
    }
}
