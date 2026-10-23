//! Driver for scripts/test-anonymity-netns.sh. Not part of the node.
//!
//!   netns_harness relay  <listen> <descriptor-out> [--lie]
//!   netns_harness echo   <listen>
//!   netns_harness tamper <descriptor-in> <descriptor-out>
//!   netns_harness client <entry.json> <middle.json> <exit.json> <target> [expect-fail]
//!
//! A relay writes the descriptor it signed to a file; the client reads the
//! three files, verifies them, and builds circuits through them in order.
//! `--lie` makes a relay sign a descriptor for a key it does not hold: the
//! signature is good, the key is wrong. `tamper` changes the key in a
//! descriptor after it was signed. With `expect-fail` the client exits 0 only
//! if no circuit could be built.

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
    let mut data: Vec<u8> = std::env::var("HIDRA_CANARY").unwrap_or_default().into_bytes();
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
            write_descriptor(
                &args[3],
                &RelayDescriptor::sign_now(&identity, addr, claimed),
            );
            let l = NodeListener::bind(addr, secret).await.unwrap();
            l.accept_loop().await.unwrap();
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
