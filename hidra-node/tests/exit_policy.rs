//! A relay connects only to the public internet on a stranger's behalf.
//!
//! The exit used to connect to whatever host:port a circuit asked for, and a
//! relay to whatever next hop the circuit named. Anyone who could reach a
//! relay could point it at the operator's own loopback services, their LAN,
//! or a cloud host's metadata service. These run real relays and real
//! circuits against the default policy and check that the door is shut,
//! while a relay explicitly set up for a one-machine network still works.

use std::net::SocketAddr;
use std::time::Duration;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use x25519_dalek::StaticSecret;

use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::relay::exit_policy::ExitPolicy;
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

/// A service only this machine should reach, as an operator would run one.
async fn local_service() -> (SocketAddr, tokio::sync::mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let _ = tx.send(()).await;
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf).await {
                let _ = s.write_all(&buf[..n]).await;
            }
        }
    });
    (addr, rx)
}

async fn relays(policy: ExitPolicy) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for _ in 0..3 {
        let l = NodeListener::bind(
            "127.0.0.1:0".parse().unwrap(),
            StaticSecret::random_from_rng(OsRng),
        )
        .await
        .unwrap()
        .with_exit_policy(policy);
        out.push(l.local_addr().unwrap());
        tokio::spawn(async move { l.accept_loop().await });
    }
    out
}

/// Hops on loopback, as on one machine; destinations public only.
const ONE_MACHINE: ExitPolicy = ExitPolicy {
    private_hops: true,
    private_targets: false,
};

#[tokio::test]
async fn the_exit_refuses_the_operators_loopback() {
    let (service, mut hits) = local_service().await;
    let addrs = relays(ONE_MACHINE).await;
    let mut circuit =
        StreamingCircuit::build(&make_relays(&addrs), StaticSecret::random_from_rng(OsRng))
            .await
            .unwrap();
    let res = circuit
        .connect(&service.ip().to_string(), service.port())
        .await;
    assert!(
        res.is_err(),
        "the exit connected to 127.0.0.1 for a stranger"
    );
    let msg = format!("{}", res.unwrap_err());
    assert!(msg.contains("policy"), "refusal should say why, got: {msg}");
    assert!(hits.try_recv().is_err(), "the local service was reached");
}

#[tokio::test]
async fn the_exit_refuses_localhost_by_name() {
    let (service, mut hits) = local_service().await;
    let addrs = relays(ONE_MACHINE).await;
    let mut circuit =
        StreamingCircuit::build(&make_relays(&addrs), StaticSecret::random_from_rng(OsRng))
            .await
            .unwrap();
    assert!(circuit.connect("localhost", service.port()).await.is_err());
    assert!(
        hits.try_recv().is_err(),
        "the local service was reached by name"
    );
}

#[tokio::test]
async fn the_exit_refuses_cloud_metadata_without_trying() {
    let addrs = relays(ONE_MACHINE).await;
    let mut circuit =
        StreamingCircuit::build(&make_relays(&addrs), StaticSecret::random_from_rng(OsRng))
            .await
            .unwrap();
    // Refused by the policy, not by a timeout: this must come back at once.
    let res = tokio::time::timeout(
        Duration::from_secs(5),
        circuit.connect("169.254.169.254", 80),
    )
    .await;
    let inner = res.expect("the refusal took as long as a connection attempt");
    let msg = format!("{}", inner.unwrap_err());
    assert!(msg.contains("policy"), "got: {msg}");
}

#[tokio::test]
async fn a_relay_refuses_a_private_next_hop() {
    // The middle relay is a public relay with the default policy; the circuit
    // asks it to continue to an address on its loopback.
    let first = relays(ONE_MACHINE).await;
    let strict = NodeListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        StaticSecret::random_from_rng(OsRng),
    )
    .await
    .unwrap();
    let strict_addr = strict.local_addr().unwrap();
    tokio::spawn(async move { strict.accept_loop().await });
    let path = make_relays(&[first[0], strict_addr, first[2]]);
    let (service, mut hits) = local_service().await;
    let built = StreamingCircuit::build(&path, StaticSecret::random_from_rng(OsRng)).await;
    if let Ok(mut c) = built {
        assert!(c
            .connect(&service.ip().to_string(), service.port())
            .await
            .is_err());
    }
    assert!(hits.try_recv().is_err());
}

#[tokio::test]
async fn a_one_machine_network_opted_in_still_works() {
    let (service, mut hits) = local_service().await;
    let addrs = relays(ExitPolicy::ALLOW_PRIVATE).await;
    let mut circuit =
        StreamingCircuit::build(&make_relays(&addrs), StaticSecret::random_from_rng(OsRng))
            .await
            .unwrap();
    circuit
        .connect(&service.ip().to_string(), service.port())
        .await
        .unwrap();
    circuit.send_data(b"hi").await.unwrap();
    assert_eq!(circuit.recv_data().await.unwrap().unwrap(), b"hi");
    assert!(hits.try_recv().is_ok());
}
