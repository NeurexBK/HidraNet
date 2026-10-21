//! Circuits built by telescoping, on loopback.
//!
//! The network-level property (the client never opens a connection to the
//! middle or the exit) is tested in scripts/test-anonymity-netns.sh, where a
//! firewall and a packet capture can see it. These tests cover what can be
//! seen from inside one process: failures abort, teardown reaches every hop,
//! hidden services meet at the introduction point, the old protocol is gone.

use std::net::SocketAddr;
use std::time::Duration;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

use hidra_node::client::circuit_pool::CircuitPool;
use hidra_node::client::streaming::StreamingCircuit;
use hidra_node::network::listener::NodeListener;
use hidra_node::p2p::dht::descriptor::VerifiedRelay;

async fn start_relays(n: usize) -> Vec<VerifiedRelay> {
    let mut relays = Vec::new();
    for _ in 0..n {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = PublicKey::from(&secret).to_bytes();
        let l = NodeListener::bind("127.0.0.1:0".parse().unwrap(), secret)
            .await
            .unwrap();
        relays.push(VerifiedRelay::pinned(l.local_addr().unwrap(), key));
        tokio::spawn(async move { l.accept_loop().await });
    }
    relays
}

fn with_wrong_key(r: &VerifiedRelay) -> VerifiedRelay {
    let other = PublicKey::from(&StaticSecret::random_from_rng(OsRng)).to_bytes();
    VerifiedRelay::pinned(r.addr(), other)
}

#[tokio::test]
async fn a_wrong_key_anywhere_in_the_path_aborts_the_circuit() {
    let relays = start_relays(3).await;

    let entry = vec![
        with_wrong_key(&relays[0]),
        relays[1].clone(),
        relays[2].clone(),
    ];
    assert!(StreamingCircuit::build(&entry).await.is_err());

    for i in 1..3 {
        let mut path = relays.clone();
        path[i] = with_wrong_key(&relays[i]);
        let err = match StreamingCircuit::build(&path).await {
            Ok(_) => panic!("hop {i} with the wrong key still gave a circuit"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("extension failed"), "hop {i}: {err}");
    }
}

#[tokio::test]
async fn a_path_that_repeats_a_relay_is_refused() {
    let relays = start_relays(2).await;
    let path = vec![relays[0].clone(), relays[1].clone(), relays[0].clone()];
    assert!(StreamingCircuit::build(&path).await.is_err());
}

/// Destroying a circuit closes the exit's connection to the target: the
/// teardown travels the whole path.
#[tokio::test]
async fn destroy_reaches_the_exit() {
    let relays = start_relays(3).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 64];
        while let Ok(n) = s.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
        let _ = closed_tx.send(());
    });

    let mut circuit = StreamingCircuit::build(&relays).await.unwrap();
    circuit
        .connect("127.0.0.1", target_addr.port())
        .await
        .unwrap();
    circuit.send_data(b"hello").await.unwrap();
    circuit.destroy().await;
    tokio::time::timeout(Duration::from_secs(5), closed_rx)
        .await
        .expect("the exit kept its connection to the target open")
        .unwrap();
}

/// A hidden service registers at the last hop of its circuit; a client
/// builds a circuit that ends at that same relay and the two are bridged.
#[tokio::test]
async fn a_hidden_service_is_reached_through_its_introduction_point() {
    let relays = start_relays(4).await;
    let intro = relays[3].clone();
    let service_hash = vec![0x5a; 20];

    let mut service =
        StreamingCircuit::build(&[relays[0].clone(), relays[1].clone(), intro.clone()])
            .await
            .unwrap();
    service
        .register_service(service_hash.clone())
        .await
        .unwrap();

    let pool = CircuitPool::new(relays.clone());
    let mut client = pool.build_circuit_to(&[intro.addr()]).await.unwrap();
    client.connect_service(service_hash).await.unwrap();

    client.send_data(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
    assert_eq!(
        service.recv_data().await.unwrap().unwrap(),
        b"GET / HTTP/1.0\r\n\r\n"
    );
    service.send_data(b"HTTP/1.0 200 OK\r\n\r\n").await.unwrap();
    assert_eq!(
        client.recv_data().await.unwrap().unwrap(),
        b"HTTP/1.0 200 OK\r\n\r\n"
    );

    // An introduction point that is not a verified relay: no circuit, and no
    // falling back to some other exit.
    let unknown: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert!(pool.build_circuit_to(&[unknown]).await.is_err());
}

/// The relay speaks only the link protocol. A client that opens with the
/// old session byte (the Noise XX session in which it presented its static
/// key) is dropped without an answer.
#[tokio::test]
async fn the_old_direct_session_is_refused() {
    let relays = start_relays(1).await;
    let mut s = TcpStream::connect(relays[0].addr()).await.unwrap();
    s.write_all(&[0x00]).await.unwrap();
    s.write_all(&[0u8; 64]).await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("the relay neither answered nor closed")
        .unwrap_or(0);
    assert_eq!(n, 0, "the relay answered a legacy session");
}

/// The whole path a client takes in production: relays announce signed
/// descriptors in the DHT, a client that knows only a bootstrap node finds
/// them, keeps the ones whose descriptors verify, and builds a circuit
/// through them — each hop held to the key its own descriptor names.
#[tokio::test]
async fn a_circuit_through_relays_found_in_the_dht() {
    use ed25519_dalek::SigningKey;
    use hidra_node::p2p::bootstrap::bootstrap;
    use hidra_node::p2p::dht::DhtNode;

    const BITS: u32 = 8;
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut boot = DhtNode::with_id_bits(any, SigningKey::generate(&mut OsRng), None, BITS)
        .await
        .unwrap();
    boot.start().await;
    let boot_addr = boot.our_info().dht_addr;

    let mut dht_relays = Vec::new();
    for _ in 0..3 {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = PublicKey::from(&secret).to_bytes();
        let l = NodeListener::bind(any, secret).await.unwrap();
        let relay_addr = l.local_addr().unwrap();
        tokio::spawn(async move { l.accept_loop().await });
        let mut node = DhtNode::relay(any, SigningKey::generate(&mut OsRng), relay_addr, key, BITS)
            .await
            .unwrap();
        node.start().await;
        bootstrap(&node, &[boot_addr]).await.unwrap();
        dht_relays.push(node);
    }
    for node in &dht_relays {
        node.announce_relay().await.unwrap();
    }

    let mut client = DhtNode::with_id_bits(any, SigningKey::generate(&mut OsRng), None, BITS)
        .await
        .unwrap();
    client.start().await;
    bootstrap(&client, &[boot_addr]).await.unwrap();

    let mut verified = Vec::new();
    for _ in 0..20 {
        verified = client
            .find_relays(10)
            .await
            .unwrap()
            .iter()
            .filter_map(|n| n.verified_relay())
            .collect();
        if verified.len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(verified.len(), 3, "every relay's descriptor should verify");

    let target = TcpListener::bind(any).await.unwrap();
    let target_addr = target.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = target.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = s.read(&mut buf).await.unwrap();
        s.write_all(&buf[..n]).await.unwrap();
    });
    let mut circuit = StreamingCircuit::build(&verified).await.unwrap();
    circuit
        .connect("127.0.0.1", target_addr.port())
        .await
        .unwrap();
    circuit.send_data(b"found in the DHT").await.unwrap();
    assert_eq!(
        circuit.recv_data().await.unwrap().unwrap(),
        b"found in the DHT"
    );
}
