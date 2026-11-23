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

/// The client learns relays and finds a hidden service without a DHT node
/// of its own: each request goes through a circuit and the last hop asks
/// its DHT. Starting from one pinned relay, the first request is a one-hop
/// circuit to it; once three are known, requests use full circuits.
#[tokio::test]
async fn relays_and_services_are_looked_up_through_circuits() {
    use ed25519_dalek::SigningKey;
    use hidra_node::p2p::bootstrap::bootstrap;
    use hidra_node::p2p::dht::DhtNode;
    use std::sync::Arc;

    const BITS: u32 = 8;
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut boot = DhtNode::with_id_bits(any, SigningKey::generate(&mut OsRng), None, BITS)
        .await
        .unwrap();
    boot.start().await;
    let boot_addr = boot.our_info().dht_addr;

    let mut relays = Vec::new();
    for _ in 0..4 {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = PublicKey::from(&secret).to_bytes();
        let l = NodeListener::bind(any, secret).await.unwrap();
        let relay_addr = l.local_addr().unwrap();
        let mut node = DhtNode::relay(any, SigningKey::generate(&mut OsRng), relay_addr, key, BITS)
            .await
            .unwrap();
        node.start().await;
        bootstrap(&node, &[boot_addr]).await.unwrap();
        let node = Arc::new(node);
        node.announce_relay().await.unwrap();
        let l = l.with_dht(Arc::clone(&node));
        tokio::spawn(async move { l.accept_loop().await });
        relays.push((VerifiedRelay::pinned(relay_addr, key), node));
    }
    // A service, announced by its intro point's own DHT node.
    let service_key = SigningKey::generate(&mut OsRng);
    let intro = relays[3].0.addr();
    boot.announce_signed_service(&service_key, vec![intro])
        .await
        .unwrap();
    let service_hash =
        hidra_node::p2p::dht::descriptor::service_hash_of(&service_key.verifying_key().to_bytes());

    let pool = CircuitPool::with_id_bits(vec![relays[0].0.clone()], BITS);
    let mut usable = 0;
    for _ in 0..20 {
        usable = pool.refresh_relays().await;
        if usable >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(usable, 4, "every relay, found through the one pinned");

    let found = pool
        .lookup_service(&service_hash)
        .await
        .unwrap()
        .expect("found");
    assert_eq!(found.intro_points, vec![intro]);
    assert!(pool.lookup_service(&[0x77; 20]).await.unwrap().is_none());
}

/// A relay without a DHT node says so; the client gets no relays and no
/// descriptor from it, and is not sent to look elsewhere.
#[tokio::test]
async fn a_relay_without_a_dht_serves_no_directory() {
    let relays = start_relays(3).await;
    let pool = CircuitPool::new(relays);
    assert_eq!(pool.refresh_relays().await, 3);
    assert!(pool.lookup_service(&[1; 20]).await.is_err());
}

/// A hidden service host publishes its descriptor through circuits: the last
/// hop of each announces it, and another client finds it the same way. A
/// descriptor that is stale, or not as the service signed it, is refused by
/// the hop and never published.
#[tokio::test]
async fn a_service_is_announced_through_circuits() {
    use ed25519_dalek::SigningKey;
    use hidra_node::p2p::bootstrap::bootstrap;
    use hidra_node::p2p::dht::DhtNode;
    use hidra_node::p2p::dht::descriptor::ServiceDescriptor;
    use std::sync::Arc;

    const BITS: u32 = 8;
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut boot = DhtNode::with_id_bits(any, SigningKey::generate(&mut OsRng), None, BITS)
        .await
        .unwrap();
    boot.start().await;
    let boot_addr = boot.our_info().dht_addr;

    let mut relays = Vec::new();
    for _ in 0..3 {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = PublicKey::from(&secret).to_bytes();
        let l = NodeListener::bind(any, secret).await.unwrap();
        let relay_addr = l.local_addr().unwrap();
        let mut node = DhtNode::relay(any, SigningKey::generate(&mut OsRng), relay_addr, key, BITS)
            .await
            .unwrap();
        node.start().await;
        bootstrap(&node, &[boot_addr]).await.unwrap();
        let l = l.with_dht(Arc::new(node));
        tokio::spawn(async move { l.accept_loop().await });
        relays.push(VerifiedRelay::pinned(relay_addr, key));
    }

    let host = CircuitPool::with_id_bits(relays.clone(), BITS);
    let service_key = SigningKey::generate(&mut OsRng);
    let intro = relays[2].addr();

    let stale = ServiceDescriptor::sign(&service_key, vec![intro], 1);
    assert_eq!(host.announce_service(&stale).await.unwrap(), 0, "stale");
    let mut moved = ServiceDescriptor::sign_now(&service_key, vec![intro]);
    moved.intro_points = vec!["203.0.113.66:9001".parse().unwrap()];
    assert_eq!(
        host.announce_service(&moved).await.unwrap(),
        0,
        "not as signed"
    );

    let good = ServiceDescriptor::sign_now(&service_key, vec![intro]);
    assert!(host.announce_service(&good).await.unwrap() > 0);

    let visitor = CircuitPool::with_id_bits(relays, BITS);
    let found = visitor
        .lookup_service(&good.service_hash())
        .await
        .unwrap()
        .expect("found");
    assert_eq!(found.intro_points, vec![intro]);
}

/// Two relays whose operator declares them one family, each naming the
/// other in its descriptor, are learned with that family through the DHT
/// (also when one of them was already pinned without it) and never put in
/// one circuit. A relay that names another without being named back is no
/// family.
#[tokio::test]
async fn relays_of_one_operator_are_kept_apart() {
    use ed25519_dalek::SigningKey;
    use hidra_node::client::path::{check_path, choose_path};
    use hidra_node::p2p::bootstrap::bootstrap;
    use hidra_node::p2p::dht::DhtNode;
    use std::sync::Arc;

    const BITS: u32 = 8;
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let mut boot = DhtNode::with_id_bits(any, SigningKey::generate(&mut OsRng), None, BITS)
        .await
        .unwrap();
    boot.start().await;
    let boot_addr = boot.our_info().dht_addr;

    let identities: Vec<SigningKey> = (0..4).map(|_| SigningKey::generate(&mut OsRng)).collect();
    let id = |i: usize| identities[i].verifying_key().to_bytes();
    // 1 and 2 are one operator's; 3 names 0, but 0 does not name 3.
    let families: [Vec<[u8; 32]>; 4] = [vec![], vec![id(2)], vec![id(1)], vec![id(0)]];
    let mut pinned = Vec::new();
    for i in 0..4 {
        let secret = StaticSecret::random_from_rng(OsRng);
        let key = PublicKey::from(&secret).to_bytes();
        let l = NodeListener::bind(any, secret).await.unwrap();
        let relay_addr = l.local_addr().unwrap();
        let mut node = DhtNode::relay_with_family(
            any,
            identities[i].clone(),
            relay_addr,
            key,
            families[i].clone(),
            BITS,
        )
        .await
        .unwrap();
        node.start().await;
        bootstrap(&node, &[boot_addr]).await.unwrap();
        let node = Arc::new(node);
        node.announce_relay().await.unwrap();
        let l = l.with_dht(Arc::clone(&node));
        tokio::spawn(async move { l.accept_loop().await });
        pinned.push(VerifiedRelay::pinned(relay_addr, key));
    }

    // Pinned, relay 1 has no family yet: a path with 1 and 2 is allowed...
    let path = [pinned[0].clone(), pinned[1].clone(), pinned[2].clone()];
    assert!(check_path(&path).is_ok());

    // ...until the directory brings its descriptor.
    let pool = CircuitPool::with_id_bits(vec![pinned[0].clone(), pinned[1].clone()], BITS);
    let mut known = Vec::new();
    for _ in 0..20 {
        pool.refresh_relays().await;
        known = pool.relays().await;
        let upgraded = known
            .iter()
            .find(|r| **r == pinned[1])
            .is_some_and(|r| known.iter().any(|o| *o == pinned[2] && r.same_family(o)));
        if known.len() == 4 && upgraded {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let get = |i: usize| known.iter().find(|r| **r == pinned[i]).unwrap().clone();
    assert!(
        get(1).same_family(&get(2)),
        "the pinned relay's family was learned"
    );
    assert!(
        !get(0).same_family(&get(3)),
        "named by 3 alone, 0 is not its family"
    );

    let err = match StreamingCircuit::build(&[get(1), get(0), get(2)]).await {
        Ok(_) => panic!("a circuit through one operator's two relays"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("one operator"), "{err}");
    for guard in &known {
        for _ in 0..100 {
            if let Ok(p) = choose_path(&known, guard, None) {
                assert!(!(p.contains(&pinned[1]) && p.contains(&pinned[2])));
            }
        }
    }
    // And the pool still builds circuits, around the family.
    let mut c = pool.build_new_circuit().await.unwrap();
    c.destroy().await;
}
