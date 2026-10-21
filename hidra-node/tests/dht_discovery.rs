use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use hidra_node::p2p::bootstrap::bootstrap;
use hidra_node::p2p::dht::descriptor::ServiceDescriptor;
use hidra_node::p2p::dht::message::{sign_and_serialize, verify_and_deserialize, DhtMessage};
use hidra_node::p2p::dht::node::{id_puzzle_ok, solve_id_puzzle, NodeId, NodeInfo};
use hidra_node::p2p::dht::DhtNode;
use tokio::net::UdpSocket;

/// The ID difficulty of every node in these tests. The public network's 24
/// bits would cost seconds per node in a debug build; the checks are the same.
const BITS: u32 = 8;

async fn spawn_dht_node(port: u16, relay_addr: Option<SocketAddr>) -> DhtNode {
    let signing_key = SigningKey::generate(&mut OsRng);
    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut node = DhtNode::with_id_bits(bind_addr, signing_key, relay_addr, BITS).await.unwrap();
    node.start().await;
    node
}

/// A NodeInfo for `key` at `addr` whose ID was earned at BITS.
fn earned_info(key: &SigningKey, addr: SocketAddr, relay: Option<SocketAddr>) -> NodeInfo {
    let pk = key.verifying_key().to_bytes();
    let nonce = solve_id_puzzle(&pk, BITS);
    NodeInfo { id: NodeId::for_node(&pk, nonce), dht_addr: addr, relay_addr: relay, public_key: pk, id_nonce: nonce, relay_descriptor: None }
}

/// A NodeInfo for `key` at `addr` with an ID nobody paid for.
fn unearned_info(key: &SigningKey, addr: SocketAddr) -> NodeInfo {
    let pk = key.verifying_key().to_bytes();
    let nonce = (0..u64::MAX).find(|n| !id_puzzle_ok(&pk, *n, BITS)).unwrap();
    NodeInfo { id: NodeId::for_node(&pk, nonce), dht_addr: addr, relay_addr: None, public_key: pk, id_nonce: nonce, relay_descriptor: None }
}

async fn recv_msg(sock: &UdpSocket, wait: Duration) -> Option<(DhtMessage, SocketAddr)> {
    let mut buf = vec![0u8; 65535];
    let (n, from) = tokio::time::timeout(wait, sock.recv_from(&mut buf)).await.ok()?.ok()?;
    verify_and_deserialize(&buf[..n]).ok().map(|(m, _)| (m, from))
}

/// A raw node: answers PING as `me`, signed with `key`, and FIND_NODE and
/// LOOKUP_SERVICE as `answer` says. Counts what it was asked.
fn spawn_raw_node(
    sock: Arc<UdpSocket>,
    key: SigningKey,
    me: NodeInfo,
    answer: impl Fn(DhtMessage, &NodeInfo) -> Option<DhtMessage> + Send + 'static,
) -> Arc<AtomicUsize> {
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = asked.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
            let Ok((msg, _)) = verify_and_deserialize(&buf[..n]) else { continue };
            counter.fetch_add(1, Ordering::SeqCst);
            let reply = match msg {
                DhtMessage::Ping { request_id, .. } => Some(DhtMessage::Pong { request_id, sender: me.clone() }),
                other => answer(other, &me),
            };
            if let Some(r) = reply {
                let _ = sock.send_to(&sign_and_serialize(&r, &key).unwrap(), from).await;
            }
        }
    });
    asked
}

#[tokio::test]
async fn a_node_with_an_unearned_id_gets_no_answer_and_no_seat() {
    let node = spawn_dht_node(0, None).await;
    let node_addr = node.our_info().dht_addr;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let my_addr = sock.local_addr().unwrap();

    // Signed by its own key, but its ID skipped the puzzle.
    let key = SigningKey::generate(&mut OsRng);
    let free = unearned_info(&key, my_addr);
    let ping = DhtMessage::Ping { request_id: 1, sender: free.clone() };
    sock.send_to(&sign_and_serialize(&ping, &key).unwrap(), node_addr).await.unwrap();
    assert!(recv_msg(&sock, Duration::from_millis(800)).await.is_none(), "no PONG for an unearned ID");
    assert!(!node.routing_table().lock().await.contains(&free.id), "and no seat in the table");

    // Claiming another node's earned ID while signing with its own key.
    let victim = SigningKey::generate(&mut OsRng);
    let stolen = earned_info(&victim, my_addr, None);
    let ping = DhtMessage::Ping { request_id: 2, sender: stolen.clone() };
    sock.send_to(&sign_and_serialize(&ping, &key).unwrap(), node_addr).await.unwrap();
    assert!(recv_msg(&sock, Duration::from_millis(800)).await.is_none(), "no PONG for a stolen ID");
    assert!(!node.routing_table().lock().await.contains(&stolen.id));

    // The same key with an earned ID: answered, then asked to prove the
    // address it wrote from, and seated once it does.
    let paid = earned_info(&key, my_addr, None);
    let ping = DhtMessage::Ping { request_id: 3, sender: paid.clone() };
    sock.send_to(&sign_and_serialize(&ping, &key).unwrap(), node_addr).await.unwrap();
    let mut got_pong = false;
    let mut got_pingback = false;
    for _ in 0..2 {
        match recv_msg(&sock, Duration::from_secs(3)).await {
            Some((DhtMessage::Pong { request_id: 3, .. }, _)) => got_pong = true,
            Some((DhtMessage::Ping { request_id, .. }, from)) => {
                got_pingback = true;
                let pong = DhtMessage::Pong { request_id, sender: paid.clone() };
                sock.send_to(&sign_and_serialize(&pong, &key).unwrap(), from).await.unwrap();
            }
            _ => {}
        }
    }
    assert!(got_pong && got_pingback, "pong {got_pong}, ping-back {got_pingback}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(node.routing_table().lock().await.address_of(&paid.id), Some(my_addr));
}

#[tokio::test]
async fn a_signed_announcement_replayed_from_another_address_seats_nothing() {
    let node = spawn_dht_node(0, None).await;
    let node_addr = node.our_info().dht_addr;

    // A relay with an earned ID, at its own address, answering PINGs as itself.
    let relay_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let relay_key = SigningKey::generate(&mut OsRng);
    let relay = earned_info(&relay_key, relay_sock.local_addr().unwrap(), Some("127.0.0.1:19911".parse().unwrap()));
    let announce = sign_and_serialize(&DhtMessage::AnnounceRelay { request_id: 77, sender: relay.clone() }, &relay_key).unwrap();

    // Someone holding a copy of that signed packet sends it from elsewhere,
    // and answers the ping-back as best it can: signed with its own key.
    let thief_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let thief_key = SigningKey::generate(&mut OsRng);
    let thief = earned_info(&thief_key, thief_sock.local_addr().unwrap(), None);
    let thief_asked = spawn_raw_node(thief_sock.clone(), thief_key, thief, |_, _| None);
    thief_sock.send_to(&announce, node_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(thief_asked.load(Ordering::SeqCst) > 0, "the replaying address was asked to prove itself");
    assert!(!node.routing_table().lock().await.contains(&relay.id), "and the replay seated nothing");

    // The relay itself, from its own address: seated there, as it describes itself.
    spawn_raw_node(relay_sock.clone(), relay_key, relay.clone(), |_, _| None);
    relay_sock.send_to(&announce, node_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let table = node.routing_table().lock().await;
    assert_eq!(table.address_of(&relay.id), Some(relay.dht_addr));
    let seated = table.find_closest(&relay.id, 1);
    assert_eq!(seated[0].relay_addr, relay.relay_addr);
}

#[tokio::test]
async fn one_node_cannot_fill_another_nodes_descriptor_store() {
    let node = spawn_dht_node(0, None).await;
    let node_addr = node.our_info().dht_addr;
    let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let key = SigningKey::generate(&mut OsRng);
    let me = earned_info(&key, sock.local_addr().unwrap(), None);
    // A hundred valid services, from keys that cost nothing.
    for i in 0..100u64 {
        let service = SigningKey::generate(&mut OsRng);
        let d = ServiceDescriptor::sign_now(&service, vec![format!("198.51.100.1:{}", 9000 + i).parse().unwrap()]);
        let msg = DhtMessage::AnnounceService { request_id: i, sender: me.clone(), service_hash: d.service_hash(), descriptor: d };
        sock.send_to(&sign_and_serialize(&msg, &key).unwrap(), node_addr).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let kept = node.stored_service_count().await;
    assert_eq!(kept, hidra_node::p2p::dht::store::MAX_NEW_PER_PUSHER_PER_HOUR, "one pusher's share an hour");

    // An honest service published afterwards is still kept.
    let publisher = spawn_dht_node(0, None).await;
    publisher.ping(node_addr).await.unwrap();
    let service = SigningKey::generate(&mut OsRng);
    publisher.announce_signed_service(&service, vec!["198.51.100.200:9001".parse().unwrap()]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(node.stored_service_count().await, kept + 1);
}

#[tokio::test]
async fn a_forged_or_older_descriptor_loses_to_the_one_the_service_signed_last() {
    // Five honest nodes around a hub.
    let hub = spawn_dht_node(0, None).await;
    let hub_addr = hub.our_info().dht_addr;
    let mut honest = Vec::new();
    for _ in 0..4 {
        let n = spawn_dht_node(0, None).await;
        bootstrap(&n, &[hub_addr]).await.unwrap();
        honest.push(n);
    }

    // The service publishes revision 1, then moves and publishes revision 2.
    let service_key = SigningKey::generate(&mut OsRng);
    let now = hidra_node::p2p::dht::store::now_secs();
    let rev1 = ServiceDescriptor::sign(&service_key, vec!["198.51.100.1:9001".parse().unwrap()], now - 60);
    let rev2 = ServiceDescriptor::sign(&service_key, vec!["198.51.100.2:9001".parse().unwrap()], now - 30);
    let service_hash = rev2.service_hash();
    let publisher = spawn_dht_node(0, None).await;
    bootstrap(&publisher, &[hub_addr]).await.unwrap();
    publisher.announce_service(rev1.clone()).await.unwrap();
    publisher.announce_service(rev2.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A liar with an earned ID, ground (as an attacker would) to sit closer
    // to the service than any honest node, so its answer is the first one a
    // lookup sees. It answers FIND_NODE with a neighbour whose ID was never
    // earned, a stolen ID at a thief's address, and an honest node at a
    // hijacker's address; and LOOKUP_SERVICE with either a "newer"
    // descriptor it signed itself under the service's key, or revision 1.
    let liar_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let target = hidra_node::p2p::dht::descriptor::service_target(&service_hash);
    let honest_best = std::iter::once(hub.our_info())
        .chain(honest.iter().map(|n| n.our_info()))
        .chain(std::iter::once(publisher.our_info()))
        .map(|i| i.id.xor_distance(&target))
        .min()
        .unwrap();
    let (liar_key, liar) = loop {
        let k = SigningKey::generate(&mut OsRng);
        let info = earned_info(&k, liar_sock.local_addr().unwrap(), None);
        if info.id.xor_distance(&target) < honest_best {
            break (k, info);
        }
    };
    let fake_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fake = unearned_info(&SigningKey::generate(&mut OsRng), fake_sock.local_addr().unwrap());
    // The thief earns a valid ID for a key it does not hold (the puzzle binds
    // an ID to a key, not to whoever solves it) and answers as itself.
    let thief_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let thief_key = SigningKey::generate(&mut OsRng);
    let stolen = earned_info(&SigningKey::generate(&mut OsRng), thief_sock.local_addr().unwrap(), None);
    // The hijacker names a real honest node at its own, silent, address.
    let hijack_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let redirected_node = honest[3].our_info().clone();
    let redirected = NodeInfo {
        dht_addr: hijack_sock.local_addr().unwrap(),
        relay_addr: Some(hijack_sock.local_addr().unwrap()),
        ..redirected_node.clone()
    };
    let mut forged = ServiceDescriptor::sign(&SigningKey::generate(&mut OsRng), vec!["203.0.113.66:9001".parse().unwrap()], now);
    forged.service_pubkey = rev2.service_pubkey;
    let serve_forged = Arc::new(AtomicBool::new(true));
    {
        let (fake, stolen, redirected, forged, rev1, serve_forged) =
            (fake.clone(), stolen.clone(), redirected.clone(), forged.clone(), rev1.clone(), serve_forged.clone());
        spawn_raw_node(liar_sock.clone(), liar_key, liar.clone(), move |msg, me| match msg {
            DhtMessage::FindNode { request_id, .. } => Some(DhtMessage::FindNodeResponse {
                request_id,
                sender: me.clone(),
                nodes: vec![fake.clone(), stolen.clone(), redirected.clone()],
            }),
            DhtMessage::LookupService { request_id, .. } => {
                let d = if serve_forged.load(Ordering::SeqCst) { forged.clone() } else { rev1.clone() };
                Some(DhtMessage::LookupServiceResponse { request_id, sender: me.clone(), descriptor: Some(d) })
            }
            _ => None,
        });
    }
    let thief_info = earned_info(&thief_key, thief_sock.local_addr().unwrap(), None);
    let thief_asked = {
        let forged = forged.clone();
        spawn_raw_node(thief_sock.clone(), thief_key, thief_info, move |msg, me| match msg {
            DhtMessage::FindNode { request_id, .. } => Some(DhtMessage::FindNodeResponse { request_id, sender: me.clone(), nodes: vec![] }),
            DhtMessage::LookupService { request_id, .. } => Some(DhtMessage::LookupServiceResponse { request_id, sender: me.clone(), descriptor: Some(forged.clone()) }),
            _ => None,
        })
    };

    // A client that knows the liar and one honest node.
    let client = spawn_dht_node(0, None).await;
    client.ping(liar.dht_addr).await.unwrap();
    client.ping(honest[0].our_info().dht_addr).await.unwrap();
    assert!(client.routing_table().lock().await.contains(&liar.id), "the liar has an earned ID and a seat");

    let (intro, pk) = client.lookup_service(&service_hash).await.unwrap().expect("found");
    assert_eq!(intro, rev2.intro_points, "the forged 'newer' descriptor lost to the service's own");
    assert_eq!(pk, rev2.service_pubkey);

    // The unearned neighbour the liar named was never asked and never seated.
    assert!(recv_msg(&fake_sock, Duration::from_millis(300)).await.is_none(), "nobody contacted the unearned node");
    assert!(!client.routing_table().lock().await.contains(&fake.id));
    // The thief was asked (the ID it showed is valid) and got no seat: it
    // cannot sign as the key that ID belongs to.
    assert!(thief_asked.load(Ordering::SeqCst) > 0, "the thief was asked");
    assert!(!client.routing_table().lock().await.contains(&stolen.id));
    // The honest node the liar redirected is seated at its own address, as
    // it describes itself, or not at all: never at the hijacker's.
    let table = client.routing_table().lock().await;
    if let Some(addr) = table.address_of(&redirected_node.id) {
        assert_eq!(addr, redirected_node.dht_addr);
        let seated = table.find_closest(&redirected_node.id, 1);
        assert_eq!(seated[0].relay_addr, redirected_node.relay_addr, "its relay address is its own");
    }
    drop(table);

    // A second client, and the liar now replays the genuine revision 1.
    serve_forged.store(false, Ordering::SeqCst);
    let client2 = spawn_dht_node(0, None).await;
    client2.ping(liar.dht_addr).await.unwrap();
    client2.ping(honest[1].our_info().dht_addr).await.unwrap();
    let (intro, _) = client2.lookup_service(&service_hash).await.unwrap().expect("found");
    assert_eq!(intro, rev2.intro_points, "an older revision loses to a newer one from another path");

    drop(publisher);
    drop(hub);
}

#[tokio::test]
async fn five_nodes_discover_each_other() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hidra_node=debug")
        .with_test_writer()
        .try_init();

    let base_port = 17100u16;

    let node0 = spawn_dht_node(base_port, None).await;
    let node1 = spawn_dht_node(base_port + 1, None).await;
    let node2 = spawn_dht_node(base_port + 2, None).await;
    let node3 = spawn_dht_node(base_port + 3, None).await;
    let node4 = spawn_dht_node(base_port + 4, None).await;

    let node0_addr: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();

    bootstrap(&node1, &[node0_addr]).await.unwrap();
    bootstrap(&node2, &[node0_addr]).await.unwrap();
    bootstrap(&node3, &[node0_addr]).await.unwrap();
    bootstrap(&node4, &[node0_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    let count0 = node0.node_count().await;
    let count1 = node1.node_count().await;
    let count2 = node2.node_count().await;
    let count3 = node3.node_count().await;
    let count4 = node4.node_count().await;

    assert!(count0 >= 4, "node0 should know at least 4 peers, found {count0}");
    assert!(count1 >= 4, "node1 should know at least 4 peers, found {count1}");
    assert!(count2 >= 4, "node2 should know at least 4 peers, found {count2}");
    assert!(count3 >= 4, "node3 should know at least 4 peers, found {count3}");
    assert!(count4 >= 4, "node4 should know at least 4 peers, found {count4}");
}

#[tokio::test]
async fn fresh_node_discovers_relays_via_dht() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hidra_node=debug")
        .with_test_writer()
        .try_init();

    let base_port = 17200u16;

    let relay0_tcp: SocketAddr = "127.0.0.1:19150".parse().unwrap();
    let relay1_tcp: SocketAddr = "127.0.0.1:19151".parse().unwrap();
    let relay2_tcp: SocketAddr = "127.0.0.1:19152".parse().unwrap();

    let relay0 = spawn_dht_node(base_port, Some(relay0_tcp)).await;
    let relay1 = spawn_dht_node(base_port + 1, Some(relay1_tcp)).await;
    let relay2 = spawn_dht_node(base_port + 2, Some(relay2_tcp)).await;
    let non_relay = spawn_dht_node(base_port + 3, None).await;

    let bootstrap_addr: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();

    bootstrap(&relay1, &[bootstrap_addr]).await.unwrap();
    bootstrap(&relay2, &[bootstrap_addr]).await.unwrap();
    bootstrap(&non_relay, &[bootstrap_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    relay0.announce_relay().await.unwrap();
    relay1.announce_relay().await.unwrap();
    relay2.announce_relay().await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let fresh_client = spawn_dht_node(base_port + 10, None).await;
    bootstrap(&fresh_client, &[bootstrap_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let relays = fresh_client.find_relays(3).await.unwrap();
    assert!(
        relays.len() >= 3,
        "fresh client should find at least 3 relays, found {}",
        relays.len()
    );

    for relay in &relays {
        assert!(
            relay.relay_addr.is_some(),
            "relay {} should have a relay_addr",
            relay.id
        );
    }
}

#[tokio::test]
async fn discovery_under_ten_seconds() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hidra_node=debug")
        .with_test_writer()
        .try_init();

    let base_port = 17300u16;

    let relay0 = spawn_dht_node(base_port, Some("127.0.0.1:19250".parse().unwrap())).await;
    let relay1 = spawn_dht_node(base_port + 1, Some("127.0.0.1:19251".parse().unwrap())).await;
    let relay2 = spawn_dht_node(base_port + 2, Some("127.0.0.1:19252".parse().unwrap())).await;
    let relay3 = spawn_dht_node(base_port + 3, Some("127.0.0.1:19253".parse().unwrap())).await;
    let relay4 = spawn_dht_node(base_port + 4, Some("127.0.0.1:19254".parse().unwrap())).await;

    let bootstrap_addr: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
    bootstrap(&relay1, &[bootstrap_addr]).await.unwrap();
    bootstrap(&relay2, &[bootstrap_addr]).await.unwrap();
    bootstrap(&relay3, &[bootstrap_addr]).await.unwrap();
    bootstrap(&relay4, &[bootstrap_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    for r in [&relay0, &relay1, &relay2, &relay3, &relay4] {
        let _ = r.announce_relay().await;
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let fresh = spawn_dht_node(base_port + 20, None).await;

    let start = std::time::Instant::now();
    bootstrap(&fresh, &[bootstrap_addr]).await.unwrap();
    let elapsed = start.elapsed();

    let peers = fresh.node_count().await;
    assert!(
        peers >= 5,
        "fresh node should discover 5+ peers in <10s, found {peers}"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "discovery took {:?}, should be <10s",
        elapsed
    );
}

/// 30% fault tolerance: 10 nodes form a network, 3 go offline,
/// remaining nodes still discover each other and find relays.
#[tokio::test]
async fn thirty_percent_fault_tolerance() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hidra_node=debug")
        .with_test_writer()
        .try_init();

    let base_port = 17400u16;
    let mut nodes = Vec::new();

    for i in 0..10u16 {
        let relay_addr = Some(
            format!("127.0.0.1:{}", 19300 + i)
                .parse::<SocketAddr>()
                .unwrap(),
        );
        nodes.push(spawn_dht_node(base_port + i, relay_addr).await);
    }

    let bootstrap_addr: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
    for i in 1..10 {
        bootstrap(&nodes[i], &[bootstrap_addr]).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    for node in &nodes {
        let _ = node.announce_relay().await;
    }

    tokio::time::sleep(Duration::from_millis(300)).await;

    // Drop 3 nodes (30%) — nodes 7, 8, 9
    drop(nodes.pop()); // node 9
    drop(nodes.pop()); // node 8
    drop(nodes.pop()); // node 7

    tokio::time::sleep(Duration::from_millis(200)).await;

    // A fresh node should still bootstrap and find relays
    let fresh = spawn_dht_node(base_port + 50, None).await;
    bootstrap(&fresh, &[bootstrap_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let peers = fresh.node_count().await;
    assert!(
        peers >= 5,
        "with 30% offline, fresh node should still find 5+ peers, found {peers}"
    );

    let relays = fresh.find_relays(3).await.unwrap();
    assert!(
        relays.len() >= 3,
        "with 30% offline, should still find 3+ relays, found {}",
        relays.len()
    );
}

/// Network self-recovery: a node drops out and re-joins, the network
/// re-integrates it without manual intervention.
#[tokio::test]
async fn network_self_recovery_after_partition() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hidra_node=debug")
        .with_test_writer()
        .try_init();

    let base_port = 17500u16;

    let node0 = spawn_dht_node(base_port, None).await;
    let node1 = spawn_dht_node(base_port + 1, None).await;
    let node2 = spawn_dht_node(base_port + 2, None).await;

    let bootstrap_addr: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
    bootstrap(&node1, &[bootstrap_addr]).await.unwrap();
    bootstrap(&node2, &[bootstrap_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(node0.node_count().await >= 2);
    assert!(node1.node_count().await >= 2);

    // Simulate partition: drop node2 and create a replacement on the same port
    drop(node2);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let node2_rejoin = spawn_dht_node(base_port + 2, None).await;
    bootstrap(&node2_rejoin, &[bootstrap_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let count = node2_rejoin.node_count().await;
    assert!(
        count >= 2,
        "re-joined node should rediscover peers, found {count}"
    );
}

/// Gossip propagation: relay announcement reaches nodes that the
/// announcer hasn't directly contacted.
#[tokio::test]
async fn gossip_propagation_of_relay_announcements() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("hidra_node=debug")
        .with_test_writer()
        .try_init();

    let base_port = 17600u16;

    // node0 is the bootstrap hub
    let node0 = spawn_dht_node(base_port, None).await;
    let node1 = spawn_dht_node(base_port + 1, None).await;
    let node2 = spawn_dht_node(base_port + 2, None).await;
    let node3 = spawn_dht_node(base_port + 3, None).await;

    let bootstrap_addr: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
    bootstrap(&node1, &[bootstrap_addr]).await.unwrap();
    bootstrap(&node2, &[bootstrap_addr]).await.unwrap();
    bootstrap(&node3, &[bootstrap_addr]).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    // A new relay only announces to node0 (its bootstrap)
    let relay = spawn_dht_node(
        base_port + 10,
        Some("127.0.0.1:19400".parse().unwrap()),
    )
    .await;
    bootstrap(&relay, &[bootstrap_addr]).await.unwrap();
    relay.announce_relay().await.unwrap();

    // Wait for gossip to propagate
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Other nodes should learn about this relay through gossip
    let mut found_relay_count = 0;
    for node in [&node0, &node1, &node2, &node3] {
        let relays = node.find_relays(5).await.unwrap();
        if relays.iter().any(|r| r.relay_addr == Some("127.0.0.1:19400".parse().unwrap())) {
            found_relay_count += 1;
        }
    }

    assert!(
        found_relay_count >= 2,
        "relay announcement should gossip to at least 2 nodes, reached {found_relay_count}"
    );
}

#[tokio::test]
async fn a_cluster_of_ground_ids_around_a_service_cannot_hide_it_from_a_clean_path() {
    // An honest network that holds the service's descriptor.
    let hub = spawn_dht_node(0, None).await;
    let hub_addr = hub.our_info().dht_addr;
    let mut honest = Vec::new();
    for _ in 0..5 {
        let n = spawn_dht_node(0, None).await;
        bootstrap(&n, &[hub_addr]).await.unwrap();
        honest.push(n);
    }
    let service_key = SigningKey::generate(&mut OsRng);
    let publisher = spawn_dht_node(0, None).await;
    bootstrap(&publisher, &[hub_addr]).await.unwrap();
    let descriptor = ServiceDescriptor::sign_now(&service_key, vec!["198.51.100.9:9001".parse().unwrap()]);
    let service_hash = descriptor.service_hash();
    publisher.announce_service(descriptor.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Sixty-four Sybils, each with a valid, earned ID ground to sit closer
    // to the service than every honest node: more than the 3K a service
    // lookup walks. They answer FIND_NODE with each other (the 20 closest to
    // what was asked, as a node would) and withhold the descriptor.
    let target = {
        let mut padded = [0u8; 32];
        padded[..20].copy_from_slice(&service_hash);
        NodeId::from_public_key(&padded)
    };
    let honest_best = std::iter::once(hub.our_info())
        .chain(honest.iter().map(|n| n.our_info()))
        .chain(std::iter::once(publisher.our_info()))
        .map(|i| i.id.xor_distance(&target))
        .min()
        .unwrap();
    let mut sybils: Vec<(std::sync::Arc<UdpSocket>, SigningKey, NodeInfo)> = Vec::new();
    while sybils.len() < 64 {
        let sock = std::sync::Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let key = loop {
            let k = SigningKey::generate(&mut OsRng);
            let info = earned_info(&k, sock.local_addr().unwrap(), None);
            if info.id.xor_distance(&target) < honest_best {
                break k;
            }
        };
        let info = earned_info(&key, sock.local_addr().unwrap(), None);
        sybils.push((sock, key, info));
    }
    let cluster: Vec<NodeInfo> = sybils.iter().map(|(_, _, i)| i.clone()).collect();
    for (index, (sock, key, me)) in sybils.iter().enumerate() {
        // Each Sybil names a different twenty of the cluster, so that a walk
        // meets all of them (a real node's answer is capped at K too).
        let cluster: Vec<NodeInfo> = (0..20).map(|j| cluster[(index * 7 + j) % cluster.len()].clone()).collect();
        let (sock, key, me) = (sock.clone(), key.clone(), me.clone());
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
                let Ok((msg, _)) = verify_and_deserialize(&buf[..n]) else { continue };
                let reply = match msg {
                    DhtMessage::Ping { request_id, .. } => DhtMessage::Pong { request_id, sender: me.clone() },
                    DhtMessage::FindNode { request_id, .. } => DhtMessage::FindNodeResponse { request_id, sender: me.clone(), nodes: cluster.clone() },
                    DhtMessage::LookupService { request_id, .. } => DhtMessage::LookupServiceResponse { request_id, sender: me.clone(), descriptor: None },
                    _ => continue,
                };
                let _ = sock.send_to(&sign_and_serialize(&reply, &key).unwrap(), from).await;
            }
        });
    }

    // A client that has met one Sybil and one honest node. Every node the
    // Sybil path finds is closer to the service than any honest node.
    let client = spawn_dht_node(0, None).await;
    client.ping(cluster[0].dht_addr).await.unwrap();
    client.ping(honest[0].our_info().dht_addr).await.unwrap();

    let found = client.lookup_service(&service_hash).await.unwrap();
    let (intro, _) = found.expect("the clean path reached the nodes that hold the descriptor");
    assert_eq!(intro, descriptor.intro_points);
    assert!(
        cluster.iter().filter(|s| client_knows(&client, s)).count() > 0,
        "the Sybil path was walked, too"
    );

    drop(publisher);
    drop(hub);
}

fn client_knows(client: &DhtNode, n: &NodeInfo) -> bool {
    client.routing_table().try_lock().map(|t| t.contains(&n.id)).unwrap_or(false)
}

#[tokio::test]
async fn a_third_party_cannot_change_how_a_node_is_seated() {
    // An honest node that only ever answers (a full node would also ping the
    // client back, and its own signed description would correct the record
    // by itself; this test is about the client's rule, so nothing helps it).
    let honest_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let honest_key = SigningKey::generate(&mut OsRng);
    let honest_info = earned_info(&honest_key, honest_sock.local_addr().unwrap(), None);
    spawn_raw_node(honest_sock, honest_key, honest_info.clone(), |msg, me| match msg {
        DhtMessage::FindNode { request_id, .. } => Some(DhtMessage::FindNodeResponse { request_id, sender: me.clone(), nodes: vec![] }),
        _ => None,
    });
    struct Honest(NodeInfo);
    impl Honest {
        fn our_info(&self) -> &NodeInfo {
            &self.0
        }
    }
    let honest = Honest(honest_info);

    // A liar names the honest node at its real address, but with the liar's
    // own relay address, and is the client's only source.
    let liar_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let liar_key = SigningKey::generate(&mut OsRng);
    let liar = earned_info(&liar_key, liar_sock.local_addr().unwrap(), None);
    let doctored = NodeInfo { relay_addr: Some(liar.dht_addr), ..honest.our_info().clone() };
    spawn_raw_node(liar_sock, liar_key, liar.clone(), move |msg, me| match msg {
        DhtMessage::FindNode { request_id, .. } => Some(DhtMessage::FindNodeResponse { request_id, sender: me.clone(), nodes: vec![doctored.clone()] }),
        _ => None,
    });
    let client = spawn_dht_node(0, None).await;
    client.ping(liar.dht_addr).await.unwrap();
    client.find_node(&NodeId::random()).await.unwrap();

    // The client asked the honest node itself, and seated it as it described
    // itself: no relay address, the one it answered from.
    let table = client.routing_table().lock().await;
    assert_eq!(table.address_of(&honest.our_info().id), Some(honest.our_info().dht_addr));
    let seated = table.find_closest(&honest.our_info().id, 1);
    assert_eq!(seated[0].id, honest.our_info().id);
    assert_eq!(seated[0].relay_addr, None, "the liar's relay address was not believed");
    drop(table);
    let relays = client.find_relays(5).await.unwrap();
    assert!(relays.iter().all(|r| r.relay_addr != Some(liar.dht_addr)));
}

#[tokio::test]
async fn a_pushed_copy_does_not_short_cut_a_lookup() {
    // The network holds revision 2 of a service.
    let hub = spawn_dht_node(0, None).await;
    let hub_addr = hub.our_info().dht_addr;
    let other = spawn_dht_node(0, None).await;
    bootstrap(&other, &[hub_addr]).await.unwrap();
    let service_key = SigningKey::generate(&mut OsRng);
    let now = hidra_node::p2p::dht::store::now_secs();
    let rev1 = ServiceDescriptor::sign(&service_key, vec!["198.51.100.1:9001".parse().unwrap()], now - 60);
    let rev2 = ServiceDescriptor::sign(&service_key, vec!["198.51.100.2:9001".parse().unwrap()], now - 30);
    let publisher = spawn_dht_node(0, None).await;
    bootstrap(&publisher, &[hub_addr]).await.unwrap();
    publisher.announce_service(rev2.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A newcomer, to whom someone pushes the genuine but older revision 1.
    let client = spawn_dht_node(0, None).await;
    bootstrap(&client, &[hub_addr]).await.unwrap();
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let key = SigningKey::generate(&mut OsRng);
    let me = earned_info(&key, sock.local_addr().unwrap(), None);
    let push = DhtMessage::AnnounceService { request_id: 1, sender: me, service_hash: rev1.service_hash(), descriptor: rev1 };
    sock.send_to(&sign_and_serialize(&push, &key).unwrap(), client.our_info().dht_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(client.stored_service_count().await, 1, "it holds the pushed copy");

    // Its lookup still asks the network, and gets revision 2.
    let (intro, _) = client.lookup_service(&rev2.service_hash()).await.unwrap().expect("found");
    assert_eq!(intro, rev2.intro_points);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cluster_seated_next_to_the_storers_cannot_make_them_drop_a_service() {
    // More honest nodes than a bucket holds.
    let hub = spawn_dht_node(0, None).await;
    let hub_addr = hub.our_info().dht_addr;
    let mut honest = vec![];
    for _ in 0..21 {
        let n = spawn_dht_node(0, None).await;
        bootstrap(&n, &[hub_addr]).await.unwrap();
        honest.push(n);
    }
    let publisher = spawn_dht_node(0, None).await;
    bootstrap(&publisher, &[hub_addr]).await.unwrap();
    let service_key = SigningKey::generate(&mut OsRng);
    let service_hash = hidra_node::p2p::dht::descriptor::service_hash_of(&service_key.verifying_key().to_bytes());
    let target = hidra_node::p2p::dht::descriptor::service_target(&service_hash);

    // Twenty-four Sybils ground closer to the service than every honest
    // node, which introduce themselves to every honest node (and answer the
    // ping-back, so they are seated) before the service publishes.
    let honest_best = std::iter::once(hub.our_info())
        .chain(honest.iter().map(|n| n.our_info()))
        .chain(std::iter::once(publisher.our_info()))
        .map(|i| i.id.xor_distance(&target))
        .min()
        .unwrap();
    let mut sybils: Vec<(Arc<UdpSocket>, SigningKey, NodeInfo)> = Vec::new();
    while sybils.len() < 24 {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let key = loop {
            let k = SigningKey::generate(&mut OsRng);
            if earned_info(&k, sock.local_addr().unwrap(), None).id.xor_distance(&target) < honest_best {
                break k;
            }
        };
        let info = earned_info(&key, sock.local_addr().unwrap(), None);
        sybils.push((sock, key, info));
    }
    let cluster: Vec<NodeInfo> = sybils.iter().map(|(_, _, i)| i.clone()).collect();
    for (sock, key, me) in &sybils {
        let cluster = cluster.clone();
        spawn_raw_node(sock.clone(), key.clone(), me.clone(), move |msg, me| match msg {
            DhtMessage::FindNode { request_id, .. } => Some(DhtMessage::FindNodeResponse { request_id, sender: me.clone(), nodes: cluster.clone() }),
            DhtMessage::LookupService { request_id, .. } => Some(DhtMessage::LookupServiceResponse { request_id, sender: me.clone(), descriptor: None }),
            _ => None,
        });
        for n in std::iter::once(&hub).chain(honest.iter()) {
            let ping = DhtMessage::Ping { request_id: rand::random(), sender: me.clone() };
            sock.send_to(&sign_and_serialize(&ping, key).unwrap(), n.our_info().dht_addr).await.unwrap();
        }
    }
    // Every honest node checks every Sybil with a ping-back; in a debug
    // build, next to the other tests, that is seconds of signatures. Wait
    // until the seats have stopped changing for three polls, and never count
    // "nothing yet" as settled.
    let mut seated = 0;
    let mut last = usize::MAX;
    let mut unchanged = 0;
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        seated = 0;
        for n in std::iter::once(&hub).chain(honest.iter()) {
            let t = n.routing_table().lock().await;
            seated += cluster.iter().filter(|s| t.contains(&s.id)).count();
        }
        unchanged = if seated == last { unchanged + 1 } else { 0 };
        last = seated;
        if seated == 22 * cluster.len() || (seated > 0 && unchanged >= 3) {
            break;
        }
    }
    assert!(seated >= 22 * 5, "the cluster is seated next to the storers ({seated} seats)");

    // The service publishes now. The honest nodes it reaches keep it:
    // a cluster from one network does not make them think they are far.
    publisher.announce_signed_service(&service_key, vec!["198.51.100.42:9001".parse().unwrap()]).await.unwrap();
    let mut holders = 0;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        holders = 0;
        for n in std::iter::once(&hub).chain(honest.iter()) {
            holders += n.stored_service_count().await;
        }
        if holders >= 15 {
            break;
        }
    }
    // Most of them keep it (all 22 when this was written; counting closer
    // nodes one by one, as before, left between none and five).
    assert!(holders >= 15, "honest nodes keep the descriptor ({holders} of 22)");

    // And a client that meets one honest node finds it.
    let client = spawn_dht_node(0, None).await;
    client.ping(honest[5].our_info().dht_addr).await.unwrap();
    let (intro, _) = client.lookup_service(&service_hash).await.unwrap().expect("found");
    assert_eq!(intro, vec!["198.51.100.42:9001".parse::<SocketAddr>().unwrap()]);
}

#[tokio::test]
async fn replaying_a_nodes_packets_from_elsewhere_does_not_hold_up_its_check() {
    let node = spawn_dht_node(0, None).await;
    let node_addr = node.our_info().dht_addr;
    // An honest node that answers PINGs at its own address.
    let h_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let h_key = SigningKey::generate(&mut OsRng);
    let h = earned_info(&h_key, h_sock.local_addr().unwrap(), None);
    spawn_raw_node(h_sock.clone(), h_key.clone(), h.clone(), |_, _| None);
    let ping = sign_and_serialize(&DhtMessage::Ping { request_id: 5, sender: h.clone() }, &h_key).unwrap();

    // An attacker replays H's packet from an address that never answers,
    // first, so a check for H's ID is already in flight there.
    let attacker = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    attacker.send_to(&ping, node_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    // H writes from its own address while that check is still waiting.
    h_sock.send_to(&ping, node_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(
        node.routing_table().lock().await.address_of(&h.id),
        Some(h.dht_addr),
        "H was checked and seated at its own address without waiting for the attacker's check to time out"
    );
}
