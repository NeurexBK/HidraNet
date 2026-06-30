use std::net::SocketAddr;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use hidra_node::p2p::bootstrap::bootstrap;
use hidra_node::p2p::dht::DhtNode;

async fn spawn_dht_node(port: u16, relay_addr: Option<SocketAddr>) -> DhtNode {
    let signing_key = SigningKey::generate(&mut OsRng);
    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut node = DhtNode::new(bind_addr, signing_key, relay_addr).await.unwrap();
    node.start().await;
    node
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
