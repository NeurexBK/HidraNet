use std::time::Duration;

use tracing::{debug, info, warn};

use crate::p2p::dht::node::NodeId;
use crate::p2p::dht::DhtNode;

const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(300);
const STALE_TIMEOUT: Duration = Duration::from_secs(600);
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

pub async fn run_maintenance_loop(dht: &DhtNode) {
    let mut maintenance_tick = tokio::time::interval(MAINTENANCE_INTERVAL);
    let mut announce_tick = tokio::time::interval(ANNOUNCE_INTERVAL);

    loop {
        tokio::select! {
            _ = maintenance_tick.tick() => {
                run_maintenance(dht).await;
            }
            _ = announce_tick.tick() => {
                if dht.our_info().is_relay() {
                    if let Err(e) = dht.announce_relay().await {
                        warn!(error = %e, "relay announcement failed");
                    }
                }
            }
        }
    }
}

async fn run_maintenance(dht: &DhtNode) {
    let stale_nodes = {
        let table = dht.routing_table().lock().await;
        table.stale_nodes(STALE_TIMEOUT)
    };

    if !stale_nodes.is_empty() {
        debug!(
            stale_count = stale_nodes.len(),
            "pinging stale nodes"
        );
    }

    for node_id in &stale_nodes {
        let node_info = {
            let table = dht.routing_table().lock().await;
            table.find_closest(node_id, 1).into_iter().find(|n| n.id == *node_id)
        };

        if let Some(info) = node_info {
            match dht.ping(info.dht_addr).await {
                Ok(_) => {
                    debug!(node_id = %node_id, "stale node responded to ping");
                }
                Err(_) => {
                    debug!(node_id = %node_id, "stale node removed (ping failed)");
                    let mut table = dht.routing_table().lock().await;
                    table.remove(node_id);
                }
            }
        }
    }

    let random_target = NodeId::random();
    match dht.find_node(&random_target).await {
        Ok(nodes) => {
            debug!(
                found = nodes.len(),
                total_peers = dht.node_count().await,
                "bucket refresh completed"
            );
        }
        Err(e) => {
            debug!(error = %e, "bucket refresh lookup failed");
        }
    }

    let total = dht.node_count().await;
    info!(
        peer_count = total,
        "DHT maintenance cycle completed"
    );
}
