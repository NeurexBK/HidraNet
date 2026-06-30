use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::Result;
use crate::p2p::dht::DhtNode;

const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

const DNS_SEEDS: &[&str] = &[
    "seed1.hidranet.io:7000",
    "seed2.hidranet.io:7000",
    "seed3.hidranet.io:7000",
];

fn resolve_dns_seeds() -> Vec<SocketAddr> {
    let mut addrs = Vec::new();
    for seed in DNS_SEEDS {
        match seed.to_socket_addrs() {
            Ok(resolved) => {
                for addr in resolved {
                    info!(seed = %seed, addr = %addr, "DNS seed resolved");
                    addrs.push(addr);
                }
            }
            Err(e) => {
                debug!(seed = %seed, error = %e, "DNS seed resolution failed");
            }
        }
    }
    addrs
}

pub async fn bootstrap(dht: &DhtNode, bootstrap_addrs: &[SocketAddr]) -> Result<usize> {
    let addrs: Vec<SocketAddr> = if bootstrap_addrs.is_empty() {
        info!("no bootstrap nodes configured, trying DNS seeds");
        resolve_dns_seeds()
    } else {
        bootstrap_addrs.to_vec()
    };

    if addrs.is_empty() {
        info!("no bootstrap nodes available (static or DNS), skipping bootstrap");
        return Ok(0);
    }

    let bootstrap_addrs = &addrs;

    info!(
        bootstrap_count = bootstrap_addrs.len(),
        "starting DHT bootstrap"
    );

    let mut contacted = 0usize;

    for addr in bootstrap_addrs {
        if *addr == dht.our_info().dht_addr {
            continue;
        }

        debug!(addr = %addr, "pinging bootstrap node");

        match tokio::time::timeout(BOOTSTRAP_TIMEOUT, dht.ping(*addr)).await {
            Ok(Ok(peer_info)) => {
                info!(
                    node_id = %peer_info.id,
                    addr = %addr,
                    is_relay = peer_info.is_relay(),
                    "bootstrap node responded"
                );
                contacted += 1;
            }
            Ok(Err(e)) => {
                warn!(addr = %addr, error = %e, "bootstrap node unreachable");
            }
            Err(_) => {
                warn!(addr = %addr, "bootstrap node timed out");
            }
        }
    }

    if contacted > 0 {
        info!(contacted, "bootstrap pings done, performing self-lookup");
        let our_id = dht.our_info().id;
        match dht.find_node(&our_id).await {
            Ok(nodes) => {
                info!(
                    discovered = nodes.len(),
                    "self-lookup completed"
                );
            }
            Err(e) => {
                warn!(error = %e, "self-lookup failed");
            }
        }
    }

    let total = dht.node_count().await;
    info!(
        bootstrap_contacted = contacted,
        total_peers = total,
        "bootstrap completed"
    );

    Ok(total)
}
