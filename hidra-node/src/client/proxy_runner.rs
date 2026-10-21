use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::client::circuit_pool::CircuitPool;
use crate::error::Result;
use crate::p2p::bootstrap::bootstrap;
use crate::p2p::dht::DhtNode;
use crate::proxy::stream_handler;
use crate::p2p::dht::descriptor::VerifiedRelay;
use crate::safelog::sensitive;

const RELAY_CACHE_TTL: Duration = Duration::from_secs(120);
const POOL_MAINTENANCE_INTERVAL: Duration =
    Duration::from_secs(30);
const MIN_RELAYS: usize = 3;

pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub dht_addr: SocketAddr,
    pub bootstrap_addrs: Vec<SocketAddr>,
    /// Relays whose keys the operator pinned in the configuration.
    pub static_relays: Vec<VerifiedRelay>,
}

pub async fn run_proxy(config: ProxyConfig) -> Result<()> {
    let listener =
        TcpListener::bind(config.listen_addr).await?;
    info!(addr = %config.listen_addr, "HidraNet proxy listening on {}", config.listen_addr);

    let signing_key = ed25519_dalek::SigningKey::generate(
        &mut rand_core::OsRng,
    );
    let mut dht = DhtNode::new(
        config.dht_addr,
        signing_key,
        None,
    )
    .await?;
    dht.start().await;

    if !config.bootstrap_addrs.is_empty() {
        if let Err(e) =
            bootstrap(&dht, &config.bootstrap_addrs).await
        {
            warn!(error = %e, "DHT bootstrap failed, will use static relays");
        }
    }
    let dht = Arc::new(dht);
    let initial_relays = discover_relays(
        &dht,
        &config.static_relays,
    )
    .await;
    info!(relay_count = initial_relays.len(), "initial relay set loaded");
    let pool = CircuitPool::new(initial_relays);
    pool.maintain().await;
    info!(pool_size = pool.pool_size().await, "circuit pool initialized");

    let pool_bg = Arc::clone(&pool);
    let dht_bg = Arc::clone(&dht);
    let static_relays = config.static_relays.clone();
    tokio::spawn(async move {
        let mut relay_refresh = Instant::now();
        loop {
            tokio::time::sleep(POOL_MAINTENANCE_INTERVAL).await;
            if relay_refresh.elapsed() > RELAY_CACHE_TTL {
                let relays = discover_relays(
                    &dht_bg,
                    &static_relays,
                )
                .await;
                if relays.len() >= MIN_RELAYS {
                    pool_bg.update_relays(relays).await;
                    relay_refresh = Instant::now();
                }
            }
            pool_bg.maintain().await;
        }
    });

    loop {
        let (stream, remote_addr) =
            listener.accept().await?;
        info!(client_ip = %sensitive(&remote_addr), "accepted SOCKS5 connection");
        let pool = Arc::clone(&pool);
        let dht_ref = Arc::clone(&dht);
        tokio::spawn(async move {
            stream_handler::handle_socks5_connection(
                stream,
                pool,
                dht_ref,
                remote_addr,
            )
            .await;
        });
    }
}

/// Relays a circuit may use: the operator's pinned ones and every relay the
/// DHT knows of whose descriptor verifies. A relay the DHT names without a
/// descriptor signed by its own identity is left out — there is no key to hold
/// it to, so it cannot be a hop.
async fn discover_relays(
    dht: &DhtNode,
    static_relays: &[VerifiedRelay],
) -> Vec<VerifiedRelay> {
    let mut all = static_relays.to_vec();
    match dht.find_relays(MIN_RELAYS * 4).await {
        Ok(nodes) => {
            let found = nodes.len();
            let mut unsigned = 0usize;
            for n in nodes {
                match n.verified_relay() {
                    Some(r) if !all.iter().any(|a| a.addr() == r.addr()) => all.push(r),
                    Some(_) => {}
                    None => unsigned += 1,
                }
            }
            info!(dht_found = found, unsigned, usable = all.len(), "relay set refreshed");
        }
        Err(e) => warn!(error = %e, "DHT relay discovery failed"),
    }
    if all.len() < MIN_RELAYS {
        warn!(
            usable = all.len(),
            "fewer verified relays than a circuit needs; circuits will fail until more are found"
        );
    }
    all
}
