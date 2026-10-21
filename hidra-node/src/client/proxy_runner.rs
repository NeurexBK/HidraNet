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
use crate::relay::registry::RelayEntry;
use crate::safelog::sensitive;

const RELAY_CACHE_TTL: Duration = Duration::from_secs(120);
const POOL_MAINTENANCE_INTERVAL: Duration =
    Duration::from_secs(30);
const MIN_RELAYS: usize = 3;

pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub dht_addr: SocketAddr,
    pub bootstrap_addrs: Vec<SocketAddr>,
    pub secret_bytes: [u8; 32],
    pub static_relays: Vec<RelayEntry>,
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
    let pool = CircuitPool::new(
        config.secret_bytes,
        initial_relays,
    );
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
                // Only replace the pool's relays when the new set still has
                // enough usable (keyed) relays, so a working set is never
                // overwritten by one that cannot build a circuit.
                if keyed_count(&relays) >= MIN_RELAYS {
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

fn keyed_count(relays: &[RelayEntry]) -> usize {
    relays
        .iter()
        .filter(|r| !r.noise_pubkey_b64.trim().is_empty())
        .count()
}

async fn discover_relays(
    dht: &DhtNode,
    static_relays: &[RelayEntry],
) -> Vec<RelayEntry> {
    // The configured relays carry their identity keys, so they are the ones a
    // circuit can actually use (each hop is pinned to its key); keep them
    // always. DHT discovery adds reach, but a discovered relay has no key on
    // record yet and so cannot be a hop until a directory distributes relay
    // keys. So the keyed static relays are never dropped for unkeyed ones.
    let mut all = static_relays.to_vec();
    match dht.find_relays(MIN_RELAYS).await {
        Ok(nodes) => {
            for n in nodes {
                let addr = n.relay_addr.unwrap_or(n.dht_addr);
                if !all.iter().any(|r| r.addr == addr) {
                    all.push(RelayEntry {
                        name: format!("{}", n.id),
                        addr,
                        noise_pubkey_b64: String::new(),
                    });
                }
            }
            info!(
                total = all.len(),
                keyed = keyed_count(&all),
                "relay set (configured keyed relays plus DHT reach)"
            );
            all
        }
        Err(e) => {
            warn!(error = %e, "DHT relay discovery failed");
            static_relays.to_vec()
        }
    }
}
