use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::client::circuit_pool::CircuitPool;
use crate::error::Result;
use crate::p2p::dht::descriptor::VerifiedRelay;
use crate::proxy::stream_handler;
use crate::safelog::sensitive;

const RELAY_CACHE_TTL: Duration = Duration::from_secs(120);
const POOL_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(30);
const MIN_RELAYS: usize = 3;

pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    /// Relays whose keys the operator pinned in the configuration: where
    /// the proxy starts from.
    pub static_relays: Vec<VerifiedRelay>,
    /// Where the entry guards are kept between runs.
    pub guard_file: std::path::PathBuf,
}

/// The SOCKS5 proxy.
///
/// It runs no DHT node and sends no DHT query. A DHT lookup goes to nodes
/// the client does not choose, from the client's own address, and a lookup
/// for a .hidra name says which site that address is about to visit. So the
/// relay list and service descriptors are asked for through circuits, and
/// the last hop of each asks its own DHT node (see `CircuitPool`).
pub async fn run_proxy(config: ProxyConfig) -> Result<()> {
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(addr = %config.listen_addr, "HidraNet proxy listening on {}", config.listen_addr);

    info!(
        relay_count = config.static_relays.len(),
        "initial relay set loaded"
    );
    if config.static_relays.is_empty() {
        warn!("no relays are pinned in the configuration; the proxy cannot build a circuit");
    }
    let pool = CircuitPool::with_guard_file(config.static_relays, config.guard_file);
    // The first refresh may go through a one-hop circuit, if fewer than
    // three relays are pinned; the second then has enough for full ones.
    pool.refresh_relays().await;
    if pool.relays().await.len() < MIN_RELAYS * 2 {
        pool.refresh_relays().await;
    }
    pool.maintain().await;
    info!(pool_size = pool.pool_size().await, "circuit pool initialized");

    let pool_bg = Arc::clone(&pool);
    tokio::spawn(async move {
        let mut relay_refresh = Instant::now();
        loop {
            tokio::time::sleep(POOL_MAINTENANCE_INTERVAL).await;
            if relay_refresh.elapsed() > RELAY_CACHE_TTL {
                pool_bg.refresh_relays().await;
                relay_refresh = Instant::now();
            }
            pool_bg.maintain().await;
        }
    });

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        info!(client_ip = %sensitive(&remote_addr), "accepted SOCKS5 connection");
        let pool = Arc::clone(&pool);
        tokio::spawn(async move {
            stream_handler::handle_socks5_connection(stream, pool, remote_addr).await;
        });
    }
}
