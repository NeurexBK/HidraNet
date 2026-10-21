use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::client::streaming::StreamingCircuit;
use crate::error::{HidraError, Result};
use crate::relay::registry::RelayEntry;

const CIRCUIT_TTL: Duration = Duration::from_secs(300);
const POOL_TARGET_SIZE: usize = 3;
const MAX_POOL_SIZE: usize = 10;

struct PoolEntry {
    circuit: StreamingCircuit,
    created_at: Instant,
}

pub struct CircuitPool {
    entries: Mutex<Vec<PoolEntry>>,
    relays: Mutex<Vec<RelayEntry>>,
    secret_bytes: [u8; 32],
}

impl CircuitPool {
    pub fn new(secret_bytes: [u8; 32], relays: Vec<RelayEntry>) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(Vec::new()),
            relays: Mutex::new(relays),
            secret_bytes,
        })
    }

    pub async fn update_relays(&self, relays: Vec<RelayEntry>) {
        let mut r = self.relays.lock().await;
        info!(
            old_count = r.len(),
            new_count = relays.len(),
            "relay list updated"
        );
        *r = relays;
    }

    pub async fn get_circuit(&self) -> Result<StreamingCircuit> {
        {
            let mut entries = self.entries.lock().await;
            while let Some(entry) = entries.pop() {
                if entry.created_at.elapsed() < CIRCUIT_TTL {
                    debug!(
                        pool_remaining = entries.len(),
                        circuit_id = entry.circuit.circuit_id(),
                        "circuit taken from pool"
                    );
                    return Ok(entry.circuit);
                }
                debug!("discarded stale pooled circuit");
            }
        }

        debug!("pool empty, building circuit on-demand");
        self.build_new_circuit().await
    }

    pub async fn build_new_circuit(&self) -> Result<StreamingCircuit> {
        let relays = self.relays.lock().await.clone();
        let selected = select_relays(&relays)?;

        let mut sb = self.secret_bytes;
        let secret = StaticSecret::from(sb);
        sb.zeroize();

        StreamingCircuit::build(&selected, secret).await
    }

    /// A fresh circuit whose last relay is `exit`: a hidden service's
    /// introduction point, which only knows the services registered with it.
    /// The other two hops are picked as usual from the rest.
    pub async fn build_circuit_via(&self, exit: std::net::SocketAddr) -> Result<StreamingCircuit> {
        let relays = self.relays.lock().await.clone();
        // The introduction point is a hop like any other: it must be a relay
        // whose identity key the client knows, or it cannot be authenticated.
        let last = relays
            .iter()
            .find(|r| r.addr == exit && !r.noise_pubkey_b64.trim().is_empty())
            .cloned()
            .ok_or_else(|| {
                HidraError::Circuit(
                    "the introduction point is not a relay with a known identity key".into(),
                )
            })?;
        let mut others: Vec<RelayEntry> = relays
            .into_iter()
            .filter(|r| r.addr != exit && !r.noise_pubkey_b64.trim().is_empty())
            .collect();
        if others.len() < 2 {
            return Err(HidraError::Circuit(format!(
                "need two relays with a known identity key besides the introduction point, have {}",
                others.len()
            )));
        }
        others.shuffle(&mut rand::thread_rng());
        others.truncate(2);
        let mut path = others;
        path.push(last);

        let mut sb = self.secret_bytes;
        let secret = StaticSecret::from(sb);
        sb.zeroize();
        StreamingCircuit::build(&path, secret).await
    }

    pub async fn maintain(&self) {
        {
            let mut entries = self.entries.lock().await;
            let before = entries.len();
            entries.retain(|e| e.created_at.elapsed() < CIRCUIT_TTL);
            let removed = before - entries.len();
            if removed > 0 {
                debug!(removed, remaining = entries.len(), "pruned stale circuits");
            }
        }

        let current = self.entries.lock().await.len();
        if current < POOL_TARGET_SIZE {
            let to_build = POOL_TARGET_SIZE - current;
            for _ in 0..to_build {
                match self.build_new_circuit().await {
                    Ok(circuit) => {
                        let mut entries = self.entries.lock().await;
                        if entries.len() < MAX_POOL_SIZE {
                            info!(
                                circuit_id = circuit.circuit_id(),
                                pool_size = entries.len() + 1,
                                "pre-built circuit added to pool"
                            );
                            entries.push(PoolEntry {
                                circuit,
                                created_at: Instant::now(),
                            });
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "circuit pre-build failed");
                        break;
                    }
                }
            }
        }
    }

    pub async fn pool_size(&self) -> usize {
        self.entries.lock().await.len()
    }
}

fn select_relays(all: &[RelayEntry]) -> Result<Vec<RelayEntry>> {
    // Only a relay whose identity key the client knows can be authenticated in
    // the handshake, so only such relays can be circuit hops; one discovered by
    // address alone (no key on record) is never used, or it could be
    // impersonated by the relay carrying its handshake.
    let mut selected: Vec<RelayEntry> = all
        .iter()
        .filter(|r| !r.noise_pubkey_b64.trim().is_empty())
        .cloned()
        .collect();
    if selected.len() < 3 {
        return Err(HidraError::Circuit(format!(
            "need at least 3 relays with a known identity key, have {}",
            selected.len()
        )));
    }
    selected.shuffle(&mut rand::thread_rng());
    selected.truncate(3);
    Ok(selected)
}
