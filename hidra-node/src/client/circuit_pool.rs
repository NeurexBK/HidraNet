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
    if all.len() < 3 {
        return Err(HidraError::Circuit(format!(
            "need at least 3 relays, have {}",
            all.len()
        )));
    }
    let mut selected = all.to_vec();
    selected.shuffle(&mut rand::thread_rng());
    selected.truncate(3);
    Ok(selected)
}
