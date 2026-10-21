use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::client::streaming::{StreamingCircuit, CIRCUIT_HOPS};
use crate::error::{HidraError, Result};
use crate::p2p::dht::descriptor::VerifiedRelay;

const CIRCUIT_TTL: Duration = Duration::from_secs(300);
const POOL_TARGET_SIZE: usize = 3;
const MAX_POOL_SIZE: usize = 10;

struct PoolEntry {
    circuit: StreamingCircuit,
    created_at: Instant,
}

/// Circuits built ahead of time, through relays whose keys were verified.
///
/// The pool holds no key of the client's: every circuit's handshakes start
/// from fresh ephemeral keys, so circuits taken from the pool share nothing a
/// relay could link.
pub struct CircuitPool {
    entries: Mutex<Vec<PoolEntry>>,
    relays: Mutex<Vec<VerifiedRelay>>,
}

impl CircuitPool {
    pub fn new(relays: Vec<VerifiedRelay>) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(Vec::new()),
            relays: Mutex::new(relays),
        })
    }

    pub async fn update_relays(&self, relays: Vec<VerifiedRelay>) {
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
        StreamingCircuit::build(&selected).await
    }

    /// A fresh circuit whose last hop is the first of `exits` that is a
    /// verified relay: how a client reaches a hidden service's introduction
    /// point. The other two hops are picked at random. A pooled circuit will
    /// not do, since its exit is wherever it happened to end.
    pub async fn build_circuit_to(&self, exits: &[SocketAddr]) -> Result<StreamingCircuit> {
        let relays = self.relays.lock().await.clone();
        let exit = exits
            .iter()
            .find_map(|a| relays.iter().find(|r| r.addr() == *a))
            .cloned()
            .ok_or_else(|| {
                HidraError::Circuit(
                    "no introduction point of this service is a relay with a verified key".into(),
                )
            })?;
        let others: Vec<VerifiedRelay> = relays
            .into_iter()
            .filter(|r| r.addr() != exit.addr() && r.transport_key() != exit.transport_key())
            .collect();
        let mut path = select_relays_n(&others, CIRCUIT_HOPS - 1)?;
        path.push(exit);
        StreamingCircuit::build(&path).await
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

fn select_relays(all: &[VerifiedRelay]) -> Result<Vec<VerifiedRelay>> {
    select_relays_n(all, CIRCUIT_HOPS)
}

fn select_relays_n(all: &[VerifiedRelay], n: usize) -> Result<Vec<VerifiedRelay>> {
    let mut distinct: Vec<VerifiedRelay> = Vec::with_capacity(all.len());
    for r in all {
        if !distinct
            .iter()
            .any(|d| d.addr() == r.addr() || d.transport_key() == r.transport_key())
        {
            distinct.push(r.clone());
        }
    }
    if distinct.len() < n {
        return Err(HidraError::Circuit(format!(
            "need at least {n} verified relays, have {}",
            distinct.len()
        )));
    }
    distinct.shuffle(&mut rand::thread_rng());
    distinct.truncate(n);
    Ok(distinct)
}
