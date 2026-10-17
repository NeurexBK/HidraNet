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

    /// A fresh circuit whose last hop is `exit`: the introduction relay a
    /// hidden service registered at. A service is registered at one relay
    /// only, so a circuit that ends anywhere else finds "service not found";
    /// picking the exit at random reached it by luck. Never taken from the
    /// pool, whose circuits end wherever they happened to.
    pub async fn build_circuit_ending_at(
        &self,
        exit: std::net::SocketAddr,
    ) -> Result<StreamingCircuit> {
        let relays = self.relays.lock().await.clone();
        let selected = select_relays_ending_at(&relays, exit)?;

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

/// Two relays at random, then `exit`. The exit is used even when it is not in
/// the known list: it came from the service's own signed descriptor.
fn select_relays_ending_at(
    all: &[RelayEntry],
    exit: std::net::SocketAddr,
) -> Result<Vec<RelayEntry>> {
    let mut others: Vec<RelayEntry> =
        all.iter().filter(|r| r.addr != exit).cloned().collect();
    if others.len() < 2 {
        return Err(HidraError::Circuit(format!(
            "need at least 2 relays besides the introduction point, have {}",
            others.len()
        )));
    }
    others.shuffle(&mut rand::thread_rng());
    others.truncate(2);
    let exit_entry = all
        .iter()
        .find(|r| r.addr == exit)
        .cloned()
        .unwrap_or_else(|| RelayEntry {
            name: "introduction-point".into(),
            addr: exit,
            noise_pubkey_b64: String::new(),
        });
    others.push(exit_entry);
    Ok(others)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(port: u16) -> RelayEntry {
        RelayEntry {
            name: format!("r{port}"),
            addr: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            noise_pubkey_b64: String::new(),
        }
    }

    #[test]
    fn a_service_circuit_ends_at_the_introduction_point() {
        let all: Vec<RelayEntry> = (1..=5).map(entry).collect();
        let exit = entry(3).addr;
        for _ in 0..50 {
            let path = select_relays_ending_at(&all, exit).unwrap();
            assert_eq!(path.len(), 3);
            assert_eq!(path[2].addr, exit);
            assert!(path[0].addr != exit && path[1].addr != exit);
            assert_ne!(path[0].addr, path[1].addr);
        }
    }

    #[test]
    fn an_unknown_introduction_point_is_still_the_exit() {
        let all: Vec<RelayEntry> = (1..=3).map(entry).collect();
        let exit = entry(9).addr;
        let path = select_relays_ending_at(&all, exit).unwrap();
        assert_eq!(path[2].addr, exit);
    }

    #[test]
    fn too_few_relays_is_an_error() {
        let all = vec![entry(1), entry(2)];
        assert!(select_relays_ending_at(&all, entry(2).addr).is_err());
    }
}
