use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::seq::SliceRandom;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::client::guards::GuardSet;
use crate::client::path::{choose_path, may_share_circuit};
use crate::client::streaming::{StreamingCircuit, CIRCUIT_HOPS};
use crate::error::{HidraError, Result};
use crate::p2p::dht::descriptor::{ServiceDescriptor, VerifiedRelay};
use crate::p2p::dht::node::NodeInfo;

const CIRCUIT_TTL: Duration = Duration::from_secs(300);
/// Relays asked for per directory request, and the most the pool keeps.
const DIRECTORY_ASK: u16 = 32;
const MAX_KNOWN_RELAYS: usize = 256;
/// Directory requests per refresh, lookup or announcement, each through its
/// own circuit and, when enough relays are known, its own exit:
/// one hop that withholds a relay or a descriptor does not decide alone.
const DIRECTORY_CIRCUITS: usize = 2;
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
    /// The ID puzzle difficulty a relay's DHT record must have paid for to
    /// be accepted from a directory answer.
    id_bits: u32,
    /// The relays every circuit starts at. See `guards`.
    guards: Mutex<GuardSet>,
}

impl CircuitPool {
    /// A pool whose entry guards last as long as it does. A client that
    /// runs more than once should keep them: `with_guard_file`.
    // The binary keeps its guards on disk (`with_guard_file`); the tests do not.
    #[allow(dead_code)]
    pub fn new(relays: Vec<VerifiedRelay>) -> Arc<Self> {
        Self::build(relays, crate::p2p::dht::node::ID_PUZZLE_BITS, GuardSet::in_memory())
    }

    /// For a network with another ID difficulty: tests, private networks.
    // The binary keeps its guards on disk (`with_guard_file`); the tests do not.
    #[allow(dead_code)]
    pub fn with_id_bits(relays: Vec<VerifiedRelay>, id_bits: u32) -> Arc<Self> {
        Self::build(relays, id_bits, GuardSet::in_memory())
    }

    /// Entry guards kept in `file` between runs, so a restart does not mean
    /// a new first hop.
    pub fn with_guard_file(relays: Vec<VerifiedRelay>, file: std::path::PathBuf) -> Arc<Self> {
        Self::build(relays, crate::p2p::dht::node::ID_PUZZLE_BITS, GuardSet::load(file))
    }

    fn build(relays: Vec<VerifiedRelay>, id_bits: u32, guards: GuardSet) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(Vec::new()),
            relays: Mutex::new(relays),
            id_bits,
            guards: Mutex::new(guards),
        })
    }

    /// The relays known, and the entry guards among them (chosen now if
    /// there are none yet).
    async fn relays_and_guards(&self) -> (Vec<VerifiedRelay>, Vec<VerifiedRelay>) {
        let relays = self.relays().await;
        let mut guards = self.guards.lock().await;
        guards.update(&relays, now_secs());
        (relays, guards.guards())
    }

    /// A circuit from the first entry guard that can build one, through a
    /// random middle, to `exit` or to a random exit (one not in
    /// `avoid_exits` while there is one). A guard that fails is not
    /// replaced; the next guard is tried. Returns the circuit and its exit.
    async fn build_from_guard(
        &self,
        exit: Option<&VerifiedRelay>,
        avoid_exits: &[SocketAddr],
    ) -> Result<(StreamingCircuit, SocketAddr)> {
        let (relays, guards) = self.relays_and_guards().await;
        let mut last = HidraError::Circuit("no entry guard".into());
        for guard in &guards {
            // The known record, which may carry the guard's family.
            let guard = relays.iter().find(|r| *r == guard).unwrap_or(guard);
            let exit = match exit {
                Some(e) => Some(e.clone()),
                None => {
                    let fresh: Vec<&VerifiedRelay> = relays
                        .iter()
                        .filter(|r| may_share_circuit(guard, r) && !avoid_exits.contains(&r.addr()))
                        .collect();
                    fresh.choose(&mut rand::thread_rng()).map(|r| (*r).clone())
                }
            };
            let path = match choose_path(&relays, guard, exit.as_ref()) {
                Ok(p) => p,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let exit_addr = path[CIRCUIT_HOPS - 1].addr();
            match StreamingCircuit::build(&path).await {
                Ok(c) => return Ok((c, exit_addr)),
                Err(e) => {
                    warn!(error = %e, "circuit through this entry guard failed; trying the next");
                    last = e;
                }
            }
        }
        Err(last)
    }

    pub async fn relays(&self) -> Vec<VerifiedRelay> {
        self.relays.lock().await.clone()
    }

    /// Learns relays from the DHT without querying it: each request goes
    /// through a circuit and the last hop asks its own DHT node. With three
    /// or more relays known that is a full circuit; with fewer, a one-hop
    /// circuit to the entry guard, which already sees this address. Every
    /// record that comes back is checked here (its ID puzzle and its signed
    /// descriptor); a hop can leave relays out, but not add one nobody
    /// signed. Returns how many relays are now usable.
    pub async fn refresh_relays(&self) -> usize {
        let known = self.relays().await;
        let mut found = Vec::new();
        let mut exits = Vec::new();
        for _ in 0..DIRECTORY_CIRCUITS {
            let circuit = if known.len() >= CIRCUIT_HOPS {
                self.build_directory_circuit(&mut exits).await
            } else {
                let (_, guards) = self.relays_and_guards().await;
                let mut built = Err(HidraError::Circuit("no entry guard".into()));
                for g in &guards {
                    built = StreamingCircuit::build_directory(g).await;
                    if built.is_ok() {
                        break;
                    }
                }
                built
            };
            let mut circuit = match circuit {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "no circuit for a directory request");
                    continue;
                }
            };
            match circuit.directory_relays(DIRECTORY_ASK).await {
                Ok(nodes) => found.extend(accept_directory_nodes(&nodes, self.id_bits)),
                Err(e) => warn!(error = %e, "directory request failed"),
            }
            circuit.destroy().await;
        }
        let mut relays = self.relays.lock().await;
        let mut added = 0usize;
        for r in found {
            // A pinned relay found with its descriptor: keep the descriptor's
            // record, which knows the relay's family.
            if let Some(k) = relays.iter_mut().find(|k| r.knows_more_than(k)) {
                *k = r;
                continue;
            }
            if relays.len() < MAX_KNOWN_RELAYS
                && !relays
                    .iter()
                    .any(|k| k.addr() == r.addr() || k.transport_key() == r.transport_key())
            {
                relays.push(r);
                added += 1;
            }
        }
        info!(added, usable = relays.len(), "relay set refreshed");
        relays.len()
    }

    /// A hidden service's descriptor, looked up through circuits so the DHT
    /// never sees who asked. Always a full circuit: the last hop learns which
    /// service, never by whom. Each answer must carry the service's own
    /// signature and be current; the newest of those wins.
    pub async fn lookup_service(&self, service_hash: &[u8; 20]) -> Result<Option<ServiceDescriptor>> {
        let mut best: Option<ServiceDescriptor> = None;
        let mut asked = 0usize;
        let mut exits = Vec::new();
        for _ in 0..DIRECTORY_CIRCUITS + 1 {
            if asked == DIRECTORY_CIRCUITS {
                break;
            }
            let mut circuit = match self.build_directory_circuit(&mut exits).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "no circuit for a service lookup");
                    continue;
                }
            };
            let answer = circuit.directory_service(*service_hash).await;
            circuit.destroy().await;
            let Ok(answer) = answer else { continue };
            asked += 1;
            if let Some(d) = answer.filter(|d| descriptor_is_current(d, service_hash, now_secs())) {
                if best.as_ref().is_none_or(|b| d.revision > b.revision) {
                    best = Some(d);
                }
            }
        }
        if asked == 0 {
            return Err(HidraError::Circuit("no circuit could ask for the service".into()));
        }
        Ok(best)
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

    /// A circuit from an entry guard to a random exit, and that exit's
    /// address: what a hidden service registers at and announces.
    pub async fn build_circuit_with_exit(&self) -> Result<(StreamingCircuit, SocketAddr)> {
        self.build_from_guard(None, &[]).await
    }

    /// A circuit from an entry guard to a random exit.
    pub async fn build_new_circuit(&self) -> Result<StreamingCircuit> {
        Ok(self.build_from_guard(None, &[]).await?.0)
    }

    /// A fresh circuit whose last hop is the first of `exits` that is a
    /// verified relay: how a client reaches a hidden service's introduction
    /// point. It starts at an entry guard, with a random middle. A pooled
    /// circuit will not do, since its exit is wherever it happened to end.
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
        Ok(self.build_from_guard(Some(&exit), &[]).await?.0)
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

impl CircuitPool {
    /// A full circuit for one directory request, ending at a relay not in
    /// `used_exits` while there is one; its exit is then added to the list.
    /// Asking the same question through different exits is what keeps one
    /// of them from deciding the answer alone.
    async fn build_directory_circuit(&self, used_exits: &mut Vec<SocketAddr>) -> Result<StreamingCircuit> {
        let (circuit, exit) = self.build_from_guard(None, used_exits).await?;
        used_exits.push(exit);
        Ok(circuit)
    }

    /// Publishes a service's descriptor through circuits, so no DHT node
    /// sees the host's address: the last hop of each circuit announces it.
    /// Always full circuits, each with another exit when the pool knows
    /// enough relays for that. Returns how many
    /// accepted it; an error if none could be asked.
    pub async fn announce_service(&self, descriptor: &ServiceDescriptor) -> Result<usize> {
        let mut accepted = 0usize;
        let mut asked = 0usize;
        let mut exits = Vec::new();
        for _ in 0..DIRECTORY_CIRCUITS + 1 {
            if asked == DIRECTORY_CIRCUITS {
                break;
            }
            let mut circuit = match self.build_directory_circuit(&mut exits).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "no circuit for a service announcement");
                    continue;
                }
            };
            let answer = circuit.directory_announce(descriptor.clone()).await;
            circuit.destroy().await;
            match answer {
                Ok(ok) => {
                    asked += 1;
                    accepted += usize::from(ok);
                }
                Err(e) => warn!(error = %e, "service announcement failed"),
            }
        }
        if asked == 0 {
            return Err(HidraError::Circuit("no circuit could announce the service".into()));
        }
        Ok(accepted)
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Signed by the service for this address, and neither expired nor from the
/// future: the same rule a DHT node applies before storing one.
fn descriptor_is_current(d: &ServiceDescriptor, service_hash: &[u8; 20], now: u64) -> bool {
    use crate::p2p::dht::store::{DESCRIPTOR_TTL_SECS, MAX_CLOCK_SKEW_SECS};
    d.verify(service_hash).is_ok()
        && d.revision <= now.saturating_add(MAX_CLOCK_SKEW_SECS)
        && d.revision.saturating_add(DESCRIPTOR_TTL_SECS) > now
}

/// The relays in a directory answer a circuit may use: records whose ID was
/// paid for at `id_bits` and whose relay descriptor the node itself signed.
fn accept_directory_nodes(nodes: &[NodeInfo], id_bits: u32) -> Vec<VerifiedRelay> {
    nodes
        .iter()
        .filter(|n| n.id_is_valid(id_bits))
        .filter_map(|n| n.verified_relay())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::dht::descriptor::RelayDescriptor;
    use crate::p2p::dht::node::{solve_id_puzzle, NodeId};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn relay_record(bits: u32, paid: bool) -> NodeInfo {
        let key = SigningKey::generate(&mut OsRng);
        let pk = key.verifying_key().to_bytes();
        let nonce = if paid { solve_id_puzzle(&pk, bits) } else { u64::MAX };
        let addr: SocketAddr = "198.51.100.9:9001".parse().unwrap();
        NodeInfo {
            id: NodeId::for_node(&pk, nonce),
            dht_addr: "198.51.100.9:7000".parse().unwrap(),
            relay_addr: Some(addr),
            public_key: pk,
            id_nonce: nonce,
            relay_descriptor: Some(RelayDescriptor::sign(&key, addr, [3; 32], 1)),
        }
    }

    /// A hop answering a directory request can invent records; they are
    /// dropped unless the ID was paid for and the relay signed the key.
    #[test]
    fn a_directory_answer_is_checked_record_by_record() {
        let good = relay_record(8, true);
        let unpaid = relay_record(8, false);
        let mut swapped = relay_record(8, true);
        swapped.relay_descriptor.as_mut().unwrap().transport_key = [4; 32];
        let accepted = accept_directory_nodes(&[good, unpaid, swapped], 8);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].transport_key(), &[3; 32]);
    }

    #[test]
    fn a_service_descriptor_must_be_signed_and_current() {
        let key = SigningKey::generate(&mut OsRng);
        let now = 1_000_000;
        let d = ServiceDescriptor::sign(&key, vec!["198.51.100.3:9001".parse().unwrap()], now);
        let hash = d.service_hash();
        assert!(descriptor_is_current(&d, &hash, now));
        assert!(!descriptor_is_current(&d, &[0; 20], now), "another address");
        assert!(!descriptor_is_current(&d, &hash, now + 7200), "expired");
        let future = ServiceDescriptor::sign(&key, d.intro_points.clone(), now + 7200);
        assert!(!descriptor_is_current(&future, &hash, now), "from the future");
        let mut moved = d.clone();
        moved.intro_points = vec!["203.0.113.66:9001".parse().unwrap()];
        assert!(!descriptor_is_current(&moved, &hash, now), "not as signed");
    }
}
