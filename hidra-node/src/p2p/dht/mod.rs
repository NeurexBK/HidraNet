pub mod descriptor;
pub mod handler;
pub mod kbuckets;
pub mod message;
pub mod node;
pub mod store;

use crate::safelog::sensitive;

// DHT node (from dht/mod.rs)
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, Semaphore};
use tracing::{debug, info, warn};

use crate::error::{HidraError, Result};
use self::descriptor::{service_target, RelayDescriptor, ServiceDescriptor};
use self::handler::DhtHandler;
use self::kbuckets::{diversity_prefix, neighbourhood, RoutingTable, UpdateResult, K};
use self::message::{sign_and_serialize, verify_and_bind, DhtMessage};
use self::node::{NodeId, NodeInfo, ID_PUZZLE_BITS};
use self::store::{now_secs, Origin, ServiceStore};

const MAX_UDP_PACKET: usize = 65535;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const PINGBACK_TIMEOUT: Duration = Duration::from_secs(3);
const ALPHA: usize = 3;

/// Lookups walk this many paths that share no node (S/Kademlia). One
/// operator who owns the nodes along one path can stall or mislead that path;
/// to hide a record from a lookup it has to sit on every path.
pub const DISJOINT_PATHS: usize = 3;

/// A whole lookup, every path together, gives up asking after this long and
/// uses what answered: a path full of addresses that never answer costs a
/// bounded wait, not one timeout after another.
const LOOKUP_BUDGET: Duration = Duration::from_secs(15);

/// What the paths of one disjoint lookup share: the nodes being asked right
/// now (claimed) and the ones that have answered a path.
#[derive(Default)]
struct Walk {
    claimed: std::sync::Mutex<HashSet<NodeId>>,
    answered: std::sync::Mutex<HashSet<NodeId>>,
}

/// How far a service lookup or announcement walks and asks: the 3K closest
/// nodes it can reach, not the K closest. A cluster of ground IDs closer to a
/// service than every honest node would otherwise end every walk before it
/// reached a single honest storer.
const SERVICE_WIDTH: usize = DISJOINT_PATHS * K;

/// A descriptor this node published or looked up itself, signed less than
/// this long ago, is answered from memory; anything else is checked against
/// the network for a newer revision first.
const LOCAL_DESCRIPTOR_FRESH_SECS: u64 = 600;

/// How often this node re-signs and re-announces the services it published,
/// well inside the hour after which other nodes forget a descriptor.
const REPUBLISH_EVERY: Duration = Duration::from_secs(15 * 60);

/// At most this many contacts are being checked by a ping-back at once, and
/// at most PINGBACKS_PER_NETWORK of them from one /24 (or /48): a handful of
/// identities that write and never answer cannot hold every check open.
const MAX_PINGBACKS: usize = 64;
const PINGBACKS_PER_NETWORK: usize = 4;

/// An address that failed a ping-back is not checked again this soon.
const PINGBACK_BACKOFF: Duration = Duration::from_secs(30);
const MAX_BACKOFF_ENTRIES: usize = 4096;

/// Services republished at once.
const REPUBLISH_CONCURRENCY: usize = 8;

/// Who a ping-back's budget is charged to: the network for public
/// addresses, the address itself for loopback and private ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CheckBudget {
    Network([u8; 7]),
    Address(SocketAddr),
}

fn check_budget(addr: &SocketAddr) -> CheckBudget {
    match diversity_prefix(addr) {
        Some(p) => CheckBudget::Network(p),
        None => CheckBudget::Address(*addr),
    }
}

/// One host, for the one-check-at-a-time rule and the back-off: the IP for
/// public addresses (a new source port is the same host), the address itself
/// for loopback and private ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum CheckHost {
    Ip(std::net::IpAddr),
    Address(SocketAddr),
}

fn check_host(addr: &SocketAddr) -> CheckHost {
    match diversity_prefix(addr) {
        Some(_) => CheckHost::Ip(addr.ip()),
        None => CheckHost::Address(*addr),
    }
}

/// What a ping-back found.
enum CheckOutcome {
    Seated,
    /// Something answered from that address, but not as the node that wrote:
    /// no back-off, or forging a node's address would silence the node.
    WrongAnswer,
    /// Nothing answered: the address backs off.
    Silent,
}

/// What the ping-backs in flight are, and who failed one recently.
#[derive(Default)]
struct Checks {
    in_flight: HashSet<(NodeId, SocketAddr)>,
    per_budget: HashMap<CheckBudget, usize>,
    per_host: HashSet<CheckHost>,
    failed: HashMap<CheckHost, Instant>,
}

type PendingMap = HashMap<u64, oneshot::Sender<(DhtMessage, SocketAddr, [u8; 32])>>;

/// The services this node announced: their key and introduction points.
type OwnServices = HashMap<[u8; 20], (SigningKey, Vec<SocketAddr>)>;

/// Everything the receive loop, the lookups and the republisher share.
struct Shared {
    socket: Arc<UdpSocket>,
    table: Arc<Mutex<RoutingTable>>,
    pending: Mutex<PendingMap>,
    store: Mutex<ServiceStore>,
    our_info: NodeInfo,
    signing_key: SigningKey,
    /// The ID puzzle difficulty this network requires (ID_PUZZLE_BITS).
    id_bits: u32,
    pingbacks: Arc<Semaphore>,
    checks: std::sync::Mutex<Checks>,
    /// The services this node announced, to republish: key and intro points.
    own_services: Mutex<OwnServices>,
    republisher_started: AtomicBool,
}

pub struct DhtNode {
    shared: Arc<Shared>,
    #[allow(dead_code)]
    shutdown_tx: Option<mpsc::Sender<()>>,
}

fn sort_by_distance(nodes: &mut [NodeInfo], target: &NodeId) {
    nodes.sort_by(|a, b| a.id.xor_distance(target).cmp(&b.id.xor_distance(target)));
}

impl DhtNode {
    /// A node of the public network: its ID costs ID_PUZZLE_BITS of work,
    /// solved here once (about two seconds on one core).
    pub async fn new(
        bind_addr: SocketAddr,
        signing_key: SigningKey,
        relay_addr: Option<SocketAddr>,
    ) -> Result<Self> {
        Self::with_id_bits(bind_addr, signing_key, relay_addr, ID_PUZZLE_BITS).await
    }

    /// A node of a network with another ID difficulty: tests, private
    /// networks. Every node of one network must use the same value, since it
    /// is also what this node requires of everyone else's ID.
    pub async fn with_id_bits(
        bind_addr: SocketAddr,
        signing_key: SigningKey,
        relay_addr: Option<SocketAddr>,
        id_bits: u32,
    ) -> Result<Self> {
        Self::build(bind_addr, signing_key, relay_addr, None, id_bits).await
    }

    /// A relay that clients can build circuits through: its node record
    /// carries a descriptor, signed with `signing_key`, naming `relay_addr`
    /// and the X25519 key the relay answers circuit handshakes with. A relay
    /// started with `new` or `with_id_bits` announces itself without one, and
    /// no client will use it.
    pub async fn relay(
        bind_addr: SocketAddr,
        signing_key: SigningKey,
        relay_addr: SocketAddr,
        transport_key: [u8; 32],
        id_bits: u32,
    ) -> Result<Self> {
        Self::build(bind_addr, signing_key, Some(relay_addr), Some(transport_key), id_bits).await
    }

    async fn build(
        bind_addr: SocketAddr,
        signing_key: SigningKey,
        relay_addr: Option<SocketAddr>,
        transport_key: Option<[u8; 32]>,
        id_bits: u32,
    ) -> Result<Self> {
        let relay_descriptor = match (relay_addr, transport_key) {
            (Some(addr), Some(key)) => Some(RelayDescriptor::sign_now(&signing_key, addr, key)),
            _ => None,
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;
        let pubkey = signing_key.verifying_key().to_bytes();
        let started = std::time::Instant::now();
        let id_nonce = tokio::task::spawn_blocking(move || node::solve_id_puzzle(&pubkey, id_bits))
            .await
            .map_err(|e| HidraError::Protocol(format!("solving the node ID puzzle: {e}")))?;
        let node_id = NodeId::for_node(&pubkey, id_nonce);
        let our_info = NodeInfo {
            id: node_id,
            dht_addr: local_addr,
            relay_addr,
            public_key: pubkey,
            id_nonce,
            relay_descriptor,
        };
        info!(
            node_id = %node_id,
            dht_addr = %local_addr,
            is_relay = relay_addr.is_some(),
            id_bits,
            puzzle_ms = started.elapsed().as_millis() as u64,
            "DHT node initialized"
        );
        Ok(Self {
            shared: Arc::new(Shared {
                socket: Arc::new(socket),
                table: Arc::new(Mutex::new(RoutingTable::new(node_id))),
                pending: Mutex::new(HashMap::new()),
                store: Mutex::new(ServiceStore::new()),
                our_info,
                signing_key,
                id_bits,
                pingbacks: Arc::new(Semaphore::new(MAX_PINGBACKS)),
                checks: std::sync::Mutex::new(Checks::default()),
                own_services: Mutex::new(HashMap::new()),
                republisher_started: AtomicBool::new(false),
            }),
            shutdown_tx: None,
        })
    }

    pub fn our_info(&self) -> &NodeInfo {
        &self.shared.our_info
    }

    pub fn routing_table(&self) -> &Arc<Mutex<RoutingTable>> {
        &self.shared.table
    }

    /// How many service descriptors this node holds.
    #[allow(dead_code)] // for operators' tooling and the integration tests
    pub async fn stored_service_count(&self) -> usize {
        self.shared.store.lock().await.len()
    }

    pub async fn start(&mut self) {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);
        let shared = Arc::clone(&self.shared);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PACKET];
            loop {
                tokio::select! {
                    result = shared.socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                if let Err(e) = process_packet(&shared, &buf[..len], addr).await {
                                    debug!(error = %e, from = %sensitive(&addr), "failed to process DHT packet");
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "UDP recv error");
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("DHT receive loop shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// Pings an address and seats whoever answers from it, as the key that
    /// signed the answer: how a node meets its first peers.
    pub async fn ping(&self, addr: SocketAddr) -> Result<NodeInfo> {
        self.shared.ping_and_seat(addr).await
    }

    /// The K closest nodes to `target` that answered this lookup themselves,
    /// found over DISJOINT_PATHS paths that share no node.
    pub async fn find_node(&self, target: &NodeId) -> Result<Vec<NodeInfo>> {
        let mut all = self.shared.lookup_wide(target, DISJOINT_PATHS, K).await;
        all.truncate(K);
        Ok(all)
    }

    pub async fn find_relays(&self, count: usize) -> Result<Vec<NodeInfo>> {
        let random_target = NodeId::random();
        let nodes = self.find_node(&random_target).await?;
        let relays: Vec<NodeInfo> = nodes.into_iter().filter(|n| n.is_relay()).collect();
        if relays.len() >= count {
            Ok(relays.into_iter().take(count).collect())
        } else {
            let mut all_relays = relays;
            let table = self.shared.table.lock().await;
            for r in table.find_relays(count) {
                if !all_relays.iter().any(|x| x.id == r.id) {
                    all_relays.push(r);
                }
            }
            all_relays.truncate(count);
            Ok(all_relays)
        }
    }

    /// Tells this relay's neighbourhood in the key space that it exists. Each
    /// node told seats it after a PING at the address the announcement came
    /// from; nobody passes the announcement on.
    pub async fn announce_relay(&self) -> Result<()> {
        if self.shared.our_info.relay_addr.is_none() {
            return Err(HidraError::Protocol(
                "cannot announce: not configured as relay".into(),
            ));
        }
        let our_id = self.shared.our_info.id;
        let mut nodes = self.shared.lookup_wide(&our_id, DISJOINT_PATHS, K).await;
        if nodes.is_empty() {
            nodes = self.shared.table.lock().await.find_closest(&our_id, K);
        }
        info!(peer_count = nodes.len(), "announcing relay presence to nearest nodes");
        for node in &nodes {
            let msg = DhtMessage::AnnounceRelay {
                request_id: new_request_id(),
                sender: self.shared.our_info.clone(),
            };
            if let Err(e) = self.shared.send(&msg, node.dht_addr).await {
                debug!(error = %e, peer = %sensitive(&node.id), "failed to announce to peer");
            }
        }
        Ok(())
    }

    pub async fn node_count(&self) -> usize {
        self.shared.table.lock().await.total_nodes()
    }

    /// Signs a descriptor for the service whose key this is, announces it,
    /// and keeps re-announcing it every REPUBLISH_EVERY for as long as this
    /// node runs (other nodes forget a descriptor an hour after it was signed).
    pub async fn announce_signed_service(
        &self,
        service_key: &SigningKey,
        intro_points: Vec<SocketAddr>,
    ) -> Result<()> {
        let descriptor = ServiceDescriptor::sign_now(service_key, intro_points.clone());
        self.shared
            .own_services
            .lock()
            .await
            .insert(descriptor.service_hash(), (service_key.clone(), intro_points));
        self.shared.announce(descriptor, Origin::Own).await?;
        if !self.shared.republisher_started.swap(true, Ordering::SeqCst) {
            // Holds the node weakly: when the node is dropped, it stops.
            let weak: Weak<Shared> = Arc::downgrade(&self.shared);
            tokio::spawn(async move {
                use futures::StreamExt;
                let mut tick = tokio::time::interval(REPUBLISH_EVERY);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                tick.tick().await; // the first tick is immediate
                loop {
                    tick.tick().await;
                    let Some(shared) = weak.upgrade() else { break };
                    let services: Vec<_> = shared
                        .own_services
                        .lock()
                        .await
                        .iter()
                        .map(|(h, v)| (*h, v.clone()))
                        .collect();
                    futures::stream::iter(services)
                        .for_each_concurrent(REPUBLISH_CONCURRENCY, |(hash, (key, intro))| {
                            let shared = Arc::clone(&shared);
                            async move {
                                // Withdrawn since the cycle began: not again.
                                if !shared.own_services.lock().await.contains_key(&hash) {
                                    return;
                                }
                                let d = ServiceDescriptor::sign_now(&key, intro);
                                if let Err(e) = shared.announce(d, Origin::Own).await {
                                    debug!(error = %e, "republishing a service failed");
                                }
                            }
                        })
                        .await;
                }
            });
        }
        Ok(())
    }

    /// Stops republishing a service this node announced (a deleted site).
    /// Other nodes forget it within the hour; this node drops its key now.
    pub async fn withdraw_service(&self, service_hash: &[u8; 20]) {
        self.shared.own_services.lock().await.remove(service_hash);
        self.shared.store.lock().await.forget_own(service_hash);
    }

    /// Publishes a descriptor the service signed: kept here, and sent to the
    /// K closest nodes to its address that each disjoint path finds. Not
    /// republished: `announce_signed_service` is what a running service uses.
    #[allow(dead_code)] // the binary signs with announce_signed_service
    pub async fn announce_service(&self, descriptor: ServiceDescriptor) -> Result<()> {
        self.shared.announce(descriptor, Origin::Own).await
    }

    /// The newest descriptor the service signed that any of the nodes found
    /// over disjoint paths holds, or this node's own recent copy. A node on
    /// the way can withhold a descriptor or hand out an older one; it cannot
    /// hand out one the service did not sign, and it loses to any path that
    /// reaches a newer one.
    pub async fn lookup_service(
        &self,
        service_hash: &[u8; 20],
    ) -> Result<Option<(Vec<SocketAddr>, [u8; 32])>> {
        let shared = &self.shared;
        let now = now_secs();
        let local = shared.store.lock().await.get(service_hash, now).cloned();
        if let Some(s) = &local {
            let mine = matches!(s.origin, Origin::Own | Origin::Fetched);
            if mine && now.saturating_sub(s.descriptor.revision) < LOCAL_DESCRIPTOR_FRESH_SECS {
                return Ok(Some((s.descriptor.intro_points.clone(), s.descriptor.service_pubkey)));
            }
        }
        let target = service_target(service_hash);
        let closest = shared.lookup_wide(&target, DISJOINT_PATHS, SERVICE_WIDTH).await;
        let answers = futures::future::join_all(closest.iter().map(|node| {
            shared.request_from(
                node,
                DhtMessage::LookupService {
                    request_id: new_request_id(),
                    sender: shared.our_info.clone(),
                    service_hash: *service_hash,
                },
            )
        }))
        .await;
        let mut best = local.map(|s| s.descriptor);
        let mut refused = 0usize;
        for answer in answers {
            if let Ok((DhtMessage::LookupServiceResponse { descriptor: Some(d), .. }, _)) = answer {
                let current = d.revision <= now.saturating_add(store::MAX_CLOCK_SKEW_SECS)
                    && d.revision.saturating_add(store::DESCRIPTOR_TTL_SECS) > now;
                if d.verify(service_hash).is_err() || !current {
                    refused += 1;
                    continue;
                }
                if best.as_ref().map(|b| d.revision > b.revision).unwrap_or(true) {
                    best = Some(d);
                }
            }
        }
        if refused > 0 {
            warn!(refused, "lookup answers carried descriptors the service did not sign, or stale ones");
        }
        if let Some(d) = &best {
            let _ = shared.store.lock().await.put(*service_hash, d.clone(), Origin::Fetched, now);
        }
        Ok(best.map(|d| (d.intro_points, d.service_pubkey)))
    }
}

impl Shared {
    async fn send(&self, msg: &DhtMessage, addr: SocketAddr) -> Result<()> {
        let packet = sign_and_serialize(msg, &self.signing_key)?;
        self.socket.send_to(&packet, addr).await?;
        debug!(dht_message_type = msg.message_type(), target = %sensitive(&addr), "sent DHT message");
        Ok(())
    }

    /// Sends a request; returns the answer, the address it came from and the
    /// key that signed it.
    async fn request_timeout(
        &self,
        msg: DhtMessage,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<(DhtMessage, SocketAddr, [u8; 32])> {
        let request_id = msg.request_id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(request_id, tx);
        let sent = self.send(&msg, addr).await;
        let result = match sent {
            Ok(()) => tokio::time::timeout(timeout, rx).await,
            Err(e) => {
                self.pending.lock().await.remove(&request_id);
                return Err(e);
            }
        };
        self.pending.lock().await.remove(&request_id);
        match result {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err(HidraError::Protocol("DHT response channel closed".into())),
            Err(_) => Err(HidraError::Protocol(format!(
                "DHT request timed out (id={request_id}, target={addr})"
            ))),
        }
    }

    async fn request(
        &self,
        msg: DhtMessage,
        addr: SocketAddr,
    ) -> Result<(DhtMessage, SocketAddr, [u8; 32])> {
        self.request_timeout(msg, addr, REQUEST_TIMEOUT).await
    }

    /// Asks `node` at its address and accepts only an answer that came from
    /// that address, signed by `node`'s own key, from `node`'s own ID. The
    /// node is then seated as it described itself, at the address it answered
    /// from: never as a third party described it.
    async fn request_from(&self, node: &NodeInfo, msg: DhtMessage) -> Result<(DhtMessage, NodeInfo)> {
        let (resp, from, signer) = self.request(msg, node.dht_addr).await?;
        if from != node.dht_addr {
            return Err(HidraError::Protocol("DHT answer came from another address".into()));
        }
        // Implied by the ID check below too (an ID is a hash of its key, and
        // verify_and_bind tied the answer's sender to the signing key); kept
        // so the rule reads where it is enforced.
        if signer != node.public_key {
            return Err(HidraError::Protocol(
                "DHT answer signed by another key than the node asked".into(),
            ));
        }
        let Some(self_described) = resp.sender().filter(|s| s.id == node.id) else {
            return Err(HidraError::Protocol("DHT answer from another node than the one asked".into()));
        };
        let seated = NodeInfo {
            dht_addr: from,
            ..self_described.clone()
        };
        self.table.lock().await.update(seated.clone());
        Ok((resp, seated))
    }

    /// Pings `addr` and seats whoever answers from that address, as the key
    /// that signed the answer (verify_and_bind tied the PONG's sender to it
    /// and checked its ID): how a node meets its first peers.
    async fn ping_and_seat(&self, addr: SocketAddr) -> Result<NodeInfo> {
        let msg = DhtMessage::Ping {
            request_id: new_request_id(),
            sender: self.our_info.clone(),
        };
        let (resp, from, _signer) = self.request_timeout(msg, addr, REQUEST_TIMEOUT).await?;
        if from != addr {
            return Err(HidraError::Protocol("PONG came from another address".into()));
        }
        let DhtMessage::Pong { sender, .. } = resp else {
            return Err(HidraError::Protocol(format!(
                "expected PONG, got {}",
                resp.message_type()
            )));
        };
        let seated = NodeInfo { dht_addr: from, ..sender };
        match self.table.lock().await.update(seated.clone()) {
            UpdateResult::Inserted | UpdateResult::Updated => {}
            other => debug!(node_id = %seated.id, result = ?other, "contact not seated"),
        }
        Ok(seated)
    }

    /// The ping-back: asks `from` and seats `contact` there only if the
    /// answer comes from that address, from that node.
    async fn check_contact(&self, from: SocketAddr, contact: &NodeInfo) -> CheckOutcome {
        let msg = DhtMessage::Ping {
            request_id: new_request_id(),
            sender: self.our_info.clone(),
        };
        let Ok((resp, at, _signer)) = self.request_timeout(msg, from, PINGBACK_TIMEOUT).await else {
            return CheckOutcome::Silent;
        };
        let DhtMessage::Pong { sender, .. } = resp else {
            return CheckOutcome::WrongAnswer;
        };
        if at != from || sender.id != contact.id || sender.public_key != contact.public_key {
            return CheckOutcome::WrongAnswer;
        }
        let seated = NodeInfo { dht_addr: from, ..sender };
        match self.table.lock().await.update(seated.clone()) {
            UpdateResult::Inserted | UpdateResult::Updated => {}
            other => debug!(node_id = %seated.id, result = ?other, "contact not seated"),
        }
        CheckOutcome::Seated
    }

    /// A request's sender, seen at `from`. Seated only after it answers a
    /// fresh PING at `from`, so a signed packet replayed from another address
    /// seats nothing. One check per host at a time, four per network, and a
    /// host that stays silent waits PINGBACK_BACKOFF before the next.
    async fn consider_contact(self: &Arc<Self>, contact: NodeInfo, from: SocketAddr) {
        if contact.id == self.our_info.id {
            return;
        }
        // Already seated, here or elsewhere: nothing to do. An inbound packet
        // never refreshes a seat (its source address can be forged); only
        // answers to this node's own requests do.
        if self.table.lock().await.address_of(&contact.id).is_some() {
            return;
        }
        let budget = check_budget(&from);
        let host = check_host(&from);
        {
            let mut checks = self.checks.lock().unwrap_or_else(|p| p.into_inner());
            let now = Instant::now();
            if checks
                .failed
                .get(&host)
                .is_some_and(|t| now.duration_since(*t) < PINGBACK_BACKOFF)
            {
                return;
            }
            if checks.per_budget.get(&budget).copied().unwrap_or(0) >= PINGBACKS_PER_NETWORK
                || checks.per_host.contains(&host)
            {
                return;
            }
            // Keyed by ID and address: someone replaying a node's packets
            // from elsewhere does not hold up the check of the real one.
            if !checks.in_flight.insert((contact.id, from)) {
                return;
            }
            checks.per_host.insert(host);
            *checks.per_budget.entry(budget).or_default() += 1;
        }
        let id = contact.id;
        let release = move |shared: &Shared, failed: bool| {
            let mut checks = shared.checks.lock().unwrap_or_else(|p| p.into_inner());
            checks.in_flight.remove(&(id, from));
            checks.per_host.remove(&host);
            if let Some(n) = checks.per_budget.get_mut(&budget) {
                *n -= 1;
                if *n == 0 {
                    checks.per_budget.remove(&budget);
                }
            }
            if failed {
                if checks.failed.len() >= MAX_BACKOFF_ENTRIES {
                    let now = Instant::now();
                    checks
                        .failed
                        .retain(|_, t| now.duration_since(*t) < PINGBACK_BACKOFF);
                }
                if checks.failed.len() < MAX_BACKOFF_ENTRIES {
                    checks.failed.insert(host, Instant::now());
                }
            }
        };
        let Ok(permit) = Arc::clone(&self.pingbacks).try_acquire_owned() else {
            release(self, false);
            return;
        };
        let shared = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit;
            let failed = match shared.check_contact(from, &contact).await {
                CheckOutcome::Seated => false,
                CheckOutcome::WrongAnswer => {
                    debug!(node_id = %contact.id, "another node answered at the contact's address");
                    false
                }
                CheckOutcome::Silent => {
                    debug!(node_id = %contact.id, "contact did not confirm its address");
                    true
                }
            };
            release(&shared, failed);
        });
    }

    /// Every path's own K closest responders, plus the `width` closest of all
    /// responders, together, nearest first. This is what a service is
    /// announced to and asked from: merging the paths and keeping only the K
    /// closest overall would let one cluster of ground IDs, closer than every
    /// honest node, fill the result and hide what the clean paths found.
    async fn lookup_wide(&self, target: &NodeId, paths: usize, width: usize) -> Vec<NodeInfo> {
        let per_path = self.lookup_paths(target, paths, width).await;
        let mut everyone: Vec<NodeInfo> = per_path.iter().flatten().cloned().collect();
        sort_by_distance(&mut everyone, target);
        let mut seen: HashSet<NodeId> = HashSet::new();
        let mut all: Vec<NodeInfo> = Vec::new();
        let chosen = per_path
            .iter()
            .flat_map(|p| p.iter().take(K))
            .chain(everyone.iter().take(width));
        for n in chosen {
            if seen.insert(n.id) {
                all.push(n.clone());
            }
        }
        sort_by_distance(&mut all, target);
        all
    }

    /// S/Kademlia's disjoint lookup. The K closest nodes this node knows are
    /// dealt out to `paths` paths; each path walks toward `target` on its
    /// own, and a node that answered one path is never asked by another, so
    /// an operator has to sit on every path to steer them all. Only nodes
    /// that answered, from the address asked and signed by their own key,
    /// count; a node named in an answer whose ID was never earned is not even
    /// asked. Each path walks until the `width` closest nodes it has seen
    /// have been asked. Returns each path's responders, nearest first.
    async fn lookup_paths(&self, target: &NodeId, paths: usize, width: usize) -> Vec<Vec<NodeInfo>> {
        // Seeds: the closest node of each network first, then the closest of
        // the rest, so that one network close to the target does not supply
        // every path's starting point.
        let seeds = {
            let table = self.table.lock().await;
            let all = table.find_closest(target, table.total_nodes());
            let mut nets = HashSet::new();
            let (mut first, mut rest): (Vec<NodeInfo>, Vec<NodeInfo>) = (Vec::new(), Vec::new());
            for n in all {
                if nets.insert(neighbourhood(&n.dht_addr)) && first.len() < K {
                    first.push(n);
                } else {
                    rest.push(n);
                }
            }
            let mut seeds = first;
            seeds.extend(rest.into_iter().take(K.saturating_sub(seeds.len())));
            seeds
        };
        if seeds.is_empty() {
            return Vec::new();
        }
        let paths = paths.clamp(1, seeds.len());
        let mut groups: Vec<Vec<NodeInfo>> = vec![Vec::new(); paths];
        for (i, n) in seeds.into_iter().enumerate() {
            groups[i % paths].push(n);
        }
        let walk = Walk::default();
        let deadline = Instant::now() + LOOKUP_BUDGET;
        futures::future::join_all(
            groups
                .into_iter()
                .map(|g| self.lookup_path(target, g, &walk, width, deadline)),
        )
        .await
    }

    async fn lookup_path(
        &self,
        target: &NodeId,
        seeds: Vec<NodeInfo>,
        walk: &Walk,
        width: usize,
        deadline: Instant,
    ) -> Vec<NodeInfo> {
        let mut seen: HashMap<NodeId, NodeInfo> = seeds.into_iter().map(|n| (n.id, n)).collect();
        // Asked by this path; not reached at the address this path had.
        let mut tried: HashSet<NodeId> = HashSet::new();
        let mut dead: HashSet<NodeId> = HashSet::new();
        let mut responded: Vec<NodeInfo> = Vec::new();
        loop {
            if Instant::now() >= deadline {
                break;
            }
            // The window: the `width` closest this path has seen, leaving out
            // the ones it could not reach, so a dead address does not take a
            // live node's place. Ask the ones in it that no path has asked.
            let (to_query, elsewhere) = {
                let mut window: Vec<NodeInfo> =
                    seen.values().filter(|n| !dead.contains(&n.id)).cloned().collect();
                sort_by_distance(&mut window, target);
                window.truncate(width);
                let mut claimed = walk.claimed.lock().unwrap_or_else(|p| p.into_inner());
                let answered = walk.answered.lock().unwrap_or_else(|p| p.into_inner());
                let picks: Vec<NodeInfo> = window
                    .iter()
                    .filter(|n| {
                        !tried.contains(&n.id) && !claimed.contains(&n.id) && !answered.contains(&n.id)
                    })
                    .take(ALPHA)
                    .cloned()
                    .collect();
                for n in &picks {
                    claimed.insert(n.id);
                }
                // Nodes in the window another path is asking right now: if it
                // cannot reach them, they come back to this path.
                let elsewhere = window.iter().any(|n| {
                    !tried.contains(&n.id) && claimed.contains(&n.id) && !answered.contains(&n.id)
                });
                (picks, elsewhere)
            };
            if to_query.is_empty() {
                if elsewhere {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                break;
            }
            for n in &to_query {
                tried.insert(n.id);
            }
            let answers = futures::future::join_all(to_query.iter().map(|node| {
                self.request_from(
                    node,
                    DhtMessage::FindNode {
                        request_id: new_request_id(),
                        sender: self.our_info.clone(),
                        target: *target,
                    },
                )
            }))
            .await;
            for (node, answer) in to_query.iter().zip(answers) {
                let Ok((DhtMessage::FindNodeResponse { nodes, .. }, seated)) = answer else {
                    // Not reached at the address this path was given: another
                    // path may know the node at its real address.
                    dead.insert(node.id);
                    walk.claimed.lock().unwrap_or_else(|p| p.into_inner()).remove(&node.id);
                    continue;
                };
                walk.answered.lock().unwrap_or_else(|p| p.into_inner()).insert(node.id);
                responded.push(seated);
                for n in nodes.into_iter().take(K) {
                    if n.id == self.our_info.id || seen.contains_key(&n.id) {
                        continue;
                    }
                    if !n.id_is_valid(self.id_bits) {
                        continue;
                    }
                    seen.insert(n.id, n);
                }
            }
        }
        sort_by_distance(&mut responded, target);
        responded
    }

    async fn announce(&self, descriptor: ServiceDescriptor, origin: Origin) -> Result<()> {
        let service_hash = descriptor.service_hash();
        descriptor.verify(&service_hash)?;
        let _ = self
            .store
            .lock()
            .await
            .put(service_hash, descriptor.clone(), origin, now_secs());
        let target = service_target(&service_hash);
        let mut nodes = self.lookup_wide(&target, DISJOINT_PATHS, SERVICE_WIDTH).await;
        if nodes.is_empty() {
            nodes = self.table.lock().await.find_closest(&target, K);
        }
        info!(peer_count = nodes.len(), "announcing hidden service to nearest nodes");
        for node in &nodes {
            let msg = DhtMessage::AnnounceService {
                request_id: new_request_id(),
                sender: self.our_info.clone(),
                service_hash,
                descriptor: descriptor.clone(),
            };
            if let Err(e) = self.send(&msg, node.dht_addr).await {
                debug!(error = %e, peer = %sensitive(&node.id), "failed to announce service to peer");
            }
        }
        Ok(())
    }
}

async fn process_packet(shared: &Arc<Shared>, data: &[u8], addr: SocketAddr) -> Result<()> {
    // The signature must be valid, the sender's key must be the signing key,
    // and its ID must be the one that key and its puzzle nonce derive, with
    // the puzzle solved: nobody squats an ID they do not hold or did not pay.
    let (msg, signer) = verify_and_bind(data, shared.id_bits)?;
    if msg.is_response() {
        let request_id = msg.request_id();
        if let Some(tx) = shared.pending.lock().await.remove(&request_id) {
            let _ = tx.send((msg, addr, signer));
        }
        return Ok(());
    }
    let result = {
        let table = shared.table.lock().await;
        let mut store = shared.store.lock().await;
        DhtHandler::handle_message(&table, msg, &shared.our_info, addr, &mut store, now_secs())
    };
    if let Some(resp) = result.response {
        let packet = sign_and_serialize(&resp, &shared.signing_key)?;
        shared.socket.send_to(&packet, addr).await?;
    }
    if let Some(contact) = result.contact {
        shared.consider_contact(contact, addr).await;
    }
    Ok(())
}

fn new_request_id() -> u64 {
    use rand::Rng;
    rand::thread_rng().r#gen()
}
