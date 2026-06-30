pub mod handler;
pub mod kbuckets;
pub mod message;
pub mod node;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex, oneshot};
use tracing::{debug, info, warn};

use crate::error::{HidraError, Result};
use crate::p2p::dht::handler::DhtHandler;
use crate::p2p::dht::kbuckets::{RoutingTable, K};
use crate::p2p::dht::message::{sign_and_serialize, verify_and_deserialize, DhtMessage};
use crate::p2p::dht::node::{NodeId, NodeInfo};

const MAX_UDP_PACKET: usize = 65535;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const ALPHA: usize = 3;

type PendingMap = HashMap<u64, oneshot::Sender<(DhtMessage, SocketAddr)>>;

pub struct DhtNode {
    socket: Arc<UdpSocket>,
    routing_table: Arc<Mutex<RoutingTable>>,
    our_info: NodeInfo,
    signing_key: SigningKey,
    pending: Arc<Mutex<PendingMap>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl DhtNode {
    pub async fn new(
        bind_addr: SocketAddr,
        signing_key: SigningKey,
        relay_addr: Option<SocketAddr>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        let pubkey = signing_key.verifying_key().to_bytes();
        let node_id = NodeId::from_public_key(&pubkey);

        let our_info = NodeInfo {
            id: node_id,
            dht_addr: local_addr,
            relay_addr,
            public_key: pubkey,
        };

        info!(
            node_id = %node_id,
            dht_addr = %local_addr,
            is_relay = relay_addr.is_some(),
            "DHT node initialized"
        );

        Ok(Self {
            socket: Arc::new(socket),
            routing_table: Arc::new(Mutex::new(RoutingTable::new(node_id))),
            our_info,
            signing_key,
            pending: Arc::new(Mutex::new(HashMap::new())),
            shutdown_tx: None,
        })
    }

    pub fn our_info(&self) -> &NodeInfo {
        &self.our_info
    }

    pub fn routing_table(&self) -> &Arc<Mutex<RoutingTable>> {
        &self.routing_table
    }

    pub async fn start(&mut self) {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let socket = Arc::clone(&self.socket);
        let table = Arc::clone(&self.routing_table);
        let pending = Arc::clone(&self.pending);
        let our_info = self.our_info.clone();
        let signing_key_bytes = self.signing_key.to_bytes();

        tokio::spawn(async move {
            let signing_key = SigningKey::from_bytes(&signing_key_bytes);
            let mut buf = vec![0u8; MAX_UDP_PACKET];

            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                if let Err(e) = process_packet(
                                    &buf[..len],
                                    addr,
                                    &table,
                                    &pending,
                                    &our_info,
                                    &signing_key,
                                    &socket,
                                ).await {
                                    debug!(error = %e, from = %addr, "failed to process DHT packet");
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

    pub async fn send_message(&self, msg: &DhtMessage, addr: SocketAddr) -> Result<()> {
        let packet = sign_and_serialize(msg, &self.signing_key)?;
        self.socket.send_to(&packet, addr).await?;
        debug!(
            dht_message_type = msg.message_type(),
            target = %addr,
            "sent DHT message"
        );
        Ok(())
    }

    pub async fn send_request(
        &self,
        msg: DhtMessage,
        addr: SocketAddr,
    ) -> Result<DhtMessage> {
        let request_id = msg.request_id();
        let (tx, rx) = oneshot::channel();

        {
            let mut pending = self.pending.lock().await;
            pending.insert(request_id, tx);
        }

        self.send_message(&msg, addr).await?;

        let result = tokio::time::timeout(REQUEST_TIMEOUT, rx).await;

        {
            let mut pending = self.pending.lock().await;
            pending.remove(&request_id);
        }

        match result {
            Ok(Ok((response, _addr))) => Ok(response),
            Ok(Err(_)) => Err(HidraError::Protocol("DHT response channel closed".into())),
            Err(_) => Err(HidraError::Protocol(format!(
                "DHT request timed out (id={request_id}, target={addr})"
            ))),
        }
    }

    pub async fn ping(&self, addr: SocketAddr) -> Result<NodeInfo> {
        let request_id = new_request_id();
        let msg = DhtMessage::Ping {
            request_id,
            sender: self.our_info.clone(),
        };

        let response = self.send_request(msg, addr).await?;
        match response {
            DhtMessage::Pong { sender, .. } => {
                let mut table = self.routing_table.lock().await;
                table.update(sender.clone());
                Ok(sender)
            }
            other => Err(HidraError::Protocol(format!(
                "expected PONG, got {}",
                other.message_type()
            ))),
        }
    }

    pub async fn find_node(&self, target: &NodeId) -> Result<Vec<NodeInfo>> {
        let initial = {
            let table = self.routing_table.lock().await;
            table.find_closest(target, K)
        };

        if initial.is_empty() {
            return Ok(vec![]);
        }

        let mut seen: HashMap<NodeId, NodeInfo> = HashMap::new();
        let mut queried: std::collections::HashSet<NodeId> = std::collections::HashSet::new();

        for node in &initial {
            seen.insert(node.id, node.clone());
        }

        loop {
            let mut candidates: Vec<NodeInfo> = seen
                .values()
                .filter(|n| !queried.contains(&n.id))
                .cloned()
                .collect();

            candidates.sort_by(|a, b| {
                let da = a.id.xor_distance(target);
                let db = b.id.xor_distance(target);
                da.cmp(&db)
            });

            let to_query: Vec<NodeInfo> = candidates.into_iter().take(ALPHA).collect();

            if to_query.is_empty() {
                break;
            }

            let mut tasks = Vec::new();
            for node in &to_query {
                queried.insert(node.id);
                let request_id = new_request_id();
                let msg = DhtMessage::FindNode {
                    request_id,
                    sender: self.our_info.clone(),
                    target: *target,
                };
                let addr = node.dht_addr;
                tasks.push(self.send_request(msg, addr));
            }

            let results = futures::future::join_all(tasks).await;

            let mut found_new = false;
            for result in results {
                if let Ok(DhtMessage::FindNodeResponse { nodes, .. }) = result {
                    for node in nodes {
                        if node.id != self.our_info.id && !seen.contains_key(&node.id) {
                            seen.insert(node.id, node.clone());
                            let mut table = self.routing_table.lock().await;
                            table.update(node);
                            found_new = true;
                        }
                    }
                }
            }

            if !found_new {
                break;
            }
        }

        let mut result: Vec<NodeInfo> = seen.into_values().collect();
        result.sort_by(|a, b| {
            let da = a.id.xor_distance(target);
            let db = b.id.xor_distance(target);
            da.cmp(&db)
        });
        result.truncate(K);

        Ok(result)
    }

    pub async fn find_relays(&self, count: usize) -> Result<Vec<NodeInfo>> {
        let random_target = NodeId::random();
        let nodes = self.find_node(&random_target).await?;

        let relays: Vec<NodeInfo> = nodes.into_iter().filter(|n| n.is_relay()).collect();

        if relays.len() >= count {
            Ok(relays.into_iter().take(count).collect())
        } else {
            let mut all_relays = relays;
            let table = self.routing_table.lock().await;
            let table_relays = table.find_relays(count);
            for r in table_relays {
                if !all_relays.iter().any(|x| x.id == r.id) {
                    all_relays.push(r);
                }
            }
            all_relays.truncate(count);
            Ok(all_relays)
        }
    }

    pub async fn announce_relay(&self) -> Result<()> {
        if self.our_info.relay_addr.is_none() {
            return Err(HidraError::Protocol(
                "cannot announce: not configured as relay".into(),
            ));
        }

        let nodes = {
            let table = self.routing_table.lock().await;
            table.find_closest(&self.our_info.id, K)
        };

        info!(
            peer_count = nodes.len(),
            "announcing relay presence to nearest nodes"
        );

        for node in &nodes {
            let msg = DhtMessage::AnnounceRelay {
                request_id: new_request_id(),
                sender: self.our_info.clone(),
            };
            if let Err(e) = self.send_message(&msg, node.dht_addr).await {
                debug!(
                    error = %e,
                    peer = %node.id,
                    "failed to announce to peer"
                );
            }
        }

        Ok(())
    }

    pub async fn node_count(&self) -> usize {
        let table = self.routing_table.lock().await;
        table.total_nodes()
    }
}

async fn process_packet(
    data: &[u8],
    addr: SocketAddr,
    table: &Arc<Mutex<RoutingTable>>,
    pending: &Arc<Mutex<PendingMap>>,
    our_info: &NodeInfo,
    signing_key: &SigningKey,
    socket: &UdpSocket,
) -> Result<()> {
    let (msg, _pubkey) = verify_and_deserialize(data)?;

    if msg.is_response() {
        let request_id = msg.request_id();
        let mut pending_map = pending.lock().await;
        if let Some(tx) = pending_map.remove(&request_id) {
            let _ = tx.send((msg, addr));
        }
        return Ok(());
    }

    let mut table_guard = table.lock().await;
    let result = DhtHandler::handle_message(&mut table_guard, msg, our_info, addr);
    drop(table_guard);

    if let Some(resp) = result.response {
        let packet = sign_and_serialize(&resp, signing_key)?;
        socket.send_to(&packet, addr).await?;
    }

    for (target, gossip_msg) in result.gossip_targets {
        let packet = sign_and_serialize(&gossip_msg, signing_key)?;
        if let Err(e) = socket.send_to(&packet, target.dht_addr).await {
            debug!(
                error = %e,
                target = %target.id,
                "gossip forwarding failed"
            );
        }
    }

    Ok(())
}

fn new_request_id() -> u64 {
    use rand::Rng;
    rand::thread_rng().r#gen()
}
