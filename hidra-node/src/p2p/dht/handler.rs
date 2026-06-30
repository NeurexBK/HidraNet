use std::net::SocketAddr;

use tracing::{debug, info};

use crate::p2p::dht::kbuckets::{RoutingTable, UpdateResult, K};
use crate::p2p::dht::message::DhtMessage;
use crate::p2p::dht::node::NodeInfo;

const GOSSIP_FANOUT: usize = 3;

pub struct HandleResult {
    pub response: Option<DhtMessage>,
    pub gossip_targets: Vec<(NodeInfo, DhtMessage)>,
}

pub struct DhtHandler;

impl DhtHandler {
    pub fn handle_message(
        table: &mut RoutingTable,
        msg: DhtMessage,
        our_info: &NodeInfo,
        _sender_addr: SocketAddr,
    ) -> HandleResult {
        let no_gossip = || HandleResult {
            response: None,
            gossip_targets: Vec::new(),
        };
        let reply = |r: DhtMessage| HandleResult {
            response: Some(r),
            gossip_targets: Vec::new(),
        };

        match msg {
            DhtMessage::Ping {
                request_id,
                sender,
            } => {
                let bucket_index = table.our_id().bucket_index(&sender.id);
                info!(
                    dht_message_type = "PING",
                    node_id = %sender.id,
                    bucket_index = ?bucket_index,
                    peer_count = table.total_nodes(),
                    "received DHT PING"
                );
                update_table(table, sender);
                reply(DhtMessage::Pong {
                    request_id,
                    sender: our_info.clone(),
                })
            }

            DhtMessage::Pong {
                request_id: _,
                sender,
            } => {
                let bucket_index = table.our_id().bucket_index(&sender.id);
                info!(
                    dht_message_type = "PONG",
                    node_id = %sender.id,
                    bucket_index = ?bucket_index,
                    peer_count = table.total_nodes(),
                    "received DHT PONG"
                );
                update_table(table, sender);
                no_gossip()
            }

            DhtMessage::FindNode {
                request_id,
                sender,
                target,
            } => {
                let bucket_index = table.our_id().bucket_index(&sender.id);
                info!(
                    dht_message_type = "FIND_NODE",
                    node_id = %sender.id,
                    target = %target,
                    bucket_index = ?bucket_index,
                    peer_count = table.total_nodes(),
                    "received FIND_NODE"
                );
                update_table(table, sender);
                let closest = table.find_closest(&target, K);
                debug!(
                    dht_message_type = "FIND_NODE_RESPONSE",
                    nodes_count = closest.len(),
                    "sending FIND_NODE response"
                );
                reply(DhtMessage::FindNodeResponse {
                    request_id,
                    nodes: closest,
                })
            }

            DhtMessage::FindNodeResponse { nodes, .. } => {
                debug!(
                    dht_message_type = "FIND_NODE_RESPONSE",
                    nodes_count = nodes.len(),
                    "received FIND_NODE response"
                );
                for node in nodes {
                    update_table(table, node);
                }
                no_gossip()
            }

            DhtMessage::Store {
                request_id,
                sender,
                key: _,
                value: _,
            } => {
                let bucket_index = table.our_id().bucket_index(&sender.id);
                info!(
                    dht_message_type = "STORE",
                    node_id = %sender.id,
                    bucket_index = ?bucket_index,
                    peer_count = table.total_nodes(),
                    "received STORE"
                );
                update_table(table, sender);
                reply(DhtMessage::StoreResponse {
                    request_id,
                    stored: true,
                })
            }

            DhtMessage::StoreResponse { .. } => no_gossip(),

            DhtMessage::AnnounceRelay {
                request_id: _,
                sender,
            } => {
                let bucket_index = table.our_id().bucket_index(&sender.id);
                let already_known = table.contains(&sender.id) && sender.is_relay();
                info!(
                    dht_message_type = "ANNOUNCE_RELAY",
                    node_id = %sender.id,
                    is_relay = sender.is_relay(),
                    bucket_index = ?bucket_index,
                    peer_count = table.total_nodes(),
                    "received relay announcement"
                );
                update_table(table, sender.clone());

                let gossip = if !already_known && sender.is_relay() {
                    let nearest = table.find_closest(&sender.id, GOSSIP_FANOUT + 1);
                    let targets: Vec<(NodeInfo, DhtMessage)> = nearest
                        .into_iter()
                        .filter(|n| n.id != sender.id && n.id != *table.our_id())
                        .take(GOSSIP_FANOUT)
                        .map(|target| {
                            let msg = DhtMessage::AnnounceRelay {
                                request_id: rand_request_id(),
                                sender: sender.clone(),
                            };
                            (target, msg)
                        })
                        .collect();

                    debug!(
                        dht_message_type = "GOSSIP_RELAY",
                        relay_id = %sender.id,
                        gossip_count = targets.len(),
                        "gossiping relay announcement"
                    );
                    targets
                } else {
                    Vec::new()
                };

                HandleResult {
                    response: None,
                    gossip_targets: gossip,
                }
            }
        }
    }
}

fn update_table(table: &mut RoutingTable, info: NodeInfo) {
    let node_id = info.id;
    let bucket_index = table.our_id().bucket_index(&node_id);
    match table.update(info) {
        UpdateResult::Inserted => {
            debug!(
                node_id = %node_id,
                bucket_index = ?bucket_index,
                peer_count = table.total_nodes(),
                "added node to routing table"
            );
        }
        UpdateResult::Updated => {
            debug!(
                node_id = %node_id,
                bucket_index = ?bucket_index,
                "updated node in routing table"
            );
        }
        UpdateResult::BucketFull { least_recent_id } => {
            debug!(
                node_id = %node_id,
                bucket_index = ?bucket_index,
                least_recent = %least_recent_id,
                "bucket full, node not added"
            );
        }
    }
}

fn rand_request_id() -> u64 {
    use rand::Rng;
    rand::thread_rng().r#gen()
}
