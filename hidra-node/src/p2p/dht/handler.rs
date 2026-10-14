//! Answers to the requests other nodes send. Nothing here seats a node in the
//! routing table: the sender of a request is handed back as a contact, and
//! `DhtNode` seats it only after it answers a fresh PING at the address the
//! request came from. A signed packet replayed from another address, or a
//! sender that cannot be reached where it claims to be, gets no seat.

use std::collections::HashSet;
use std::net::SocketAddr;
use tracing::{debug, info};

use crate::p2p::dht::descriptor::service_target;
use crate::p2p::dht::kbuckets::{neighbourhood, Neighbourhood, RoutingTable, K};
use crate::p2p::dht::message::DhtMessage;
use crate::p2p::dht::node::{NodeId, NodeInfo};
use crate::p2p::dht::store::{Origin, ServiceStore};

pub struct HandleResult {
    pub response: Option<DhtMessage>,
    /// The request's sender, to seat once it proves the address it wrote
    /// from (`verify_and_bind` already tied it to the signing key).
    pub contact: Option<NodeInfo>,
}

/// How many networks may be closer to a service's address than this node
/// before a pushed descriptor for it is not this node's to keep.
pub const NEAR_NEIGHBOURHOODS: usize = 3 * K;

/// True when fewer than NEAR_NEIGHBOURHOODS networks this node knows are
/// closer to `target` than it is. Counted by network (one per /24 or /48),
/// not by node: a cluster of ground IDs closer to a service than every honest
/// node could otherwise make the honest storers believe they are no longer
/// near it, refuse its next republish, and let the descriptor expire with
/// only the cluster holding it. Filling a store is what the quota and the
/// eviction rules are for, not this.
pub fn is_near(table: &RoutingTable, our_id: &NodeId, target: &NodeId) -> bool {
    let ours = our_id.xor_distance(target);
    let mut closer: HashSet<Neighbourhood> = HashSet::new();
    for n in table.find_closest(target, table.total_nodes()) {
        if n.id.xor_distance(target) >= ours {
            break;
        }
        closer.insert(neighbourhood(&n.dht_addr));
        if closer.len() >= NEAR_NEIGHBOURHOODS {
            return false;
        }
    }
    true
}

pub struct DhtHandler;

impl DhtHandler {
    pub fn handle_message(
        table: &RoutingTable,
        msg: DhtMessage,
        our_info: &NodeInfo,
        _sender_addr: SocketAddr,
        services: &mut ServiceStore,
        now: u64,
    ) -> HandleResult {
        let contact = msg.sender().cloned();
        let reply = |r: DhtMessage| HandleResult {
            response: Some(r),
            contact: contact.clone(),
        };
        match msg {
            DhtMessage::Ping { request_id, sender } => {
                info!(
                    dht_message_type = "PING",
                    node_id = %sender.id,
                    peer_count = table.total_nodes(),
                    "received DHT PING"
                );
                reply(DhtMessage::Pong {
                    request_id,
                    sender: our_info.clone(),
                })
            }
            DhtMessage::FindNode { request_id, sender, target } => {
                info!(
                    dht_message_type = "FIND_NODE",
                    node_id = %sender.id,
                    target = %target,
                    peer_count = table.total_nodes(),
                    "received FIND_NODE"
                );
                let closest = table.find_closest(&target, K);
                debug!(nodes_count = closest.len(), "sending FIND_NODE response");
                reply(DhtMessage::FindNodeResponse {
                    request_id,
                    sender: our_info.clone(),
                    nodes: closest,
                })
            }
            DhtMessage::Store { request_id, sender, .. } => {
                info!(dht_message_type = "STORE", node_id = %sender.id, "received STORE");
                reply(DhtMessage::StoreResponse {
                    request_id,
                    stored: true,
                })
            }
            DhtMessage::AnnounceService {
                request_id: _,
                sender,
                service_hash,
                descriptor,
            } => {
                let near = is_near(table, &our_info.id, &service_target(&service_hash));
                let kept = near
                    && services
                        .put(service_hash, descriptor, Origin::Pushed(sender.id), now)
                        .is_ok();
                info!(
                    dht_message_type = "ANNOUNCE_SERVICE",
                    node_id = %sender.id,
                    near,
                    kept,
                    stored = services.len(),
                    "received service announcement"
                );
                HandleResult { response: None, contact }
            }
            DhtMessage::LookupService {
                request_id,
                sender,
                service_hash,
            } => {
                info!(
                    dht_message_type = "LOOKUP_SERVICE",
                    node_id = %sender.id,
                    "received service lookup"
                );
                reply(DhtMessage::LookupServiceResponse {
                    request_id,
                    sender: our_info.clone(),
                    descriptor: services.get(&service_hash, now).map(|s| s.descriptor.clone()),
                })
            }
            DhtMessage::AnnounceRelay { request_id: _, sender } => {
                // Seated like any contact, after a PING at the address it
                // wrote from. Not passed on: a relay announces itself to its
                // own neighbourhood, and passing announcements on is what
                // let one packet loop through the network.
                info!(
                    dht_message_type = "ANNOUNCE_RELAY",
                    node_id = %sender.id,
                    is_relay = sender.is_relay(),
                    "received relay announcement"
                );
                HandleResult { response: None, contact }
            }
            // Answers go to the request that is waiting for them (see
            // `process_packet`); one that reaches here is unsolicited and
            // seats nothing.
            DhtMessage::Pong { .. }
            | DhtMessage::FindNodeResponse { .. }
            | DhtMessage::StoreResponse { .. }
            | DhtMessage::LookupServiceResponse { .. } => HandleResult {
                response: None,
                contact: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::dht::descriptor::ServiceDescriptor;
    use crate::p2p::dht::node::ID_LEN;
    use crate::p2p::dht::store::now_secs;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn info(id: [u8; ID_LEN], port: u16) -> NodeInfo {
        NodeInfo {
            id: NodeId(id),
            dht_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            relay_addr: None,
            public_key: [0u8; 32],
            id_nonce: 0,
        }
    }

    fn public(id: [u8; ID_LEN], net: u8, host: u8) -> NodeInfo {
        NodeInfo {
            id: NodeId(id),
            dht_addr: format!("198.{net}.100.{host}:7000").parse().unwrap(),
            relay_addr: None,
            public_key: [0u8; 32],
            id_nonce: 0,
        }
    }

    #[test]
    fn nearness_counts_networks_not_nodes() {
        let now = now_secs();
        let key = SigningKey::generate(&mut OsRng);
        let d = ServiceDescriptor::sign(&key, vec!["198.51.100.7:9001".parse().unwrap()], now);
        let hash = d.service_hash();
        let target = service_target(&hash);
        // A storer close to the service: its ID differs from the target only
        // in the low 16 bits. A node at distance (0xFFFF - j) from the target
        // is closer than it, and sits in its bucket for the highest bit of j,
        // so nodes closer than it spread over many buckets.
        let with_low = |low: u16| {
            let mut id = target.0;
            let t = u16::from_be_bytes([id[ID_LEN - 2], id[ID_LEN - 1]]);
            let v = (t ^ low).to_be_bytes();
            id[ID_LEN - 2] = v[0];
            id[ID_LEN - 1] = v[1];
            id
        };
        let me = info(with_low(0xFFFF), 7000);
        let closer = |i: usize| with_low(0xFFFF - ((1u16 << (6 + i / 7)) + (i % 7) as u16));
        let msg = DhtMessage::AnnounceService {
            request_id: 1,
            sender: info([7; ID_LEN], 9000),
            service_hash: hash,
            descriptor: d.clone(),
        };

        // A cluster of IDs closer to the service, from five networks: this
        // node still counts itself near and keeps the descriptor.
        let mut table = RoutingTable::new(me.id);
        for i in 0..63usize {
            table.update(public(closer(i), (i % 5) as u8, i as u8 + 1));
        }
        assert!(table.total_nodes() >= 20, "the cluster holds at least a bucket's worth of seats");
        let mut store = ServiceStore::new();
        let r = DhtHandler::handle_message(&table, msg.clone(), &me, "127.0.0.1:9000".parse().unwrap(), &mut store, now);
        assert!(store.get(&hash, now).is_some(), "a cluster from five networks does not push it out");
        assert!(r.contact.is_some());

        // As many distinct networks closer as NEAR_NEIGHBOURHOODS: not this
        // node's to keep.
        let mut table = RoutingTable::new(me.id);
        for i in 0..63usize {
            table.update(public(closer(i), i as u8, 1));
        }
        assert!(table.total_nodes() >= NEAR_NEIGHBOURHOODS);
        let mut store = ServiceStore::new();
        DhtHandler::handle_message(&table, msg.clone(), &me, "127.0.0.1:9000".parse().unwrap(), &mut store, now);
        assert!(store.get(&hash, now).is_none(), "behind that many networks, it does not keep it");

        // A node with an empty table is as near as anyone it knows of.
        let empty = RoutingTable::new(me.id);
        DhtHandler::handle_message(&empty, msg, &me, "127.0.0.1:9000".parse().unwrap(), &mut store, now);
        assert!(store.get(&hash, now).is_some());
    }

    #[test]
    fn nearness_turns_at_exactly_sixty_networks() {
        let now = now_secs();
        let key = SigningKey::generate(&mut OsRng);
        let d = ServiceDescriptor::sign(&key, vec!["198.51.100.7:9001".parse().unwrap()], now);
        let hash = d.service_hash();
        let target = service_target(&hash);
        let with_low = |low: u16| {
            let mut id = target.0;
            let t = u16::from_be_bytes([id[ID_LEN - 2], id[ID_LEN - 1]]);
            let v = (t ^ low).to_be_bytes();
            id[ID_LEN - 2] = v[0];
            id[ID_LEN - 1] = v[1];
            id
        };
        let me = info(with_low(0xFFFF), 7000);
        let closer = |i: usize| with_low(0xFFFF - ((1u16 << (6 + i / 7)) + (i % 7) as u16));
        // Farther from the service than this node: they differ from it above
        // the low 16 bits, so they never count, however many networks.
        let farther = |i: usize| {
            let mut id = target.0;
            id[ID_LEN - 3] ^= 1 << (i % 8);
            id[ID_LEN - 4] ^= (i / 8) as u8;
            id
        };
        let keeps = |closer_networks: usize| {
            let mut table = RoutingTable::new(me.id);
            for i in 0..closer_networks {
                table.update(public(closer(i), i as u8, 1));
            }
            for i in 0..16usize {
                table.update(public(farther(i), 200 + (i % 50) as u8, i as u8 + 1));
            }
            assert_eq!(
                table.find_closest(&target, table.total_nodes()).iter()
                    .filter(|n| n.id.xor_distance(&target) < me.id.xor_distance(&target))
                    .count(),
                closer_networks,
                "every closer node is seated"
            );
            let msg = DhtMessage::AnnounceService {
                request_id: 1,
                sender: info([7; ID_LEN], 9000),
                service_hash: hash,
                descriptor: d.clone(),
            };
            let mut store = ServiceStore::new();
            DhtHandler::handle_message(&table, msg, &me, "127.0.0.1:9000".parse().unwrap(), &mut store, now);
            store.get(&hash, now).is_some()
        };
        assert!(keeps(NEAR_NEIGHBOURHOODS - 1), "fifty-nine closer networks: still near");
        assert!(!keeps(NEAR_NEIGHBOURHOODS), "sixty closer networks: not near");
    }

    #[test]
    fn unsolicited_answers_seat_nothing() {
        let me = info([1; ID_LEN], 7000);
        let table = RoutingTable::new(me.id);
        let mut store = ServiceStore::new();
        let stranger = info([9; ID_LEN], 7001);
        for msg in [
            DhtMessage::Pong { request_id: 1, sender: stranger.clone() },
            DhtMessage::FindNodeResponse { request_id: 1, sender: stranger.clone(), nodes: vec![stranger.clone()] },
            DhtMessage::LookupServiceResponse { request_id: 1, sender: stranger.clone(), descriptor: None },
        ] {
            let r = DhtHandler::handle_message(&table, msg, &me, "127.0.0.1:7001".parse().unwrap(), &mut store, 0);
            assert!(r.contact.is_none() && r.response.is_none());
        }
    }
}
