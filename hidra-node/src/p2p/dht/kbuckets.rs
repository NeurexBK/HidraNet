use std::time::Instant;

use crate::p2p::dht::node::{NodeId, NodeInfo, ID_BITS};

pub const K: usize = 20;

#[derive(Debug)]
struct BucketEntry {
    info: NodeInfo,
    last_seen: Instant,
}

#[derive(Debug)]
struct KBucket {
    entries: Vec<BucketEntry>,
}

impl KBucket {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(K),
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_full(&self) -> bool {
        self.entries.len() >= K
    }

    fn contains(&self, id: &NodeId) -> bool {
        self.entries.iter().any(|e| e.info.id == *id)
    }

    fn update_or_insert(&mut self, info: NodeInfo) -> UpdateResult {
        if let Some(pos) = self.entries.iter().position(|e| e.info.id == info.id) {
            self.entries[pos].info = info;
            self.entries[pos].last_seen = Instant::now();
            let entry = self.entries.remove(pos);
            self.entries.push(entry);
            UpdateResult::Updated
        } else if !self.is_full() {
            self.entries.push(BucketEntry {
                info,
                last_seen: Instant::now(),
            });
            UpdateResult::Inserted
        } else {
            UpdateResult::BucketFull {
                least_recent_id: self.entries[0].info.id,
            }
        }
    }

    fn remove(&mut self, id: &NodeId) -> bool {
        if let Some(pos) = self.entries.iter().position(|e| e.info.id == *id) {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    fn get_nodes(&self) -> Vec<NodeInfo> {
        self.entries.iter().map(|e| e.info.clone()).collect()
    }

    fn stale_nodes(&self, timeout: std::time::Duration) -> Vec<NodeId> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|e| now.duration_since(e.last_seen) > timeout)
            .map(|e| e.info.id)
            .collect()
    }
}

#[derive(Debug)]
pub enum UpdateResult {
    Inserted,
    Updated,
    BucketFull { least_recent_id: NodeId },
}

pub struct RoutingTable {
    our_id: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(our_id: NodeId) -> Self {
        let mut buckets = Vec::with_capacity(ID_BITS);
        for _ in 0..ID_BITS {
            buckets.push(KBucket::new());
        }
        Self { our_id, buckets }
    }

    pub fn our_id(&self) -> &NodeId {
        &self.our_id
    }

    pub fn update(&mut self, info: NodeInfo) -> UpdateResult {
        if info.id == self.our_id {
            return UpdateResult::Updated;
        }

        let bucket_idx = match self.our_id.bucket_index(&info.id) {
            Some(idx) => idx,
            None => return UpdateResult::Updated,
        };

        self.buckets[bucket_idx].update_or_insert(info)
    }

    pub fn remove(&mut self, id: &NodeId) {
        if let Some(idx) = self.our_id.bucket_index(id) {
            self.buckets[idx].remove(id);
        }
    }

    pub fn find_closest(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        let mut all_nodes: Vec<NodeInfo> = self
            .buckets
            .iter()
            .flat_map(|b| b.get_nodes())
            .collect();

        all_nodes.sort_by(|a, b| {
            let da = a.id.xor_distance(target);
            let db = b.id.xor_distance(target);
            da.cmp(&db)
        });

        all_nodes.truncate(count);
        all_nodes
    }

    pub fn find_relays(&self, count: usize) -> Vec<NodeInfo> {
        let mut relays: Vec<NodeInfo> = self
            .buckets
            .iter()
            .flat_map(|b| b.get_nodes())
            .filter(|n| n.is_relay())
            .collect();

        use rand::seq::SliceRandom;
        relays.shuffle(&mut rand::thread_rng());
        relays.truncate(count);
        relays
    }

    pub fn stale_nodes(&self, timeout: std::time::Duration) -> Vec<NodeId> {
        self.buckets
            .iter()
            .flat_map(|b| b.stale_nodes(timeout))
            .collect()
    }

    pub fn total_nodes(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn all_nodes(&self) -> Vec<NodeInfo> {
        self.buckets.iter().flat_map(|b| b.get_nodes()).collect()
    }

    pub fn bucket_stats(&self) -> Vec<(usize, usize)> {
        self.buckets
            .iter()
            .enumerate()
            .filter(|(_, b)| b.len() > 0)
            .map(|(i, b)| (i, b.len()))
            .collect()
    }

    pub fn contains(&self, id: &NodeId) -> bool {
        if let Some(idx) = self.our_id.bucket_index(id) {
            self.buckets[idx].contains(id)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::dht::node::ID_LEN;

    fn make_node(id_byte: u8, port: u16) -> NodeInfo {
        NodeInfo {
            id: NodeId([id_byte; ID_LEN]),
            dht_addr: format!("127.0.0.1:{port}").parse().unwrap(),
            relay_addr: None,
            public_key: [0u8; 32],
        }
    }

    fn make_relay(id_byte: u8, dht_port: u16, relay_port: u16) -> NodeInfo {
        NodeInfo {
            id: NodeId([id_byte; ID_LEN]),
            dht_addr: format!("127.0.0.1:{dht_port}").parse().unwrap(),
            relay_addr: Some(format!("127.0.0.1:{relay_port}").parse().unwrap()),
            public_key: [0u8; 32],
        }
    }

    #[test]
    fn insert_and_find() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);

        let node = make_node(0x01, 7001);
        let result = table.update(node.clone());
        assert!(matches!(result, UpdateResult::Inserted));

        let closest = table.find_closest(&NodeId([0x01; ID_LEN]), 10);
        assert_eq!(closest.len(), 1);
        assert_eq!(closest[0].id, node.id);
    }

    #[test]
    fn bucket_limit_k() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);

        for i in 0..K + 5 {
            let mut id = [0u8; ID_LEN];
            id[0] = 0x80;
            id[1] = i as u8;
            let node = NodeInfo {
                id: NodeId(id),
                dht_addr: format!("127.0.0.1:{}", 7000 + i).parse().unwrap(),
                relay_addr: None,
                public_key: [0u8; 32],
            };
            table.update(node);
        }

        assert_eq!(table.total_nodes(), K);
    }

    #[test]
    fn find_closest_returns_sorted() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);

        table.update(make_node(0xFF, 7001));
        table.update(make_node(0x01, 7002));
        table.update(make_node(0x80, 7003));

        let target = NodeId([0x00; ID_LEN]);
        let closest = table.find_closest(&target, 3);

        assert_eq!(closest[0].id, NodeId([0x01; ID_LEN]));
    }

    #[test]
    fn remove_node() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);

        let node = make_node(0x42, 7001);
        table.update(node.clone());
        assert!(table.contains(&node.id));

        table.remove(&node.id);
        assert!(!table.contains(&node.id));
    }

    #[test]
    fn find_relays_only() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);

        table.update(make_node(0x01, 7001));
        table.update(make_relay(0x02, 7002, 9150));
        table.update(make_node(0x03, 7003));
        table.update(make_relay(0x04, 7004, 9151));

        let relays = table.find_relays(10);
        assert_eq!(relays.len(), 2);
        assert!(relays.iter().all(|r| r.is_relay()));
    }

    #[test]
    fn self_insert_is_noop() {
        let our_id = NodeId([0x42; ID_LEN]);
        let mut table = RoutingTable::new(our_id);

        let self_node = make_node(0x42, 7001);
        table.update(self_node);
        assert_eq!(table.total_nodes(), 0);
    }

    #[test]
    fn update_moves_to_tail() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);

        let node1 = make_node(0x80, 7001);
        let mut node2_id = [0u8; ID_LEN];
        node2_id[0] = 0x80;
        node2_id[1] = 0x01;
        let node2 = NodeInfo {
            id: NodeId(node2_id),
            dht_addr: "127.0.0.1:7002".parse().unwrap(),
            relay_addr: None,
            public_key: [0u8; 32],
        };

        table.update(node1.clone());
        table.update(node2.clone());
        table.update(node1.clone());

        let target = NodeId([0x80; ID_LEN]);
        let closest = table.find_closest(&target, 2);
        assert_eq!(closest.len(), 2);
    }
}
