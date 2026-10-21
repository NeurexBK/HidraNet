use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use crate::p2p::dht::node::{NodeId, NodeInfo, ID_BITS};

pub const K: usize = 20;

/// How many nodes of one network neighbourhood (an IPv4 /24, an IPv6 /48) a
/// bucket keeps, and the whole table. Addresses are the one thing a Sybil
/// operator cannot mint by the thousand: a puzzle costs CPU, but a hundred
/// identities on one rented server still share its /24, so they get two
/// seats in a bucket and ten in the table, not the table.
pub const MAX_PER_PREFIX_IN_BUCKET: usize = 2;
pub const MAX_PER_PREFIX_IN_TABLE: usize = 10;

/// Which network an address is in, for anything that should count one
/// operator's addresses once: an IPv4 /24 or IPv6 /48 on the public internet,
/// the host itself for addresses that are not (each LAN host counts alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Neighbourhood {
    Prefix([u8; 7]),
    Host(IpAddr),
}

pub fn neighbourhood(addr: &SocketAddr) -> Neighbourhood {
    match diversity_prefix(addr) {
        Some(p) => Neighbourhood::Prefix(p),
        None => Neighbourhood::Host(addr.ip()),
    }
}

/// The neighbourhood an address belongs to, for the limits above; None for
/// addresses that are not on the public internet (loopback, private, link
/// local, unique local, unspecified), which no outside operator can fill a
/// table with and which a LAN or a test legitimately shares.
pub fn diversity_prefix(addr: &SocketAddr) -> Option<[u8; 7]> {
    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() {
                return None;
            }
            let o = v4.octets();
            Some([4, o[0], o[1], o[2], 0, 0, 0])
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return diversity_prefix(&SocketAddr::new(IpAddr::V4(v4), addr.port()));
            }
            let seg = v6.segments();
            let unique_local = (seg[0] & 0xfe00) == 0xfc00;
            let link_local = (seg[0] & 0xffc0) == 0xfe80;
            if v6.is_loopback() || v6.is_unspecified() || unique_local || link_local {
                return None;
            }
            let o = v6.octets();
            Some([6, o[0], o[1], o[2], o[3], o[4], o[5]])
        }
    }
}

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
        Self { entries: Vec::with_capacity(K) }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn is_full(&self) -> bool {
        self.entries.len() >= K
    }

    #[allow(dead_code)]
    fn contains(&self, id: &NodeId) -> bool {
        self.entries.iter().any(|e| e.info.id == *id)
    }

    fn count_prefix(&self, prefix: &[u8; 7], except: &NodeId) -> usize {
        self.entries
            .iter()
            .filter(|e| e.info.id != *except && diversity_prefix(&e.info.dht_addr).as_ref() == Some(prefix))
            .count()
    }

    fn update_or_insert(&mut self, info: NodeInfo) -> UpdateResult {
        if let Some(pos) =
            self.entries.iter().position(|e| e.info.id == info.id)
        {
            // The address a node was verified at stays until the node stops
            // answering there; another claim does not move it.
            if self.entries[pos].info.dht_addr != info.dht_addr {
                return UpdateResult::AddressKept;
            }
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
        if let Some(pos) =
            self.entries.iter().position(|e| e.info.id == *id)
        {
            self.entries.remove(pos);
            true
        } else {
            false
        }
    }

    fn get_nodes(&self) -> Vec<NodeInfo> {
        self.entries.iter().map(|e| e.info.clone()).collect()
    }

    fn stale_nodes(
        &self,
        timeout: std::time::Duration,
    ) -> Vec<NodeId> {
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
    BucketFull {
        #[allow(dead_code)] // for a future eviction ping, as Kademlia describes
        least_recent_id: NodeId,
    },
    /// Its network neighbourhood already has its share of the table.
    TooManyFromPrefix,
    /// The node is seated at another address, which stays.
    AddressKept,
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

    #[allow(dead_code)]
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
        if let Some(prefix) = diversity_prefix(&info.dht_addr) {
            let in_bucket = self.buckets[bucket_idx].count_prefix(&prefix, &info.id);
            let in_table: usize = self
                .buckets
                .iter()
                .map(|b| b.count_prefix(&prefix, &info.id))
                .sum();
            if in_bucket >= MAX_PER_PREFIX_IN_BUCKET || in_table >= MAX_PER_PREFIX_IN_TABLE {
                return UpdateResult::TooManyFromPrefix;
            }
        }
        self.buckets[bucket_idx].update_or_insert(info)
    }

    pub fn remove(&mut self, id: &NodeId) {
        if let Some(idx) = self.our_id.bucket_index(id) {
            self.buckets[idx].remove(id);
        }
    }

    pub fn find_closest(
        &self,
        target: &NodeId,
        count: usize,
    ) -> Vec<NodeInfo> {
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

    pub fn stale_nodes(
        &self,
        timeout: std::time::Duration,
    ) -> Vec<NodeId> {
        self.buckets
            .iter()
            .flat_map(|b| b.stale_nodes(timeout))
            .collect()
    }

    pub fn total_nodes(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    /// The address this node is seated at, if it is seated.
    pub fn address_of(&self, id: &NodeId) -> Option<SocketAddr> {
        let idx = self.our_id.bucket_index(id)?;
        self.buckets[idx]
            .entries
            .iter()
            .find(|e| e.info.id == *id)
            .map(|e| e.info.dht_addr)
    }

    #[allow(dead_code)] // the integration tests read the table through the library
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
            id_nonce: 0,
            relay_descriptor: None,
        }
    }

    fn make_relay(id_byte: u8, dht_port: u16, relay_port: u16) -> NodeInfo {
        NodeInfo {
            id: NodeId([id_byte; ID_LEN]),
            dht_addr: format!("127.0.0.1:{dht_port}").parse().unwrap(),
            relay_addr: Some(format!("127.0.0.1:{relay_port}").parse().unwrap()),
            public_key: [0u8; 32],
            id_nonce: 0,
            relay_descriptor: None,
        }
    }

    fn public_node(first: u8, second: u8, net: [u8; 3], host: u8) -> NodeInfo {
        let mut id = [0u8; ID_LEN];
        id[0] = first;
        id[1] = second;
        NodeInfo {
            id: NodeId(id),
            dht_addr: format!("{}.{}.{}.{host}:7000", net[0], net[1], net[2]).parse().unwrap(),
            relay_addr: None,
            public_key: [0u8; 32],
            id_nonce: 0,
            relay_descriptor: None,
        }
    }

    #[test]
    fn one_neighbourhood_gets_two_seats_in_a_bucket_and_ten_in_the_table() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);
        // Twenty identities from one /24, all for the same bucket.
        let mut inserted = 0;
        for i in 0..20u8 {
            if matches!(table.update(public_node(0x80, i, [198, 51, 100], i + 1)), UpdateResult::Inserted) {
                inserted += 1;
            }
        }
        assert_eq!(inserted, MAX_PER_PREFIX_IN_BUCKET);
        // Another /24 still gets in.
        assert!(matches!(table.update(public_node(0x80, 99, [203, 0, 113], 1)), UpdateResult::Inserted));

        // Spread over many buckets, one /24 stops at the table-wide cap.
        let mut table = RoutingTable::new(our_id);
        let mut total = 0;
        for bucket in 0..40u8 {
            let first = 0x80u8 >> (bucket % 8);
            for j in 0..2u8 {
                if matches!(
                    table.update(public_node(first, bucket * 2 + j, [192, 0, 2], bucket * 2 + j + 1)),
                    UpdateResult::Inserted
                ) {
                    total += 1;
                }
            }
        }
        assert_eq!(total, MAX_PER_PREFIX_IN_TABLE);

        // An existing entry may refresh itself at its cap.
        let mut table = RoutingTable::new(our_id);
        let a = public_node(0x80, 1, [198, 51, 100], 1);
        let b = public_node(0x80, 2, [198, 51, 100], 2);
        assert!(matches!(table.update(a.clone()), UpdateResult::Inserted));
        assert!(matches!(table.update(b), UpdateResult::Inserted));
        assert!(matches!(table.update(a), UpdateResult::Updated));
    }

    #[test]
    fn a_seated_node_keeps_its_address() {
        let our_id = NodeId([0x00; ID_LEN]);
        let mut table = RoutingTable::new(our_id);
        let real = public_node(0x80, 1, [198, 51, 100], 1);
        assert!(matches!(table.update(real.clone()), UpdateResult::Inserted));
        let mut moved = real.clone();
        moved.dht_addr = "203.0.113.66:7000".parse().unwrap();
        moved.relay_addr = Some("203.0.113.66:9001".parse().unwrap());
        assert!(matches!(table.update(moved), UpdateResult::AddressKept));
        assert_eq!(table.address_of(&real.id), Some(real.dht_addr));
        let seated = table.find_closest(&real.id, 1);
        assert_eq!(seated[0].relay_addr, None, "nor does its relay address change");
        // Once it is gone (it stopped answering), another address may be seated.
        table.remove(&real.id);
        let mut moved = real.clone();
        moved.dht_addr = "203.0.113.66:7000".parse().unwrap();
        assert!(matches!(table.update(moved), UpdateResult::Inserted));
    }

    #[test]
    fn loopback_private_and_local_addresses_are_not_limited() {
        for a in ["127.0.0.1:1", "10.1.2.3:1", "192.168.1.1:1", "172.16.0.1:1", "169.254.1.1:1", "[::1]:1", "[fd00::1]:1", "[fe80::1]:1", "[::ffff:10.0.0.1]:1"] {
            assert!(diversity_prefix(&a.parse().unwrap()).is_none(), "{a}");
        }
        for a in ["198.51.100.7:1", "[2001:db8::1]:1", "[::ffff:198.51.100.7]:1"] {
            assert!(diversity_prefix(&a.parse().unwrap()).is_some(), "{a}");
        }
        assert_eq!(
            diversity_prefix(&"198.51.100.7:1".parse().unwrap()),
            diversity_prefix(&"[::ffff:198.51.100.200]:9".parse().unwrap()),
            "an IPv4-mapped address is its IPv4 /24"
        );
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
            id_nonce: 0,
            relay_descriptor: None,
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
            id_nonce: 0,
            relay_descriptor: None,
        };

        table.update(node1.clone());
        table.update(node2.clone());
        table.update(node1.clone());

        let target = NodeId([0x80; ID_LEN]);
        let closest = table.find_closest(&target, 2);
        assert_eq!(closest.len(), 2);
    }
}
