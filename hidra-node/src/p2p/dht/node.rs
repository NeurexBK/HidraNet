use std::fmt;
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};

pub const ID_LEN: usize = 20;
pub const ID_BITS: usize = ID_LEN * 8;

/// How much work a node ID costs, in leading zero bits of the puzzle half of
/// its hash: 2^24 BLAKE3 evaluations, about two seconds on one core, once per
/// key. Every node of a network must use the same value; tests and private
/// networks pass their own to `DhtNode::with_id_bits`.
///
/// What it buys: a node's ID is only known once the work is done (the ID and
/// the puzzle are two halves of the same hash), so an operator who wants an
/// ID near a target cannot test closeness for free and pay only for the IDs
/// it keeps. Landing one identity among the K closest to a key in a network
/// of N nodes costs about (N / K) * 2^ID_PUZZLE_BITS hashes, and owning the
/// whole closest set K times that. It raises the price of an eclipse with
/// the size of the network; it does not make one impossible for an attacker
/// with hardware to spend, which is why lookups also take disjoint paths and
/// service records are signed by the service itself.
pub const ID_PUZZLE_BITS: u32 = 24;

/// The most a network can ask: the puzzle half of the hash is 12 bytes.
pub const MAX_ID_PUZZLE_BITS: u32 = 64;

const ID_DOMAIN: &[u8] = b"hidra/node-id/v1";

fn id_hash(public_key: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ID_DOMAIN);
    h.update(public_key);
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut n = 0;
    for b in bytes {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// True when `nonce` solves the ID puzzle for this key at `bits` difficulty.
pub fn id_puzzle_ok(public_key: &[u8; 32], nonce: u64, bits: u32) -> bool {
    let h = id_hash(public_key, nonce);
    leading_zero_bits(&h[ID_LEN..]) >= bits.min(MAX_ID_PUZZLE_BITS)
}

/// The first nonce that solves the puzzle for this key: deterministic, so a
/// node that keeps its key keeps its ID across restarts.
pub fn solve_id_puzzle(public_key: &[u8; 32], bits: u32) -> u64 {
    let bits = bits.min(MAX_ID_PUZZLE_BITS);
    let mut nonce = 0u64;
    loop {
        let h = id_hash(public_key, nonce);
        if leading_zero_bits(&h[ID_LEN..]) >= bits {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; ID_LEN]);

impl NodeId {
    /// A node's ID: the first half of the hash whose second half is the
    /// puzzle. Only `NodeInfo::id_is_valid` decides whether it was earned.
    pub fn for_node(public_key: &[u8; 32], nonce: u64) -> Self {
        let h = id_hash(public_key, nonce);
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&h[..ID_LEN]);
        Self(id)
    }

    /// A position in the key space for a 32-byte value (a service's address
    /// is placed here). Not a node ID: node IDs come from `for_node`.
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let hash = blake3::hash(pubkey);
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&hash.as_bytes()[..ID_LEN]);
        Self(id)
    }

    pub fn random() -> Self {
        let mut id = [0u8; ID_LEN];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
        Self(id)
    }

    pub fn xor_distance(&self, other: &NodeId) -> [u8; ID_LEN] {
        let mut dist = [0u8; ID_LEN];
        for (d, (a, b)) in dist
            .iter_mut()
            .zip(self.0.iter().zip(other.0.iter()))
        {
            *d = a ^ b;
        }
        dist
    }

    pub fn bucket_index(&self, other: &NodeId) -> Option<usize> {
        let dist = self.xor_distance(other);
        leading_bit_position(&dist)
    }
    /// True when self sits nearer `target` in XOR space than `other` does.
    ///
    /// Only the test uses it today — the lookup loops sort by distance rather
    /// than compare pairwise — but it is the definition the whole routing
    /// table rests on, and a test that pins it is worth more than the line
    /// it costs.
    #[allow(dead_code)]
    pub fn is_closer(&self, target: &NodeId, other: &NodeId) -> bool {
        let d_self = self.xor_distance(target);
        let d_other = other.xor_distance(target);
        d_self < d_other
    }
}

fn leading_bit_position(data: &[u8; ID_LEN]) -> Option<usize> {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            let bit_in_byte = 7 - byte.leading_zeros() as usize;
            return Some((ID_LEN - 1 - i) * 8 + bit_in_byte);
        }
    }
    None
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "..)")
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub dht_addr: SocketAddr,
    pub relay_addr: Option<SocketAddr>,
    pub public_key: [u8; 32],
    /// The nonce that solves this key's ID puzzle; the ID derives from it.
    pub id_nonce: u64,
}

impl NodeInfo {
    pub fn is_relay(&self) -> bool {
        self.relay_addr.is_some()
    }

    /// The ID is the one this key and nonce derive, and the nonce solves the
    /// puzzle at `bits`. A NodeInfo that fails this is a claim nobody paid
    /// for, wherever it came from: a sender, a FIND_NODE answer, a gossip.
    pub fn id_is_valid(&self, bits: u32) -> bool {
        self.id == NodeId::for_node(&self.public_key, self.id_nonce)
            && id_puzzle_ok(&self.public_key, self.id_nonce, bits)
    }
}

impl PartialEq for NodeInfo {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for NodeInfo {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_distance_identity() {
        let a = NodeId([0xAA; ID_LEN]);
        let dist = a.xor_distance(&a);
        assert_eq!(dist, [0u8; ID_LEN]);
    }

    #[test]
    fn xor_distance_symmetry() {
        let a = NodeId([0xAA; ID_LEN]);
        let b = NodeId([0x55; ID_LEN]);
        assert_eq!(a.xor_distance(&b), b.xor_distance(&a));
    }

    #[test]
    fn bucket_index_same_node_is_none() {
        let a = NodeId([0x42; ID_LEN]);
        assert!(a.bucket_index(&a).is_none());
    }

    #[test]
    fn bucket_index_lsb_difference() {
        let mut a = [0u8; ID_LEN];
        let mut b = [0u8; ID_LEN];
        a[ID_LEN - 1] = 0x00;
        b[ID_LEN - 1] = 0x01;
        let id_a = NodeId(a);
        let id_b = NodeId(b);
        assert_eq!(id_a.bucket_index(&id_b), Some(0));
    }

    #[test]
    fn bucket_index_msb_difference() {
        let a = [0u8; ID_LEN];
        let mut b = [0u8; ID_LEN];
        b[0] = 0x80;
        let id_a = NodeId(a);
        let id_b = NodeId(b);
        assert_eq!(id_a.bucket_index(&id_b), Some(ID_BITS - 1));
    }

    #[test]
    fn from_public_key_deterministic() {
        let key = [0x42u8; 32];
        let id1 = NodeId::from_public_key(&key);
        let id2 = NodeId::from_public_key(&key);
        assert_eq!(id1, id2);
    }

    #[test]
    fn an_id_is_earned_by_its_nonce_and_bound_to_its_key() {
        let key = [0x42u8; 32];
        let bits = 10;
        let nonce = solve_id_puzzle(&key, bits);
        assert!(id_puzzle_ok(&key, nonce, bits));
        assert_eq!(solve_id_puzzle(&key, bits), nonce, "deterministic");
        let info = NodeInfo {
            id: NodeId::for_node(&key, nonce),
            dht_addr: "127.0.0.1:7000".parse().unwrap(),
            relay_addr: None,
            public_key: key,
            id_nonce: nonce,
        };
        assert!(info.id_is_valid(bits));

        // Another nonce: another ID, and (almost surely) no solved puzzle.
        let unpaid = (0..u64::MAX).find(|n| !id_puzzle_ok(&key, *n, bits)).unwrap();
        let mut free = info.clone();
        free.id_nonce = unpaid;
        free.id = NodeId::for_node(&key, unpaid);
        assert!(!free.id_is_valid(bits), "an ID without the work is refused");

        // A chosen ID with a valid nonce of another key: refused.
        let mut squatted = info.clone();
        squatted.public_key = [0x43u8; 32];
        assert!(!squatted.id_is_valid(bits));

        // A chosen ID that is not the one the key and nonce derive: refused.
        let mut chosen = info;
        chosen.id = NodeId([0u8; ID_LEN]);
        assert!(!chosen.id_is_valid(bits));
    }

    #[test]
    fn the_puzzle_costs_what_its_bits_say() {
        // Each extra bit doubles the expected work; check that solutions at
        // 12 bits are rarer than at 4 by a wide margin over many keys.
        let mut work4 = 0u64;
        let mut work12 = 0u64;
        for i in 0..64u8 {
            let key = [i; 32];
            work4 += solve_id_puzzle(&key, 4) + 1;
            work12 += solve_id_puzzle(&key, 12) + 1;
        }
        assert!(work12 > work4 * 32, "work4={work4} work12={work12}");
    }

    #[test]
    fn is_closer() {
        let target = NodeId([0x00; ID_LEN]);
        let close = NodeId([0x01; ID_LEN]);
        let far = NodeId([0xFF; ID_LEN]);
        assert!(close.is_closer(&target, &far));
        assert!(!far.is_closer(&target, &close));
    }
}
