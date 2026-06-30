use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

pub const ID_LEN: usize = 20;
pub const ID_BITS: usize = ID_LEN * 8;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; ID_LEN]);

impl NodeId {
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
        for i in 0..ID_LEN {
            dist[i] = self.0[i] ^ other.0[i];
        }
        dist
    }

    pub fn bucket_index(&self, other: &NodeId) -> Option<usize> {
        let dist = self.xor_distance(other);
        leading_bit_position(&dist)
    }

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
}

impl NodeInfo {
    pub fn is_relay(&self) -> bool {
        self.relay_addr.is_some()
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
    fn is_closer() {
        let target = NodeId([0x00; ID_LEN]);
        let close = NodeId([0x01; ID_LEN]);
        let far = NodeId([0xFF; ID_LEN]);
        assert!(close.is_closer(&target, &far));
        assert!(!far.is_closer(&target, &close));
    }
}
