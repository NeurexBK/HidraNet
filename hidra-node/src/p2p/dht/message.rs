use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{HidraError, Result};
use crate::p2p::dht::node::{NodeId, NodeInfo};

const MAGIC: &[u8; 4] = b"HDHT";
const SIGNATURE_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + SIGNATURE_LEN + PUBKEY_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessage {
    Ping {
        request_id: u64,
        sender: NodeInfo,
    },
    Pong {
        request_id: u64,
        sender: NodeInfo,
    },
    FindNode {
        request_id: u64,
        sender: NodeInfo,
        target: NodeId,
    },
    FindNodeResponse {
        request_id: u64,
        nodes: Vec<NodeInfo>,
    },
    Store {
        request_id: u64,
        sender: NodeInfo,
        key: NodeId,
        value: Vec<u8>,
    },
    StoreResponse {
        request_id: u64,
        stored: bool,
    },
    AnnounceRelay {
        request_id: u64,
        sender: NodeInfo,
    },
}

impl DhtMessage {
    pub fn request_id(&self) -> u64 {
        match self {
            Self::Ping { request_id, .. }
            | Self::Pong { request_id, .. }
            | Self::FindNode { request_id, .. }
            | Self::FindNodeResponse { request_id, .. }
            | Self::Store { request_id, .. }
            | Self::StoreResponse { request_id, .. }
            | Self::AnnounceRelay { request_id, .. } => *request_id,
        }
    }

    pub fn message_type(&self) -> &'static str {
        match self {
            Self::Ping { .. } => "PING",
            Self::Pong { .. } => "PONG",
            Self::FindNode { .. } => "FIND_NODE",
            Self::FindNodeResponse { .. } => "FIND_NODE_RESPONSE",
            Self::Store { .. } => "STORE",
            Self::StoreResponse { .. } => "STORE_RESPONSE",
            Self::AnnounceRelay { .. } => "ANNOUNCE_RELAY",
        }
    }

    pub fn is_response(&self) -> bool {
        matches!(
            self,
            Self::Pong { .. } | Self::FindNodeResponse { .. } | Self::StoreResponse { .. }
        )
    }
}

pub fn sign_and_serialize(msg: &DhtMessage, signing_key: &SigningKey) -> Result<Vec<u8>> {
    let payload = bincode::serialize(msg)
        .map_err(|e| HidraError::Protocol(format!("DHT message serialize failed: {e}")))?;

    let pubkey_bytes = signing_key.verifying_key().to_bytes();

    let mut sign_data = Vec::with_capacity(PUBKEY_LEN + payload.len());
    sign_data.extend_from_slice(&pubkey_bytes);
    sign_data.extend_from_slice(&payload);

    let signature = signing_key.sign(&sign_data);

    let mut packet = Vec::with_capacity(HEADER_LEN + payload.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&signature.to_bytes());
    packet.extend_from_slice(&pubkey_bytes);
    packet.extend_from_slice(&payload);

    Ok(packet)
}

pub fn verify_and_deserialize(packet: &[u8]) -> Result<(DhtMessage, [u8; 32])> {
    if packet.len() < HEADER_LEN {
        return Err(HidraError::Protocol("DHT packet too short".into()));
    }

    if &packet[..4] != MAGIC {
        return Err(HidraError::Protocol("invalid DHT magic bytes".into()));
    }

    let sig_bytes: [u8; SIGNATURE_LEN] = packet[4..4 + SIGNATURE_LEN]
        .try_into()
        .map_err(|_| HidraError::Protocol("invalid signature length".into()))?;

    let pubkey_bytes: [u8; PUBKEY_LEN] = packet[4 + SIGNATURE_LEN..HEADER_LEN]
        .try_into()
        .map_err(|_| HidraError::Protocol("invalid pubkey length".into()))?;

    let payload = &packet[HEADER_LEN..];

    let signature = Signature::from_bytes(&sig_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| HidraError::Crypto(format!("invalid Ed25519 public key: {e}")))?;

    let mut sign_data = Vec::with_capacity(PUBKEY_LEN + payload.len());
    sign_data.extend_from_slice(&pubkey_bytes);
    sign_data.extend_from_slice(payload);

    verifying_key
        .verify(&sign_data, &signature)
        .map_err(|_| HidraError::Crypto("DHT message signature verification failed".into()))?;

    let msg: DhtMessage = bincode::deserialize(payload)
        .map_err(|e| HidraError::Protocol(format!("DHT message deserialize failed: {e}")))?;

    Ok((msg, pubkey_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::dht::node::ID_LEN;
    use rand_core::OsRng;

    fn test_node_info() -> NodeInfo {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        NodeInfo {
            id: NodeId::from_public_key(&pubkey),
            dht_addr: "127.0.0.1:7000".parse().unwrap(),
            relay_addr: None,
            public_key: pubkey,
        }
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let info = test_node_info();
        let msg = DhtMessage::Ping {
            request_id: 42,
            sender: info,
        };

        let packet = sign_and_serialize(&msg, &signing_key).unwrap();
        let (decoded, pubkey) = verify_and_deserialize(&packet).unwrap();

        assert_eq!(decoded.request_id(), 42);
        assert_eq!(pubkey, signing_key.verifying_key().to_bytes());
    }

    #[test]
    fn tampered_packet_rejected() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let info = test_node_info();
        let msg = DhtMessage::Ping {
            request_id: 1,
            sender: info,
        };

        let mut packet = sign_and_serialize(&msg, &signing_key).unwrap();
        let last = packet.len() - 1;
        packet[last] ^= 0xFF;

        assert!(verify_and_deserialize(&packet).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        let info = test_node_info();
        let msg = DhtMessage::Ping {
            request_id: 1,
            sender: info,
        };

        let mut packet = sign_and_serialize(&msg, &key1).unwrap();
        let key2_bytes = key2.verifying_key().to_bytes();
        packet[4 + SIGNATURE_LEN..4 + SIGNATURE_LEN + PUBKEY_LEN]
            .copy_from_slice(&key2_bytes);

        assert!(verify_and_deserialize(&packet).is_err());
    }

    #[test]
    fn find_node_roundtrip() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let info = test_node_info();
        let target = NodeId([0xAB; ID_LEN]);

        let msg = DhtMessage::FindNode {
            request_id: 99,
            sender: info,
            target,
        };

        let packet = sign_and_serialize(&msg, &signing_key).unwrap();
        let (decoded, _) = verify_and_deserialize(&packet).unwrap();

        match decoded {
            DhtMessage::FindNode {
                request_id, target, ..
            } => {
                assert_eq!(request_id, 99);
                assert_eq!(target.0, [0xAB; ID_LEN]);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn message_type_names() {
        let info = test_node_info();
        assert_eq!(
            DhtMessage::Ping {
                request_id: 0,
                sender: info.clone()
            }
            .message_type(),
            "PING"
        );
        assert_eq!(
            DhtMessage::FindNode {
                request_id: 0,
                sender: info,
                target: NodeId([0; ID_LEN])
            }
            .message_type(),
            "FIND_NODE"
        );
    }
}
