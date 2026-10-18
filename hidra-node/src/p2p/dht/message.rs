use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::{HidraError, Result};
use crate::p2p::dht::descriptor::ServiceDescriptor;
use crate::p2p::dht::node::{NodeId, NodeInfo};

/// Version 2 of the wire format: node IDs carry their puzzle nonce and
/// service descriptors their service's signature. A version-1 node drops
/// these packets at the magic instead of misreading them, and the other way
/// round.
const MAGIC: &[u8; 4] = b"HDT2";
const SIGNATURE_LEN: usize = 64;
const PUBKEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + SIGNATURE_LEN + PUBKEY_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtMessage {
    Ping { request_id: u64, sender: NodeInfo },
    Pong { request_id: u64, sender: NodeInfo },
    FindNode { request_id: u64, sender: NodeInfo, target: NodeId },
    /// `sender` is the answering node's own description, signed with the
    /// packet: what gets seated, never a third party's copy of it.
    FindNodeResponse { request_id: u64, sender: NodeInfo, nodes: Vec<NodeInfo> },
    Store { request_id: u64, sender: NodeInfo, key: NodeId, value: Vec<u8> },
    StoreResponse { request_id: u64, stored: bool },
    AnnounceRelay { request_id: u64, sender: NodeInfo },
    AnnounceService {
        request_id: u64,
        sender: NodeInfo,
        service_hash: [u8; 20],
        descriptor: ServiceDescriptor,
    },
    LookupService {
        request_id: u64,
        sender: NodeInfo,
        service_hash: [u8; 20],
    },
    LookupServiceResponse {
        request_id: u64,
        sender: NodeInfo,
        descriptor: Option<ServiceDescriptor>,
    },
}

impl DhtMessage {
    /// The node that claims to have sent this. Every message but
    /// STORE_RESPONSE carries one, and `verify_and_bind` holds it to the key
    /// that signed the packet.
    pub fn sender(&self) -> Option<&NodeInfo> {
        match self {
            Self::Ping { sender, .. }
            | Self::Pong { sender, .. }
            | Self::FindNode { sender, .. }
            | Self::FindNodeResponse { sender, .. }
            | Self::Store { sender, .. }
            | Self::AnnounceRelay { sender, .. }
            | Self::AnnounceService { sender, .. }
            | Self::LookupService { sender, .. }
            | Self::LookupServiceResponse { sender, .. } => Some(sender),
            Self::StoreResponse { .. } => None,
        }
    }

    pub fn request_id(&self) -> u64 {
        match self {
            Self::Ping { request_id, .. }
            | Self::Pong { request_id, .. }
            | Self::FindNode { request_id, .. }
            | Self::FindNodeResponse { request_id, .. }
            | Self::Store { request_id, .. }
            | Self::StoreResponse { request_id, .. }
            | Self::AnnounceRelay { request_id, .. }
            | Self::AnnounceService { request_id, .. }
            | Self::LookupService { request_id, .. }
            | Self::LookupServiceResponse { request_id, .. } => *request_id,
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
            Self::AnnounceService { .. } => "ANNOUNCE_SERVICE",
            Self::LookupService { .. } => "LOOKUP_SERVICE",
            Self::LookupServiceResponse { .. } => "LOOKUP_SERVICE_RESPONSE",
        }
    }

    pub fn is_response(&self) -> bool {
        matches!(
            self,
            Self::Pong { .. }
                | Self::FindNodeResponse { .. }
                | Self::StoreResponse { .. }
                | Self::LookupServiceResponse { .. }
        )
    }
}

pub fn sign_and_serialize(
    msg: &DhtMessage,
    signing_key: &SigningKey,
) -> Result<Vec<u8>> {
    let payload = bincode::serialize(msg).map_err(|e| {
        HidraError::Protocol(format!(
            "DHT message serialize failed: {e}"
        ))
    })?;
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let mut sign_data =
        Vec::with_capacity(PUBKEY_LEN + payload.len());
    sign_data.extend_from_slice(&pubkey_bytes);
    sign_data.extend_from_slice(&payload);
    let signature = signing_key.sign(&sign_data);
    let mut packet =
        Vec::with_capacity(HEADER_LEN + payload.len());
    packet.extend_from_slice(MAGIC);
    packet.extend_from_slice(&signature.to_bytes());
    packet.extend_from_slice(&pubkey_bytes);
    packet.extend_from_slice(&payload);
    Ok(packet)
}

/// Verifies the packet's signature AND binds the sender to the key that made
/// it: the sender's public key is the signing key, and its ID is the one that
/// key and its puzzle nonce derive, with the puzzle solved at `id_bits`. A
/// message whose sender claims another key, another ID, or an ID nobody paid
/// for is refused. This is what the DHT calls on every packet.
pub fn verify_and_bind(packet: &[u8], id_bits: u32) -> Result<(DhtMessage, [u8; 32])> {
    let (msg, pubkey) = verify_and_deserialize(packet)?;
    if let Some(sender) = msg.sender()
        && (sender.public_key != pubkey || !sender.id_is_valid(id_bits))
    {
        return Err(HidraError::Protocol(
            "DHT sender id does not match the signing key".into(),
        ));
    }
    Ok((msg, pubkey))
}

/// Verifies the packet's signature only; `verify_and_bind` is what the DHT
/// uses, because a valid signature alone does not tie the sender's claimed
/// ID to the key.
pub fn verify_and_deserialize(
    packet: &[u8],
) -> Result<(DhtMessage, [u8; 32])> {
    if packet.len() < HEADER_LEN {
        return Err(HidraError::Protocol(
            "DHT packet too short".into(),
        ));
    }
    if &packet[..4] != MAGIC {
        return Err(HidraError::Protocol(
            "invalid DHT magic bytes".into(),
        ));
    }
    let sig_bytes: [u8; SIGNATURE_LEN] =
        packet[4..4 + SIGNATURE_LEN].try_into().map_err(|_| {
            HidraError::Protocol("invalid signature length".into())
        })?;
    let pubkey_bytes: [u8; PUBKEY_LEN] =
        packet[4 + SIGNATURE_LEN..HEADER_LEN]
            .try_into()
            .map_err(|_| {
                HidraError::Protocol("invalid pubkey length".into())
            })?;
    let payload = &packet[HEADER_LEN..];
    let signature = Signature::from_bytes(&sig_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_bytes).map_err(|e| {
            HidraError::Crypto(format!(
                "invalid Ed25519 public key: {e}"
            ))
        })?;
    let mut sign_data =
        Vec::with_capacity(PUBKEY_LEN + payload.len());
    sign_data.extend_from_slice(&pubkey_bytes);
    sign_data.extend_from_slice(payload);
    verifying_key.verify(&sign_data, &signature).map_err(|_| {
        HidraError::Crypto(
            "DHT message signature verification failed".into(),
        )
    })?;
    let msg: DhtMessage =
        bincode::deserialize(payload).map_err(|e| {
            HidraError::Protocol(format!(
                "DHT message deserialize failed: {e}"
            ))
        })?;
    Ok((msg, pubkey_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::dht::node::{solve_id_puzzle, ID_LEN};
    use rand_core::OsRng;

    const BITS: u32 = 6;

    fn info_for(key: &SigningKey) -> NodeInfo {
        let pubkey = key.verifying_key().to_bytes();
        let nonce = solve_id_puzzle(&pubkey, BITS);
        NodeInfo {
            id: NodeId::for_node(&pubkey, nonce),
            dht_addr: "127.0.0.1:7000".parse().unwrap(),
            relay_addr: None,
            public_key: pubkey,
            id_nonce: nonce,
        }
    }

    fn test_node_info() -> NodeInfo {
        info_for(&SigningKey::generate(&mut OsRng))
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
    fn sender_id_must_match_the_signing_key() {
        // Signed with key A, claiming the ID (and public key) of key B: a
        // valid signature, and still refused.
        let key_a = SigningKey::generate(&mut OsRng);
        let key_b = SigningKey::generate(&mut OsRng);
        let claimed = info_for(&key_b);
        let msg = DhtMessage::Ping {
            request_id: 7,
            sender: claimed.clone(),
        };
        let packet = sign_and_serialize(&msg, &key_a).unwrap();
        assert!(verify_and_deserialize(&packet).is_ok(), "the signature itself is fine");
        let err = verify_and_bind(&packet, BITS).unwrap_err().to_string();
        assert!(err.contains("does not match the signing key"), "{err}");

        // The same ID claimed by its real holder passes.
        let honest = sign_and_serialize(&msg, &key_b).unwrap();
        assert!(verify_and_bind(&honest, BITS).is_ok());

        // The right ID but another public key in the NodeInfo: refused too,
        // or the routing table would remember a key nobody holds.
        let mut mixed = claimed;
        mixed.public_key = key_a.verifying_key().to_bytes();
        let msg = DhtMessage::Ping {
            request_id: 8,
            sender: mixed,
        };
        let packet = sign_and_serialize(&msg, &key_b).unwrap();
        assert!(verify_and_bind(&packet, BITS).is_err());

        // A response carries no sender; it is matched by request id and the
        // signature alone is checked.
        let resp = DhtMessage::StoreResponse {
            request_id: 9,
            stored: true,
        };
        let packet = sign_and_serialize(&resp, &key_a).unwrap();
        assert!(verify_and_bind(&packet, BITS).is_ok());
    }

    #[test]
    fn a_sender_whose_id_skipped_the_puzzle_is_refused() {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = key.verifying_key().to_bytes();
        let unpaid = (0..u64::MAX)
            .find(|n| !crate::p2p::dht::node::id_puzzle_ok(&pubkey, *n, BITS))
            .unwrap();
        let free = NodeInfo {
            id: NodeId::for_node(&pubkey, unpaid),
            dht_addr: "127.0.0.1:7000".parse().unwrap(),
            relay_addr: None,
            public_key: pubkey,
            id_nonce: unpaid,
        };
        let msg = DhtMessage::Ping {
            request_id: 1,
            sender: free,
        };
        let packet = sign_and_serialize(&msg, &key).unwrap();
        assert!(verify_and_deserialize(&packet).is_ok(), "signed by its own key");
        assert!(verify_and_bind(&packet, BITS).is_err(), "but its ID was never earned");
        assert!(verify_and_bind(&packet, 0).is_ok(), "at zero difficulty it would pass");
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
