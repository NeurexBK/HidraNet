use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::{HidraError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionCell {
    pub circuit_id: u32,
    pub cell_type: CellType,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellType {
    Data,
    Created,
    Destroy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerHeader {
    pub next_hop: Option<SocketAddr>,
}

impl OnionCell {
    pub fn serialize_bincode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| HidraError::Protocol(format!("cell serialization failed: {e}")))
    }

    pub fn deserialize_bincode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| HidraError::Protocol(format!("cell deserialization failed: {e}")))
    }
}

impl LayerHeader {
    pub fn serialize_bincode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| HidraError::Protocol(format!("header serialization failed: {e}")))
    }

    pub fn deserialize_bincode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| HidraError::Protocol(format!("header deserialization failed: {e}")))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayCommand {
    Connect { host: String, port: u16 },
    Connected,
    Data(Vec<u8>),
    End,
    ConnectFailed(String),
    ResolveDns { hostname: String },
    DnsResolved { addresses: Vec<String> },
}

impl RelayCommand {
    pub fn serialize_bincode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| HidraError::Protocol(format!("relay command serialize failed: {e}")))
    }

    pub fn deserialize_bincode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| HidraError::Protocol(format!("relay command deserialize failed: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_roundtrip() {
        let cell = OnionCell {
            circuit_id: 42,
            cell_type: CellType::Data,
            body: b"test payload".to_vec(),
        };
        let bytes = cell.serialize_bincode().unwrap();
        let decoded = OnionCell::deserialize_bincode(&bytes).unwrap();
        assert_eq!(decoded.circuit_id, 42);
        assert_eq!(decoded.cell_type, CellType::Data);
        assert_eq!(decoded.body, b"test payload");
    }

    #[test]
    fn header_with_next_hop() {
        let header = LayerHeader {
            next_hop: Some("127.0.0.1:9151".parse().unwrap()),
        };
        let bytes = header.serialize_bincode().unwrap();
        let decoded = LayerHeader::deserialize_bincode(&bytes).unwrap();
        assert_eq!(
            decoded.next_hop,
            Some("127.0.0.1:9151".parse().unwrap())
        );
    }

    #[test]
    fn header_exit_node() {
        let header = LayerHeader { next_hop: None };
        let bytes = header.serialize_bincode().unwrap();
        let decoded = LayerHeader::deserialize_bincode(&bytes).unwrap();
        assert!(decoded.next_hop.is_none());
    }
}
