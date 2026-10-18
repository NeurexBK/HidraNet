use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::{HidraError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerHeader {
    pub next_hop: Option<SocketAddr>,
}

impl LayerHeader {
    pub fn serialize_bincode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            HidraError::Protocol(format!("header serialization failed: {e}"))
        })
    }

    pub fn deserialize_bincode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            HidraError::Protocol(format!("header deserialization failed: {e}"))
        })
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
    /// A service asking this relay to introduce clients to it. Carries the
    /// service key, the time and the key's signature over the address and
    /// the time (`crypto::service_auth`): without them anyone could register
    /// someone else's address and be that site.
    RegisterService {
        service_hash: Vec<u8>,
        service_pubkey: [u8; 32],
        timestamp: u64,
        signature: Vec<u8>,
    },
    ServiceRegistered,
    ConnectService { service_hash: Vec<u8> },
    ServiceConnected,
}

impl RelayCommand {
    pub fn serialize_bincode(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| {
            HidraError::Protocol(format!(
                "relay command serialize failed: {e}"
            ))
        })
    }

    pub fn deserialize_bincode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| {
            HidraError::Protocol(format!(
                "relay command deserialize failed: {e}"
            ))
        })
    }
}

// cell_roundtrip used to live here. It exercised an OnionCell and a CellType
// that nothing in either target ever constructed — protocol scaffolding that
// was never wired up — so the test was the type's only consumer. Both are
// gone; git has them if the cell format is ever built out.
#[cfg(test)]
mod tests {
    use super::*;


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
