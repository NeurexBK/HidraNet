use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::error::{HidraError, Result};

/// What a client says to one hop of its circuit, and what that hop answers.
/// It travels inside that hop's layer, so only the hop it is for can read it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayCommand {
    Connect { host: String, port: u16 },
    Connected,
    Data(Vec<u8>),
    End,
    ConnectFailed(String),
    ResolveDns { hostname: String },
    DnsResolved { addresses: Vec<String> },
    RegisterService { service_hash: Vec<u8> },
    ServiceRegistered,
    ConnectService { service_hash: Vec<u8> },
    ServiceConnected,
    /// Grow the circuit by one hop: dial `addr`, bring the link up against
    /// `transport_key`, and pass `handshake` on to the relay there. The
    /// handshake is the client's and is end to end with that relay; this hop
    /// only carries it.
    Extend {
        addr: SocketAddr,
        transport_key: [u8; 32],
        handshake: Vec<u8>,
    },
    /// The new hop's answer to the handshake, carried back unchanged.
    Extended { handshake: Vec<u8> },
    /// The extension did not happen. The client tears the circuit down; it
    /// never tries the next hop some other way.
    ExtendFailed,
    /// A liveness probe for the exit, answered with a fixed acknowledgement.
    /// Its content is never logged.
    Probe(Vec<u8>),
    ProbeReply(Vec<u8>),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_roundtrip() {
        let cmd = RelayCommand::Extend {
            addr: "198.51.100.2:9001".parse().unwrap(),
            transport_key: [7; 32],
            handshake: vec![1; 1616],
        };
        let back = RelayCommand::deserialize_bincode(&cmd.serialize_bincode().unwrap()).unwrap();
        match back {
            RelayCommand::Extend { addr, transport_key, handshake } => {
                assert_eq!(addr, "198.51.100.2:9001".parse().unwrap());
                assert_eq!(transport_key, [7; 32]);
                assert_eq!(handshake.len(), 1616);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn garbage_is_not_a_command() {
        assert!(RelayCommand::deserialize_bincode(&[0xff; 3]).is_err());
    }
}
