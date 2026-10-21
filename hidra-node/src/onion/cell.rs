use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::error::{HidraError, Result};

/// Every cell's innermost body is exactly this long: a command, its length
/// before it, zeros after. Whoever originates a cell — the client going out,
/// the last hop coming back — pads it, and only the other end unpads it, so
/// every cell on a link has the same size whatever it carries. Before, a
/// cell was as long as its contents, and anyone watching a link could read
/// off the size of every request and every response, which is most of what
/// website fingerprinting needs.
///
/// The largest command is the extension reply that carries the hybrid
/// handshake's message B (about 1.7 kB with ML-KEM-1024), so 2 kB leaves room.
pub const CELL_BODY: usize = 2048;
const LEN_PREFIX: usize = 2;
/// The most a command can be and still fit one cell.
pub const MAX_COMMAND: usize = CELL_BODY - LEN_PREFIX;
/// The most stream data one `Data` cell carries: a command, less bincode's
/// enum tag (4 bytes) and vector length (8 bytes).
pub const MAX_DATA: usize = MAX_COMMAND - 12;

/// A command as the innermost body of a cell.
pub fn pad_cell(command: &[u8]) -> Result<Vec<u8>> {
    if command.len() > MAX_COMMAND {
        return Err(HidraError::Protocol(format!(
            "a {}-byte command does not fit one cell ({MAX_COMMAND} at most)",
            command.len()
        )));
    }
    let mut body = Vec::with_capacity(CELL_BODY);
    body.extend_from_slice(&(command.len() as u16).to_be_bytes());
    body.extend_from_slice(command);
    body.resize(CELL_BODY, 0);
    Ok(body)
}

/// The command inside a cell's innermost body.
pub fn unpad_cell(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() != CELL_BODY {
        return Err(HidraError::Protocol(format!(
            "a cell body of {} bytes, not {CELL_BODY}",
            body.len()
        )));
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if len > MAX_COMMAND {
        return Err(HidraError::Protocol("a cell's length field runs past its body".into()));
    }
    Ok(body[LEN_PREFIX..LEN_PREFIX + len].to_vec())
}

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
    /// Circuit extension (telescoping). The client, to add a hop without ever
    /// opening a direct connection to it, asks the circuit's current last hop
    /// to open a link to `to` and carry this Noise handshake message (A) to
    /// it. The carrying hop holds neither party's key, so it cannot read the
    /// handshake; it only pipes the frames, and the new hop sees the carrying
    /// hop's address, never the client's.
    Extend { to: SocketAddr, frame: Vec<u8> },
    /// The new hop's Noise reply (message B), carried back to the client.
    Extended { frame: Vec<u8> },
    /// The client's final Noise message (C) and its CreateCircuit, already
    /// sealed with the key the two just agreed, carried to the new hop in one
    /// step. The carrying hop cannot read either.
    ExtendFinish { frame_c: Vec<u8>, frame_create: Vec<u8> },
    /// The new hop's sealed CircuitCreated, carried back to the client.
    ExtendDone { frame_created: Vec<u8> },
    /// Extension refused at the current last hop: a non-public next address,
    /// or the new hop would not answer.
    ExtendError(String),
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
    fn a_padded_cell_is_always_the_same_size() {
        for len in [0, 1, 500, MAX_COMMAND] {
            let command = vec![0xAB; len];
            let body = pad_cell(&command).unwrap();
            assert_eq!(body.len(), CELL_BODY);
            assert_eq!(unpad_cell(&body).unwrap(), command);
        }
    }

    #[test]
    fn a_command_too_big_for_a_cell_is_refused() {
        assert!(pad_cell(&vec![0; MAX_COMMAND + 1]).is_err());
    }

    #[test]
    fn a_body_of_the_wrong_size_or_length_is_refused() {
        assert!(unpad_cell(&vec![0; CELL_BODY - 1]).is_err());
        let mut body = pad_cell(b"x").unwrap();
        body[0] = 0xFF;
        body[1] = 0xFF;
        assert!(unpad_cell(&body).is_err());
    }

    #[test]
    fn a_full_data_cell_is_exactly_one_cell() {
        let full = RelayCommand::Data(vec![0; MAX_DATA]).serialize_bincode().unwrap();
        assert_eq!(full.len(), MAX_COMMAND);
        let over = RelayCommand::Data(vec![0; MAX_DATA + 1]).serialize_bincode().unwrap();
        assert!(pad_cell(&over).is_err());
    }

    #[test]
    fn the_largest_control_command_fits_a_cell() {
        // The extension reply carries the hybrid handshake's message B,
        // measured at 1680 bytes; the relay refuses handshake frames past
        // 4096, but the real ones must fit one cell.
        let reply = RelayCommand::Extended { frame: vec![0; 1680] }.serialize_bincode().unwrap();
        assert!(pad_cell(&reply).is_ok());
    }

    #[test]
    fn header_exit_node() {
        let header = LayerHeader { next_hop: None };
        let bytes = header.serialize_bincode().unwrap();
        let decoded = LayerHeader::deserialize_bincode(&bytes).unwrap();
        assert!(decoded.next_hop.is_none());
    }
}
