use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::crypto::handshake::TransportCipher;
use crate::error::{HidraError, Result};

const MAX_FRAME_SIZE: usize = 65_536;

// ---------------------------------------------------------------------------
// Wire-level message types
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    CreateCircuit { circuit_id: u32 },
    CircuitCreated { circuit_id: u32 },
    Relay { circuit_id: u32, data: Vec<u8> },
}

impl Message {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Ping(data) => {
                let mut buf = Vec::with_capacity(1 + data.len());
                buf.push(0x01);
                buf.extend_from_slice(data);
                buf
            }
            Self::Pong(data) => {
                let mut buf = Vec::with_capacity(1 + data.len());
                buf.push(0x02);
                buf.extend_from_slice(data);
                buf
            }
            Self::CreateCircuit { circuit_id } => {
                let mut buf = Vec::with_capacity(5);
                buf.push(0x10);
                buf.extend_from_slice(&circuit_id.to_be_bytes());
                buf
            }
            Self::CircuitCreated { circuit_id } => {
                let mut buf = Vec::with_capacity(5);
                buf.push(0x11);
                buf.extend_from_slice(&circuit_id.to_be_bytes());
                buf
            }
            Self::Relay { circuit_id, data } => {
                let mut buf = Vec::with_capacity(5 + data.len());
                buf.push(0x20);
                buf.extend_from_slice(&circuit_id.to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(HidraError::Protocol("empty message body".into()));
        }
        match data[0] {
            0x01 => Ok(Self::Ping(data[1..].to_vec())),
            0x02 => Ok(Self::Pong(data[1..].to_vec())),
            0x10 => {
                if data.len() < 5 {
                    return Err(HidraError::Protocol("CreateCircuit too short".into()));
                }
                let circuit_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                Ok(Self::CreateCircuit { circuit_id })
            }
            0x11 => {
                if data.len() < 5 {
                    return Err(HidraError::Protocol("CircuitCreated too short".into()));
                }
                let circuit_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                Ok(Self::CircuitCreated { circuit_id })
            }
            0x20 => {
                if data.len() < 5 {
                    return Err(HidraError::Protocol("Relay message too short".into()));
                }
                let circuit_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                Ok(Self::Relay {
                    circuit_id,
                    data: data[5..].to_vec(),
                })
            }
            tag => Err(HidraError::Protocol(format!(
                "unknown message type: 0x{tag:02x}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed TCP framing (4-byte BE header)
// ---------------------------------------------------------------------------
pub async fn write_frame(stream: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| HidraError::Protocol("frame exceeds u32 size limit".into()))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(HidraError::Protocol(format!(
            "frame size {len} exceeds maximum {MAX_FRAME_SIZE}"
        )));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// SecureConnection — post-handshake encrypted bidirectional channel
// ---------------------------------------------------------------------------
pub struct SecureConnection {
    stream: TcpStream,
    send_cipher: TransportCipher,
    recv_cipher: TransportCipher,
}

impl SecureConnection {
    pub fn new(
        stream: TcpStream,
        send_cipher: TransportCipher,
        recv_cipher: TransportCipher,
    ) -> Self {
        Self {
            stream,
            send_cipher,
            recv_cipher,
        }
    }

    pub async fn send_message(&mut self, msg: &Message) -> Result<()> {
        let plaintext = msg.serialize();
        let ciphertext = self.send_cipher.encrypt(&plaintext)?;
        write_frame(&mut self.stream, &ciphertext).await
    }

    pub async fn recv_message(&mut self) -> Result<Message> {
        let ciphertext = read_frame(&mut self.stream).await?;
        let plaintext = self.recv_cipher.decrypt(&ciphertext)?;
        Message::deserialize(&plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_roundtrip() {
        let msg = Message::Ping(b"HidraPing".to_vec());
        let bytes = msg.serialize();
        let decoded = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn pong_roundtrip() {
        let msg = Message::Pong(b"HidraPong".to_vec());
        let bytes = msg.serialize();
        let decoded = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn empty_body_is_error() {
        assert!(Message::deserialize(&[]).is_err());
    }

    #[test]
    fn unknown_tag_is_error() {
        assert!(Message::deserialize(&[0xFF, 0x01]).is_err());
    }

    #[test]
    fn ping_with_empty_payload() {
        let msg = Message::Ping(vec![]);
        let bytes = msg.serialize();
        assert_eq!(bytes, vec![0x01]);
        let decoded = Message::deserialize(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }
}
