use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::crypto::handshake::TransportCipher;
use crate::error::{HidraError, Result};

const MAX_FRAME_SIZE: usize = 65_536;

// ---------------------------------------------------------------------------
// Wire-level message types
// ---------------------------------------------------------------------------
/// What travels on a link, inside its encryption.
///
/// A `circuit_id` names a circuit on this link only. Each relay picks a fresh
/// one for the link to the next hop and keeps the mapping, so no identifier is
/// shared by two links of the same circuit and no two relays can line up their
/// logs by it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// Message A of a circuit handshake, for the relay at the far end of this
    /// link.
    Create { circuit_id: u32, handshake: Vec<u8> },
    /// Its message B.
    Created { circuit_id: u32, handshake: Vec<u8> },
    /// A relay cell: onion-encrypted, one layer per hop.
    Relay { circuit_id: u32, data: Vec<u8> },
    /// The circuit is gone; tear down everything that belongs to it.
    Destroy { circuit_id: u32 },
}

fn with_id(tag: u8, circuit_id: u32, body: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5 + body.len());
    buf.push(tag);
    buf.extend_from_slice(&circuit_id.to_be_bytes());
    buf.extend_from_slice(body);
    buf
}

fn read_id(data: &[u8], what: &str) -> Result<u32> {
    if data.len() < 5 {
        return Err(HidraError::Protocol(format!("{what} too short")));
    }
    Ok(u32::from_be_bytes([data[1], data[2], data[3], data[4]]))
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
            Self::Create { circuit_id, handshake } => with_id(0x12, *circuit_id, handshake),
            Self::Created { circuit_id, handshake } => with_id(0x13, *circuit_id, handshake),
            Self::Destroy { circuit_id } => with_id(0x14, *circuit_id, &[]),
            Self::Relay { circuit_id, data } => with_id(0x20, *circuit_id, data),
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(HidraError::Protocol("empty message body".into()));
        }
        match data[0] {
            0x01 => Ok(Self::Ping(data[1..].to_vec())),
            0x02 => Ok(Self::Pong(data[1..].to_vec())),
            0x12 => Ok(Self::Create {
                circuit_id: read_id(data, "Create")?,
                handshake: data[5..].to_vec(),
            }),
            0x13 => Ok(Self::Created {
                circuit_id: read_id(data, "Created")?,
                handshake: data[5..].to_vec(),
            }),
            0x14 => Ok(Self::Destroy {
                circuit_id: read_id(data, "Destroy")?,
            }),
            0x20 => Ok(Self::Relay {
                circuit_id: read_id(data, "Relay message")?,
                data: data[5..].to_vec(),
            }),
            tag => Err(HidraError::Protocol(format!(
                "unknown message type: 0x{tag:02x}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// Length-prefixed TCP framing (4-byte BE header)
// ---------------------------------------------------------------------------
pub async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len())
        .map_err(|_| HidraError::Protocol("frame exceeds u32 size limit".into()))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(data).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
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

    // The node splits every link (`into_split`); these whole-connection
    // calls are for the integration tests, which drive a link by hand.
    #[allow(dead_code)]
    pub async fn send_message(&mut self, msg: &Message) -> Result<()> {
        let plaintext = msg.serialize();
        let ciphertext = self.send_cipher.encrypt(&plaintext)?;
        write_frame(&mut self.stream, &ciphertext).await
    }

    #[allow(dead_code)]
    pub async fn recv_message(&mut self) -> Result<Message> {
        let ciphertext = read_frame(&mut self.stream).await?;
        let plaintext = self.recv_cipher.decrypt(&ciphertext)?;
        Message::deserialize(&plaintext)
    }

    /// Separate halves, so one task can wait for the next message while
    /// another writes: reading a frame is not cancel-safe, so it must not sit
    /// in a `select!` next to anything else.
    pub fn into_split(self) -> (LinkReader, LinkWriter) {
        let (rd, wr) = self.stream.into_split();
        (
            LinkReader { stream: rd, cipher: self.recv_cipher },
            LinkWriter { stream: wr, cipher: self.send_cipher },
        )
    }
}

pub struct LinkReader {
    stream: OwnedReadHalf,
    cipher: TransportCipher,
}

impl LinkReader {
    pub async fn recv_message(&mut self) -> Result<Message> {
        let ciphertext = read_frame(&mut self.stream).await?;
        let plaintext = self.cipher.decrypt(&ciphertext)?;
        Message::deserialize(&plaintext)
    }

    /// Reads on its own task and hands each message over a channel, which a
    /// `select!` can wait on safely. The channel closes after the first
    /// error, which is passed on.
    pub fn spawn(mut self) -> tokio::sync::mpsc::Receiver<Result<Message>> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let msg = self.recv_message().await;
                let stop = msg.is_err();
                if tx.send(msg).await.is_err() || stop {
                    break;
                }
            }
        });
        rx
    }
}

pub struct LinkWriter {
    stream: OwnedWriteHalf,
    cipher: TransportCipher,
}

impl LinkWriter {
    pub async fn send_message(&mut self, msg: &Message) -> Result<()> {
        let ciphertext = self.cipher.encrypt(&msg.serialize())?;
        write_frame(&mut self.stream, &ciphertext).await
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
    fn circuit_messages_roundtrip() {
        for msg in [
            Message::Create { circuit_id: 7, handshake: vec![1, 2, 3] },
            Message::Created { circuit_id: 7, handshake: vec![4] },
            Message::Relay { circuit_id: u32::MAX, data: vec![] },
            Message::Destroy { circuit_id: 0 },
        ] {
            assert_eq!(Message::deserialize(&msg.serialize()).unwrap(), msg);
        }
        assert!(Message::deserialize(&[0x12, 0, 0]).is_err());
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
