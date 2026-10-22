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
    /// Like `Relay`, but it marks the cell that opens the data stream: a relay
    /// that forwards a `StreamBegin` relays the one reply and then switches
    /// that circuit from control (one request, one reply) to streaming (data
    /// flowing both ways). Control cells before it — circuit extension — stay
    /// `Relay`, so a relay never streams until the stream actually begins.
    StreamBegin { circuit_id: u32, data: Vec<u8> },
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
            Self::StreamBegin { circuit_id, data } => {
                let mut buf = Vec::with_capacity(5 + data.len());
                buf.push(0x21);
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
            0x21 => {
                if data.len() < 5 {
                    return Err(HidraError::Protocol("StreamBegin message too short".into()));
                }
                let circuit_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                Ok(Self::StreamBegin {
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

/// Reads length-prefixed frames, safely inside `tokio::select!`.
///
/// `read_frame` takes a frame with two `read_exact` calls, and `read_exact`
/// is not cancel safe. The streaming loops race a frame read against the
/// other direction in a `select!`; whenever the other side won while a frame
/// was arriving in pieces, the read was dropped with the length, or part of
/// the body, already taken off the socket. Those bytes were gone, the next
/// read started in the middle of a frame, and the stream broke — most often
/// when data flowed both ways at once, which is ordinary browsing.
///
/// This keeps what it has read in its own buffer and only reads with
/// `read_buf`, which either appends what arrived or reads nothing, so a read
/// dropped at any point loses nothing: the next call picks up where it was.
/// One reader per stream, kept for as long as the stream is read from.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn read_frame(&mut self, stream: &mut TcpStream) -> Result<Vec<u8>> {
        loop {
            if let Some(frame) = self.take_frame()? {
                return Ok(frame);
            }
            if stream.read_buf(&mut self.buf).await? == 0 {
                return Err(HidraError::Io(std::io::Error::from(
                    std::io::ErrorKind::UnexpectedEof,
                )));
            }
        }
    }

    /// A whole frame off the front of the buffer, if one is there.
    fn take_frame(&mut self) -> Result<Option<Vec<u8>>> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(HidraError::Protocol(format!(
                "frame size {len} exceeds maximum {MAX_FRAME_SIZE}"
            )));
        }
        if self.buf.len() < 4 + len {
            self.buf.reserve(4 + len - self.buf.len());
            return Ok(None);
        }
        let frame = self.buf[4..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some(frame))
    }
}

// ---------------------------------------------------------------------------
// SecureConnection — post-handshake encrypted bidirectional channel
// ---------------------------------------------------------------------------
pub struct SecureConnection {
    stream: TcpStream,
    send_cipher: TransportCipher,
    recv_cipher: TransportCipher,
    reader: FrameReader,
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
            reader: FrameReader::new(),
        }
    }

    pub async fn send_message(&mut self, msg: &Message) -> Result<()> {
        let plaintext = msg.serialize();
        let ciphertext = self.send_cipher.encrypt(&plaintext)?;
        write_frame(&mut self.stream, &ciphertext).await
    }

    /// Cancel safe: the frame is read through `FrameReader`, and decrypted
    /// only once it is whole, so the cipher's nonce never skips ahead.
    pub async fn recv_message(&mut self) -> Result<Message> {
        let ciphertext = self.reader.read_frame(&mut self.stream).await?;
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

    /// A connected pair of sockets on loopback.
    async fn socket_pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (a, b) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (a.unwrap(), b.unwrap().0)
    }

    /// The streaming loops race a frame read against the other direction. A
    /// frame that arrives in two pieces, with the other branch winning in
    /// between, must still come out whole.
    #[tokio::test]
    async fn frame_reader_survives_being_dropped_mid_frame() {
        let (mut tx, mut rx) = socket_pair().await;
        let body: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let writer = tokio::spawn(async move {
            tx.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
            tx.write_all(&body[..1000]).await.unwrap();
            tx.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            tx.write_all(&body[1000..]).await.unwrap();
            tx.flush().await.unwrap();
            (tx, body)
        });

        let mut reader = FrameReader::new();
        let mut interrupted = 0;
        let frame = loop {
            tokio::select! {
                f = reader.read_frame(&mut rx) => break f.unwrap(),
                _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => interrupted += 1,
            }
        };
        let (_tx, body) = writer.await.unwrap();
        assert!(interrupted > 0, "the read was never dropped mid-frame, so this proved nothing");
        assert_eq!(frame, body);
    }

    #[tokio::test]
    async fn frame_reader_returns_frames_written_back_to_back() {
        let (mut tx, mut rx) = socket_pair().await;
        let mut wire = Vec::new();
        for i in 0..5u8 {
            let body = vec![i; 10 + i as usize];
            wire.extend_from_slice(&(body.len() as u32).to_be_bytes());
            wire.extend_from_slice(&body);
        }
        tx.write_all(&wire).await.unwrap();
        let mut reader = FrameReader::new();
        for i in 0..5u8 {
            assert_eq!(reader.read_frame(&mut rx).await.unwrap(), vec![i; 10 + i as usize]);
        }
    }

    #[tokio::test]
    async fn frame_reader_refuses_an_oversized_length() {
        let (mut tx, mut rx) = socket_pair().await;
        tx.write_all(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes()).await.unwrap();
        assert!(FrameReader::new().read_frame(&mut rx).await.is_err());
    }

    #[tokio::test]
    async fn frame_reader_reports_a_closed_stream() {
        let (mut tx, mut rx) = socket_pair().await;
        tx.write_all(&[0, 0, 0, 9, 1, 2]).await.unwrap();
        drop(tx);
        assert!(FrameReader::new().read_frame(&mut rx).await.is_err());
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
