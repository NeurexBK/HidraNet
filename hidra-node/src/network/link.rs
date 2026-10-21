//! A link: one TCP connection between two nodes, encrypted with the NK
//! handshake against the key of the node that was dialled.
//!
//! The dialling side proves nothing about itself. A client dials only its
//! entry relay; a relay dials the next hop when a client asks it to extend.
//! Either way the side that dials knows which key it expects, and the link
//! comes up only if the far end holds it.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::circuit_handshake::{Initiator, respond};
use crate::error::{HidraError, Result};
use crate::network::connection::{SecureConnection, read_frame, write_frame};

/// First byte on a new connection: what follows is a link handshake.
pub const PROTO_LINK: u8 = 0x02;

/// How long a dial and its handshake may take before the link is given up.
pub const LINK_TIMEOUT: Duration = Duration::from_secs(15);

/// Dials `addr` and completes the handshake against `relay_key`. Fails, and
/// sends nothing further, if the node there does not hold that key.
pub async fn connect(addr: SocketAddr, relay_key: &[u8; 32]) -> Result<SecureConnection> {
    let attempt = async {
        let mut stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?;
        stream.write_all(&[PROTO_LINK]).await?;
        let (init, msg_a) = Initiator::start(&PublicKey::from(*relay_key))?;
        write_frame(&mut stream, &msg_a).await?;
        let msg_b = read_frame(&mut stream).await?;
        let keys = init.finish(&msg_b)?;
        Ok(SecureConnection::new(stream, keys.send, keys.recv))
    };
    tokio::time::timeout(LINK_TIMEOUT, attempt)
        .await
        .map_err(|_| HidraError::Relay("link handshake timed out".into()))?
}

/// The answering side, after the protocol byte has been read.
pub async fn accept(
    mut stream: TcpStream,
    static_secret: &StaticSecret,
) -> Result<SecureConnection> {
    let attempt = async {
        stream.set_nodelay(true)?;
        let msg_a = read_frame(&mut stream).await?;
        let (msg_b, keys) = respond(static_secret, &msg_a)?;
        write_frame(&mut stream, &msg_b).await?;
        Ok(SecureConnection::new(stream, keys.send, keys.recv))
    };
    tokio::time::timeout(LINK_TIMEOUT, attempt)
        .await
        .map_err(|_| HidraError::Relay("link handshake timed out".into()))?
}
