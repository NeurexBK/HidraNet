use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

use crate::crypto::handshake::{HandshakeState, Role};
use crate::error::Result;
use crate::network::connection::{read_frame, write_frame, Message, SecureConnection};
use crate::relay::router::RelayRouter;

pub const PROTO_NOISE_SESSION: u8 = 0x00;
pub const PROTO_FORWARDED_CELL: u8 = 0x01;

pub struct NodeListener {
    listener: TcpListener,
    static_secret: Arc<[u8; 32]>,
}

impl NodeListener {
    pub async fn bind(addr: SocketAddr, static_secret: StaticSecret) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!(listen_addr = %addr, "TCP listener bound");
        Ok(Self {
            listener,
            static_secret: Arc::new(static_secret.to_bytes()),
        })
    }

    pub async fn accept_loop(&self) -> Result<()> {
        let router = RelayRouter::new(Arc::clone(&self.static_secret));

        loop {
            let (mut stream, remote_addr) = self.listener.accept().await?;
            info!(remote_addr = %remote_addr, "accepted connection");

            let mut proto_byte = [0u8; 1];
            if let Err(e) = stream.read_exact(&mut proto_byte).await {
                warn!(error = %e, "failed to read protocol byte");
                continue;
            }

            match proto_byte[0] {
                PROTO_NOISE_SESSION => {
                    router.handle_client_connection(stream, remote_addr).await;
                }
                PROTO_FORWARDED_CELL => {
                    router.handle_forwarded_cell(stream, remote_addr).await;
                }
                other => {
                    warn!(proto = other, "unknown protocol byte, dropping connection");
                }
            }
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener.local_addr().map_err(Into::into)
    }
}

pub async fn connect_to_peer(
    addr: SocketAddr,
    static_secret: StaticSecret,
) -> Result<()> {
    let session_id = Uuid::new_v4().to_string();
    let _span = tracing::info_span!(
        "session",
        session_id = %session_id,
        remote_addr = %addr,
        role = "initiator",
    )
    .entered();

    info!("connecting to peer");
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    info!("TCP connection established");

    stream.write_all(&[PROTO_NOISE_SESSION]).await?;

    debug!("starting Noise XX handshake as initiator");
    let mut handshake = HandshakeState::new(Role::Initiator, static_secret);

    let msg_a = handshake.write_message_a()?;
    write_frame(&mut stream, &msg_a).await?;

    let msg_b = read_frame(&mut stream).await?;
    handshake.read_message_b(&msg_b)?;

    let msg_c = handshake.write_message_c()?;
    write_frame(&mut stream, &msg_c).await?;

    info!("Noise XX handshake completed");

    let (send_cipher, recv_cipher) = handshake.into_transport()?;
    let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

    let ping = Message::Ping(b"HidraPing".to_vec());
    conn.send_message(&ping).await?;
    info!("sent encrypted Ping");

    let msg = conn.recv_message().await?;
    match msg {
        Message::Pong(ref data) => {
            info!(payload = %String::from_utf8_lossy(data), "received encrypted Pong");
        }
        Message::Ping(_) => {
            warn!("unexpected Ping from responder");
        }
        _ => {
            warn!("unexpected message from responder");
        }
    }

    info!("session completed");
    Ok(())
}
