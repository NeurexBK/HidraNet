use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

use crate::crypto::handshake::{HandshakeState, Role};
use crate::crypto::hybrid_sig::HybridSigningKey;
use crate::error::Result;
use crate::network::connection::{read_frame, write_frame, Message, SecureConnection};
use crate::relay::router::RelayRouter;
use crate::safelog::sensitive;

pub const PROTO_NOISE_SESSION: u8 = 0x00;
pub const PROTO_FORWARDED_CELL: u8 = 0x01;

/// How long a freshly accepted peer gets to say which protocol it speaks.
const PROTOCOL_BYTE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

pub struct NodeListener {
    listener: TcpListener,
    static_secret: Arc<[u8; 32]>,
    /// The identity this relay proves in every handshake, when it has one.
    identity: Option<Arc<HybridSigningKey>>,
}

impl NodeListener {
    pub async fn bind(addr: SocketAddr, static_secret: StaticSecret) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!(listen_addr = %addr, "TCP listener bound");
        Ok(Self {
            listener,
            static_secret: Arc::new(static_secret.to_bytes()),
            identity: None,
        })
    }

    /// Prove this identity (Ed25519 and ML-DSA-87) to every client that
    /// connects. Without it the relay is authenticated by its X25519 static
    /// key alone, which is how it always was.
    pub fn with_identity(mut self, identity: HybridSigningKey) -> Self {
        self.identity = Some(Arc::new(identity));
        self
    }

    pub async fn accept_loop(&self) -> Result<()> {
        let router = Arc::new(RelayRouter::new(
            Arc::clone(&self.static_secret),
            self.identity.clone(),
        ));

        loop {
            let (mut stream, remote_addr) = self.listener.accept().await?;
            info!(remote_addr = %sensitive(&remote_addr), "accepted connection");

            // The protocol byte used to be read right here, in the accept
            // loop. One peer that connected and sent nothing stopped every
            // other peer from being accepted, for as long as it stayed
            // quiet. Each connection now waits on its own task, and only
            // for a bounded time.
            let router = Arc::clone(&router);
            tokio::spawn(async move {
                let mut proto_byte = [0u8; 1];
                let read = tokio::time::timeout(
                    PROTOCOL_BYTE_DEADLINE,
                    stream.read_exact(&mut proto_byte),
                )
                .await;
                match read {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(error = %e, "failed to read protocol byte");
                        return;
                    }
                    Err(_) => {
                        warn!("peer sent no protocol byte in time, dropping connection");
                        return;
                    }
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
            });
        }
    }

    /// The address this listener actually bound to.
    ///
    /// Used by the integration tests, which bind to port 0 and need to learn
    /// what they got. Nothing in the running node asks — it already knows the
    /// address it configured — so the compiler would otherwise call it dead.
    #[allow(dead_code)]
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
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
        remote_addr = %sensitive(&addr),
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
            info!(bytes = data.len(), "received encrypted Pong");
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
