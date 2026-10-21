use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

use crate::crypto::handshake::{HandshakeState, Role};
use crate::error::Result;
use crate::network::connection::{read_frame, write_frame, Message, SecureConnection};
use crate::relay::exit_policy::ExitPolicy;
use crate::relay::router::RelayRouter;
use crate::safelog::sensitive;

/// The first byte of every connection to a relay says what it is.
///
/// A Noise session with a client — directly, or piped by the hop before during
/// a circuit extension. Version 2: circuits on it use the counting layers of
/// `onion::layer`.
pub const PROTO_NOISE_SESSION: u8 = 0x02;
/// A link from the relay before this one on a circuit. Version 2: a Noise
/// session too. Version 1 (0x01) carried cells in the clear.
pub const PROTO_RELAY_LINK: u8 = 0x03;
/// What version 1 sent: a client session with the old layers (0x00), and a
/// relay link in the clear (0x01). Refused, and said so in the log, so a relay
/// or client that was not upgraded fails plainly instead of mid-circuit.
const PROTO_V1: [u8; 2] = [0x00, 0x01];

/// How long a freshly accepted connection has to send its single protocol
/// byte before its handler task gives up, so a client that connects and then
/// goes silent cannot tie a task up for good.
const PROTO_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct NodeListener {
    listener: TcpListener,
    static_secret: Arc<[u8; 32]>,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
}

impl NodeListener {
    pub async fn bind(addr: SocketAddr, static_secret: StaticSecret) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!(listen_addr = %addr, "TCP listener bound");
        Ok(Self {
            listener,
            static_secret: Arc::new(static_secret.to_bytes()),
            policy: ExitPolicy::STRICT,
            dial_source: None,
        })
    }

    /// Where the relay behind this listener connects for others. Public
    /// addresses only unless this is called; see `relay::exit_policy`.
    pub fn with_exit_policy(mut self, policy: ExitPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Pin the address this relay's outbound hop connections are made from.
    /// Off by default; used by tests to tell each hop's connections apart by
    /// source, and available to a node that wants to fix its egress address.
    #[allow(dead_code)]
    pub fn with_dial_source(mut self, source: IpAddr) -> Self {
        self.dial_source = Some(source);
        self
    }

    pub async fn accept_loop(&self) -> Result<()> {
        let router = Arc::new(
            RelayRouter::new(Arc::clone(&self.static_secret))
                .with_policy(self.policy)
                .with_dial_source(self.dial_source),
        );

        loop {
            let (mut stream, remote_addr) = self.listener.accept().await?;
            info!(remote_addr = %sensitive(&remote_addr), "accepted connection");

            // Read the one protocol byte inside a per-connection task, under a
            // timeout. Done inline, a client that connects but never sends the
            // byte would stall the whole accept loop and freeze the relay for
            // everyone; now it holds up only — and only briefly — its own task.
            let router = Arc::clone(&router);
            tokio::spawn(async move {
                let mut proto_byte = [0u8; 1];
                match tokio::time::timeout(PROTO_READ_TIMEOUT, stream.read_exact(&mut proto_byte))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        warn!(error = %e, "failed to read protocol byte");
                        return;
                    }
                    Err(_) => {
                        warn!("timed out reading protocol byte");
                        return;
                    }
                }

                match proto_byte[0] {
                    PROTO_NOISE_SESSION => {
                        router.handle_client_connection(stream, remote_addr).await;
                    }
                    PROTO_RELAY_LINK => {
                        router.handle_relay_link(stream, remote_addr).await;
                    }
                    old if PROTO_V1.contains(&old) => {
                        warn!(proto = old, "a peer speaks circuit protocol v1, which this relay no longer accepts; it needs upgrading");
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
