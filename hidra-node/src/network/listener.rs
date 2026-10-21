use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tracing::{debug, info};
use x25519_dalek::StaticSecret;

use crate::error::Result;
use crate::network::link::PROTO_LINK;
use crate::relay::router::RelayRouter;

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

    /// Accepts links and hands each to the relay router.
    ///
    /// Nothing about the connecting side is logged: on an entry relay it is a
    /// user's address. The protocol byte is read on the connection's own task,
    /// so a peer that connects and says nothing holds up no one else.
    pub async fn accept_loop(&self) -> Result<()> {
        let router = RelayRouter::new(Arc::clone(&self.static_secret));

        loop {
            let (mut stream, _) = self.listener.accept().await?;
            let router = router.clone();
            tokio::spawn(async move {
                let mut proto_byte = [0u8; 1];
                let read = tokio::time::timeout(
                    crate::network::link::LINK_TIMEOUT,
                    stream.read_exact(&mut proto_byte),
                )
                .await;
                match read {
                    Ok(Ok(_)) if proto_byte[0] == PROTO_LINK => router.handle_link(stream).await,
                    Ok(Ok(_)) => debug!(proto = proto_byte[0], "unknown protocol byte, dropping connection"),
                    _ => debug!("connection closed before its protocol byte"),
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
