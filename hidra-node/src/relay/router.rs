//! A relay's side of a circuit.
//!
//! Every link carries one circuit. The first message on it is a CREATE: the
//! client's (or the previous relay's) handshake for this relay, answered with
//! CREATED. After that, every RELAY cell has this relay's layer removed. What
//! is underneath is either for the next hop, and goes out on the link to it
//! under that link's own circuit id, or for this relay: a command, of which
//! EXTEND is how a circuit grows.
//!
//! On EXTEND the relay dials the address it is given, brings the link up
//! against the key it is given, and passes the client's handshake on in a
//! CREATE. The handshake is between the client and the next relay; this one
//! sees only opaque bytes going one way and opaque bytes coming back, and
//! learns no key from them.
//!
//! What a relay knows about a circuit is the link it came in on and, once
//! extended, the link it goes out on. Its log records neither the circuit ids
//! (each link has its own, so they would let relays' logs be lined up) nor
//! the address of anyone on either side.

use std::collections::HashMap;
use std::sync::Arc;

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};
use x25519_dalek::StaticSecret;

use crate::crypto::circuit_handshake::respond;
use crate::error::{HidraError, Result};
use crate::network::connection::{LinkWriter, Message};
use crate::network::link;
use crate::onion::cell::RelayCommand;
use crate::onion::layer::{Peeled, RelayHop};
use crate::safelog::sensitive;

/// How long an exit waits for a target to accept a connection.
const TARGET_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

pub struct ClientPipe {
    pub from_client: mpsc::Receiver<Vec<u8>>,
    pub to_client: mpsc::Sender<Vec<u8>>,
}

type IntroRegistry = Arc<Mutex<HashMap<Vec<u8>, mpsc::Sender<ClientPipe>>>>;

#[derive(Clone)]
pub struct RelayRouter {
    static_secret_bytes: Arc<[u8; 32]>,
    intro_registry: IntroRegistry,
}

impl RelayRouter {
    pub fn new(static_secret_bytes: Arc<[u8; 32]>) -> Self {
        Self {
            static_secret_bytes,
            intro_registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Serves one link, after its protocol byte, until the circuit on it ends.
    pub async fn handle_link(&self, stream: TcpStream) {
        let secret = StaticSecret::from(*self.static_secret_bytes);
        let result = serve_link(stream, &secret, &self.intro_registry).await;
        drop(secret);
        match result {
            Ok(()) => debug!("circuit closed"),
            Err(e) => debug!(error = %e, "circuit ended with an error"),
        }
    }
}

fn new_circuit_id() -> u32 {
    rand::thread_rng().gen_range(1..=u32::MAX)
}

/// The far side of an exit: what the circuit's data goes to.
enum Exit {
    None,
    Tcp {
        read: OwnedReadHalf,
        write: OwnedWriteHalf,
    },
    /// A hidden service's circuit at its introduction point, waiting for
    /// clients and bridging one at a time.
    Service {
        service_hash: Vec<u8>,
        clients: mpsc::Receiver<ClientPipe>,
        registered: mpsc::Sender<ClientPipe>,
        current: Option<ClientPipe>,
    },
    /// A client's circuit at the introduction point, bridged to the service.
    ToService {
        to_service: mpsc::Sender<Vec<u8>>,
        from_service: mpsc::Receiver<Vec<u8>>,
    },
}

enum ExitEvent {
    TargetData(Vec<u8>),
    TargetClosed,
    ClientArrived(ClientPipe),
    ClientData(Vec<u8>),
    ClientLeft,
    ServiceData(Vec<u8>),
    ServiceLeft,
}

async fn next_exit_event(exit: &mut Exit, buf: &mut [u8]) -> ExitEvent {
    match exit {
        Exit::None => std::future::pending().await,
        Exit::Tcp { read, .. } => match read.read(buf).await {
            Ok(0) | Err(_) => ExitEvent::TargetClosed,
            Ok(n) => ExitEvent::TargetData(buf[..n].to_vec()),
        },
        Exit::Service { clients, current, .. } => match current {
            None => match clients.recv().await {
                Some(pipe) => ExitEvent::ClientArrived(pipe),
                None => std::future::pending().await,
            },
            Some(pipe) => match pipe.from_client.recv().await {
                Some(data) => ExitEvent::ClientData(data),
                None => ExitEvent::ClientLeft,
            },
        },
        Exit::ToService { from_service, .. } => match from_service.recv().await {
            Some(data) => ExitEvent::ServiceData(data),
            None => ExitEvent::ServiceLeft,
        },
    }
}

async fn recv_next(
    next: &mut Option<(u32, LinkWriter, mpsc::Receiver<Result<Message>>)>,
) -> Option<Result<Message>> {
    match next {
        Some((_, _, rx)) => rx.recv().await,
        None => std::future::pending().await,
    }
}

/// One circuit, from the relay's side.
struct Hop<'a> {
    in_cid: u32,
    hop: RelayHop,
    back: LinkWriter,
    next: Option<(u32, LinkWriter, mpsc::Receiver<Result<Message>>)>,
    exit: Exit,
    intro_registry: &'a IntroRegistry,
}

impl Hop<'_> {
    /// Sends a command this relay writes to the client.
    async fn answer(&mut self, cmd: &RelayCommand) -> Result<()> {
        let cell = self.hop.originate(&cmd.serialize_bincode()?)?;
        self.back
            .send_message(&Message::Relay { circuit_id: self.in_cid, data: cell })
            .await
    }

    async fn from_client(&mut self, cell: &[u8]) -> Result<()> {
        match self.hop.peel(cell)? {
            Peeled::Onward(inner) => {
                let Some((out_cid, writer, _)) = self.next.as_mut() else {
                    return Err(HidraError::Circuit("a cell for a hop past this one, which is the last".into()));
                };
                writer
                    .send_message(&Message::Relay { circuit_id: *out_cid, data: inner })
                    .await
            }
            Peeled::Here(body) => {
                let cmd = RelayCommand::deserialize_bincode(&body)?;
                self.command(cmd).await
            }
        }
    }

    async fn command(&mut self, cmd: RelayCommand) -> Result<()> {
        match cmd {
            RelayCommand::Extend { addr, transport_key, handshake } => {
                if self.next.is_some() || !matches!(self.exit, Exit::None) {
                    return Err(HidraError::Circuit("extend on a circuit already in use".into()));
                }
                match extend(addr, &transport_key, handshake).await {
                    Ok((out_cid, writer, rx, answer)) => {
                        self.next = Some((out_cid, writer, rx));
                        info!("circuit extended");
                        self.answer(&RelayCommand::Extended { handshake: answer }).await
                    }
                    Err(e) => {
                        info!(error = %e, "extend failed");
                        self.answer(&RelayCommand::ExtendFailed).await
                    }
                }
            }
            RelayCommand::Connect { host, port } => {
                if self.next.is_some() || !matches!(self.exit, Exit::None) {
                    return Err(HidraError::Circuit("connect on a circuit already in use".into()));
                }
                info!(host = %sensitive(&host), port, "exit relay — connecting to target");
                let target = format!("{host}:{port}");
                let attempt = tokio::time::timeout(TARGET_TIMEOUT, TcpStream::connect(&target)).await;
                match attempt {
                    Ok(Ok(stream)) => {
                        let (read, write) = stream.into_split();
                        self.exit = Exit::Tcp { read, write };
                        self.answer(&RelayCommand::Connected).await
                    }
                    Ok(Err(e)) => {
                        info!(error = %e, "exit relay — connect failed");
                        self.answer(&RelayCommand::ConnectFailed(e.to_string())).await
                    }
                    Err(_) => self.answer(&RelayCommand::ConnectFailed("timed out".into())).await,
                }
            }
            RelayCommand::ResolveDns { hostname } => {
                info!(hostname = %sensitive(&hostname), "exit relay — DNS resolution");
                let addresses = match tokio::net::lookup_host(format!("{hostname}:0")).await {
                    Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
                    Err(e) => {
                        info!(error = %e, "DNS resolution failed");
                        Vec::new()
                    }
                };
                self.answer(&RelayCommand::DnsResolved { addresses }).await
            }
            RelayCommand::RegisterService { service_hash } => {
                if self.next.is_some() || !matches!(self.exit, Exit::None) {
                    return Err(HidraError::Circuit("register on a circuit already in use".into()));
                }
                info!(service = %sensitive(&hex(&service_hash)), "intro relay — registering hidden service");
                let (tx, rx) = mpsc::channel::<ClientPipe>(16);
                self.intro_registry.lock().await.insert(service_hash.clone(), tx.clone());
                self.exit = Exit::Service {
                    service_hash,
                    clients: rx,
                    registered: tx,
                    current: None,
                };
                self.answer(&RelayCommand::ServiceRegistered).await
            }
            RelayCommand::ConnectService { service_hash } => {
                if self.next.is_some() || !matches!(self.exit, Exit::None) {
                    return Err(HidraError::Circuit("connect on a circuit already in use".into()));
                }
                info!(service = %sensitive(&hex(&service_hash)), "intro relay — client connecting to service");
                let pipe_tx = self.intro_registry.lock().await.get(&service_hash).cloned();
                let Some(pipe_tx) = pipe_tx else {
                    return self
                        .answer(&RelayCommand::ConnectFailed("service not found at this intro point".into()))
                        .await;
                };
                let (to_service, from_client) = mpsc::channel::<Vec<u8>>(256);
                let (to_client, from_service) = mpsc::channel::<Vec<u8>>(256);
                if pipe_tx.send(ClientPipe { from_client, to_client }).await.is_err() {
                    return self
                        .answer(&RelayCommand::ConnectFailed("service handler disconnected".into()))
                        .await;
                }
                self.exit = Exit::ToService { to_service, from_service };
                self.answer(&RelayCommand::ServiceConnected).await
            }
            RelayCommand::Data(payload) => {
                match &mut self.exit {
                    Exit::Tcp { write, .. } => {
                        if write.write_all(&payload).await.is_err() {
                            self.exit = Exit::None;
                            return self.answer(&RelayCommand::End).await;
                        }
                    }
                    Exit::Service { current: Some(pipe), .. } => {
                        let _ = pipe.to_client.send(payload).await;
                    }
                    Exit::ToService { to_service, .. } => {
                        let _ = to_service.send(payload).await;
                    }
                    _ => debug!("data with nowhere to go"),
                }
                Ok(())
            }
            RelayCommand::End => {
                match &mut self.exit {
                    Exit::Service { current, .. } => *current = None,
                    Exit::Tcp { .. } | Exit::ToService { .. } => self.exit = Exit::None,
                    Exit::None => {}
                }
                debug!("stream ended by the client");
                Ok(())
            }
            RelayCommand::Probe(bytes) => {
                // The length, never the content.
                info!(bytes = bytes.len(), "probe received");
                self.answer(&RelayCommand::ProbeReply(b"Received, agent".to_vec())).await
            }
            other => Err(HidraError::Circuit(format!(
                "a client does not send {}",
                command_name(&other)
            ))),
        }
    }

    async fn from_exit(&mut self, event: ExitEvent) -> Result<()> {
        match event {
            ExitEvent::TargetData(data) | ExitEvent::ClientData(data) | ExitEvent::ServiceData(data) => {
                self.answer(&RelayCommand::Data(data)).await
            }
            ExitEvent::TargetClosed | ExitEvent::ServiceLeft => {
                self.exit = Exit::None;
                self.answer(&RelayCommand::End).await
            }
            ExitEvent::ClientArrived(pipe) => {
                if let Exit::Service { current, .. } = &mut self.exit {
                    *current = Some(pipe);
                }
                info!("intro relay — bridging client to service");
                Ok(())
            }
            ExitEvent::ClientLeft => {
                if let Exit::Service { current, .. } = &mut self.exit {
                    *current = None;
                }
                Ok(())
            }
        }
    }

    async fn teardown(mut self) {
        if let Some((out_cid, mut writer, _)) = self.next.take() {
            let _ = writer.send_message(&Message::Destroy { circuit_id: out_cid }).await;
        }
        if let Exit::Service { service_hash, registered, .. } = &self.exit {
            let mut reg = self.intro_registry.lock().await;
            if reg.get(service_hash).is_some_and(|tx| tx.same_channel(registered)) {
                reg.remove(service_hash);
                info!("intro relay — service deregistered");
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn command_name(cmd: &RelayCommand) -> &'static str {
    match cmd {
        RelayCommand::Connected => "CONNECTED",
        RelayCommand::ConnectFailed(_) => "CONNECT_FAILED",
        RelayCommand::DnsResolved { .. } => "DNS_RESOLVED",
        RelayCommand::ServiceRegistered => "SERVICE_REGISTERED",
        RelayCommand::ServiceConnected => "SERVICE_CONNECTED",
        RelayCommand::Extended { .. } => "EXTENDED",
        RelayCommand::ExtendFailed => "EXTEND_FAILED",
        RelayCommand::ProbeReply(_) => "PROBE_REPLY",
        _ => "this command",
    }
}

/// Dials the next hop, brings the link up against its key, and runs the
/// client's handshake with it. Returns the new link and the relay's answer.
async fn extend(
    addr: std::net::SocketAddr,
    transport_key: &[u8; 32],
    handshake: Vec<u8>,
) -> Result<(u32, LinkWriter, mpsc::Receiver<Result<Message>>, Vec<u8>)> {
    let conn = link::connect(addr, transport_key).await?;
    let (reader, mut writer) = conn.into_split();
    let mut rx = reader.spawn();
    let out_cid = new_circuit_id();
    writer
        .send_message(&Message::Create { circuit_id: out_cid, handshake })
        .await?;
    let answer = tokio::time::timeout(link::LINK_TIMEOUT, rx.recv())
        .await
        .map_err(|_| HidraError::Relay("next hop did not answer CREATE".into()))?;
    match answer {
        Some(Ok(Message::Created { circuit_id, handshake })) if circuit_id == out_cid => {
            Ok((out_cid, writer, rx, handshake))
        }
        Some(Err(e)) => Err(e),
        _ => Err(HidraError::Relay("next hop refused CREATE".into())),
    }
}

async fn serve_link(
    stream: TcpStream,
    secret: &StaticSecret,
    intro_registry: &IntroRegistry,
) -> Result<()> {
    let conn = link::accept(stream, secret).await?;
    let (reader, mut back) = conn.into_split();
    let mut inbound = reader.spawn();

    let first = tokio::time::timeout(link::LINK_TIMEOUT, inbound.recv())
        .await
        .map_err(|_| HidraError::Relay("no CREATE on a new link".into()))?;
    let (in_cid, hop) = match first {
        Some(Ok(Message::Create { circuit_id, handshake })) => {
            let (answer, keys) = respond(secret, &handshake)?;
            back.send_message(&Message::Created { circuit_id, handshake: answer })
                .await?;
            (circuit_id, RelayHop::new(keys))
        }
        Some(Ok(Message::Ping(_))) => {
            return back.send_message(&Message::Pong(b"HidraPong".to_vec())).await;
        }
        Some(Err(e)) => return Err(e),
        _ => return Err(HidraError::Protocol("a link must start with CREATE".into())),
    };
    info!("circuit created");

    let mut hop = Hop {
        in_cid,
        hop,
        back,
        next: None,
        exit: Exit::None,
        intro_registry,
    };
    let mut buf = vec![0u8; 16 * 1024];
    let result = loop {
        let step = tokio::select! {
            msg = inbound.recv() => match msg {
                Some(Ok(Message::Relay { circuit_id, data })) if circuit_id == hop.in_cid => {
                    hop.from_client(&data).await
                }
                Some(Ok(Message::Destroy { .. })) | None => break Ok(()),
                Some(Ok(_)) => Err(HidraError::Protocol("unexpected message on a circuit link".into())),
                Some(Err(e)) => Err(e),
            },
            msg = recv_next(&mut hop.next) => match msg {
                Some(Ok(Message::Relay { circuit_id, data }))
                    if hop.next.as_ref().is_some_and(|(id, _, _)| *id == circuit_id) =>
                {
                    match hop.hop.relay_back(&data) {
                        Ok(cell) => hop.back
                            .send_message(&Message::Relay { circuit_id: hop.in_cid, data: cell })
                            .await,
                        Err(e) => Err(e),
                    }
                }
                _ => {
                    // The rest of the circuit is gone; so is this part of it.
                    hop.next = None;
                    let _ = hop.back.send_message(&Message::Destroy { circuit_id: hop.in_cid }).await;
                    break Ok(());
                }
            },
            event = next_exit_event(&mut hop.exit, &mut buf) => hop.from_exit(event).await,
        };
        if let Err(e) = step {
            let _ = hop.back.send_message(&Message::Destroy { circuit_id: hop.in_cid }).await;
            break Err(e);
        }
    };
    hop.teardown().await;
    if let Err(ref e) = result {
        warn!(error = %e, "circuit torn down");
    }
    result
}
