use crate::safelog::sensitive;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rand_core::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, Instrument};
use uuid::Uuid;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::crypto::handshake::{HandshakeState, Role};
use crate::error::{HidraError, Result};
use crate::network::connection::{read_frame, write_frame, Message, SecureConnection};
use crate::network::listener::{PROTO_NOISE_SESSION, PROTO_RELAY_LINK};
use crate::onion::cell::{pad_cell, unpad_cell, LayerHeader, RelayCommand, MAX_DATA};
use crate::onion::layer::LayerCipher;
use crate::relay::exit_policy::ExitPolicy;

struct CircuitEntry {
    /// This relay's layer of the circuit. It counts the cells each way, so a
    /// cell opens once, in order, and only in its own direction.
    layer: LayerCipher,
    /// When this circuit's state was last used, refreshed on every cell. Reaped
    /// by time since last use (not since registration) so a circuit a client
    /// still holds — including one idle in its pool — is never reaped out from
    /// under it, while abandoned ones stay bounded by CIRCUIT_TTL and
    /// MAX_CIRCUITS.
    last_used: std::time::Instant,
}

pub struct ClientPipe {
    pub from_client: mpsc::Receiver<Vec<u8>>,
    pub to_client: mpsc::Sender<Vec<u8>>,
}

type IntroRegistry = Arc<Mutex<HashMap<Vec<u8>, mpsc::Sender<ClientPipe>>>>;
type Circuits = Arc<Mutex<HashMap<u32, CircuitEntry>>>;

pub struct RelayRouter {
    circuits: Circuits,
    static_secret_bytes: Arc<[u8; 32]>,
    intro_registry: IntroRegistry,
    policy: ExitPolicy,
    /// When set, the address every outbound hop connection is sent from. Off
    /// by default (the kernel chooses); a node that pins its egress sets it.
    dial_source: Option<IpAddr>,
}

/// Which side of this relay a link faces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LinkKind {
    /// A Noise session with a client: directly from a client to its guard, or
    /// piped by the hop before during a circuit extension. Its session key
    /// becomes this relay's layer of the one circuit it creates.
    Client,
    /// A link from the relay before this one on a circuit, carrying cells it
    /// has already peeled. Encrypted, but it creates no circuit: the cells it
    /// carries open only under layers their circuits' clients agreed.
    Relay,
}

/// What every link task shares.
#[derive(Clone)]
struct Ctx {
    circuits: Circuits,
    intro_registry: IntroRegistry,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
}

impl RelayRouter {
    pub fn new(static_secret_bytes: Arc<[u8; 32]>) -> Self {
        Self {
            circuits: Arc::new(Mutex::new(HashMap::new())),
            static_secret_bytes,
            intro_registry: Arc::new(Mutex::new(HashMap::new())),
            policy: ExitPolicy::STRICT,
            dial_source: None,
        }
    }

    /// Where this relay will connect for others. Strict unless changed.
    pub fn with_policy(mut self, policy: ExitPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Pin the address outbound hop connections are made from. Default: off.
    #[allow(dead_code)]
    pub fn with_dial_source(mut self, source: Option<IpAddr>) -> Self {
        self.dial_source = source;
        self
    }

    fn ctx(&self) -> Ctx {
        Ctx {
            circuits: Arc::clone(&self.circuits),
            intro_registry: Arc::clone(&self.intro_registry),
            policy: self.policy,
            dial_source: self.dial_source,
        }
    }

    pub async fn handle_client_connection(&self, stream: TcpStream, remote_addr: SocketAddr) {
        let span = tracing::info_span!(
            "relay_session",
            session_id = %Uuid::new_v4(),
            remote_addr = %sensitive(&remote_addr),
            role = "relay_responder",
        );
        self.serve(stream, LinkKind::Client, span);
    }

    pub async fn handle_relay_link(&self, stream: TcpStream, remote_addr: SocketAddr) {
        let span = tracing::info_span!("relay_link", remote_addr = %sensitive(&remote_addr));
        self.serve(stream, LinkKind::Relay, span);
    }

    fn serve(&self, stream: TcpStream, kind: LinkKind, span: tracing::Span) {
        let secret_bytes = Arc::clone(&self.static_secret_bytes);
        let ctx = self.ctx();
        tokio::spawn(
            async move {
                debug!(?kind, "link accepted — starting Noise handshake");
                if let Err(e) = handle_link(stream, &secret_bytes, kind, ctx).await {
                    warn!(error = %e, ?kind, "link ended with an error");
                }
            }
            .instrument(span),
        );
    }
}

/// The responder side of a link's Noise XX handshake, then the link itself.
async fn handle_link(
    mut stream: TcpStream,
    secret_bytes: &[u8; 32],
    kind: LinkKind,
    ctx: Ctx,
) -> Result<()> {
    let mut sb = *secret_bytes;
    let secret = StaticSecret::from(sb);
    sb.zeroize();
    let mut handshake = HandshakeState::new(Role::Responder, secret);
    // Bound the whole responder handshake: a peer that passes the (already
    // timed) protocol byte and then stalls on a handshake frame must not pin
    // this task and its socket for good.
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let msg_a = read_frame(&mut stream).await?;
        handshake.read_message_a(&msg_a)?;
        let msg_b = handshake.write_message_b()?;
        write_frame(&mut stream, &msg_b).await?;
        let msg_c = read_frame(&mut stream).await?;
        handshake.read_message_c(&msg_c)?;
        Ok::<(), HidraError>(())
    })
    .await
    .map_err(|_| HidraError::Protocol("responder handshake timed out".into()))??;
    debug!(?kind, "Noise XX handshake completed");
    let (send_cipher, recv_cipher) = handshake.into_transport()?;
    // Only a client session's key becomes a circuit layer, and only once: two
    // circuits under one key would count from zero together and reuse nonces.
    let session_key = match kind {
        LinkKind::Client => Some(recv_cipher.session_key()?),
        LinkKind::Relay => None,
    };
    let conn = SecureConnection::new(stream, send_cipher, recv_cipher);
    serve_link(conn, kind, session_key, ctx).await
}

/// Serves one link until it closes: circuit creation (client sessions only),
/// control cells one request at a time, and the cell that opens a stream,
/// after which the link carries that stream until it ends.
async fn serve_link(
    mut conn: SecureConnection,
    kind: LinkKind,
    mut session_key: Option<[u8; 32]>,
    ctx: Ctx,
) -> Result<()> {
    // The hop this relay forwards to (opened once and reused), and a
    // half-finished extension awaiting its second round. The circuit stays in
    // control mode (one request, one reply) until a stream begins.
    let mut next: Option<SecureConnection> = None;
    let mut next_addr: Option<SocketAddr> = None;
    let mut pending_extend: Option<TcpStream> = None;
    // Whether this link has a built circuit on it yet. A link that has only
    // handshaked, or that holds a half-finished extension to the next hop, is
    // still being set up and may idle only briefly; one carrying a built
    // circuit — including one a client keeps parked in its pool — may idle as
    // long as the client keeps it.
    let mut built = false;

    let result = async {
        loop {
            let idle = if built && pending_extend.is_none() { BUILT_CIRCUIT_IDLE } else { CONTROL_IDLE };
            let msg = match tokio::time::timeout(idle, conn.recv_message()).await {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    debug!(error = %e, "link closed or error");
                    break;
                }
                Err(_) => {
                    debug!("link idle too long; dropping");
                    break;
                }
            };
            match msg {
                Message::CreateCircuit { circuit_id } if kind == LinkKind::Client => {
                    let Some(mut key) = session_key.take() else {
                        return Err(HidraError::Circuit("a session creates one circuit".into()));
                    };
                    let layer = LayerCipher::new(&key);
                    key.zeroize();
                    create_circuit(&ctx.circuits, circuit_id, layer).await?;
                    built = true;
                    conn.send_message(&Message::CircuitCreated { circuit_id }).await?;
                    info!(circuit_id, "circuit created");
                }
                Message::Relay { circuit_id, data } => {
                    built = true;
                    let (header, inner) = open_control(&ctx.circuits, circuit_id, &data).await?;
                    let reply = match header.next_hop {
                        Some(hop) => {
                            info!(circuit_id, next_hop = %sensitive(&hop), "forwarding control cell");
                            let ns = ensure_next(&mut next, &mut next_addr, hop, &ctx).await?;
                            ns.send_message(&Message::Relay { circuit_id, data: inner }).await?;
                            read_next_relay(ns).await?
                        }
                        // The cell ends here: this hop takes the command out of
                        // its padding and pads the answer it originates.
                        None => {
                            let command = unpad_cell(&inner)?;
                            let answer =
                                handle_control(&command, circuit_id, &mut pending_extend, ctx.policy, ctx.dial_source)
                                    .await?;
                            pad_cell(&answer)?
                        }
                    };
                    let sealed = seal_reply(&ctx.circuits, circuit_id, &reply).await?;
                    conn.send_message(&Message::Relay { circuit_id, data: sealed }).await?;
                }
                Message::StreamBegin { circuit_id, data } => {
                    // The circuit leaves the table here: its layer now belongs
                    // to the stream, and the circuit ends with it.
                    let (mut layer, header, inner) = open_stream(&ctx.circuits, circuit_id, &data).await?;
                    match header.next_hop {
                        Some(hop) => {
                            info!(circuit_id, next_hop = %sensitive(&hop), "forwarding stream open");
                            let ns = ensure_next(&mut next, &mut next_addr, hop, &ctx).await?;
                            ns.send_message(&Message::StreamBegin { circuit_id, data: inner }).await?;
                            let reply = read_next_relay(ns).await?;
                            let sealed = layer.seal_backward(&reply)?;
                            conn.send_message(&Message::Relay { circuit_id, data: sealed }).await?;
                            relay_streaming_loop(&mut conn, ns, circuit_id, &mut layer).await?;
                        }
                        None => {
                            let cmd = RelayCommand::deserialize_bincode(&unpad_cell(&inner)?)?;
                            handle_exit_command(cmd, &mut conn, circuit_id, &mut layer, &ctx).await?;
                        }
                    }
                    break;
                }
                Message::Ping(ref data) if kind == LinkKind::Client => {
                    info!(bytes = data.len(), "received Ping (legacy)");
                    conn.send_message(&Message::Pong(b"HidraPong".to_vec())).await?;
                }
                other => {
                    warn!(?other, ?kind, "unexpected message on this link; closing it");
                    break;
                }
            }
        }
        Ok(())
    }
    .await;
    if let Some(mut k) = session_key {
        k.zeroize();
    }
    debug!(?kind, "link ended");
    result
}

/// Registers a circuit, after reaping those unused for a while, unless the
/// relay is full or the id is already taken. Taking an id that exists used to
/// replace that circuit's key: anyone who knew a circuit's id could break it.
async fn create_circuit(circuits: &Circuits, circuit_id: u32, layer: LayerCipher) -> Result<()> {
    let mut map = circuits.lock().await;
    let now = std::time::Instant::now();
    map.retain(|_, e| now.duration_since(e.last_used) < CIRCUIT_TTL);
    if map.len() >= MAX_CIRCUITS {
        warn!(circuit_id, "relay at circuit capacity; refusing new circuit");
        return Err(HidraError::Circuit("relay at circuit capacity".into()));
    }
    if map.contains_key(&circuit_id) {
        warn!(circuit_id, "circuit id already in use; refusing to replace it");
        return Err(HidraError::Circuit("circuit id already in use".into()));
    }
    map.insert(circuit_id, CircuitEntry { layer, last_used: now });
    Ok(())
}

/// Opens a control cell of a circuit with this relay's layer of it.
async fn open_control(circuits: &Circuits, circuit_id: u32, data: &[u8]) -> Result<(LayerHeader, Vec<u8>)> {
    let mut map = circuits.lock().await;
    let entry = map
        .get_mut(&circuit_id)
        .ok_or_else(|| HidraError::Circuit(format!("unknown circuit {circuit_id}")))?;
    entry.last_used = std::time::Instant::now();
    entry.layer.open_forward_cell(data)
}

/// Seals a reply to the client with this relay's layer of the circuit.
async fn seal_reply(circuits: &Circuits, circuit_id: u32, reply: &[u8]) -> Result<Vec<u8>> {
    let mut map = circuits.lock().await;
    let entry = map
        .get_mut(&circuit_id)
        .ok_or_else(|| HidraError::Circuit(format!("unknown circuit {circuit_id}")))?;
    entry.last_used = std::time::Instant::now();
    entry.layer.seal_backward(reply)
}

/// Opens the cell that begins a circuit's stream and takes the circuit out of
/// the table, its layer with it. Taken only once the cell has opened, so a
/// cell that does not open cannot end someone else's circuit.
async fn open_stream(
    circuits: &Circuits,
    circuit_id: u32,
    data: &[u8],
) -> Result<(LayerCipher, LayerHeader, Vec<u8>)> {
    let mut map = circuits.lock().await;
    let entry = map
        .get_mut(&circuit_id)
        .ok_or_else(|| HidraError::Circuit(format!("unknown circuit {circuit_id}")))?;
    let (header, inner) = entry.layer.open_forward_cell(data)?;
    let entry = map.remove(&circuit_id).expect("the entry was just found");
    Ok((entry.layer, header, inner))
}

/// The link to the next hop, opened once per circuit and reused.
async fn ensure_next<'a>(
    next: &'a mut Option<SecureConnection>,
    next_addr: &mut Option<SocketAddr>,
    hop: SocketAddr,
    ctx: &Ctx,
) -> Result<&'a mut SecureConnection> {
    if next.is_none() || *next_addr != Some(hop) {
        *next = Some(connect_to_next(hop, ctx.policy, ctx.dial_source).await?);
        *next_addr = Some(hop);
    }
    Ok(next.as_mut().expect("next link was just set"))
}

/// Reads one `Relay` reply from the next hop.
async fn read_next_relay(ns: &mut SecureConnection) -> Result<Vec<u8>> {
    // A hop that accepts the connection but never replies must not pin this
    // task (and the links it holds) for good. The bound sits well above the
    // downstream budget — one bounded next-hop connect plus propagation — so
    // legitimate traffic never trips it.
    let msg = tokio::time::timeout(NEXT_HOP_REPLY_TIMEOUT, ns.recv_message())
        .await
        .map_err(|_| HidraError::Relay("the next hop did not reply in time".into()))??;
    match msg {
        Message::Relay { data, .. } => Ok(data),
        other => Err(HidraError::Relay(format!("unexpected response from next hop: {other:?}"))),
    }
}

/// A control command addressed to this hop. Circuit extension is carried here;
/// anything else is the legacy one-shot echo the simple client expects (real
/// traffic arrives as `StreamBegin`). Returns the reply bytes to seal and send
/// back. The carrying relay holds neither party's key, so it only pipes the
/// handshake frames and cannot read them.
async fn handle_control(
    inner: &[u8],
    circuit_id: u32,
    pending_extend: &mut Option<TcpStream>,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
) -> Result<Vec<u8>> {
    match RelayCommand::deserialize_bincode(inner) {
        Ok(RelayCommand::Extend { to, frame }) => {
            if frame.len() > MAX_HANDSHAKE_FRAME {
                return RelayCommand::ExtendError("extension handshake frame too large".into())
                    .serialize_bincode();
            }
            if !policy.permits_hop(&to) {
                warn!(circuit_id, "extension refused: next hop is not a public address");
                return RelayCommand::ExtendError("next hop refused by relay policy".into())
                    .serialize_bincode();
            }
            info!(circuit_id, hop = %sensitive(&to), "carrying a circuit extension to the next hop");
            let reply = match open_and_carry(to, &frame, dial_source).await {
                Ok((hop, msg_b)) => {
                    *pending_extend = Some(hop);
                    RelayCommand::Extended { frame: msg_b }
                }
                Err(e) => {
                    warn!(circuit_id, error = %e, "extension to the next hop failed");
                    RelayCommand::ExtendError(format!("{e}"))
                }
            };
            Ok(reply.serialize_bincode()?)
        }
        Ok(RelayCommand::ExtendFinish { frame_c, frame_create }) => {
            if frame_c.len() > MAX_HANDSHAKE_FRAME || frame_create.len() > MAX_HANDSHAKE_FRAME {
                return RelayCommand::ExtendError("extension handshake frame too large".into())
                    .serialize_bincode();
            }
            let reply = match pending_extend.take() {
                Some(mut hop) => match finish_carry(&mut hop, &frame_c, &frame_create).await {
                    Ok(created) => RelayCommand::ExtendDone { frame_created: created },
                    Err(e) => {
                        warn!(circuit_id, error = %e, "finishing the extension failed");
                        RelayCommand::ExtendError(format!("{e}"))
                    }
                },
                None => RelayCommand::ExtendError("no extension is in progress".into()),
            };
            Ok(reply.serialize_bincode()?)
        }
        _ => {
            // Not an extension: the length only, never the content. This is a
            // payload a user sent through the circuit; the exit answers with a
            // fixed acknowledgement, as the simple one-shot client expects.
            info!(circuit_id, bytes = inner.len(), "exit node - received payload (legacy)");
            Ok(b"Received, agent".to_vec())
        }
    }
}

/// How long the whole carried extension (connect, writes and read) may take on
/// the next hop, so a slow or black-hole target cannot tie up the control path.
const EXTEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a link that is still being set up — one whose circuit is not yet
/// built, or that holds a half-finished extension to the next hop — may sit
/// idle between cells before it is dropped, so a stalled build never holds a
/// connection (or a carried next-hop link) open for good.
const CONTROL_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a fully built circuit's link may sit idle between cells. A client
/// keeps a built circuit in its pool and may not send on it for a while, so
/// this must exceed that pool lifetime (the client's CIRCUIT_TTL, 300s) or a
/// pooled circuit would be torn down relay-side while the client still hands
/// it out. The circuit itself stays bounded by CIRCUIT_TTL and MAX_CIRCUITS.
const BUILT_CIRCUIT_IDLE: std::time::Duration = std::time::Duration::from_secs(330);
/// A Noise handshake message, or the small sealed CreateCircuit, carried in an
/// extension cell is at most this big; a larger client-supplied frame is
/// refused rather than written to the next hop.
const MAX_HANDSHAKE_FRAME: usize = 4096;
/// How long a TCP connection to the next hop, or from the exit to its target,
/// may take to open, so a black-hole address cannot park a relay task on a
/// connect that never completes.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long to wait for the next hop's reply to a forwarded control or
/// stream-open cell. Finite so a silent hop cannot hold a relay task and its
/// links open for good, but well above the downstream budget (one bounded
/// connect plus propagation) so real traffic is never cut off.
const NEXT_HOP_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a circuit's per-relay state is kept with no use before it is reaped
/// (the timer is refreshed on each cell). This must exceed the client's
/// pooled-circuit lifetime (its own CIRCUIT_TTL, 300s) so the relay never
/// discards a circuit a client may still present from its pool; it mirrors
/// BUILT_CIRCUIT_IDLE.
const CIRCUIT_TTL: std::time::Duration = std::time::Duration::from_secs(330);
/// The most circuits one relay keeps state for at once; past this, new
/// CreateCircuit requests are refused rather than growing the map unbounded.
const MAX_CIRCUITS: usize = 65_536;
/// How long a Noise handshake may take once the protocol byte has been read; a
/// peer that then stalls on a handshake frame is dropped instead of pinning
/// the task and its socket. A real handshake completes in well under a second.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// The most addresses a DNS answer carries back, so it always fits one cell.
const MAX_DNS_ANSWERS: usize = 16;

/// Opens a link to a new hop and carries the client's Noise message A to it,
/// returning the hop's reply B and the still-open link for the matching
/// `ExtendFinish`.
async fn open_and_carry(
    to: SocketAddr,
    msg_a: &[u8],
    dial_source: Option<IpAddr>,
) -> Result<(TcpStream, Vec<u8>)> {
    // Every step is bounded by one timeout, and the address never reaches an
    // error or a log: it is the next hop a user is heading to.
    tokio::time::timeout(EXTEND_TIMEOUT, async move {
        let mut hop = dial(to, dial_source)
            .await
            .map_err(|_| HidraError::Relay("could not reach the next hop".into()))?;
        hop.write_all(&[PROTO_NOISE_SESSION]).await?;
        write_frame(&mut hop, msg_a).await?;
        let msg_b = read_frame(&mut hop).await?;
        Ok((hop, msg_b))
    })
    .await
    .map_err(|_| HidraError::Relay("the next hop did not answer in time".into()))?
}

/// Carries the client's final Noise message C and sealed CreateCircuit to the
/// new hop, and brings its sealed CircuitCreated back. The link is dropped
/// after; the new hop keeps the registered circuit, which later cells reach
/// over the relay link from this hop.
async fn finish_carry(hop: &mut TcpStream, msg_c: &[u8], sealed_create: &[u8]) -> Result<Vec<u8>> {
    tokio::time::timeout(EXTEND_TIMEOUT, async move {
        write_frame(hop, msg_c).await?;
        write_frame(hop, sealed_create).await?;
        read_frame(hop).await
    })
    .await
    .map_err(|_| HidraError::Relay("the next hop did not answer in time".into()))?
}

/// Seals a command back to the client, padded to one cell, and sends it.
async fn reply(
    conn: &mut SecureConnection,
    circuit_id: u32,
    layer: &mut LayerCipher,
    cmd: &RelayCommand,
) -> Result<()> {
    let sealed = layer.seal_backward(&pad_cell(&cmd.serialize_bincode()?)?)?;
    conn.send_message(&Message::Relay { circuit_id, data: sealed }).await
}

/// Sends stream data back to the client in as many cells as it takes.
async fn reply_data(
    conn: &mut SecureConnection,
    circuit_id: u32,
    layer: &mut LayerCipher,
    data: &[u8],
) -> Result<()> {
    for piece in data.chunks(MAX_DATA) {
        reply(conn, circuit_id, layer, &RelayCommand::Data(piece.to_vec())).await?;
    }
    Ok(())
}

/// The command a stream cell from the client carries, out of its padding.
fn open_command(layer: &mut LayerCipher, data: &[u8]) -> Result<RelayCommand> {
    RelayCommand::deserialize_bincode(&unpad_cell(&layer.open_forward(data)?)?)
}

async fn handle_exit_command(
    cmd: RelayCommand,
    conn: &mut SecureConnection,
    circuit_id: u32,
    layer: &mut LayerCipher,
    ctx: &Ctx,
) -> Result<()> {
    match cmd {
        RelayCommand::Connect { host, port } => {
            info!(circuit_id, host = %sensitive(&host), port, "exit relay — connecting to target");
            let target_addr = format!("{host}:{port}");
            let resolved = ctx.policy.resolve_target(&host, port).await;
            let mut target = match exit_connect(resolved).await {
                Ok(t) => {
                    info!(circuit_id, target = %sensitive(&target_addr), "exit relay — connected to target");
                    t
                }
                Err(e) => {
                    warn!(circuit_id, error = %e, target = %sensitive(&target_addr), "exit relay — connect failed");
                    return reply(conn, circuit_id, layer, &RelayCommand::ConnectFailed(format!("{e}"))).await;
                }
            };
            reply(conn, circuit_id, layer, &RelayCommand::Connected).await?;
            exit_streaming_loop(conn, &mut target, circuit_id, layer).await
        }
        RelayCommand::RegisterService { service_hash, service_pubkey, timestamp, signature } => {
            if let Err(e) = crate::crypto::service_auth::verify_registration(
                &service_hash,
                &service_pubkey,
                timestamp,
                &signature,
            ) {
                warn!(circuit_id, error = %e, "intro relay — registration refused");
                return reply(conn, circuit_id, layer, &RelayCommand::ConnectFailed(format!("{e}"))).await;
            }
            info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay — registering hidden service");
            let (pipe_tx, mut pipe_rx) = mpsc::channel::<ClientPipe>(16);
            ctx.intro_registry.lock().await.insert(service_hash.clone(), pipe_tx);
            reply(conn, circuit_id, layer, &RelayCommand::ServiceRegistered).await?;
            info!(circuit_id, "intro relay — service registered, waiting for clients");
            while let Some(mut client_pipe) = pipe_rx.recv().await {
                info!(circuit_id, "intro relay — bridging client to service");
                if let Err(e) = bridge(
                    conn,
                    circuit_id,
                    layer,
                    &client_pipe.to_client,
                    &mut client_pipe.from_client,
                )
                .await
                {
                    warn!(error = %e, "service bridge session ended");
                }
            }
            ctx.intro_registry.lock().await.remove(&service_hash);
            info!(circuit_id, "intro relay — service deregistered");
            Ok(())
        }
        RelayCommand::ConnectService { service_hash } => {
            info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay — client connecting to service");
            let pipe_tx = ctx.intro_registry.lock().await.get(&service_hash).cloned();
            let Some(pipe_tx) = pipe_tx else {
                warn!(circuit_id, "intro relay — service not found");
                let fail = RelayCommand::ConnectFailed("service not found at this intro point".into());
                return reply(conn, circuit_id, layer, &fail).await;
            };
            let (client_to_svc_tx, client_to_svc_rx) = mpsc::channel::<Vec<u8>>(256);
            let (svc_to_client_tx, mut svc_to_client_rx) = mpsc::channel::<Vec<u8>>(256);
            let client_pipe = ClientPipe {
                from_client: client_to_svc_rx,
                to_client: svc_to_client_tx,
            };
            if pipe_tx.send(client_pipe).await.is_err() {
                warn!(circuit_id, "intro relay — service handler gone");
                let fail = RelayCommand::ConnectFailed("service handler disconnected".into());
                return reply(conn, circuit_id, layer, &fail).await;
            }
            reply(conn, circuit_id, layer, &RelayCommand::ServiceConnected).await?;
            info!(circuit_id, "intro relay — bridging client ↔ service");
            bridge(conn, circuit_id, layer, &client_to_svc_tx, &mut svc_to_client_rx).await
        }
        RelayCommand::ResolveDns { hostname } => {
            info!(circuit_id, hostname = %sensitive(&hostname), "exit relay — DNS resolution");
            let addr_str = format!("{hostname}:0");
            let addresses: Vec<String> = match tokio::net::lookup_host(&addr_str).await {
                Ok(addrs) => ctx
                    .policy
                    .filter_answer(addrs.map(|a| a.ip()).collect())
                    .into_iter()
                    .take(MAX_DNS_ANSWERS)
                    .map(|ip| ip.to_string())
                    .collect(),
                Err(e) => {
                    warn!(circuit_id, hostname = %sensitive(&hostname), error = %e, "DNS resolution failed");
                    Vec::new()
                }
            };
            reply(conn, circuit_id, layer, &RelayCommand::DnsResolved { addresses }).await
        }
        other => {
            warn!(circuit_id, cmd = ?other, "unexpected relay command at exit");
            Ok(())
        }
    }
}

async fn exit_streaming_loop(
    conn: &mut SecureConnection,
    target: &mut TcpStream,
    circuit_id: u32,
    layer: &mut LayerCipher,
) -> Result<()> {
    let mut target_buf = vec![0u8; 16384];
    loop {
        // Both reads are cancel safe: recv_message reads through the link's
        // FrameReader, and a TcpStream read either reads or does not.
        tokio::select! {
            msg_result = conn.recv_message() => {
                let data = match msg_result {
                    Ok(Message::Relay { data, .. }) => data,
                    _ => break,
                };
                match open_command(layer, &data)? {
                    RelayCommand::Data(payload) => {
                        if target.write_all(&payload).await.is_err() { break; }
                    }
                    RelayCommand::End => {
                        debug!(circuit_id, "exit relay — stream ended by client");
                        break;
                    }
                    _ => {}
                }
            }
            n = target.read(&mut target_buf) => {
                match n {
                    Ok(0) => {
                        debug!(circuit_id, "exit relay — target closed connection");
                        let _ = reply(conn, circuit_id, layer, &RelayCommand::End).await;
                        break;
                    }
                    Ok(n) => reply_data(conn, circuit_id, layer, &target_buf[..n]).await?,
                    Err(_) => break,
                }
            }
        }
    }
    info!(circuit_id, "exit streaming loop ended");
    Ok(())
}

/// Carries a stream between the hop before and the hop after: each cell from
/// the client loses this relay's layer on the way out, each cell towards it
/// gains one.
async fn relay_streaming_loop(
    conn: &mut SecureConnection,
    next: &mut SecureConnection,
    circuit_id: u32,
    layer: &mut LayerCipher,
) -> Result<()> {
    loop {
        // Both reads are cancel safe (each link reads through its FrameReader).
        tokio::select! {
            msg_result = conn.recv_message() => {
                let data = match msg_result {
                    Ok(Message::Relay { data, .. }) => data,
                    _ => break,
                };
                let opened = layer.open_forward(&data)?;
                next.send_message(&Message::Relay { circuit_id, data: opened }).await?;
            }
            msg_result = next.recv_message() => {
                let data = match msg_result {
                    Ok(Message::Relay { data, .. }) => data,
                    _ => break,
                };
                let sealed = layer.seal_backward(&data)?;
                conn.send_message(&Message::Relay { circuit_id, data: sealed }).await?;
            }
        }
    }
    info!(circuit_id, "relay streaming loop ended");
    Ok(())
}

/// Bridges a circuit at its intro relay to the other end of a hidden-service
/// connection, through a pair of channels: the service's circuit to one
/// client's, or a client's to the service's.
async fn bridge(
    conn: &mut SecureConnection,
    circuit_id: u32,
    layer: &mut LayerCipher,
    to_other: &mpsc::Sender<Vec<u8>>,
    from_other: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    loop {
        tokio::select! {
            msg_result = conn.recv_message() => {
                let data = match msg_result {
                    Ok(Message::Relay { data, .. }) => data,
                    _ => break,
                };
                match open_command(layer, &data)? {
                    RelayCommand::Data(payload) => {
                        if to_other.send(payload).await.is_err() {
                            break;
                        }
                    }
                    RelayCommand::End => break,
                    _ => {}
                }
            }
            data = from_other.recv() => {
                match data {
                    Some(payload) => reply_data(conn, circuit_id, layer, &payload).await?,
                    None => break,
                }
            }
        }
    }
    debug!(circuit_id, "hidden-service bridge ended");
    Ok(())
}

/// Connect to an exit destination the policy has already resolved and
/// checked, trying its addresses in order until one answers: a name's first
/// address can be one this exit cannot reach (IPv6 on an IPv4-only host).
async fn exit_connect(resolved: std::result::Result<Vec<SocketAddr>, String>) -> std::io::Result<TcpStream> {
    let addrs = resolved.map_err(|why| std::io::Error::new(std::io::ErrorKind::PermissionDenied, why))?;
    let mut last = std::io::Error::new(std::io::ErrorKind::NotFound, "destination did not resolve");
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = e,
            Err(_) => last = std::io::Error::new(std::io::ErrorKind::TimedOut, "exit connection timed out"),
        }
    }
    Err(last)
}

/// Opens the link to the next hop on a circuit: a Noise XX session, so what
/// crosses the network between two relays — which circuit a cell belongs to,
/// what kind of cell it is — is no longer in the clear, and nobody between
/// them can slip a cell in. This relay shows a key made for the link alone.
/// It does not check the next hop's key: the client already pinned it in its
/// own handshake with that hop, and the cells the link carries open only
/// under the layers the two agreed.
async fn connect_to_next(
    addr: SocketAddr,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
) -> Result<SecureConnection> {
    // The next hop is named by whoever built the circuit; without this a
    // circuit could be pointed at the relay's own loopback or network.
    if !policy.permits_hop(&addr) {
        warn!("next hop refused by this relay's policy: not a public address");
        return Err(HidraError::Relay("next hop refused by relay policy".into()));
    }
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, dial(addr, dial_source))
        .await
        .map_err(|_| HidraError::Relay("could not connect to the next hop".into()))?
        .map_err(|_| HidraError::Relay("could not connect to the next hop".into()))?;
    let mut handshake = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        stream.write_all(&[PROTO_RELAY_LINK]).await?;
        write_frame(&mut stream, &handshake.write_message_a()?).await?;
        let msg_b = read_frame(&mut stream).await?;
        handshake.read_message_b(&msg_b)?;
        write_frame(&mut stream, &handshake.write_message_c()?).await?;
        Ok::<(), HidraError>(())
    })
    .await
    .map_err(|_| HidraError::Relay("the next hop did not complete the link handshake in time".into()))??;
    let (send_cipher, recv_cipher) = handshake.into_transport()?;
    Ok(SecureConnection::new(stream, send_cipher, recv_cipher))
}

/// Opens a TCP connection to `addr`, from `source` if one is set (a node that
/// pins its egress address). Default (None) lets the kernel choose the source,
/// exactly as a plain connect did.
async fn dial(addr: SocketAddr, source: Option<IpAddr>) -> std::io::Result<TcpStream> {
    match source {
        Some(ip) => {
            let socket = if addr.is_ipv4() {
                tokio::net::TcpSocket::new_v4()?
            } else {
                tokio::net::TcpSocket::new_v6()?
            };
            socket.bind(SocketAddr::new(ip, 0))?;
            socket.connect(addr).await
        }
        None => TcpStream::connect(addr).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name whose first address this exit cannot reach — IPv6 on an
    /// IPv4-only host — still connects through the next one. It used to fail
    /// outright, which is what broke reaching "localhost" on a machine where
    /// it resolves to ::1 first.
    #[tokio::test]
    async fn the_exit_tries_each_address_until_one_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        // A port on ::1 nothing listens on (or no IPv6 at all): refused either way.
        let unreachable: SocketAddr = format!("[::1]:{}", open.port()).parse().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        let stream = exit_connect(Ok(vec![unreachable, open])).await;
        assert!(stream.is_ok(), "the second address was never tried: {:?}", stream.err());
        assert!(accept.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn the_exit_reports_the_last_failure_when_none_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        assert!(exit_connect(Ok(vec![closed])).await.is_err());
        assert!(exit_connect(Err("refused by policy".into())).await.is_err());
    }
}
