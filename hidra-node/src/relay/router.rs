use crate::safelog::sensitive;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn, Instrument};
use uuid::Uuid;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::crypto::handshake::{HandshakeState, Role};
use crate::error::{HidraError, Result};
use crate::network::connection::{
    read_frame, write_frame, FrameReader, Message, SecureConnection,
};
use crate::network::listener::{PROTO_FORWARDED_CELL, PROTO_NOISE_SESSION};
use crate::onion::cell::{LayerHeader, RelayCommand};
use crate::relay::exit_policy::ExitPolicy;
use crate::onion::layer::{
    decrypt_stream, encrypt_stream, peel_layer, wrap_layer,
};

struct CircuitEntry {
    session_key: [u8; 32],
    /// When this circuit's state was last used, refreshed on every `circuit_key`
    /// lookup. Reaped by time since last use (not since registration) so a
    /// circuit a client still holds — including one idle in its pool — is never
    /// reaped out from under it, while abandoned ones stay bounded by
    /// CIRCUIT_TTL and MAX_CIRCUITS.
    last_used: std::time::Instant,
}

impl Drop for CircuitEntry {
    fn drop(&mut self) {
        self.session_key.zeroize();
    }
}

pub struct ClientPipe {
    pub from_client: mpsc::Receiver<Vec<u8>>,
    pub to_client: mpsc::Sender<Vec<u8>>,
}

type IntroRegistry = Arc<Mutex<HashMap<Vec<u8>, mpsc::Sender<ClientPipe>>>>;

pub struct RelayRouter {
    circuits: Arc<Mutex<HashMap<u32, CircuitEntry>>>,
    static_secret_bytes: Arc<[u8; 32]>,
    intro_registry: IntroRegistry,
    policy: ExitPolicy,
    /// When set, the address every outbound hop connection is sent from. Off
    /// by default (the kernel chooses); a node that pins its egress sets it.
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

    pub async fn handle_client_connection(
        &self,
        stream: TcpStream,
        remote_addr: SocketAddr,
    ) {
        let session_id = Uuid::new_v4().to_string();
        let span = tracing::info_span!(
            "relay_session",
            session_id = %session_id,
            remote_addr = %sensitive(&remote_addr),
            role = "relay_responder",
        );
        let circuits = Arc::clone(&self.circuits);
        let secret_bytes = Arc::clone(&self.static_secret_bytes);
        let intro_reg = Arc::clone(&self.intro_registry);
        let policy = self.policy;
        let dial_source = self.dial_source;
        tokio::spawn(
            async move {
                info!("client connection — starting Noise handshake");
                if let Err(e) = handle_noise_session(
                    stream,
                    &secret_bytes,
                    circuits,
                    intro_reg,
                    policy,
                    dial_source,
                )
                .await
                {
                    warn!(error = %e, "relay session failed");
                }
            }
            .instrument(span),
        );
    }

    pub async fn handle_forwarded_cell(
        &self,
        stream: TcpStream,
        remote_addr: SocketAddr,
    ) {
        let span = tracing::info_span!(
            "forwarded_cell",
            remote_addr = %sensitive(&remote_addr),
        );
        let circuits = Arc::clone(&self.circuits);
        let intro_reg = Arc::clone(&self.intro_registry);
        let policy = self.policy;
        let dial_source = self.dial_source;
        tokio::spawn(
            async move {
                debug!("forwarded cell connection");
                if let Err(e) =
                    handle_forwarded(stream, circuits, intro_reg, policy, dial_source).await
                {
                    warn!(error = %e, "forwarded cell processing failed");
                }
            }
            .instrument(span),
        );
    }
}

async fn handle_noise_session(
    mut stream: TcpStream,
    secret_bytes: &[u8; 32],
    circuits: Arc<Mutex<HashMap<u32, CircuitEntry>>>,
    intro_registry: IntroRegistry,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
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
    info!("relay Noise XX handshake completed");
    let (send_cipher, recv_cipher) = handshake.into_transport()?;
    let session_key = recv_cipher.session_key()?;
    let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

    // Per-circuit state on this link: the hop this relay forwards to (opened
    // once and reused), and a half-finished extension awaiting its second
    // round. The circuit stays in control mode (one request, one reply) until
    // a stream begins.
    let mut next_stream: Option<TcpStream> = None;
    let mut next_addr: Option<SocketAddr> = None;
    let mut pending_extend: Option<TcpStream> = None;
    // Whether a circuit has been built on this link yet. A connection that has
    // only handshaked (no CreateCircuit), or that holds a half-finished
    // extension to the next hop, is still being set up and may idle only
    // briefly; a fully built circuit — including one a client keeps parked in
    // its pool — may idle as long as the client keeps it, so it is not torn
    // down out from under a pooled circuit.
    let mut circuit_built = false;

    loop {
        let idle = if circuit_built && pending_extend.is_none() {
            BUILT_CIRCUIT_IDLE
        } else {
            CONTROL_IDLE
        };
        let msg = match tokio::time::timeout(idle, conn.recv_message()).await {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                debug!(error = %e, "connection closed or error");
                break;
            }
            Err(_) => {
                debug!("control phase idle too long; dropping");
                break;
            }
        };
        match msg {
            Message::CreateCircuit { circuit_id } => {
                info!(circuit_id, "creating circuit");
                {
                    let mut map = circuits.lock().await;
                    let now = std::time::Instant::now();
                    // Reap circuits unused for a while first, then refuse if
                    // still at the cap, so a client cannot grow this map without
                    // bound.
                    map.retain(|_, e| now.duration_since(e.last_used) < CIRCUIT_TTL);
                    if map.len() >= MAX_CIRCUITS {
                        warn!(circuit_id, "relay at circuit capacity; refusing new circuit");
                        return Err(HidraError::Circuit("relay at circuit capacity".into()));
                    }
                    map.insert(circuit_id, CircuitEntry { session_key, last_used: now });
                }
                circuit_built = true;
                conn.send_message(&Message::CircuitCreated { circuit_id })
                    .await?;
                info!(circuit_id, "circuit created");
            }
            Message::Relay { circuit_id, data } => {
                let key = circuit_key(&circuits, circuit_id).await?;
                let (header, inner) = peel_layer(&key, &data)?;
                match header.next_hop {
                    Some(next_addr_hop) => {
                        info!(circuit_id, next_hop = %sensitive(&next_addr_hop), "forwarding control cell");
                        let ns =
                            ensure_next(&mut next_stream, &mut next_addr, next_addr_hop, policy, dial_source).await?;
                        write_frame(ns, &Message::Relay { circuit_id, data: inner }.serialize()).await?;
                        let reply = read_next_relay(ns).await?;
                        let wrapped = wrap_layer(&key, &LayerHeader { next_hop: None }, &reply)?;
                        conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                    }
                    None => {
                        let reply =
                            handle_control(&inner, circuit_id, &mut pending_extend, policy, dial_source).await?;
                        let wrapped = wrap_layer(&key, &LayerHeader { next_hop: None }, &reply)?;
                        conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                    }
                }
            }
            Message::StreamBegin { circuit_id, data } => {
                let key = circuit_key(&circuits, circuit_id).await?;
                let (header, inner) = peel_layer(&key, &data)?;
                match header.next_hop {
                    Some(next_addr_hop) => {
                        info!(circuit_id, next_hop = %sensitive(&next_addr_hop), "forwarding stream open");
                        let ns =
                            ensure_next(&mut next_stream, &mut next_addr, next_addr_hop, policy, dial_source).await?;
                        write_frame(ns, &Message::StreamBegin { circuit_id, data: inner }.serialize()).await?;
                        let reply = read_next_relay(ns).await?;
                        let wrapped = wrap_layer(&key, &LayerHeader { next_hop: None }, &reply)?;
                        conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                        info!(circuit_id, "entering relay streaming loop");
                        relay_streaming_loop(&mut conn, ns, circuit_id, &key).await?;
                        break;
                    }
                    None => {
                        let cmd = RelayCommand::deserialize_bincode(&inner)?;
                        handle_exit_command(cmd, &mut conn, circuit_id, &key, &intro_registry, policy)
                            .await?;
                        break;
                    }
                }
            }
            Message::Ping(ref data) => {
                info!(bytes = data.len(), "received Ping (legacy)");
                conn.send_message(&Message::Pong(b"HidraPong".to_vec()))
                    .await?;
            }
            other => {
                warn!(?other, "unexpected message in relay session");
            }
        }
    }
    info!("relay session ended");
    Ok(())
}

async fn handle_forwarded(
    mut stream: TcpStream,
    circuits: Arc<Mutex<HashMap<u32, CircuitEntry>>>,
    intro_registry: IntroRegistry,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
) -> Result<()> {
    let mut next_stream: Option<TcpStream> = None;
    let mut next_addr: Option<SocketAddr> = None;
    let mut pending_extend: Option<TcpStream> = None;
    // Whether this forwarded link has carried a cell for a real circuit yet.
    // See handle_noise_session: a link still being set up (nothing carried yet,
    // or a half-finished extension) idles only briefly; one carrying a built
    // circuit may idle as long as a client keeps that circuit pooled.
    let mut carrying = false;

    loop {
        let idle = if carrying && pending_extend.is_none() {
            BUILT_CIRCUIT_IDLE
        } else {
            CONTROL_IDLE
        };
        let frame = match tokio::time::timeout(idle, read_frame(&mut stream)).await {
            Ok(Ok(f)) => f,
            Ok(Err(_)) => break,
            Err(_) => break,
        };
        match Message::deserialize(&frame)? {
            Message::Relay { circuit_id, data } => {
                let key = circuit_key(&circuits, circuit_id).await?;
                // A real circuit cell arrived; once built this link may idle.
                carrying = true;
                let (header, inner) = peel_layer(&key, &data)?;
                match header.next_hop {
                    Some(next_addr_hop) => {
                        info!(circuit_id, next_hop = %sensitive(&next_addr_hop), "forwarding control cell further");
                        let ns =
                            ensure_next(&mut next_stream, &mut next_addr, next_addr_hop, policy, dial_source).await?;
                        write_frame(ns, &Message::Relay { circuit_id, data: inner }.serialize()).await?;
                        let reply = read_next_relay(ns).await?;
                        let wrapped = wrap_layer(&key, &LayerHeader { next_hop: None }, &reply)?;
                        write_frame(&mut stream, &Message::Relay { circuit_id, data: wrapped }.serialize()).await?;
                    }
                    None => {
                        let reply =
                            handle_control(&inner, circuit_id, &mut pending_extend, policy, dial_source).await?;
                        let wrapped = wrap_layer(&key, &LayerHeader { next_hop: None }, &reply)?;
                        write_frame(&mut stream, &Message::Relay { circuit_id, data: wrapped }.serialize()).await?;
                    }
                }
            }
            Message::StreamBegin { circuit_id, data } => {
                let key = circuit_key(&circuits, circuit_id).await?;
                let (header, inner) = peel_layer(&key, &data)?;
                match header.next_hop {
                    Some(next_addr_hop) => {
                        info!(circuit_id, next_hop = %sensitive(&next_addr_hop), "forwarding stream open further");
                        let ns =
                            ensure_next(&mut next_stream, &mut next_addr, next_addr_hop, policy, dial_source).await?;
                        write_frame(ns, &Message::StreamBegin { circuit_id, data: inner }.serialize()).await?;
                        let reply = read_next_relay(ns).await?;
                        let wrapped = wrap_layer(&key, &LayerHeader { next_hop: None }, &reply)?;
                        write_frame(&mut stream, &Message::Relay { circuit_id, data: wrapped }.serialize()).await?;
                        info!(circuit_id, "entering forwarded streaming loop");
                        forwarded_streaming_loop(&mut stream, ns, circuit_id, &key).await?;
                        break;
                    }
                    None => {
                        let cmd = RelayCommand::deserialize_bincode(&inner)?;
                        handle_exit_forwarded(cmd, &mut stream, circuit_id, &key, &intro_registry, policy)
                            .await?;
                        break;
                    }
                }
            }
            other => {
                warn!(?other, "unexpected forwarded message type");
                break;
            }
        }
    }
    Ok(())
}

/// This relay's layer key for a circuit, by its id.
async fn circuit_key(
    circuits: &Arc<Mutex<HashMap<u32, CircuitEntry>>>,
    circuit_id: u32,
) -> Result<[u8; 32]> {
    let mut map = circuits.lock().await;
    let entry = map
        .get_mut(&circuit_id)
        .ok_or_else(|| HidraError::Circuit(format!("unknown circuit {circuit_id}")))?;
    // Refresh the last-use time so the reap measures idleness from last use,
    // not from registration (see CircuitEntry.last_used / CIRCUIT_TTL).
    entry.last_used = std::time::Instant::now();
    Ok(entry.session_key)
}

/// The forwarding link to the next hop, opened once per circuit and reused.
async fn ensure_next<'a>(
    next_stream: &'a mut Option<TcpStream>,
    next_addr: &mut Option<SocketAddr>,
    next: SocketAddr,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
) -> Result<&'a mut TcpStream> {
    if next_stream.is_none() || *next_addr != Some(next) {
        let s = connect_to_next(next, policy, dial_source).await?;
        *next_stream = Some(s);
        *next_addr = Some(next);
    }
    Ok(next_stream.as_mut().expect("next stream was just set"))
}

/// Reads one `Relay` reply from the next hop.
async fn read_next_relay(ns: &mut TcpStream) -> Result<Vec<u8>> {
    // A hop that accepts the connection but never replies must not pin this
    // task (and the links it holds) for good. The bound sits well above the
    // downstream budget — one bounded next-hop connect plus propagation — so
    // legitimate traffic never trips it.
    let frame = tokio::time::timeout(NEXT_HOP_REPLY_TIMEOUT, read_frame(ns))
        .await
        .map_err(|_| HidraError::Relay("the next hop did not reply in time".into()))??;
    match Message::deserialize(&frame)? {
        Message::Relay { data, .. } => Ok(data),
        other => Err(HidraError::Relay(format!(
            "unexpected response from next hop: {other:?}"
        ))),
    }
}

/// A control command addressed to this hop. Circuit extension is carried here;
/// anything else is the legacy one-shot echo the simple client expects (real
/// traffic arrives as `StreamBegin`). Returns the reply bytes to wrap and send
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

/// Opens a link to a new hop and carries the client's Noise message A to it,
/// returning the hop's reply B and the still-open link for the matching
/// `ExtendFinish`.
/// How long the whole carried extension (connect, writes and read) may take on
/// the next hop, so a slow or black-hole target cannot tie up the control path.
const EXTEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long a connection that is still being set up — one whose circuit is not
/// yet built, or that holds a half-finished extension to the next hop — may sit
/// idle between cells before it is dropped, so a stalled build never holds a
/// connection (or a carried next-hop link) open for good.
const CONTROL_IDLE: std::time::Duration = std::time::Duration::from_secs(60);
/// How long a fully built circuit's control link may sit idle between cells. A
/// client keeps a built circuit in its pool and may not send on it for a while,
/// so this must exceed that pool lifetime (the client's CIRCUIT_TTL, 300s) or a
/// pooled circuit would be torn down relay-side while the client still hands it
/// out. The circuit itself stays bounded by CIRCUIT_TTL and MAX_CIRCUITS.
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
/// (the timer is refreshed on each use in `circuit_key`). This must exceed the
/// client's pooled-circuit lifetime (its own CIRCUIT_TTL, 300s) so the relay
/// never discards a circuit a client may still present from its pool; it
/// mirrors BUILT_CIRCUIT_IDLE.
const CIRCUIT_TTL: std::time::Duration = std::time::Duration::from_secs(330);
/// The most circuits one relay keeps state for at once; past this, new
/// CreateCircuit requests are refused rather than growing the map unbounded.
const MAX_CIRCUITS: usize = 65_536;
/// How long the responder Noise handshake may take once the protocol byte has
/// been read; a peer that then stalls on a handshake frame is dropped instead
/// of pinning the task and its socket. A real handshake completes in well under
/// a second.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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
/// after; the new hop keeps the registered circuit, which later data reaches
/// over the ordinary forwarded link.
async fn finish_carry(hop: &mut TcpStream, msg_c: &[u8], sealed_create: &[u8]) -> Result<Vec<u8>> {
    tokio::time::timeout(EXTEND_TIMEOUT, async move {
        write_frame(hop, msg_c).await?;
        write_frame(hop, sealed_create).await?;
        read_frame(hop).await
    })
    .await
    .map_err(|_| HidraError::Relay("the next hop did not answer in time".into()))?
}

async fn handle_exit_command(
    cmd: RelayCommand,
    conn: &mut SecureConnection,
    circuit_id: u32,
    key: &[u8; 32],
    intro_registry: &IntroRegistry,
    policy: ExitPolicy,
) -> Result<()> {
    match cmd {
        RelayCommand::Connect { host, port } => {
            info!(circuit_id, host = %sensitive(&host), port, "exit relay — connecting to target");
            let target_addr = format!("{host}:{port}");
            let resolved = policy.resolve_target(&host, port).await;
            let mut target =
                match exit_connect(resolved).await {
                    Ok(t) => {
                        info!(circuit_id, target = %sensitive(&target_addr), "exit relay — connected to target");
                        t
                    }
                    Err(e) => {
                        warn!(circuit_id, error = %e, target = %sensitive(&target_addr), "exit relay — connect failed");
                        let fail = RelayCommand::ConnectFailed(
                            format!("{e}"),
                        );
                        let fail_data = fail.serialize_bincode()?;
                        let wrapped = wrap_layer(
                            key,
                            &LayerHeader { next_hop: None },
                            &fail_data,
                        )?;
                        conn.send_message(&Message::Relay {
                            circuit_id,
                            data: wrapped,
                        })
                        .await?;
                        return Ok(());
                    }
                };
            let connected = RelayCommand::Connected;
            let connected_data = connected.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &connected_data,
            )?;
            conn.send_message(&Message::Relay {
                circuit_id,
                data: wrapped,
            })
            .await?;
            exit_streaming_loop(conn, &mut target, circuit_id, key)
                .await
        }
        RelayCommand::RegisterService { service_hash, service_pubkey, timestamp, signature } => {
            if let Err(e) = crate::crypto::service_auth::verify_registration(
                &service_hash,
                &service_pubkey,
                timestamp,
                &signature,
            ) {
                warn!(circuit_id, error = %e, "intro relay — registration refused");
                let fail = RelayCommand::ConnectFailed(format!("{e}"));
                let fail_data = fail.serialize_bincode()?;
                let wrapped = wrap_layer(key, &LayerHeader { next_hop: None }, &fail_data)?;
                conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                return Ok(());
            }
            info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay — registering hidden service");
            let (pipe_tx, mut pipe_rx) = mpsc::channel::<ClientPipe>(16);
            {
                let mut reg = intro_registry.lock().await;
                reg.insert(service_hash.clone(), pipe_tx);
            }
            let ack = RelayCommand::ServiceRegistered;
            let ack_data = ack.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &ack_data,
            )?;
            conn.send_message(&Message::Relay {
                circuit_id,
                data: wrapped,
            })
            .await?;
            info!(circuit_id, "intro relay — service registered, waiting for clients");
            while let Some(mut client_pipe) = pipe_rx.recv().await {
                info!(circuit_id, "intro relay — bridging client to service");
                if let Err(e) = bridge_service_session(
                    conn,
                    circuit_id,
                    key,
                    &mut client_pipe.from_client,
                    &client_pipe.to_client,
                )
                .await
                {
                    warn!(error = %e, "service bridge session ended");
                }
            }
            {
                let mut reg = intro_registry.lock().await;
                reg.remove(&service_hash);
            }
            info!(circuit_id, "intro relay — service deregistered");
            Ok(())
        }
        RelayCommand::ConnectService { service_hash } => {
            info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay — client connecting to service");
            let pipe_tx = {
                let reg = intro_registry.lock().await;
                reg.get(&service_hash).cloned()
            };
            let Some(pipe_tx) = pipe_tx else {
                warn!(circuit_id, "intro relay — service not found");
                let fail = RelayCommand::ConnectFailed(
                    "service not found at this intro point".into(),
                );
                let fail_data = fail.serialize_bincode()?;
                let wrapped = wrap_layer(
                    key,
                    &LayerHeader { next_hop: None },
                    &fail_data,
                )?;
                conn.send_message(&Message::Relay {
                    circuit_id,
                    data: wrapped,
                })
                .await?;
                return Ok(());
            };
            let (client_to_svc_tx, client_to_svc_rx) =
                mpsc::channel::<Vec<u8>>(256);
            let (svc_to_client_tx, mut svc_to_client_rx) =
                mpsc::channel::<Vec<u8>>(256);
            let client_pipe = ClientPipe {
                from_client: client_to_svc_rx,
                to_client: svc_to_client_tx,
            };
            if pipe_tx.send(client_pipe).await.is_err() {
                warn!(circuit_id, "intro relay — service handler gone");
                let fail = RelayCommand::ConnectFailed(
                    "service handler disconnected".into(),
                );
                let fail_data = fail.serialize_bincode()?;
                let wrapped = wrap_layer(
                    key,
                    &LayerHeader { next_hop: None },
                    &fail_data,
                )?;
                conn.send_message(&Message::Relay {
                    circuit_id,
                    data: wrapped,
                })
                .await?;
                return Ok(());
            }
            let ack = RelayCommand::ServiceConnected;
            let ack_data = ack.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &ack_data,
            )?;
            conn.send_message(&Message::Relay {
                circuit_id,
                data: wrapped,
            })
            .await?;
            info!(circuit_id, "intro relay — bridging client ↔ service");
            bridge_client_to_service(
                conn,
                circuit_id,
                key,
                client_to_svc_tx,
                &mut svc_to_client_rx,
            )
            .await
        }
        RelayCommand::ResolveDns { hostname } => {
            info!(circuit_id, hostname = %sensitive(&hostname), "exit relay — DNS resolution");
            let addr_str = format!("{hostname}:0");
            let addresses: Vec<String> =
                match tokio::net::lookup_host(&addr_str).await {
                    Ok(addrs) => policy
                        .filter_answer(addrs.map(|a| a.ip()).collect())
                        .into_iter()
                        .map(|ip| ip.to_string())
                        .collect(),
                    Err(e) => {
                        warn!(circuit_id, hostname = %sensitive(&hostname), error = %e, "DNS resolution failed");
                        Vec::new()
                    }
                };
            let resp = RelayCommand::DnsResolved { addresses };
            let resp_data = resp.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &resp_data,
            )?;
            conn.send_message(&Message::Relay {
                circuit_id,
                data: wrapped,
            })
            .await?;
            Ok(())
        }
        other => {
            warn!(circuit_id, cmd = ?other, "unexpected relay command at exit");
            Ok(())
        }
    }
}

async fn handle_exit_forwarded(
    cmd: RelayCommand,
    upstream: &mut TcpStream,
    circuit_id: u32,
    key: &[u8; 32],
    intro_registry: &IntroRegistry,
    policy: ExitPolicy,
) -> Result<()> {
    match cmd {
        RelayCommand::RegisterService { service_hash, service_pubkey, timestamp, signature } => {
            if let Err(e) = crate::crypto::service_auth::verify_registration(
                &service_hash,
                &service_pubkey,
                timestamp,
                &signature,
            ) {
                warn!(circuit_id, error = %e, "intro relay — registration refused");
                let fail = RelayCommand::ConnectFailed(format!("{e}"));
                let fail_data = fail.serialize_bincode()?;
                let wrapped = wrap_layer(key, &LayerHeader { next_hop: None }, &fail_data)?;
                write_frame(upstream, &Message::Relay { circuit_id, data: wrapped }.serialize()).await?;
                return Ok(());
            }
            info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay (forwarded) — registering service");
            let (pipe_tx, mut pipe_rx) = mpsc::channel::<ClientPipe>(16);
            {
                let mut reg = intro_registry.lock().await;
                reg.insert(service_hash.clone(), pipe_tx);
            }
            let ack = RelayCommand::ServiceRegistered;
            let ack_data = ack.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &ack_data,
            )?;
            let msg = Message::Relay { circuit_id, data: wrapped };
            write_frame(upstream, &msg.serialize()).await?;
            info!(circuit_id, "intro relay (forwarded) — service registered, waiting");
            // Stay registered and hand each client over, one at a time, the
            // way the direct path does. This used to deregister straight
            // after the acknowledgement, so a service behind a full circuit
            // was never reachable at all.
            while let Some(mut client_pipe) = pipe_rx.recv().await {
                info!(circuit_id, "intro relay (forwarded) — bridging client to service");
                let to_client = client_pipe.to_client.clone();
                if let Err(e) = bridge_forwarded_client_to_service(
                    upstream,
                    circuit_id,
                    key,
                    to_client,
                    &mut client_pipe.from_client,
                )
                .await
                {
                    warn!(error = %e, "service bridge session ended");
                    break;
                }
            }
            {
                let mut reg = intro_registry.lock().await;
                reg.remove(&service_hash);
            }
            Ok(())
        }
        RelayCommand::ConnectService { service_hash } => {
            info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay (forwarded) — client connecting");
            let pipe_tx = {
                let reg = intro_registry.lock().await;
                reg.get(&service_hash).cloned()
            };
            let Some(pipe_tx) = pipe_tx else {
                let fail = RelayCommand::ConnectFailed(
                    "service not found".into(),
                );
                let fail_data = fail.serialize_bincode()?;
                let wrapped = wrap_layer(
                    key,
                    &LayerHeader { next_hop: None },
                    &fail_data,
                )?;
                let msg = Message::Relay { circuit_id, data: wrapped };
                write_frame(upstream, &msg.serialize()).await?;
                return Ok(());
            };
            let (client_to_svc_tx, client_to_svc_rx) =
                mpsc::channel::<Vec<u8>>(256);
            let (svc_to_client_tx, mut svc_to_client_rx) =
                mpsc::channel::<Vec<u8>>(256);
            let client_pipe = ClientPipe {
                from_client: client_to_svc_rx,
                to_client: svc_to_client_tx,
            };
            if pipe_tx.send(client_pipe).await.is_err() {
                let fail = RelayCommand::ConnectFailed(
                    "service handler disconnected".into(),
                );
                let fail_data = fail.serialize_bincode()?;
                let wrapped = wrap_layer(
                    key,
                    &LayerHeader { next_hop: None },
                    &fail_data,
                )?;
                let msg = Message::Relay { circuit_id, data: wrapped };
                write_frame(upstream, &msg.serialize()).await?;
                return Ok(());
            }
            let ack = RelayCommand::ServiceConnected;
            let ack_data = ack.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &ack_data,
            )?;
            let msg = Message::Relay { circuit_id, data: wrapped };
            write_frame(upstream, &msg.serialize()).await?;
            bridge_forwarded_client_to_service(
                upstream,
                circuit_id,
                key,
                client_to_svc_tx,
                &mut svc_to_client_rx,
            )
            .await
        }
        RelayCommand::Connect { host, port } => {
            info!(circuit_id, host = %sensitive(&host), port, "exit relay (forwarded) — connecting to target");
            let target_addr = format!("{host}:{port}");
            let resolved = policy.resolve_target(&host, port).await;
            let mut target =
                match exit_connect(resolved).await {
                    Ok(t) => {
                        info!(circuit_id, target = %sensitive(&target_addr), "exit relay — connected");
                        t
                    }
                    Err(e) => {
                        warn!(circuit_id, error = %e, "exit relay — connect failed");
                        let fail = RelayCommand::ConnectFailed(
                            format!("{e}"),
                        );
                        let fail_data = fail.serialize_bincode()?;
                        let wrapped = wrap_layer(
                            key,
                            &LayerHeader { next_hop: None },
                            &fail_data,
                        )?;
                        let msg = Message::Relay {
                            circuit_id,
                            data: wrapped,
                        };
                        write_frame(upstream, &msg.serialize())
                            .await?;
                        return Ok(());
                    }
                };
            let connected = RelayCommand::Connected;
            let connected_data = connected.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &connected_data,
            )?;
            let msg = Message::Relay {
                circuit_id,
                data: wrapped,
            };
            write_frame(upstream, &msg.serialize()).await?;
            exit_forwarded_streaming_loop(
                upstream,
                &mut target,
                circuit_id,
                key,
            )
            .await
        }
        RelayCommand::ResolveDns { hostname } => {
            info!(circuit_id, hostname = %sensitive(&hostname), "exit relay (forwarded) — DNS resolution");
            let addr_str = format!("{hostname}:0");
            let addresses: Vec<String> =
                match tokio::net::lookup_host(&addr_str).await {
                    Ok(addrs) => policy
                        .filter_answer(addrs.map(|a| a.ip()).collect())
                        .into_iter()
                        .map(|ip| ip.to_string())
                        .collect(),
                    Err(e) => {
                        warn!(circuit_id, hostname = %sensitive(&hostname), error = %e, "DNS resolution failed");
                        Vec::new()
                    }
                };
            let resp = RelayCommand::DnsResolved { addresses };
            let resp_data = resp.serialize_bincode()?;
            let wrapped = wrap_layer(
                key,
                &LayerHeader { next_hop: None },
                &resp_data,
            )?;
            let msg = Message::Relay {
                circuit_id,
                data: wrapped,
            };
            write_frame(upstream, &msg.serialize()).await?;
            Ok(())
        }
        other => {
            warn!(circuit_id, cmd = ?other, "unexpected relay command (forwarded exit)");
            Ok(())
        }
    }
}

async fn exit_streaming_loop(
    conn: &mut SecureConnection,
    target: &mut TcpStream,
    circuit_id: u32,
    key: &[u8; 32],
) -> Result<()> {
    let mut target_buf = vec![0u8; 16384];
    loop {
        tokio::select! {
            msg_result = conn.recv_message() => {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(_) => break,
                };
                match msg {
                    Message::Relay { data, .. } => {
                        let decrypted = decrypt_stream(key, &data)?;
                        let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                        match cmd {
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
                    _ => break,
                }
            }
            n = target.read(&mut target_buf) => {
                match n {
                    Ok(0) => {
                        debug!(circuit_id, "exit relay — target closed connection");
                        let end = RelayCommand::End;
                        let end_data = end.serialize_bincode()?;
                        let wrapped = encrypt_stream(key, &end_data)?;
                        let _ = conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await;
                        break;
                    }
                    Ok(n) => {
                        let data_cmd = RelayCommand::Data(target_buf[..n].to_vec());
                        let data_bytes = data_cmd.serialize_bincode()?;
                        let wrapped = encrypt_stream(key, &data_bytes)?;
                        conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                    }
                    Err(_) => break,
                }
            }
        }
    }
    info!(circuit_id, "exit streaming loop ended");
    Ok(())
}

async fn exit_forwarded_streaming_loop(
    upstream: &mut TcpStream,
    target: &mut TcpStream,
    circuit_id: u32,
    key: &[u8; 32],
) -> Result<()> {
    let mut target_buf = vec![0u8; 16384];
    // Read through a FrameReader: raced in the select! below, a plain
    // read_frame dropped halfway loses the bytes it took (see FrameReader).
    let mut up = FrameReader::new();
    loop {
        tokio::select! {
            frame_result = up.read_frame(upstream) => {
                let frame = match frame_result {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let msg = Message::deserialize(&frame)?;
                match msg {
                    Message::Relay { data, .. } => {
                        let decrypted = decrypt_stream(key, &data)?;
                        let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                        match cmd {
                            RelayCommand::Data(payload) => {
                                if target.write_all(&payload).await.is_err() { break; }
                            }
                            RelayCommand::End => {
                                debug!(circuit_id, "exit forwarded — stream ended");
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ => break,
                }
            }
            n = target.read(&mut target_buf) => {
                match n {
                    Ok(0) => {
                        let end = RelayCommand::End;
                        let end_data = end.serialize_bincode()?;
                        let wrapped = encrypt_stream(key, &end_data)?;
                        let msg = Message::Relay { circuit_id, data: wrapped };
                        let _ = write_frame(upstream, &msg.serialize()).await;
                        break;
                    }
                    Ok(n) => {
                        let data_cmd = RelayCommand::Data(target_buf[..n].to_vec());
                        let data_bytes = data_cmd.serialize_bincode()?;
                        let wrapped = encrypt_stream(key, &data_bytes)?;
                        let msg = Message::Relay { circuit_id, data: wrapped };
                        write_frame(upstream, &msg.serialize()).await?;
                    }
                    Err(_) => break,
                }
            }
        }
    }
    info!(circuit_id, "exit forwarded streaming loop ended");
    Ok(())
}

async fn relay_streaming_loop(
    conn: &mut SecureConnection,
    next_stream: &mut TcpStream,
    circuit_id: u32,
    key: &[u8; 32],
) -> Result<()> {
    // Both reads in the select! below are cancel safe: recv_message reads
    // through the connection's FrameReader, and the next hop through its own.
    let mut down = FrameReader::new();
    loop {
        tokio::select! {
            msg_result = conn.recv_message() => {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(_) => break,
                };
                match msg {
                    Message::Relay { data, .. } => {
                        let decrypted = decrypt_stream(key, &data)?;
                        let relay_msg = Message::Relay { circuit_id, data: decrypted };
                        write_frame(next_stream, &relay_msg.serialize()).await?;
                    }
                    _ => break,
                }
            }
            frame_result = down.read_frame(next_stream) => {
                let frame = match frame_result {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let msg = Message::deserialize(&frame)?;
                match msg {
                    Message::Relay { data, .. } => {
                        let wrapped = encrypt_stream(key, &data)?;
                        conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                    }
                    _ => break,
                }
            }
        }
    }
    info!(circuit_id, "relay streaming loop ended");
    Ok(())
}

async fn forwarded_streaming_loop(
    upstream: &mut TcpStream,
    downstream: &mut TcpStream,
    circuit_id: u32,
    key: &[u8; 32],
) -> Result<()> {
    // One FrameReader per side: raced in the select! below, a plain
    // read_frame dropped halfway loses the bytes it took (see FrameReader).
    let mut up = FrameReader::new();
    let mut down = FrameReader::new();
    loop {
        tokio::select! {
            frame_result = up.read_frame(upstream) => {
                let frame = match frame_result {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let msg = Message::deserialize(&frame)?;
                match msg {
                    Message::Relay { data, .. } => {
                        let decrypted = decrypt_stream(key, &data)?;
                        let relay_msg = Message::Relay { circuit_id, data: decrypted };
                        write_frame(downstream, &relay_msg.serialize()).await?;
                    }
                    _ => break,
                }
            }
            frame_result = down.read_frame(downstream) => {
                let frame = match frame_result {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let msg = Message::deserialize(&frame)?;
                match msg {
                    Message::Relay { data, .. } => {
                        let wrapped = encrypt_stream(key, &data)?;
                        let out_msg = Message::Relay { circuit_id, data: wrapped };
                        write_frame(upstream, &out_msg.serialize()).await?;
                    }
                    _ => break,
                }
            }
        }
    }
    info!(circuit_id, "forwarded streaming loop ended");
    Ok(())
}

async fn bridge_service_session(
    conn: &mut SecureConnection,
    circuit_id: u32,
    key: &[u8; 32],
    from_client: &mut mpsc::Receiver<Vec<u8>>,
    to_client: &mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    loop {
        tokio::select! {
            msg_result = conn.recv_message() => {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(_) => break,
                };
                match msg {
                    Message::Relay { data, .. } => {
                        let decrypted = decrypt_stream(key, &data)?;
                        let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                        match cmd {
                            RelayCommand::Data(payload) => {
                                if to_client.send(payload).await.is_err() {
                                    break;
                                }
                            }
                            RelayCommand::End => break,
                            _ => {}
                        }
                    }
                    _ => break,
                }
            }
            data = from_client.recv() => {
                match data {
                    Some(payload) => {
                        let cmd = RelayCommand::Data(payload);
                        let cmd_data = cmd.serialize_bincode()?;
                        let wrapped = encrypt_stream(key, &cmd_data)?;
                        conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                    }
                    None => break,
                }
            }
        }
    }
    debug!(circuit_id, "service bridge session ended");
    Ok(())
}

async fn bridge_client_to_service(
    conn: &mut SecureConnection,
    circuit_id: u32,
    key: &[u8; 32],
    to_service: mpsc::Sender<Vec<u8>>,
    from_service: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    loop {
        tokio::select! {
            msg_result = conn.recv_message() => {
                let msg = match msg_result {
                    Ok(m) => m,
                    Err(_) => break,
                };
                match msg {
                    Message::Relay { data, .. } => {
                        let decrypted = decrypt_stream(key, &data)?;
                        let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                        match cmd {
                            RelayCommand::Data(payload) => {
                                if to_service.send(payload).await.is_err() {
                                    break;
                                }
                            }
                            RelayCommand::End => break,
                            _ => {}
                        }
                    }
                    _ => break,
                }
            }
            data = from_service.recv() => {
                match data {
                    Some(payload) => {
                        let cmd = RelayCommand::Data(payload);
                        let cmd_data = cmd.serialize_bincode()?;
                        let wrapped = encrypt_stream(key, &cmd_data)?;
                        conn.send_message(&Message::Relay { circuit_id, data: wrapped }).await?;
                    }
                    None => break,
                }
            }
        }
    }
    debug!(circuit_id, "client-to-service bridge ended");
    Ok(())
}

async fn bridge_forwarded_client_to_service(
    upstream: &mut TcpStream,
    circuit_id: u32,
    key: &[u8; 32],
    to_service: mpsc::Sender<Vec<u8>>,
    from_service: &mut mpsc::Receiver<Vec<u8>>,
) -> Result<()> {
    // Cancel safe, as in forwarded_streaming_loop.
    let mut up = FrameReader::new();
    loop {
        tokio::select! {
            frame_result = up.read_frame(upstream) => {
                let frame = match frame_result {
                    Ok(f) => f,
                    Err(_) => break,
                };
                let msg = Message::deserialize(&frame)?;
                match msg {
                    Message::Relay { data, .. } => {
                        let decrypted = decrypt_stream(key, &data)?;
                        let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
                        match cmd {
                            RelayCommand::Data(payload) => {
                                if to_service.send(payload).await.is_err() {
                                    break;
                                }
                            }
                            RelayCommand::End => break,
                            _ => {}
                        }
                    }
                    _ => break,
                }
            }
            data = from_service.recv() => {
                match data {
                    Some(payload) => {
                        let cmd = RelayCommand::Data(payload);
                        let cmd_data = cmd.serialize_bincode()?;
                        let wrapped = encrypt_stream(key, &cmd_data)?;
                        let msg = Message::Relay { circuit_id, data: wrapped };
                        write_frame(upstream, &msg.serialize()).await?;
                    }
                    None => break,
                }
            }
        }
    }
    debug!(circuit_id, "forwarded client-to-service bridge ended");
    Ok(())
}

/// Connect to an exit destination the policy has already resolved and checked.
async fn exit_connect(resolved: std::result::Result<SocketAddr, String>) -> std::io::Result<TcpStream> {
    match resolved {
        Ok(addr) => match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(r) => r,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "exit connection timed out",
            )),
        },
        Err(why) => Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, why)),
    }
}

async fn connect_to_next(
    addr: SocketAddr,
    policy: ExitPolicy,
    dial_source: Option<IpAddr>,
) -> Result<TcpStream> {
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
    stream.write_all(&[PROTO_FORWARDED_CELL]).await?;
    Ok(stream)
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
