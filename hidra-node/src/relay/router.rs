use crate::safelog::sensitive;
use std::collections::HashMap;
use std::net::SocketAddr;
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
    read_frame, write_frame, Message, SecureConnection,
};
use crate::network::listener::PROTO_FORWARDED_CELL;
use crate::onion::cell::{LayerHeader, RelayCommand};
use crate::onion::layer::{
    decrypt_stream, encrypt_stream, peel_layer, wrap_layer,
};

struct CircuitEntry {
    session_key: [u8; 32],
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
}

impl RelayRouter {
    pub fn new(static_secret_bytes: Arc<[u8; 32]>) -> Self {
        Self {
            circuits: Arc::new(Mutex::new(HashMap::new())),
            static_secret_bytes,
            intro_registry: Arc::new(Mutex::new(HashMap::new())),
        }
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
        tokio::spawn(
            async move {
                info!("client connection — starting Noise handshake");
                if let Err(e) = handle_noise_session(
                    stream,
                    &secret_bytes,
                    circuits,
                    intro_reg,
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
        tokio::spawn(
            async move {
                debug!("forwarded cell connection");
                if let Err(e) =
                    handle_forwarded(stream, circuits, intro_reg).await
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
) -> Result<()> {
    let mut sb = *secret_bytes;
    let secret = StaticSecret::from(sb);
    sb.zeroize();
    let mut handshake = HandshakeState::new(Role::Responder, secret);
    let msg_a = read_frame(&mut stream).await?;
    handshake.read_message_a(&msg_a)?;
    let msg_b = handshake.write_message_b()?;
    write_frame(&mut stream, &msg_b).await?;
    let msg_c = read_frame(&mut stream).await?;
    handshake.read_message_c(&msg_c)?;
    info!("relay Noise XX handshake completed");
    let (send_cipher, recv_cipher) = handshake.into_transport()?;
    let session_key = recv_cipher.session_key()?;
    let mut conn =
        SecureConnection::new(stream, send_cipher, recv_cipher);

    loop {
        let msg = match conn.recv_message().await {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "connection closed or error");
                break;
            }
        };
        match msg {
            Message::CreateCircuit { circuit_id } => {
                info!(circuit_id, "creating circuit");
                let mut map = circuits.lock().await;
                map.insert(circuit_id, CircuitEntry { session_key });
                conn.send_message(&Message::CircuitCreated {
                    circuit_id,
                })
                .await?;
                info!(circuit_id, "circuit created");
            }
            Message::Relay { circuit_id, data } => {
                let key = {
                    let map = circuits.lock().await;
                    let entry =
                        map.get(&circuit_id).ok_or_else(|| {
                            HidraError::Circuit(format!(
                                "unknown circuit {circuit_id}"
                            ))
                        })?;
                    entry.session_key
                };
                let (header, inner) = peel_layer(&key, &data)?;
                info!(
                    circuit_id,
                    has_next_hop = header.next_hop.is_some(),
                    "peeled onion layer"
                );
                match header.next_hop {
                    Some(next_addr) => {
                        info!(circuit_id, next_hop = %sensitive(&next_addr), "forwarding to next relay");
                        let mut next_stream =
                            connect_to_next(next_addr).await?;
                        let relay_msg = Message::Relay {
                            circuit_id,
                            data: inner,
                        };
                        write_frame(
                            &mut next_stream,
                            &relay_msg.serialize(),
                        )
                        .await?;
                        let resp_frame =
                            read_frame(&mut next_stream).await?;
                        let resp_msg =
                            Message::deserialize(&resp_frame)?;
                        let resp_data = match resp_msg {
                            Message::Relay { data, .. } => data,
                            other => {
                                return Err(HidraError::Relay(
                                    format!("unexpected response from next hop: {other:?}"),
                                ));
                            }
                        };
                        let response_wrapped = wrap_layer(
                            &key,
                            &LayerHeader { next_hop: None },
                            &resp_data,
                        )?;
                        conn.send_message(&Message::Relay {
                            circuit_id,
                            data: response_wrapped,
                        })
                        .await?;
                        info!(circuit_id, "entering relay streaming loop");
                        relay_streaming_loop(
                            &mut conn,
                            &mut next_stream,
                            circuit_id,
                            &key,
                        )
                        .await?;
                        break;
                    }
                    None => {
                        if let Ok(cmd) =
                            RelayCommand::deserialize_bincode(&inner)
                        {
                            handle_exit_command(
                                cmd,
                                &mut conn,
                                circuit_id,
                                &key,
                                &intro_registry,
                            )
                            .await?;
                            break;
                        }
                        // The length, and never the content. This is traffic a
                        // user sent through the circuit, decrypted at the exit:
                        // writing it to the log puts what they said on an
                        // operator's disk, which is worse than writing who they
                        // are.
                        info!(
                            circuit_id,
                            bytes = inner.len(),
                            "exit node — received payload (legacy)"
                        );
                        let response_wrapped = wrap_layer(
                            &key,
                            &LayerHeader { next_hop: None },
                            b"Received, agent",
                        )?;
                        conn.send_message(&Message::Relay {
                            circuit_id,
                            data: response_wrapped,
                        })
                        .await?;
                        info!(circuit_id, "exit node — sent legacy response");
                    }
                }
            }
            Message::Ping(ref data) => {
                info!(bytes = data.len(), "received Ping (legacy)");
                conn.send_message(&Message::Pong(
                    b"HidraPong".to_vec(),
                ))
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
) -> Result<()> {
    let frame = read_frame(&mut stream).await?;
    let msg = Message::deserialize(&frame)?;
    match msg {
        Message::Relay { circuit_id, data } => {
            let key = {
                let map = circuits.lock().await;
                let entry = map.get(&circuit_id).ok_or_else(|| {
                    HidraError::Circuit(format!(
                        "forwarded cell: unknown circuit {circuit_id}"
                    ))
                })?;
                entry.session_key
            };
            let (header, inner) = peel_layer(&key, &data)?;
            info!(
                circuit_id,
                has_next_hop = header.next_hop.is_some(),
                "forwarded cell — peeled layer"
            );
            match header.next_hop {
                Some(next_addr) => {
                    info!(circuit_id, next_hop = %sensitive(&next_addr), "forwarding further");
                    let mut next_stream =
                        connect_to_next(next_addr).await?;
                    let relay_msg = Message::Relay {
                        circuit_id,
                        data: inner,
                    };
                    write_frame(
                        &mut next_stream,
                        &relay_msg.serialize(),
                    )
                    .await?;
                    let resp_frame =
                        read_frame(&mut next_stream).await?;
                    let resp_msg =
                        Message::deserialize(&resp_frame)?;
                    let resp_data = match resp_msg {
                        Message::Relay { data, .. } => data,
                        other => {
                            return Err(HidraError::Relay(format!(
                                "unexpected response: {other:?}"
                            )));
                        }
                    };
                    let response_wrapped = wrap_layer(
                        &key,
                        &LayerHeader { next_hop: None },
                        &resp_data,
                    )?;
                    let out_msg = Message::Relay {
                        circuit_id,
                        data: response_wrapped,
                    };
                    write_frame(&mut stream, &out_msg.serialize())
                        .await?;
                    info!(circuit_id, "entering forwarded streaming loop");
                    forwarded_streaming_loop(
                        &mut stream,
                        &mut next_stream,
                        circuit_id,
                        &key,
                    )
                    .await?;
                }
                None => {
                    if let Ok(cmd) =
                        RelayCommand::deserialize_bincode(&inner)
                    {
                        handle_exit_forwarded(
                            cmd,
                            &mut stream,
                            circuit_id,
                            &key,
                            &intro_registry,
                        )
                        .await?;
                    } else {
                        // The length, and never the content. This is traffic a
                        // user sent through the circuit, decrypted at the exit:
                        // writing it to the log puts what they said on an
                        // operator's disk, which is worse than writing who they
                        // are.
                        info!(
                            circuit_id,
                            bytes = inner.len(),
                            "exit node — received payload (legacy)"
                        );
                        let response_wrapped = wrap_layer(
                            &key,
                            &LayerHeader { next_hop: None },
                            b"Received, agent",
                        )?;
                        let out_msg = Message::Relay {
                            circuit_id,
                            data: response_wrapped,
                        };
                        write_frame(
                            &mut stream,
                            &out_msg.serialize(),
                        )
                        .await?;
                        info!(circuit_id, "sent legacy response back");
                    }
                }
            }
        }
        other => {
            warn!(?other, "unexpected forwarded message type");
        }
    }
    Ok(())
}

async fn handle_exit_command(
    cmd: RelayCommand,
    conn: &mut SecureConnection,
    circuit_id: u32,
    key: &[u8; 32],
    intro_registry: &IntroRegistry,
) -> Result<()> {
    match cmd {
        RelayCommand::Connect { host, port } => {
            info!(circuit_id, host = %sensitive(&host), port, "exit relay — connecting to target");
            let target_addr = format!("{host}:{port}");
            let mut target =
                match TcpStream::connect(&target_addr).await {
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
        RelayCommand::RegisterService { service_hash } => {
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
                    Ok(addrs) => {
                        addrs.map(|a| a.ip().to_string()).collect()
                    }
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
) -> Result<()> {
    match cmd {
        RelayCommand::RegisterService { service_hash } => {
            info!(circuit_id, hash = ?service_hash.iter().map(|b| format!("{b:02x}")).collect::<String>(), "intro relay (forwarded) — registering service");
            let (pipe_tx, pipe_rx) = mpsc::channel::<ClientPipe>(16);
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
            {
                let mut reg = intro_registry.lock().await;
                reg.remove(&service_hash);
            }
            drop(pipe_rx);
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
            let mut target =
                match TcpStream::connect(&target_addr).await {
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
                    Ok(addrs) => {
                        addrs.map(|a| a.ip().to_string()).collect()
                    }
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
    loop {
        tokio::select! {
            frame_result = read_frame(upstream) => {
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
            frame_result = read_frame(next_stream) => {
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
    loop {
        tokio::select! {
            frame_result = read_frame(upstream) => {
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
            frame_result = read_frame(downstream) => {
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
    loop {
        tokio::select! {
            frame_result = read_frame(upstream) => {
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

async fn connect_to_next(addr: SocketAddr) -> Result<TcpStream> {
    let mut stream =
        TcpStream::connect(addr).await.map_err(|e| {
            HidraError::Relay(format!(
                "failed to connect to next hop {addr}: {e}"
            ))
        })?;
    stream.write_all(&[PROTO_FORWARDED_CELL]).await?;
    Ok(stream)
}
