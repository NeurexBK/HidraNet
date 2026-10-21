use crate::safelog::sensitive;
use std::net::SocketAddr;

use rand::Rng;
use rand_core::OsRng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, info};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::handshake::{HandshakeState, Role};
use crate::crypto::service_auth::{ClientHandshake, SealedChannel};
use crate::error::{HidraError, Result};
use crate::network::connection::{read_frame, write_frame, Message, SecureConnection};
use crate::network::listener::PROTO_NOISE_SESSION;
use crate::onion::builder::{build_onion, peel_response_layers};
use crate::onion::cell::RelayCommand;
use crate::onion::circuit::{Circuit, CircuitHop};
use crate::onion::layer::{decrypt_stream, encrypt_stream};
use crate::relay::registry::RelayEntry;

pub struct StreamingCircuit {
    conn: SecureConnection,
    circuit: Circuit,
    relay_addrs: Vec<SocketAddr>,
    /// Set once a hidden service has proven itself: everything sent and
    /// received after that is sealed end to end, past the relay bridging it.
    sealed: Option<SealedChannel>,
}

impl StreamingCircuit {
    pub async fn build(relays: &[RelayEntry], client_secret: StaticSecret) -> Result<Self> {
        if relays.len() < 3 {
            return Err(HidraError::Circuit(
                "need at least 3 relays for streaming circuit".into(),
            ));
        }
        // The long-term client key is never shown to a relay any more: each
        // hop gets its own throwaway key (see `build_telescoped`), so no relay
        // can recognise the client or link two of its circuits. The parameter
        // stays for the callers that still hold one.
        drop(client_secret);
        let (conn, circuit) = build_telescoped(relays).await?;
        let relay_addrs: Vec<SocketAddr> = relays.iter().take(3).map(|r| r.addr).collect();
        Ok(Self {
            conn,
            circuit,
            relay_addrs,
            sealed: None,
        })
    }

    pub async fn connect(&mut self, host: &str, port: u16) -> Result<()> {
        let cmd = RelayCommand::Connect {
            host: host.to_string(),
            port,
        };
        let cmd_data = cmd.serialize_bincode()?;
        let onion_data = build_onion(&self.circuit, &cmd_data)?;
        // The cell that opens the stream: each hop relays the one reply and
        // then switches this circuit to streaming.
        self.conn
            .send_message(&Message::StreamBegin {
                circuit_id: self.circuit.id,
                data: onion_data,
            })
            .await?;
        let response_msg = self.conn.recv_message().await?;
        let response_data = match response_msg {
            Message::Relay { data, .. } => data,
            other => {
                return Err(HidraError::Circuit(format!(
                    "expected Relay response, got: {other:?}"
                )));
            }
        };
        let decrypted = peel_response_layers(&self.circuit, response_data)?;
        let resp_cmd = RelayCommand::deserialize_bincode(&decrypted)?;
        match resp_cmd {
            RelayCommand::Connected => {
                info!(circuit_id = self.circuit.id, host = %sensitive(host), port, "streaming circuit connected to target");
                Ok(())
            }
            RelayCommand::ConnectFailed(reason) => {
                Err(HidraError::Circuit(format!("connect failed: {reason}")))
            }
            other => Err(HidraError::Circuit(format!(
                "unexpected connect response: {other:?}"
            ))),
        }
    }

    /// Sends one command to the circuit's last relay as the cell that opens a
    /// stream, and returns its first answer. Used by tests to send commands by
    /// hand.
    #[allow(dead_code)]
    pub async fn request(&mut self, cmd: &RelayCommand) -> Result<RelayCommand> {
        let onion = build_onion(&self.circuit, &cmd.serialize_bincode()?)?;
        self.conn
            .send_message(&Message::StreamBegin {
                circuit_id: self.circuit.id,
                data: onion,
            })
            .await?;
        let data = match self.conn.recv_message().await? {
            Message::Relay { data, .. } => data,
            other => {
                return Err(HidraError::Circuit(format!(
                    "expected Relay response, got: {other:?}"
                )));
            }
        };
        RelayCommand::deserialize_bincode(&peel_response_layers(&self.circuit, data)?)
    }

    pub async fn connect_service(&mut self, service_hash: Vec<u8>) -> Result<()> {
        let cmd = RelayCommand::ConnectService { service_hash };
        let onion_data = build_onion(&self.circuit, &cmd.serialize_bincode()?)?;
        self.conn
            .send_message(&Message::StreamBegin {
                circuit_id: self.circuit.id,
                data: onion_data,
            })
            .await?;
        let data = match self.conn.recv_message().await? {
            Message::Relay { data, .. } => data,
            other => {
                return Err(HidraError::Circuit(format!(
                    "expected Relay response, got: {other:?}"
                )));
            }
        };
        match RelayCommand::deserialize_bincode(&peel_response_layers(&self.circuit, data)?)? {
            RelayCommand::ServiceConnected => {
                info!(circuit_id = self.circuit.id, "connected to hidden service");
                Ok(())
            }
            RelayCommand::ConnectFailed(reason) => Err(HidraError::Circuit(format!(
                "service connect failed: {reason}"
            ))),
            other => Err(HidraError::Circuit(format!(
                "unexpected service connect response: {other:?}"
            ))),
        }
    }

    /// Connects to a hidden service and makes it prove it is the one its
    /// address names, with the key from its signed descriptor, before a byte
    /// of the client's goes to it. Whoever answered for the address without
    /// that key is refused here.
    pub async fn connect_service_authenticated(
        &mut self,
        service_pubkey: &[u8; 32],
    ) -> Result<()> {
        let service_hash = crate::p2p::dht::descriptor::service_hash_of(service_pubkey).to_vec();
        self.connect_service(service_hash).await?;
        let (handshake, hello) = ClientHandshake::start();
        self.send_raw(&hello).await?;
        let answer = self.recv_raw().await?.ok_or_else(|| {
            HidraError::Circuit("hidden service closed before proving itself".into())
        })?;
        self.sealed = Some(handshake.finish(service_pubkey, &answer)?);
        info!(circuit_id = self.circuit.id, "hidden service proved its address");
        Ok(())
    }

    pub async fn register_service(
        &mut self,
        service_key: &ed25519_dalek::SigningKey,
    ) -> Result<()> {
        let (service_pubkey, timestamp, signature) =
            crate::crypto::service_auth::registration_proof(service_key);
        let service_hash = crate::p2p::dht::descriptor::service_hash_of(&service_pubkey).to_vec();
        let cmd = RelayCommand::RegisterService {
            service_hash,
            service_pubkey,
            timestamp,
            signature,
        };
        let cmd_data = cmd.serialize_bincode()?;
        let onion_data = build_onion(&self.circuit, &cmd_data)?;
        self.conn
            .send_message(&Message::StreamBegin {
                circuit_id: self.circuit.id,
                data: onion_data,
            })
            .await?;
        let response_msg = self.conn.recv_message().await?;
        let response_data = match response_msg {
            Message::Relay { data, .. } => data,
            other => {
                return Err(HidraError::Circuit(format!(
                    "expected Relay response, got: {other:?}"
                )));
            }
        };
        let decrypted = peel_response_layers(&self.circuit, response_data)?;
        let resp_cmd = RelayCommand::deserialize_bincode(&decrypted)?;
        match resp_cmd {
            RelayCommand::ServiceRegistered => {
                info!(circuit_id = self.circuit.id, "service registered at intro point");
                Ok(())
            }
            RelayCommand::ConnectFailed(reason) => Err(HidraError::Circuit(format!(
                "service registration failed: {reason}"
            ))),
            other => Err(HidraError::Circuit(format!(
                "unexpected register response: {other:?}"
            ))),
        }
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
        match self.sealed.as_mut() {
            Some(ch) => {
                let sealed = ch.seal(data)?;
                self.send_raw(&sealed).await
            }
            None => self.send_raw(data).await,
        }
    }

    pub async fn recv_data(&mut self) -> Result<Option<Vec<u8>>> {
        match self.recv_raw().await? {
            Some(payload) => match self.sealed.as_mut() {
                Some(ch) => ch.open(&payload).map(Some),
                None => Ok(Some(payload)),
            },
            None => Ok(None),
        }
    }

    /// A Data cell as it goes over the circuit, sealed or not.
    pub async fn send_raw(&mut self, data: &[u8]) -> Result<()> {
        let cmd = RelayCommand::Data(data.to_vec());
        let cmd_data = cmd.serialize_bincode()?;
        let encrypted = wrap_all_stream_layers(&self.circuit, &cmd_data)?;
        self.conn
            .send_message(&Message::Relay {
                circuit_id: self.circuit.id,
                data: encrypted,
            })
            .await
    }

    pub async fn recv_raw(&mut self) -> Result<Option<Vec<u8>>> {
        let msg = self.conn.recv_message().await?;
        let data = match msg {
            Message::Relay { data, .. } => data,
            other => {
                return Err(HidraError::Circuit(format!(
                    "expected Relay, got: {other:?}"
                )));
            }
        };
        let decrypted = peel_all_stream_layers(&self.circuit, data)?;
        let cmd = RelayCommand::deserialize_bincode(&decrypted)?;
        match cmd {
            RelayCommand::Data(payload) => Ok(Some(payload)),
            RelayCommand::End => Ok(None),
            other => Err(HidraError::Circuit(format!(
                "unexpected stream command: {other:?}"
            ))),
        }
    }

    pub async fn send_end(&mut self) -> Result<()> {
        let cmd = RelayCommand::End;
        let cmd_data = cmd.serialize_bincode()?;
        let encrypted = wrap_all_stream_layers(&self.circuit, &cmd_data)?;
        self.conn
            .send_message(&Message::Relay {
                circuit_id: self.circuit.id,
                data: encrypted,
            })
            .await
    }

    pub fn circuit_id(&self) -> u32 {
        self.circuit.id
    }

    pub fn hop_count(&self) -> usize {
        self.relay_addrs.len()
    }

    pub fn relay_chain_display(&self) -> String {
        self.relay_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" -> ")
    }
}

/// The Noise static identity key the client expects a relay to prove. It comes
/// from the relay list the client trusts (the operator's config); a relay with
/// no key on record cannot be authenticated, so it is refused rather than used
/// unverified.
fn expected_key(relay: &RelayEntry) -> Result<PublicKey> {
    let b64 = relay.noise_pubkey_b64.trim();
    if b64.is_empty() {
        return Err(HidraError::Circuit(
            "a relay on the circuit has no identity key on record; refusing to build an unauthenticated circuit"
                .into(),
        ));
    }
    let bytes = BASE64
        .decode(b64)
        .map_err(|_| HidraError::Circuit("a relay's identity key is not valid base64".into()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| HidraError::Circuit("a relay's identity key is not 32 bytes".into()))?;
    Ok(PublicKey::from(arr))
}

/// Confirms the peer proved possession of the key the client pinned for it.
/// Noise XX binds the responder's static key into the shared secret, so a relay
/// that lacks the private half cannot complete the handshake and one that used a
/// different key is caught here; either way the circuit is refused.
fn check_identity(handshake: &HandshakeState, expected: &PublicKey) -> Result<()> {
    match handshake.remote_static_public() {
        Some(got) if got.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err(HidraError::Circuit(
            "a relay presented an identity key that does not match the one on record; refusing the circuit"
                .into(),
        )),
    }
}

/// Builds a three-hop circuit without ever opening a direct connection to any
/// hop but the first (the guard). The guard is reached directly - it always
/// sees the client, as a guard must. Each later hop is reached *through* the
/// circuit already built: the client drives a Noise handshake with it whose
/// messages are carried, unread, by the hops in between, so the new hop sees
/// the hop before it, never the client. Every hop gets its own ephemeral key.
pub(crate) async fn build_telescoped(
    relays: &[RelayEntry],
) -> Result<(SecureConnection, Circuit)> {
    let circuit_id: u32 = rand::thread_rng().r#gen();
    info!(circuit_id, "building circuit by extension");
    let chosen: Vec<&RelayEntry> = relays.iter().take(3).collect();

    let guard_expected = expected_key(chosen[0])?;
    let (mut conn, guard_key) =
        direct_handshake(chosen[0].addr, &guard_expected, circuit_id).await?;
    let mut hops = vec![CircuitHop {
        addr: chosen[0].addr,
        session_key: guard_key,
    }];
    info!(hop = 0, relay = %sensitive(&chosen[0].name), "guard hop established (direct)");

    for (i, relay) in chosen.iter().enumerate().skip(1) {
        let expected = expected_key(relay)?;
        let partial = Circuit::new(circuit_id, hops.clone());
        let key = extend_to(&mut conn, &partial, relay.addr, &expected).await?;
        hops.push(CircuitHop {
            addr: relay.addr,
            session_key: key,
        });
        info!(hop = i, relay = %sensitive(&relay.name), "hop extended through the circuit");
    }

    Ok((conn, Circuit::new(circuit_id, hops)))
}

/// A direct Noise XX handshake with the guard, then registers the circuit.
/// The key is a fresh throwaway, so the guard cannot tie this circuit to any
/// other.
async fn direct_handshake(
    addr: SocketAddr,
    expected: &PublicKey,
    circuit_id: u32,
) -> Result<(SecureConnection, [u8; 32])> {
    let mut stream = TcpStream::connect(addr)
        .await
        // The guard's address is the client's own entry point; keep it out of
        // any error string that might later be logged.
        .map_err(|_| HidraError::Relay("could not connect to the guard".into()))?;
    stream.write_all(&[PROTO_NOISE_SESSION]).await?;
    let secret = StaticSecret::random_from_rng(OsRng);
    let mut handshake = HandshakeState::new(Role::Initiator, secret);
    write_frame(&mut stream, &handshake.write_message_a()?).await?;
    let msg_b = read_frame(&mut stream).await?;
    handshake.read_message_b(&msg_b)?;
    // The guard proved possession of this key's private half in the handshake;
    // refuse it if it is not the relay we meant to reach.
    check_identity(&handshake, expected)?;
    write_frame(&mut stream, &handshake.write_message_c()?).await?;
    debug!(relay = %sensitive(&addr), "handshake done");
    let (send_cipher, recv_cipher) = handshake.into_transport()?;
    let session_key = send_cipher.session_key()?;
    let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);
    conn.send_message(&Message::CreateCircuit { circuit_id }).await?;
    match conn.recv_message().await? {
        Message::CircuitCreated { circuit_id: cid } if cid == circuit_id => {
            debug!(circuit_id, "guard registered the circuit");
        }
        other => {
            return Err(HidraError::Circuit(format!(
                "expected CircuitCreated, got: {other:?}"
            )));
        }
    }
    Ok((conn, session_key))
}

/// Extends the circuit by one hop, through the hops already in it. Drives a
/// Noise XX handshake with the new hop as initiator; the handshake messages
/// ride as `Extend`/`ExtendFinish` control cells, which the carrying hops pipe
/// without being able to read. Returns the new hop's layer key.
async fn extend_to(
    conn: &mut SecureConnection,
    partial: &Circuit,
    to: SocketAddr,
    expected: &PublicKey,
) -> Result<[u8; 32]> {
    let secret = StaticSecret::random_from_rng(OsRng);
    let mut handshake = HandshakeState::new(Role::Initiator, secret);
    let msg_a = handshake.write_message_a()?;

    // Round one: message A out, message B back.
    let msg_b = match control_round(conn, partial, &RelayCommand::Extend { to, frame: msg_a }).await? {
        RelayCommand::Extended { frame } => frame,
        RelayCommand::ExtendError(why) => {
            return Err(HidraError::Circuit(format!("could not extend the circuit: {why}")));
        }
        other => {
            return Err(HidraError::Circuit(format!(
                "unexpected reply to extend: {other:?}"
            )));
        }
    };
    handshake.read_message_b(&msg_b)?;
    // The new hop proved possession of this key's private half; a carrying
    // relay that answered in its place (or any other mismatch) is refused here,
    // before the handshake finishes, so the circuit is never built through it.
    check_identity(&handshake, expected)?;
    let msg_c = handshake.write_message_c()?;
    let (mut send_cipher, mut recv_cipher) = handshake.into_transport()?;
    let session_key = send_cipher.session_key()?;

    // The new hop expects CreateCircuit next, sealed with the key just agreed.
    // We seal it here; the carrying hops cannot read it.
    let sealed_create =
        send_cipher.encrypt(&Message::CreateCircuit { circuit_id: partial.id }.serialize())?;

    // Round two: message C and the sealed CreateCircuit out, the sealed
    // CircuitCreated back.
    let sealed_created = match control_round(
        conn,
        partial,
        &RelayCommand::ExtendFinish {
            frame_c: msg_c,
            frame_create: sealed_create,
        },
    )
    .await?
    {
        RelayCommand::ExtendDone { frame_created } => frame_created,
        RelayCommand::ExtendError(why) => {
            return Err(HidraError::Circuit(format!("could not finish extending: {why}")));
        }
        other => {
            return Err(HidraError::Circuit(format!(
                "unexpected reply to extend-finish: {other:?}"
            )));
        }
    };
    match Message::deserialize(&recv_cipher.decrypt(&sealed_created)?)? {
        Message::CircuitCreated { circuit_id: cid } if cid == partial.id => {}
        other => {
            return Err(HidraError::Circuit(format!(
                "the new hop did not confirm the circuit: {other:?}"
            )));
        }
    }
    Ok(session_key)
}

/// Sends one control command onion-wrapped for the hops built so far and
/// returns the one reply, peeled back.
async fn control_round(
    conn: &mut SecureConnection,
    partial: &Circuit,
    cmd: &RelayCommand,
) -> Result<RelayCommand> {
    let onion = build_onion(partial, &cmd.serialize_bincode()?)?;
    conn.send_message(&Message::Relay {
        circuit_id: partial.id,
        data: onion,
    })
    .await?;
    let data = match conn.recv_message().await? {
        Message::Relay { data, .. } => data,
        other => {
            return Err(HidraError::Circuit(format!(
                "expected a relay reply, got: {other:?}"
            )));
        }
    };
    RelayCommand::deserialize_bincode(&peel_response_layers(partial, data)?)
}

fn wrap_all_stream_layers(circuit: &Circuit, data: &[u8]) -> Result<Vec<u8>> {
    let mut current = data.to_vec();
    for hop in circuit.hops.iter().rev() {
        current = encrypt_stream(&hop.session_key, &current)?;
    }
    Ok(current)
}

fn peel_all_stream_layers(circuit: &Circuit, data: Vec<u8>) -> Result<Vec<u8>> {
    let mut current = data;
    for hop in &circuit.hops {
        current = decrypt_stream(&hop.session_key, &current)?;
    }
    Ok(current)
}
