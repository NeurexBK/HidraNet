use std::net::SocketAddr;

use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{debug, info};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::crypto::handshake::{HandshakeState, Role};
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
    #[allow(dead_code)]
    extra_conns: Vec<SecureConnection>,
}

impl StreamingCircuit {
    pub async fn build(
        relays: &[RelayEntry],
        client_secret: StaticSecret,
    ) -> Result<Self> {
        if relays.len() < 3 {
            return Err(HidraError::Circuit(
                "need at least 3 relays for streaming circuit".into(),
            ));
        }

        let circuit_id: u32 = rand::thread_rng().r#gen();
        info!(circuit_id, "building streaming circuit");

        let mut hops = Vec::with_capacity(3);
        let mut connections: Vec<SecureConnection> = Vec::with_capacity(3);

        for (i, relay) in relays.iter().take(3).enumerate() {
            let mut secret_bytes = client_secret.to_bytes();
            let hop_secret = StaticSecret::from(secret_bytes);
            secret_bytes.zeroize();

            let (conn, session_key) =
                handshake_with_relay(relay.addr, hop_secret, circuit_id).await?;

            hops.push(CircuitHop {
                addr: relay.addr,
                session_key,
            });
            connections.push(conn);

            info!(hop = i, relay = %relay.name, "streaming circuit hop established");
        }

        let relay_addrs: Vec<SocketAddr> = relays.iter().take(3).map(|r| r.addr).collect();
        let circuit = Circuit::new(circuit_id, hops);
        let mut iter = connections.into_iter();
        let entry_conn = iter.next().ok_or_else(|| {
            HidraError::Circuit("no entry connection".into())
        })?;
        let extra_conns: Vec<SecureConnection> = iter.collect();

        Ok(Self {
            conn: entry_conn,
            circuit,
            relay_addrs,
            extra_conns,
        })
    }

    pub async fn connect(&mut self, host: &str, port: u16) -> Result<()> {
        let cmd = RelayCommand::Connect {
            host: host.to_string(),
            port,
        };
        let cmd_data = cmd.serialize_bincode()?;

        let onion_data = build_onion(&self.circuit, &cmd_data)?;

        self.conn
            .send_message(&Message::Relay {
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
                info!(circuit_id = self.circuit.id, host, port, "streaming circuit connected to target");
                Ok(())
            }
            RelayCommand::ConnectFailed(reason) => {
                Err(HidraError::Circuit(format!("connect failed: {reason}")))
            }
            other => {
                Err(HidraError::Circuit(format!(
                    "unexpected connect response: {other:?}"
                )))
            }
        }
    }

    pub async fn send_data(&mut self, data: &[u8]) -> Result<()> {
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

    pub async fn recv_data(&mut self) -> Result<Option<Vec<u8>>> {
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

    pub fn relay_chain(&self) -> &[SocketAddr] {
        &self.relay_addrs
    }

    pub fn hop_count(&self) -> usize {
        self.relay_addrs.len()
    }

    pub fn relay_chain_display(&self) -> String {
        self.relay_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" → ")
    }
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

async fn handshake_with_relay(
    addr: SocketAddr,
    static_secret: StaticSecret,
    circuit_id: u32,
) -> Result<(SecureConnection, [u8; 32])> {
    let mut stream = TcpStream::connect(addr).await.map_err(|e| {
        HidraError::Relay(format!("failed to connect to relay {addr}: {e}"))
    })?;

    stream.write_all(&[PROTO_NOISE_SESSION]).await?;

    let mut handshake = HandshakeState::new(Role::Initiator, static_secret);

    let msg_a = handshake.write_message_a()?;
    write_frame(&mut stream, &msg_a).await?;

    let msg_b = read_frame(&mut stream).await?;
    handshake.read_message_b(&msg_b)?;

    let msg_c = handshake.write_message_c()?;
    write_frame(&mut stream, &msg_c).await?;

    debug!(addr = %addr, "handshake done");

    let (send_cipher, recv_cipher) = handshake.into_transport()?;
    let session_key = send_cipher.session_key()?;
    let mut conn = SecureConnection::new(stream, send_cipher, recv_cipher);

    conn.send_message(&Message::CreateCircuit { circuit_id })
        .await?;

    let response = conn.recv_message().await?;
    match response {
        Message::CircuitCreated {
            circuit_id: cid, ..
        } if cid == circuit_id => {
            debug!(circuit_id, "circuit registered at relay");
        }
        other => {
            return Err(HidraError::Circuit(format!(
                "expected CircuitCreated, got: {other:?}"
            )));
        }
    }

    Ok((conn, session_key))
}
