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
use crate::onion::circuit::{Circuit, CircuitHop};
use crate::relay::registry::RelayEntry;

pub async fn run_client_session(
    relays: &[RelayEntry],
    client_secret: StaticSecret,
    payload: &str,
) -> Result<String> {
    if relays.len() < 3 {
        return Err(HidraError::Circuit(
            "need at least 3 relays for onion routing".into(),
        ));
    }

    let circuit_id: u32 = rand::thread_rng().r#gen();
    info!(circuit_id, "building 3-hop circuit");

    let mut hops = Vec::with_capacity(3);
    let mut connections: Vec<SecureConnection> = Vec::with_capacity(3);

    for (i, relay) in relays.iter().take(3).enumerate() {
        info!(
            hop = i,
            relay = %relay.name,
            addr = %relay.addr,
            "establishing Noise XX handshake with relay"
        );

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

        info!(
            hop = i,
            relay = %relay.name,
            "handshake completed, circuit extended"
        );
    }

    let circuit = Circuit::new(circuit_id, hops);

    info!(circuit_id, payload, "building onion packet");
    let onion_data = build_onion(&circuit, payload.as_bytes())?;
    debug!(circuit_id, onion_size = onion_data.len(), "onion built");

    let entry_conn = &mut connections[0];
    entry_conn
        .send_message(&Message::Relay {
            circuit_id,
            data: onion_data,
        })
        .await?;
    info!(circuit_id, "onion sent to entry relay");

    let response_msg = entry_conn.recv_message().await?;
    let response_data = match response_msg {
        Message::Relay { data, .. } => data,
        other => {
            return Err(HidraError::Circuit(format!(
                "unexpected response from entry relay: {other:?}"
            )))
        }
    };

    info!(circuit_id, "received response, peeling layers");
    let plaintext = peel_response_layers(&circuit, response_data)?;
    let response_str = String::from_utf8(plaintext)
        .map_err(|e| HidraError::Circuit(format!("response is not valid UTF-8: {e}")))?;

    info!(circuit_id, response = %response_str, "circuit complete");
    Ok(response_str)
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

    debug!(addr = %addr, "handshake done, extracting session key");

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
