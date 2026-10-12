use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;
use x25519_dalek::StaticSecret;

use crate::crypto::handshake::{HandshakeState, Role};
use crate::error::{HidraError, Result};
use crate::network::connection::{Message, SecureConnection, read_frame, write_frame};
use crate::network::listener::PROTO_NOISE_SESSION;
use crate::relay::registry::RelayEntry;
use crate::safelog::sensitive;

pub(super) async fn handshake_with_relay(
    relay: &RelayEntry,
    static_secret: StaticSecret,
    circuit_id: u32,
) -> Result<(SecureConnection, [u8; 32])> {
    let expected_key = relay.expected_noise_key()?;
    let addr = relay.addr;
    let mut stream = TcpStream::connect(addr).await.map_err(|e| {
        HidraError::Relay(format!(
            "failed to connect to relay {}: {e}",
            sensitive(&addr)
        ))
    })?;

    stream.write_all(&[PROTO_NOISE_SESSION]).await?;

    let mut handshake = HandshakeState::new(Role::Initiator, static_secret);

    let msg_a = handshake.write_message_a()?;
    write_frame(&mut stream, &msg_a).await?;

    let msg_b = read_frame(&mut stream).await?;
    handshake.read_message_b(&msg_b)?;

    // Message B authenticates the responder's static key inside the
    // handshake. Check the configured identity before disclosing our static
    // key in message C or creating a circuit on the remote node.
    if let Some(expected) = expected_key {
        let actual = handshake.remote_static_public().ok_or_else(|| {
            HidraError::Handshake("relay did not supply a static public key".into())
        })?;
        if actual.as_bytes() != &expected {
            return Err(HidraError::Handshake(
                "relay public key does not match configured identity".into(),
            ));
        }
    }

    let msg_c = handshake.write_message_c()?;
    write_frame(&mut stream, &msg_c).await?;

    debug!(relay = %sensitive(&addr), "handshake done, extracting session key");

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
