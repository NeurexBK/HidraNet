use rand::Rng;
use tracing::{debug, info};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use crate::client::handshake::handshake_with_relay;
use crate::error::{HidraError, Result};
use crate::network::connection::{Message, SecureConnection};
use crate::onion::builder::{build_onion, peel_response_layers};
use crate::onion::circuit::{Circuit, CircuitHop};
use crate::relay::registry::RelayEntry;
use crate::safelog::sensitive;

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
            relay = %sensitive(&relay.name),
            addr = %sensitive(&relay.addr),
            "establishing Noise XX handshake with relay"
        );

        let mut secret_bytes = client_secret.to_bytes();
        let hop_secret = StaticSecret::from(secret_bytes);
        secret_bytes.zeroize();

        let (conn, session_key) =
            handshake_with_relay(relay, hop_secret, circuit_id).await?;

        hops.push(CircuitHop {
            addr: relay.addr,
            session_key,
        });
        connections.push(conn);

        info!(
            hop = i,
            relay = %sensitive(&relay.name),
            "handshake completed, circuit extended"
        );
    }

    let circuit = Circuit::new(circuit_id, hops);

    info!(circuit_id, bytes = payload.len(), "building onion packet");
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

    info!(circuit_id, bytes = response_str.len(), "circuit complete");
    Ok(response_str)
}
