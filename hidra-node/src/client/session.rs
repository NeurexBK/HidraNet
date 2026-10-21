use tracing::info;
use x25519_dalek::StaticSecret;

use crate::client::streaming::build_telescoped;
use crate::error::{HidraError, Result};
use crate::network::connection::Message;
use crate::onion::builder::{build_onion, peel_response_layers};
use crate::relay::registry::RelayEntry;

/// Builds a three-hop circuit by extension (so no hop but the guard is ever
/// connected to directly) and sends one payload through it, returning the
/// exit's reply. The simple one-shot client; real traffic goes through
/// `StreamingCircuit` and the SOCKS proxy.
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
    // Each hop now gets its own ephemeral key inside `build_telescoped`; the
    // long-term key is no longer shown to any relay.
    drop(client_secret);

    let (mut conn, circuit) = build_telescoped(relays).await?;
    info!(circuit_id = circuit.id, bytes = payload.len(), "sending payload through the circuit");

    let onion_data = build_onion(&circuit, payload.as_bytes())?;
    conn.send_message(&Message::Relay {
        circuit_id: circuit.id,
        data: onion_data,
    })
    .await?;

    let response_data = match conn.recv_message().await? {
        Message::Relay { data, .. } => data,
        other => {
            return Err(HidraError::Circuit(format!(
                "unexpected response from entry relay: {other:?}"
            )));
        }
    };

    let plaintext = peel_response_layers(&circuit, response_data)?;
    let response_str = String::from_utf8(plaintext)
        .map_err(|e| HidraError::Circuit(format!("response is not valid UTF-8: {e}")))?;
    info!(circuit_id = circuit.id, bytes = response_str.len(), "circuit complete");
    Ok(response_str)
}
