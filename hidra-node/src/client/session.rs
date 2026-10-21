use tracing::info;

use crate::client::streaming::StreamingCircuit;
use crate::error::{HidraError, Result};
use crate::p2p::dht::descriptor::VerifiedRelay;

/// Builds a circuit through `relays`, sends `payload` to the exit as a probe,
/// and returns the exit's acknowledgement. A connectivity check for the
/// command line: the circuit is the same one the proxy uses.
pub async fn run_client_session(relays: &[VerifiedRelay], payload: &str) -> Result<String> {
    let mut circuit = StreamingCircuit::build(relays).await?;
    let result = circuit.probe(payload.as_bytes()).await;
    circuit.destroy().await;
    let reply = result?;
    let reply = String::from_utf8(reply)
        .map_err(|e| HidraError::Circuit(format!("response is not valid UTF-8: {e}")))?;
    info!(bytes = reply.len(), "circuit complete");
    Ok(reply)
}
