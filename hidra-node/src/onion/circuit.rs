use std::net::SocketAddr;

use crate::onion::layer::LayerCipher;

/// One hop as the client holds it: where it is, and the layer the two share.
/// The layer counts the cells each way, so a hop is never copied: two copies
/// would count apart and the circuit would stop opening.
pub struct CircuitHop {
    pub addr: SocketAddr,
    pub layer: LayerCipher,
}

impl std::fmt::Debug for CircuitHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitHop")
            .field("addr", &self.addr)
            .field("layer", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug)]
pub struct Circuit {
    pub id: u32,
    pub hops: Vec<CircuitHop>,
}

impl Circuit {
    pub fn new(id: u32, hops: Vec<CircuitHop>) -> Self {
        Self { id, hops }
    }
}
