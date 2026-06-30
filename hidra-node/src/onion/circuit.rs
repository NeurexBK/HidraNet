use std::net::SocketAddr;

use zeroize::Zeroize;

#[derive(Clone)]
pub struct CircuitHop {
    pub addr: SocketAddr,
    pub session_key: [u8; 32],
}

impl std::fmt::Debug for CircuitHop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircuitHop")
            .field("addr", &self.addr)
            .field("session_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for CircuitHop {
    fn drop(&mut self) {
        self.session_key.zeroize();
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
