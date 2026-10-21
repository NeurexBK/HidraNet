use crate::error::Result;
use crate::onion::cell::{pad_cell, unpad_cell, LayerHeader};
use crate::onion::circuit::Circuit;

/// Wraps a control cell for every hop of the circuit, innermost for the last,
/// around a command padded to one cell (`cell::CELL_BODY`). Each hop's layer
/// counts the cell, so the circuit is borrowed mutably.
pub fn build_onion(circuit: &mut Circuit, payload: &[u8]) -> Result<Vec<u8>> {
    let mut current = pad_cell(payload)?;
    let last = circuit.hops.len().saturating_sub(1);
    for i in (0..circuit.hops.len()).rev() {
        let next_hop = if i == last { None } else { Some(circuit.hops[i + 1].addr) };
        current = circuit.hops[i]
            .layer
            .seal_forward_cell(&LayerHeader { next_hop }, &current)?;
    }
    Ok(current)
}

/// Opens a reply that came back through every hop, outermost (the guard's)
/// first, and returns the command the last hop padded into it.
pub fn peel_response_layers(circuit: &mut Circuit, mut data: Vec<u8>) -> Result<Vec<u8>> {
    for hop in circuit.hops.iter_mut() {
        data = hop.layer.open_backward(&data)?;
    }
    unpad_cell(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::circuit::CircuitHop;
    use crate::onion::layer::LayerCipher;

    fn hop(port: u16, key: u8) -> CircuitHop {
        CircuitHop {
            addr: format!("127.0.0.1:{port}").parse().unwrap(),
            layer: LayerCipher::new(&[key; 32]),
        }
    }

    fn circuit() -> Circuit {
        Circuit::new(1, vec![hop(9150, 0x11), hop(9151, 0x22), hop(9152, 0x33)])
    }

    #[test]
    fn three_layer_onion_build_and_peel() {
        let mut client = circuit();
        let onion = build_onion(&mut client, b"Hello, hidden world").unwrap();

        // What each relay holds: the same session keys, counting on its own.
        let mut relays = [0x11u8, 0x22, 0x33].map(|k| LayerCipher::new(&[k; 32]));
        let (h1, inner1) = relays[0].open_forward_cell(&onion).unwrap();
        assert_eq!(h1.next_hop, Some("127.0.0.1:9151".parse().unwrap()));
        let (h2, inner2) = relays[1].open_forward_cell(&inner1).unwrap();
        assert_eq!(h2.next_hop, Some("127.0.0.1:9152".parse().unwrap()));
        let (h3, inner3) = relays[2].open_forward_cell(&inner2).unwrap();
        assert!(h3.next_hop.is_none());
        assert_eq!(unpad_cell(&inner3).unwrap(), b"Hello, hidden world");
    }

    #[test]
    fn response_onion_build_and_peel() {
        let mut client = circuit();
        let mut relays = [0x11u8, 0x22, 0x33].map(|k| LayerCipher::new(&[k; 32]));

        // As relays send a reply back: the exit seals first, the guard last.
        let mut reply = pad_cell(b"Received, agent").unwrap();
        for relay in relays.iter_mut().rev() {
            reply = relay.seal_backward(&reply).unwrap();
        }
        assert_eq!(peel_response_layers(&mut client, reply).unwrap(), b"Received, agent");
    }
}
