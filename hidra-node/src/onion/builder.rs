use crate::error::Result;
use crate::onion::cell::LayerHeader;
use crate::onion::circuit::Circuit;
use crate::onion::layer::wrap_layer;

pub fn build_onion(circuit: &Circuit, payload: &[u8]) -> Result<Vec<u8>> {
    let hops = &circuit.hops;
    let mut current = payload.to_vec();

    for i in (0..hops.len()).rev() {
        let next_hop = if i == hops.len() - 1 {
            None
        } else {
            Some(hops[i + 1].addr)
        };

        let header = LayerHeader { next_hop };
        current = wrap_layer(&hops[i].session_key, &header, &current)?;
    }

    Ok(current)
}

pub fn build_response_onion(circuit: &Circuit, payload: &[u8]) -> Result<Vec<u8>> {
    let hops = &circuit.hops;
    let mut current = payload.to_vec();

    // Simulates relay response path: exit wraps first (innermost), entry wraps last (outermost)
    for hop in hops.iter().rev() {
        let header = LayerHeader { next_hop: None };
        current = wrap_layer(&hop.session_key, &header, &current)?;
    }

    Ok(current)
}

pub fn peel_response_layers(circuit: &Circuit, mut data: Vec<u8>) -> Result<Vec<u8>> {
    // Response outermost layer is from entry relay (hop[0]), peel forward
    for hop in &circuit.hops {
        let (_, inner) = crate::onion::layer::peel_layer(&hop.session_key, &data)?;
        data = inner;
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::circuit::CircuitHop;
    use crate::onion::layer::peel_layer;

    #[test]
    fn three_layer_onion_build_and_peel() {
        let hop1 = CircuitHop {
            addr: "127.0.0.1:9150".parse().unwrap(),
            session_key: [0x11; 32],
        };
        let hop2 = CircuitHop {
            addr: "127.0.0.1:9151".parse().unwrap(),
            session_key: [0x22; 32],
        };
        let hop3 = CircuitHop {
            addr: "127.0.0.1:9152".parse().unwrap(),
            session_key: [0x33; 32],
        };

        let circuit = Circuit::new(1, vec![hop1, hop2, hop3]);
        let payload = b"Ola, mundo oculto";

        let onion = build_onion(&circuit, payload).unwrap();

        let (h1, inner1) = peel_layer(&[0x11; 32], &onion).unwrap();
        assert_eq!(h1.next_hop, Some("127.0.0.1:9151".parse().unwrap()));

        let (h2, inner2) = peel_layer(&[0x22; 32], &inner1).unwrap();
        assert_eq!(h2.next_hop, Some("127.0.0.1:9152".parse().unwrap()));

        let (h3, inner3) = peel_layer(&[0x33; 32], &inner2).unwrap();
        assert!(h3.next_hop.is_none());
        assert_eq!(inner3, payload);
    }

    #[test]
    fn response_onion_build_and_peel() {
        let hop1 = CircuitHop {
            addr: "127.0.0.1:9150".parse().unwrap(),
            session_key: [0x11; 32],
        };
        let hop2 = CircuitHop {
            addr: "127.0.0.1:9151".parse().unwrap(),
            session_key: [0x22; 32],
        };
        let hop3 = CircuitHop {
            addr: "127.0.0.1:9152".parse().unwrap(),
            session_key: [0x33; 32],
        };

        let circuit = Circuit::new(1, vec![hop1, hop2, hop3]);
        let response = b"Recebido, agente";

        let onion = build_response_onion(&circuit, response).unwrap();
        let peeled = peel_response_layers(&circuit, onion).unwrap();
        assert_eq!(peeled, response);
    }
}
