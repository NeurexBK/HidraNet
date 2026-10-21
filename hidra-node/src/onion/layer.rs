//! Relay-cell encryption: one layer per hop, each under the keys of that
//! hop's own handshake with the client.
//!
//! Every layer is ChaCha20-Poly1305 with a counter nonce, one counter per hop
//! and direction. Cells on a circuit arrive in order (each link is one TCP
//! connection), so a counter needs no space on the wire, and a cell that is
//! dropped, replayed or reordered by a relay fails the next hop's tag instead
//! of being accepted.
//!
//! Inside a layer, the first byte says whether the cell stops here:
//!
//! - towards the exit, `ONWARD` means "send the rest to the next hop", `HERE`
//!   means "the rest is a command for you";
//! - towards the client, `ORIGIN` means "this hop wrote it" and `RELAYED`
//!   means "this hop carried it back from further along", so the client knows
//!   which hop is talking.
//!
//! The layer does not name the next hop. A relay learns where its part of the
//! circuit goes when the client asks it to extend, and from nothing else.

use crate::crypto::circuit_handshake::Keys;
use crate::crypto::handshake::TransportCipher;
use crate::error::{HidraError, Result};

const ONWARD: u8 = 0x00;
const HERE: u8 = 0x01;
const RELAYED: u8 = ONWARD;
const ORIGIN: u8 = HERE;

fn framed(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(1 + body.len());
    v.push(kind);
    v.extend_from_slice(body);
    v
}

fn split(mut plain: Vec<u8>) -> Result<(u8, Vec<u8>)> {
    if plain.is_empty() {
        return Err(HidraError::Crypto("empty relay cell".into()));
    }
    let kind = plain.remove(0);
    Ok((kind, plain))
}

/// The client's keys for one hop.
pub struct ClientHop {
    forward: TransportCipher,
    backward: TransportCipher,
}

impl ClientHop {
    pub fn new(keys: Keys) -> Self {
        Self {
            forward: keys.send,
            backward: keys.recv,
        }
    }
}

/// The client's side of a circuit's layers, entry first.
#[derive(Default)]
#[allow(clippy::len_without_is_empty)]
pub struct ClientLayers {
    hops: Vec<ClientHop>,
}

impl ClientLayers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, hop: ClientHop) {
        self.hops.push(hop);
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Wraps `body` for hop `target` (0 is the entry): its layer innermost,
    /// then one layer for each hop before it.
    pub fn seal(&mut self, target: usize, body: &[u8]) -> Result<Vec<u8>> {
        if target >= self.hops.len() {
            return Err(HidraError::Circuit("no such hop".into()));
        }
        let mut cell = self.hops[target].forward.encrypt(&framed(HERE, body))?;
        for hop in self.hops[..target].iter_mut().rev() {
            cell = hop.forward.encrypt(&framed(ONWARD, &cell))?;
        }
        Ok(cell)
    }

    /// Opens a cell that came back from the entry: which hop wrote it, and
    /// what it says.
    pub fn open(&mut self, cell: &[u8]) -> Result<(usize, Vec<u8>)> {
        let mut current = cell.to_vec();
        for (i, hop) in self.hops.iter_mut().enumerate() {
            let (kind, inner) = split(hop.backward.decrypt(&current)?)?;
            match kind {
                ORIGIN => return Ok((i, inner)),
                RELAYED => current = inner,
                _ => return Err(HidraError::Crypto("unknown relay cell kind".into())),
            }
        }
        Err(HidraError::Circuit(
            "a cell claims to come from beyond the last hop".into(),
        ))
    }
}

/// What a relay's layer held.
pub enum Peeled {
    /// For the next hop: send it on unchanged.
    Onward(Vec<u8>),
    /// For this relay.
    Here(Vec<u8>),
}

/// A relay's keys for the one circuit hop it is.
pub struct RelayHop {
    forward: TransportCipher,
    backward: TransportCipher,
}

impl RelayHop {
    pub fn new(keys: Keys) -> Self {
        Self {
            forward: keys.recv,
            backward: keys.send,
        }
    }

    /// Removes this relay's layer from a cell going towards the exit.
    pub fn peel(&mut self, cell: &[u8]) -> Result<Peeled> {
        let (kind, inner) = split(self.forward.decrypt(cell)?)?;
        match kind {
            HERE => Ok(Peeled::Here(inner)),
            ONWARD => Ok(Peeled::Onward(inner)),
            _ => Err(HidraError::Crypto("unknown relay cell kind".into())),
        }
    }

    /// A cell this relay writes to the client.
    pub fn originate(&mut self, body: &[u8]) -> Result<Vec<u8>> {
        self.backward.encrypt(&framed(ORIGIN, body))
    }

    /// Adds this relay's layer to a cell coming back from the next hop.
    pub fn relay_back(&mut self, inner: &[u8]) -> Result<Vec<u8>> {
        self.backward.encrypt(&framed(RELAYED, inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::circuit_handshake::{respond, Initiator};
    use rand_core::OsRng;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// A client with `n` hops, and each hop's relay-side keys.
    fn circuit(n: usize) -> (ClientLayers, Vec<RelayHop>) {
        let mut client = ClientLayers::new();
        let mut relays = Vec::new();
        for _ in 0..n {
            let s = StaticSecret::random_from_rng(OsRng);
            let (init, a) = Initiator::start(&PublicKey::from(&s)).unwrap();
            let (b, rkeys) = respond(&s, &a).unwrap();
            client.push(ClientHop::new(init.finish(&b).unwrap()));
            relays.push(RelayHop::new(rkeys));
        }
        (client, relays)
    }

    /// A cell for the exit passes the entry and the middle as opaque bytes and
    /// opens only at the exit; the answer comes back through both and the
    /// client knows the exit wrote it.
    #[test]
    fn a_cell_opens_only_at_its_hop_and_the_answer_names_its_writer() {
        let (mut client, mut relays) = circuit(3);
        let cell = client.seal(2, b"for the exit").unwrap();

        let Peeled::Onward(at_middle) = relays[0].peel(&cell).unwrap() else { panic!() };
        assert!(!at_middle.windows(12).any(|w| w == b"for the exit"));
        let Peeled::Onward(at_exit) = relays[1].peel(&at_middle).unwrap() else { panic!() };
        let Peeled::Here(body) = relays[2].peel(&at_exit).unwrap() else { panic!() };
        assert_eq!(body, b"for the exit");

        let back = relays[2].originate(b"from the exit").unwrap();
        let back = relays[1].relay_back(&back).unwrap();
        let back = relays[0].relay_back(&back).unwrap();
        assert_eq!(client.open(&back).unwrap(), (2, b"from the exit".to_vec()));

        // The middle can speak too, and is told apart from the exit.
        let mid = relays[1].originate(b"extended").unwrap();
        let mid = relays[0].relay_back(&mid).unwrap();
        assert_eq!(client.open(&mid).unwrap(), (1, b"extended".to_vec()));
    }

    /// A relay that replays a cell, or skips one, breaks the circuit at the
    /// next hop instead of getting it accepted.
    #[test]
    fn a_replayed_or_dropped_cell_is_refused() {
        let (mut client, mut relays) = circuit(2);
        let first = client.seal(1, b"one").unwrap();
        let second = client.seal(1, b"two").unwrap();
        let Peeled::Onward(f) = relays[0].peel(&first).unwrap() else { panic!() };
        let Peeled::Onward(s) = relays[0].peel(&second).unwrap() else { panic!() };
        // The entry drops `first` and passes `second`.
        assert!(relays[1].peel(&s).is_err());
        drop(f);

        let (mut client, mut relays) = circuit(2);
        let cell = client.seal(0, b"once").unwrap();
        assert!(relays[0].peel(&cell).is_ok());
        assert!(relays[0].peel(&cell).is_err(), "the same cell twice");
    }

    #[test]
    fn a_tampered_cell_is_refused() {
        let (mut client, mut relays) = circuit(1);
        let mut cell = client.seal(0, b"data").unwrap();
        cell[0] ^= 1;
        assert!(relays[0].peel(&cell).is_err());
    }

    #[test]
    fn a_cell_from_past_the_last_hop_is_refused() {
        let (mut client, mut relays) = circuit(1);
        let fake = relays[0].relay_back(b"nothing behind me").unwrap();
        assert!(client.open(&fake).is_err());
        assert!(client.seal(1, b"x").is_err());
    }
}
