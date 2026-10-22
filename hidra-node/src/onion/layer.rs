//! One hop's layer of a circuit: what the client and that hop seal and open
//! for each other.
//!
//! The layer used to be ChaCha20-Poly1305 under the hop's Noise session key,
//! with a random nonce sent beside every cell and nothing to say where in
//! the circuit's life a cell belonged. So any cell that opened once opened
//! again: a hop, or anyone who could see the link between two hops, could
//! send a cell a second time (the exit would then repeat a request to the
//! destination), deliver cells out of order, or send a forward cell back
//! towards the client, since one key served both directions. And the key was
//! the guard link's own Noise transport key, used by two constructions at
//! once.
//!
//! Now each hop derives two keys from its session key, one per direction
//! (HKDF-SHA256, labelled), and each direction counts its cells. The count is
//! the nonce, so it never travels: a cell opens only under the key of its
//! direction and only as the next one expected. A replayed, reordered,
//! dropped or reflected cell fails to open and the circuit is torn down —
//! which is all such a cell can now achieve. A cell that fails to open does
//! not move the count, so whoever sent it cannot push the real ones out of
//! step.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::error::{HidraError, Result};
use crate::onion::cell::LayerHeader;

const FORWARD_LABEL: &[u8] = b"HidraNet onion layer v2: client to hop";
const BACKWARD_LABEL: &[u8] = b"HidraNet onion layer v2: hop to client";

/// One direction: its key and the count of the next cell.
struct Direction {
    key: [u8; 32],
    next: u64,
}

impl Direction {
    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.next.to_be_bytes());
        n
    }

    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.next == u64::MAX {
            return Err(HidraError::Crypto("circuit layer exhausted its cell count".into()));
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| HidraError::Crypto("invalid layer key".into()))?;
        let out = cipher
            .encrypt((&self.nonce()).into(), Payload { msg: plaintext, aad: &[] })
            .map_err(|_| HidraError::Crypto("layer encryption failed".into()))?;
        self.next += 1;
        Ok(out)
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| HidraError::Crypto("invalid layer key".into()))?;
        // The count moves only once the cell has proven itself.
        let out = cipher
            .decrypt((&self.nonce()).into(), Payload { msg: ciphertext, aad: &[] })
            .map_err(|_| {
                HidraError::Crypto("layer cell did not open: not the next cell of this circuit".into())
            })?;
        self.next += 1;
        Ok(out)
    }
}

impl Drop for Direction {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// The layer one hop and the client share for one circuit. Both ends build
/// it from the same session key; the client seals forward and opens
/// backward, the hop the other way round.
pub struct LayerCipher {
    forward: Direction,
    backward: Direction,
}

impl LayerCipher {
    pub fn new(session_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, session_key);
        let mut forward = [0u8; 32];
        let mut backward = [0u8; 32];
        hk.expand(FORWARD_LABEL, &mut forward)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        hk.expand(BACKWARD_LABEL, &mut backward)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self {
            forward: Direction { key: forward, next: 0 },
            backward: Direction { key: backward, next: 0 },
        }
    }

    /// Client side: a cell towards the hop.
    pub fn seal_forward(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.forward.seal(plaintext)
    }

    /// Hop side: a cell from the client.
    pub fn open_forward(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.forward.open(ciphertext)
    }

    /// Hop side: a cell towards the client.
    pub fn seal_backward(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.backward.seal(plaintext)
    }

    /// Client side: a cell from the hop.
    pub fn open_backward(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.backward.open(ciphertext)
    }

    /// Client side: a control cell, with the header that tells the hop where
    /// to send what is inside.
    pub fn seal_forward_cell(&mut self, header: &LayerHeader, inner: &[u8]) -> Result<Vec<u8>> {
        let header_bytes = header.serialize_bincode()?;
        let mut plaintext = Vec::with_capacity(4 + header_bytes.len() + inner.len());
        plaintext.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
        plaintext.extend_from_slice(&header_bytes);
        plaintext.extend_from_slice(inner);
        self.seal_forward(&plaintext)
    }

    /// Hop side: a control cell, split into its header and what it carries.
    pub fn open_forward_cell(&mut self, ciphertext: &[u8]) -> Result<(LayerHeader, Vec<u8>)> {
        let plaintext = self.open_forward(ciphertext)?;
        if plaintext.len() < 4 {
            return Err(HidraError::Crypto("decrypted layer too short for header length".into()));
        }
        let header_len =
            u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
        if plaintext.len() < 4 + header_len {
            return Err(HidraError::Crypto("decrypted layer too short for header".into()));
        }
        let header = LayerHeader::deserialize_bincode(&plaintext[4..4 + header_len])?;
        Ok((header, plaintext[4 + header_len..].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn pair() -> (LayerCipher, LayerCipher) {
        (LayerCipher::new(&[0x42; 32]), LayerCipher::new(&[0x42; 32]))
    }

    #[test]
    fn control_cell_roundtrip() {
        let (mut client, mut hop) = pair();
        let header = LayerHeader { next_hop: Some("127.0.0.1:9151".parse::<SocketAddr>().unwrap()) };
        let sealed = client.seal_forward_cell(&header, b"secret message").unwrap();
        let (h, inner) = hop.open_forward_cell(&sealed).unwrap();
        assert_eq!(h.next_hop, Some("127.0.0.1:9151".parse().unwrap()));
        assert_eq!(inner, b"secret message");
    }

    #[test]
    fn both_directions_roundtrip_in_order() {
        let (mut client, mut hop) = pair();
        for i in 0..5u8 {
            let up = client.seal_forward(&[i; 10]).unwrap();
            assert_eq!(hop.open_forward(&up).unwrap(), vec![i; 10]);
            let down = hop.seal_backward(&[i; 20]).unwrap();
            assert_eq!(client.open_backward(&down).unwrap(), vec![i; 20]);
        }
    }

    #[test]
    fn a_replayed_cell_is_refused() {
        let (mut client, mut hop) = pair();
        let cell = client.seal_forward(b"GET / HTTP/1.1").unwrap();
        hop.open_forward(&cell).unwrap();
        assert!(hop.open_forward(&cell).is_err(), "the same cell opened twice");
    }

    #[test]
    fn cells_out_of_order_are_refused() {
        let (mut client, mut hop) = pair();
        let first = client.seal_forward(b"one").unwrap();
        let second = client.seal_forward(b"two").unwrap();
        assert!(hop.open_forward(&second).is_err(), "a later cell opened first");
        assert_eq!(hop.open_forward(&first).unwrap(), b"one");
        assert_eq!(hop.open_forward(&second).unwrap(), b"two");
    }

    #[test]
    fn a_forward_cell_sent_back_is_refused() {
        let (mut client, _hop) = pair();
        let cell = client.seal_forward(b"towards the hop").unwrap();
        assert!(client.open_backward(&cell).is_err(), "a forward cell opened as a backward one");
    }

    #[test]
    fn a_forged_cell_does_not_move_the_count() {
        let (mut client, mut hop) = pair();
        assert!(hop.open_forward(&[0u8; 40]).is_err());
        let cell = client.seal_forward(b"the real first cell").unwrap();
        assert_eq!(hop.open_forward(&cell).unwrap(), b"the real first cell");
    }

    #[test]
    fn a_tampered_cell_is_refused() {
        let (mut client, mut hop) = pair();
        let mut cell = client.seal_forward(b"data").unwrap();
        let last = cell.len() - 1;
        cell[last] ^= 0xFF;
        assert!(hop.open_forward(&cell).is_err());
    }

    #[test]
    fn another_session_key_cannot_open() {
        let mut client = LayerCipher::new(&[0x42; 32]);
        let mut stranger = LayerCipher::new(&[0x43; 32]);
        let cell = client.seal_forward(b"data").unwrap();
        assert!(stranger.open_forward(&cell).is_err());
    }

    #[test]
    fn the_layer_keys_are_not_the_session_key() {
        let session = [0x42u8; 32];
        let layer = LayerCipher::new(&session);
        assert_ne!(layer.forward.key, session);
        assert_ne!(layer.backward.key, session);
        assert_ne!(layer.forward.key, layer.backward.key);
    }
}
