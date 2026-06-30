use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand::RngCore;

use crate::error::{HidraError, Result};
use crate::onion::cell::LayerHeader;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

pub fn wrap_layer(key: &[u8; 32], header: &LayerHeader, inner: &[u8]) -> Result<Vec<u8>> {
    let header_bytes = header.serialize_bincode()?;
    let header_len = (header_bytes.len() as u32).to_be_bytes();

    let mut plaintext = Vec::with_capacity(4 + header_bytes.len() + inner.len());
    plaintext.extend_from_slice(&header_len);
    plaintext.extend_from_slice(&header_bytes);
    plaintext.extend_from_slice(inner);

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| HidraError::Crypto("invalid layer key".into()))?;

    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: &plaintext,
                aad: &[],
            },
        )
        .map_err(|_| HidraError::Crypto("layer encryption failed".into()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn peel_layer(key: &[u8; 32], encrypted: &[u8]) -> Result<(LayerHeader, Vec<u8>)> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(HidraError::Crypto("layer data too short".into()));
    }

    let nonce: [u8; NONCE_LEN] = encrypted[..NONCE_LEN]
        .try_into()
        .map_err(|_| HidraError::Crypto("invalid nonce".into()))?;
    let ciphertext = &encrypted[NONCE_LEN..];

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| HidraError::Crypto("invalid layer key".into()))?;

    let plaintext = cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| HidraError::Crypto("layer decryption failed".into()))?;

    if plaintext.len() < 4 {
        return Err(HidraError::Crypto("decrypted layer too short for header length".into()));
    }

    let header_len = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]])
        as usize;

    if plaintext.len() < 4 + header_len {
        return Err(HidraError::Crypto("decrypted layer too short for header".into()));
    }

    let header = LayerHeader::deserialize_bincode(&plaintext[4..4 + header_len])?;
    let inner = plaintext[4 + header_len..].to_vec();

    Ok((header, inner))
}

pub fn encrypt_stream(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| HidraError::Crypto("invalid stream key".into()))?;

    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: data,
                aad: &[],
            },
        )
        .map_err(|_| HidraError::Crypto("stream encryption failed".into()))?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt_stream(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>> {
    if encrypted.len() < NONCE_LEN + TAG_LEN {
        return Err(HidraError::Crypto("stream data too short".into()));
    }

    let nonce: [u8; NONCE_LEN] = encrypted[..NONCE_LEN]
        .try_into()
        .map_err(|_| HidraError::Crypto("invalid nonce".into()))?;
    let ciphertext = &encrypted[NONCE_LEN..];

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| HidraError::Crypto("invalid stream key".into()))?;

    cipher
        .decrypt(
            (&nonce).into(),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| HidraError::Crypto("stream decryption failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn wrap_and_peel_roundtrip() {
        let key = [0x42u8; 32];
        let header = LayerHeader {
            next_hop: Some("127.0.0.1:9151".parse::<SocketAddr>().unwrap()),
        };
        let payload = b"secret message";

        let encrypted = wrap_layer(&key, &header, payload).unwrap();
        let (peeled_header, peeled_inner) = peel_layer(&key, &encrypted).unwrap();

        assert_eq!(
            peeled_header.next_hop,
            Some("127.0.0.1:9151".parse().unwrap())
        );
        assert_eq!(peeled_inner, payload);
    }

    #[test]
    fn wrong_key_rejected() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let header = LayerHeader { next_hop: None };

        let encrypted = wrap_layer(&key, &header, b"data").unwrap();
        assert!(peel_layer(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn tampered_data_rejected() {
        let key = [0x42u8; 32];
        let header = LayerHeader { next_hop: None };

        let mut encrypted = wrap_layer(&key, &header, b"data").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(peel_layer(&key, &encrypted).is_err());
    }

    #[test]
    fn exit_node_header() {
        let key = [0xAA; 32];
        let header = LayerHeader { next_hop: None };

        let encrypted = wrap_layer(&key, &header, b"exit payload").unwrap();
        let (h, inner) = peel_layer(&key, &encrypted).unwrap();

        assert!(h.next_hop.is_none());
        assert_eq!(inner, b"exit payload");
    }
}
