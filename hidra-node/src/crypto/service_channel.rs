//! End-to-end encryption between a visitor and a `.hidra` service.
//!
//! The onion layers protect each hop, but they end at the introduction relay:
//! that relay used to bridge a visitor's circuit to the service's circuit in
//! the clear, so it read every page and every request that went through it.
//! This channel runs inside the bridged stream, so the introduction relay only
//! ever carries ciphertext.
//!
//! The handshake, one round trip:
//!
//! ```text
//! visitor -> service   HELLO   e_c (X25519) | ek_c (ML-KEM-1024)
//! service -> visitor   ACCEPT  e_s (X25519) | ct (ML-KEM-1024) | pk_s | sig
//! ```
//!
//! * The session secret mixes X25519(e_c, e_s) with the ML-KEM shared secret,
//!   so recorded traffic stays safe against a future quantum computer unless
//!   both are broken, the same hybrid the node-to-node handshake uses.
//! * Both key pairs are ephemeral and never stored: a later theft of the
//!   service's key does not open a recorded session (forward secrecy).
//! * `pk_s` is the service's Ed25519 key, and `sig` signs the whole
//!   transcript with it. The visitor accepts `pk_s` only if it hashes to the
//!   address it asked for, the same derivation that makes the address, so the
//!   address itself authenticates the service and no relay can stand in for
//!   it.
//!
//! After that, each record is ChaCha20-Poly1305 with a separate key and a
//! counter nonce in each direction. Records are carried one per `Data`
//! payload, whose boundaries the circuit preserves.

use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{HidraError, Result};

const HELLO: u8 = 0x01;
const ACCEPT: u8 = 0x02;
const DATA: u8 = 0x03;
const CLOSE: u8 = 0x04;

const DH_LEN: usize = 32;
const KEM_EK_LEN: usize = 1568;
const KEM_CT_LEN: usize = 1568;
const PK_LEN: usize = 32;
const SIG_LEN: usize = 64;

const HELLO_LEN: usize = 1 + DH_LEN + KEM_EK_LEN;
const ACCEPT_LEN: usize = 1 + DH_LEN + KEM_CT_LEN + PK_LEN + SIG_LEN;

const PROTOCOL: &str = "HidraNet service channel v1: X25519+MLKEM1024, Ed25519, ChaCha20-Poly1305";

/// The 20-byte hash a `.hidra` address is made of, for a service key.
pub fn address_hash(service_pubkey: &[u8; 32]) -> [u8; 20] {
    let full = blake3::hash(service_pubkey);
    let mut out = [0u8; 20];
    out.copy_from_slice(&full.as_bytes()[..20]);
    out
}

/// What a record turned out to be, once opened.
#[derive(Debug, PartialEq, Eq)]
pub enum Inbound {
    /// Application bytes.
    Data(Vec<u8>),
    /// The other side finished; nothing more will come in this session.
    Close,
}

/// One direction's AEAD state.
struct Cipher {
    key: [u8; 32],
    nonce: u64,
}

impl Cipher {
    fn new(key: [u8; 32]) -> Self {
        Self { key, nonce: 0 }
    }

    fn next_nonce(&mut self) -> Result<[u8; 12]> {
        if self.nonce == u64::MAX {
            return Err(HidraError::Crypto("service channel nonce exhausted".into()));
        }
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
        Ok(n)
    }

    fn seal(&mut self, kind: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.next_nonce()?;
        let aead = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| HidraError::Crypto("bad service channel key".into()))?;
        let ct = aead
            .encrypt(
                (&nonce).into(),
                Payload {
                    msg: plaintext,
                    aad: &[kind],
                },
            )
            .map_err(|_| HidraError::Crypto("service channel encryption failed".into()))?;
        let mut out = Vec::with_capacity(1 + ct.len());
        out.push(kind);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open(&mut self, record: &[u8]) -> Result<Inbound> {
        let (&kind, body) = record
            .split_first()
            .ok_or_else(|| HidraError::Crypto("empty service channel record".into()))?;
        if kind != DATA && kind != CLOSE {
            return Err(HidraError::Crypto(
                "unexpected service channel record".into(),
            ));
        }
        let nonce = self.next_nonce()?;
        let aead = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| HidraError::Crypto("bad service channel key".into()))?;
        let pt = aead
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: body,
                    aad: &[kind],
                },
            )
            .map_err(|_| {
                HidraError::Crypto("service channel record failed authentication".into())
            })?;
        Ok(if kind == CLOSE {
            Inbound::Close
        } else {
            Inbound::Data(pt)
        })
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// An established channel: one end of it.
pub struct Channel {
    send: Cipher,
    recv: Cipher,
}

impl Channel {
    /// Seal application bytes into one record.
    pub fn seal(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.send.seal(DATA, data)
    }

    /// Seal the authenticated end-of-session record.
    pub fn seal_close(&mut self) -> Result<Vec<u8>> {
        self.send.seal(CLOSE, &[])
    }

    /// Open one record from the other side. Fails on anything forged,
    /// replayed, reordered or truncated.
    pub fn open(&mut self, record: &[u8]) -> Result<Inbound> {
        self.recv.open(record)
    }
}

/// The transcript hash both sides sign or check, and derive keys from.
fn transcript(service_hash: &[u8; 20], hello: &[u8], e_s: &[u8], ct: &[u8], pk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(PROTOCOL);
    h.update(service_hash);
    h.update(hello);
    h.update(e_s);
    h.update(ct);
    h.update(pk);
    *h.finalize().as_bytes()
}

/// Client and server keys from the hybrid secret and the transcript.
fn session_keys(dh: &[u8; 32], kem_ss: &[u8], th: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut ikm = Vec::with_capacity(32 + kem_ss.len() + 32);
    ikm.extend_from_slice(dh);
    ikm.extend_from_slice(kem_ss);
    ikm.extend_from_slice(th);
    let c2s = blake3::derive_key("HidraNet service channel v1 client to service", &ikm);
    let s2c = blake3::derive_key("HidraNet service channel v1 service to client", &ikm);
    ikm.zeroize();
    (c2s, s2c)
}

/// The visitor's side, between sending HELLO and reading ACCEPT.
pub struct ClientHandshake {
    service_hash: [u8; 20],
    e: StaticSecret,
    dk: DecapsulationKey,
    hello: Vec<u8>,
}

impl ClientHandshake {
    /// Start a handshake with the service at `service_hash`. Returns the state
    /// and the HELLO record to send.
    pub fn start(service_hash: [u8; 20]) -> (Self, Vec<u8>) {
        let e = StaticSecret::random_from_rng(OsRng);
        let (dk, ek) = MlKem1024::generate_keypair();
        let mut hello = Vec::with_capacity(HELLO_LEN);
        hello.push(HELLO);
        hello.extend_from_slice(PublicKey::from(&e).as_bytes());
        hello.extend_from_slice(&ek.to_bytes());
        let state = Self {
            service_hash,
            e,
            dk,
            hello: hello.clone(),
        };
        (state, hello)
    }

    /// Read ACCEPT. Succeeds only if it was signed by the key the address was
    /// made from.
    pub fn finish(self, accept: &[u8]) -> Result<Channel> {
        if accept.len() != ACCEPT_LEN || accept[0] != ACCEPT {
            return Err(HidraError::Handshake("malformed service ACCEPT".into()));
        }
        let mut off = 1;
        let e_s: [u8; 32] = accept[off..off + DH_LEN]
            .try_into()
            .expect("length checked");
        off += DH_LEN;
        let ct_bytes = &accept[off..off + KEM_CT_LEN];
        off += KEM_CT_LEN;
        let pk: [u8; 32] = accept[off..off + PK_LEN]
            .try_into()
            .expect("length checked");
        off += PK_LEN;
        let sig: [u8; 64] = accept[off..off + SIG_LEN]
            .try_into()
            .expect("length checked");

        if address_hash(&pk) != self.service_hash {
            return Err(HidraError::Handshake(
                "service key does not match the .hidra address".into(),
            ));
        }
        let th = transcript(&self.service_hash, &self.hello, &e_s, ct_bytes, &pk);
        let vk = VerifyingKey::from_bytes(&pk)
            .map_err(|_| HidraError::Handshake("invalid service key".into()))?;
        vk.verify(&th, &Signature::from_bytes(&sig))
            .map_err(|_| HidraError::Handshake("service signature does not verify".into()))?;

        let ct = Ciphertext::try_from(ct_bytes)
            .map_err(|_| HidraError::Handshake("ML-KEM ciphertext has the wrong length".into()))?;
        let mut kem_ss = self.dk.decapsulate(&ct);
        let dh = self.e.diffie_hellman(&PublicKey::from(e_s));
        let (c2s, s2c) = session_keys(dh.as_bytes(), &kem_ss, &th);
        kem_ss.as_mut_slice().zeroize();
        Ok(Channel {
            send: Cipher::new(c2s),
            recv: Cipher::new(s2c),
        })
    }
}

/// Whether a record from a visitor starts a new session.
pub fn is_hello(record: &[u8]) -> bool {
    record.first() == Some(&HELLO)
}

/// The service's side: answer a HELLO. Returns the channel and the ACCEPT
/// record to send back.
pub fn accept(signing_key: &SigningKey, hello: &[u8]) -> Result<(Channel, Vec<u8>)> {
    if hello.len() != HELLO_LEN || hello[0] != HELLO {
        return Err(HidraError::Handshake("malformed service HELLO".into()));
    }
    let e_c: [u8; 32] = hello[1..1 + DH_LEN].try_into().expect("length checked");
    let ek = EncapsulationKey::new_from_slice(&hello[1 + DH_LEN..])
        .map_err(|_| HidraError::Handshake("ML-KEM encapsulation key rejected".into()))?;

    let pk = signing_key.verifying_key().to_bytes();
    let service_hash = address_hash(&pk);

    let e = StaticSecret::random_from_rng(OsRng);
    let e_pub = PublicKey::from(&e);
    let (ct, mut kem_ss) = ek.encapsulate();

    let th = transcript(&service_hash, hello, e_pub.as_bytes(), &ct, &pk);
    let sig = signing_key.sign(&th);

    let dh = e.diffie_hellman(&PublicKey::from(e_c));
    let (c2s, s2c) = session_keys(dh.as_bytes(), &kem_ss, &th);
    kem_ss.as_mut_slice().zeroize();

    let mut out = Vec::with_capacity(ACCEPT_LEN);
    out.push(ACCEPT);
    out.extend_from_slice(e_pub.as_bytes());
    out.extend_from_slice(&ct);
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sig.to_bytes());
    Ok((
        Channel {
            send: Cipher::new(s2c),
            recv: Cipher::new(c2s),
        },
        out,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (Channel, Channel, SigningKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let hash = address_hash(&sk.verifying_key().to_bytes());
        let (client, hello) = ClientHandshake::start(hash);
        assert!(is_hello(&hello));
        let (server, accept_msg) = accept(&sk, &hello).unwrap();
        let client = client.finish(&accept_msg).unwrap();
        (client, server, sk)
    }

    #[test]
    fn both_directions_round_trip() {
        let (mut c, mut s, _) = pair();
        let r = c.seal(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(
            s.open(&r).unwrap(),
            Inbound::Data(b"GET / HTTP/1.1\r\n\r\n".to_vec())
        );
        let r = s.seal(b"HTTP/1.1 200 OK").unwrap();
        assert_eq!(
            c.open(&r).unwrap(),
            Inbound::Data(b"HTTP/1.1 200 OK".to_vec())
        );
        let r = s.seal_close().unwrap();
        assert_eq!(c.open(&r).unwrap(), Inbound::Close);
    }

    #[test]
    fn the_relay_in_the_middle_sees_no_plaintext() {
        let (mut c, _s, _) = pair();
        let secret = b"card number 4111 1111 1111 1111";
        let r = c.seal(secret).unwrap();
        assert!(!r.windows(secret.len()).any(|w| w == secret));
    }

    #[test]
    fn a_service_without_the_addresss_key_is_refused() {
        let real = SigningKey::generate(&mut OsRng);
        let impostor = SigningKey::generate(&mut OsRng);
        let hash = address_hash(&real.verifying_key().to_bytes());
        let (client, hello) = ClientHandshake::start(hash);
        let (_, accept_msg) = accept(&impostor, &hello).unwrap();
        assert!(client.finish(&accept_msg).is_err());
    }

    #[test]
    fn a_tampered_accept_is_refused() {
        let sk = SigningKey::generate(&mut OsRng);
        let hash = address_hash(&sk.verifying_key().to_bytes());
        for i in [5usize, 40, 1000, ACCEPT_LEN - 10] {
            let (client, hello) = ClientHandshake::start(hash);
            let (_, mut accept_msg) = accept(&sk, &hello).unwrap();
            accept_msg[i] ^= 1;
            assert!(client.finish(&accept_msg).is_err(), "byte {i}");
        }
    }

    #[test]
    fn tampered_replayed_or_reordered_records_are_refused() {
        // Tampered.
        let (mut c, mut s, _) = pair();
        let mut bad = c.seal(b"one").unwrap();
        bad[3] ^= 1;
        assert!(s.open(&bad).is_err());

        // Replayed.
        let (mut c, mut s, _) = pair();
        let a = c.seal(b"one").unwrap();
        assert!(s.open(&a).is_ok());
        assert!(s.open(&a).is_err(), "replay");

        // Reordered.
        let (mut c, mut s, _) = pair();
        let _first = c.seal(b"one").unwrap();
        let second = c.seal(b"two").unwrap();
        assert!(s.open(&second).is_err(), "reorder");
    }

    #[test]
    fn each_session_has_its_own_keys() {
        let sk = SigningKey::generate(&mut OsRng);
        let hash = address_hash(&sk.verifying_key().to_bytes());
        let (c1, h1) = ClientHandshake::start(hash);
        let (_, a1) = accept(&sk, &h1).unwrap();
        let mut c1 = c1.finish(&a1).unwrap();
        let (c2, h2) = ClientHandshake::start(hash);
        let (_, a2) = accept(&sk, &h2).unwrap();
        let mut c2 = c2.finish(&a2).unwrap();
        assert_ne!(c1.seal(b"same").unwrap(), c2.seal(b"same").unwrap());
    }
}
