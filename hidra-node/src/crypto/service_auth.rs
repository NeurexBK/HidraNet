//! Proving a hidden service is the one its `.hidra` address names.
//!
//! A `.hidra` address is the BLAKE3 of the service's Ed25519 key. The relay
//! that introduces a client to a service used to hand the client to whoever
//! had registered that address with it, with no proof, and the client never
//! checked who answered: anyone could register someone else's address and
//! be that site. Two things close it.
//!
//! **Registration** carries a fresh signature by the service key, so a relay
//! only introduces clients to whoever holds that key ([`registration_proof`],
//! [`verify_registration`]).
//!
//! **Every session** starts with the client challenging the service before
//! anything else is said. The client sends an ephemeral X25519 key and a
//! nonce; the service answers with an ephemeral key of its own and an
//! Ed25519 signature, by the address's key, over both and the address. The
//! client checks it against the key in the signed descriptor. From then on
//! everything is sealed with keys from that exchange, so the relay in the
//! middle can neither impersonate the service nor read what passes through.
//!
//! Wire format, carried as the payload of ordinary stream `Data` cells:
//!
//! ```text
//! hello  = "HSA1" | client_eph(32) | nonce(32)
//! answer = "HSB1" | service_eph(32) | signature(64)
//! sealed = ChaCha20-Poly1305(key_dir, counter_nonce, data)
//! ```

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{HidraError, Result};
use crate::p2p::dht::descriptor::service_hash_of;

pub const HELLO_MAGIC: &[u8; 4] = b"HSA1";
pub const ANSWER_MAGIC: &[u8; 4] = b"HSB1";
pub const HELLO_LEN: usize = 4 + 32 + 32;
pub const ANSWER_LEN: usize = 4 + 32 + 64;

const SESSION_DOMAIN: &[u8] = b"hidra/service-auth/v1";
const REGISTER_DOMAIN: &[u8] = b"hidra/service-register/v1";
const KDF_C2S: &str = "hidra service-auth v1 client-to-service";
const KDF_S2C: &str = "hidra service-auth v1 service-to-client";

/// How far a registration's timestamp may be from the relay's clock.
pub const REGISTRATION_MAX_SKEW_SECS: u64 = 600;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn auth_err(msg: &str) -> HidraError {
    HidraError::Protocol(format!("hidden service authentication: {msg}"))
}

// ── Registration ────────────────────────────────────────────────────────────

fn registration_bytes(service_hash: &[u8; 20], timestamp: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(REGISTER_DOMAIN.len() + 28);
    b.extend_from_slice(REGISTER_DOMAIN);
    b.extend_from_slice(service_hash);
    b.extend_from_slice(&timestamp.to_le_bytes());
    b
}

/// What a service sends with its registration: its key, the time, and its
/// signature over the address and the time.
pub fn registration_proof(service_key: &SigningKey) -> ([u8; 32], u64, Vec<u8>) {
    let pk = service_key.verifying_key().to_bytes();
    let ts = now_secs();
    let sig = service_key.sign(&registration_bytes(&service_hash_of(&pk), ts));
    (pk, ts, sig.to_bytes().to_vec())
}

/// A relay's check before it introduces anyone to `service_hash`: the key is
/// the one the address names, the time is recent, and the key signed it.
pub fn verify_registration(
    service_hash: &[u8],
    service_pubkey: &[u8; 32],
    timestamp: u64,
    signature: &[u8],
) -> Result<()> {
    if service_hash.len() != 20 || service_hash_of(service_pubkey)[..] != service_hash[..] {
        return Err(auth_err("the key is not the one this address names"));
    }
    if now_secs().abs_diff(timestamp) > REGISTRATION_MAX_SKEW_SECS {
        return Err(auth_err("registration is too old or from the future"));
    }
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| auth_err("a signature is 64 bytes"))?;
    let key =
        VerifyingKey::from_bytes(service_pubkey).map_err(|_| auth_err("not an Ed25519 key"))?;
    let mut hash = [0u8; 20];
    hash.copy_from_slice(service_hash);
    key.verify_strict(
        &registration_bytes(&hash, timestamp),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| auth_err("the service did not sign this registration"))
}

// ── Sessions ────────────────────────────────────────────────────────────────

fn transcript(
    service_hash: &[u8; 20],
    client_eph: &[u8; 32],
    nonce: &[u8; 32],
    service_eph: &[u8; 32],
) -> Vec<u8> {
    let mut t = Vec::with_capacity(SESSION_DOMAIN.len() + 20 + 96);
    t.extend_from_slice(SESSION_DOMAIN);
    t.extend_from_slice(service_hash);
    t.extend_from_slice(client_eph);
    t.extend_from_slice(nonce);
    t.extend_from_slice(service_eph);
    t
}

/// The keys both ends derive: one per direction, from the shared secret and
/// the whole transcript, so a changed byte anywhere gives different keys.
fn session_keys(shared: &[u8; 32], transcript: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut material = Vec::with_capacity(32 + transcript.len());
    material.extend_from_slice(shared);
    material.extend_from_slice(transcript);
    let c2s = blake3::derive_key(KDF_C2S, &material);
    let s2c = blake3::derive_key(KDF_S2C, &material);
    material.zeroize();
    (c2s, s2c)
}

/// One sealed direction: a key and a counter that is the nonce. The bridge
/// delivers in order, so a message out of order, replayed or dropped makes
/// the next one fail to open, and the session ends.
struct Direction {
    cipher: ChaCha20Poly1305,
    counter: u64,
}

impl Direction {
    fn new(mut key: [u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        key.zeroize();
        Self { cipher, counter: 0 }
    }

    fn nonce(&mut self) -> Result<[u8; 12]> {
        let c = self.counter;
        self.counter = c
            .checked_add(1)
            .ok_or_else(|| auth_err("session exhausted"))?;
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&c.to_be_bytes());
        Ok(n)
    }
}

/// What sealing adds to a message: the Poly1305 tag (the nonce is the count,
/// so it does not travel). A client splits what it sends so that each sealed
/// piece still fits one cell.
pub const SEAL_OVERHEAD: usize = 16;

/// An authenticated session with a hidden service, from either end.
pub struct SealedChannel {
    send: Direction,
    recv: Direction,
}

impl SealedChannel {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let n = self.send.nonce()?;
        self.send
            .cipher
            .encrypt(Nonce::from_slice(&n), plaintext)
            .map_err(|_| auth_err("could not seal"))
    }

    pub fn open(&mut self, sealed: &[u8]) -> Result<Vec<u8>> {
        let n = self.recv.nonce()?;
        self.recv
            .cipher
            .decrypt(Nonce::from_slice(&n), sealed)
            .map_err(|_| auth_err("a message failed to open: altered, replayed or out of order"))
    }
}

/// The client's half, between sending the hello and reading the answer.
pub struct ClientHandshake {
    eph: StaticSecret,
    eph_pub: [u8; 32],
    nonce: [u8; 32],
}

impl ClientHandshake {
    /// Starts a session: the state to keep, and the hello to send.
    pub fn start() -> (Self, Vec<u8>) {
        let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let eph_pub = PublicKey::from(&eph).to_bytes();
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let mut hello = Vec::with_capacity(HELLO_LEN);
        hello.extend_from_slice(HELLO_MAGIC);
        hello.extend_from_slice(&eph_pub);
        hello.extend_from_slice(&nonce);
        (
            Self {
                eph,
                eph_pub,
                nonce,
            },
            hello,
        )
    }

    /// Checks the answer against the service's key from its signed
    /// descriptor, and opens the session. Anything else is refused.
    pub fn finish(self, service_pubkey: &[u8; 32], answer: &[u8]) -> Result<SealedChannel> {
        if answer.len() != ANSWER_LEN || &answer[..4] != ANSWER_MAGIC {
            return Err(auth_err("the service did not answer the challenge"));
        }
        let mut service_eph = [0u8; 32];
        service_eph.copy_from_slice(&answer[4..36]);
        let sig: [u8; 64] = answer[36..]
            .try_into()
            .map_err(|_| auth_err("bad signature length"))?;
        let hash = service_hash_of(service_pubkey);
        let t = transcript(&hash, &self.eph_pub, &self.nonce, &service_eph);
        let key =
            VerifyingKey::from_bytes(service_pubkey).map_err(|_| auth_err("not an Ed25519 key"))?;
        key.verify_strict(&t, &Signature::from_bytes(&sig))
            .map_err(|_| auth_err("the answer is not signed by this address's key"))?;
        let mut shared = self
            .eph
            .diffie_hellman(&PublicKey::from(service_eph))
            .to_bytes();
        if shared == [0u8; 32] {
            return Err(auth_err("degenerate key exchange"));
        }
        let (c2s, s2c) = session_keys(&shared, &t);
        shared.zeroize();
        Ok(SealedChannel {
            send: Direction::new(c2s),
            recv: Direction::new(s2c),
        })
    }
}

/// True when this payload is a session's opening hello.
pub fn is_hello(payload: &[u8]) -> bool {
    payload.len() == HELLO_LEN && &payload[..4] == HELLO_MAGIC
}

/// The service's half: answers a hello, signed with the address's key, and
/// opens its end of the session.
pub fn answer_hello(service_key: &SigningKey, hello: &[u8]) -> Result<(SealedChannel, Vec<u8>)> {
    if !is_hello(hello) {
        return Err(auth_err("a session must start with the challenge"));
    }
    let mut client_eph = [0u8; 32];
    client_eph.copy_from_slice(&hello[4..36]);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&hello[36..68]);
    let eph = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let service_eph = PublicKey::from(&eph).to_bytes();
    let hash = service_hash_of(&service_key.verifying_key().to_bytes());
    let t = transcript(&hash, &client_eph, &nonce, &service_eph);
    let sig = service_key.sign(&t);
    let mut shared = eph.diffie_hellman(&PublicKey::from(client_eph)).to_bytes();
    if shared == [0u8; 32] {
        return Err(auth_err("degenerate key exchange"));
    }
    let (c2s, s2c) = session_keys(&shared, &t);
    shared.zeroize();
    let mut answer = Vec::with_capacity(ANSWER_LEN);
    answer.extend_from_slice(ANSWER_MAGIC);
    answer.extend_from_slice(&service_eph);
    answer.extend_from_slice(&sig.to_bytes());
    Ok((
        SealedChannel {
            send: Direction::new(s2c),
            recv: Direction::new(c2s),
        },
        answer,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn the_real_service_is_accepted_and_both_ends_talk() {
        let svc = key();
        let (hs, hello) = ClientHandshake::start();
        let (mut s, answer) = answer_hello(&svc, &hello).unwrap();
        let mut c = hs.finish(&svc.verifying_key().to_bytes(), &answer).unwrap();
        let sealed = c.seal(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert_ne!(
            &sealed[..],
            b"GET / HTTP/1.0\r\n\r\n",
            "the relay must not see plaintext"
        );
        assert_eq!(s.open(&sealed).unwrap(), b"GET / HTTP/1.0\r\n\r\n");
        let back = s.seal(b"200 OK").unwrap();
        assert_eq!(c.open(&back).unwrap(), b"200 OK");
        for i in 0..50u8 {
            let m = c.seal(&[i; 100]).unwrap();
            assert_eq!(s.open(&m).unwrap(), vec![i; 100]);
        }
    }

    #[test]
    fn sealing_adds_exactly_the_stated_overhead() {
        let svc = key();
        let (hs, hello) = ClientHandshake::start();
        let (_, answer) = answer_hello(&svc, &hello).unwrap();
        let mut c = hs.finish(&svc.verifying_key().to_bytes(), &answer).unwrap();
        for len in [0, 1, 1000] {
            assert_eq!(c.seal(&vec![0; len]).unwrap().len(), len + SEAL_OVERHEAD);
        }
    }

    #[test]
    fn someone_else_answering_for_the_address_is_refused() {
        let real = key();
        let impostor = key();
        let (hs, hello) = ClientHandshake::start();
        let (_, answer) = answer_hello(&impostor, &hello).unwrap();
        assert!(
            hs.finish(&real.verifying_key().to_bytes(), &answer)
                .is_err()
        );
    }

    #[test]
    fn a_tampered_or_replayed_answer_is_refused() {
        let svc = key();
        let pk = svc.verifying_key().to_bytes();
        let (hs1, hello1) = ClientHandshake::start();
        let (_, answer1) = answer_hello(&svc, &hello1).unwrap();
        // Replayed into another session: signed over another nonce.
        let (hs2, _hello2) = ClientHandshake::start();
        assert!(hs2.finish(&pk, &answer1).is_err());
        // Tampered key exchange.
        let mut bad = answer1.clone();
        bad[10] ^= 1;
        assert!(hs1.finish(&pk, &bad).is_err());
        // Not an answer at all.
        let (hs3, _) = ClientHandshake::start();
        assert!(hs3.finish(&pk, b"HTTP/1.0 200 OK").is_err());
    }

    #[test]
    fn altered_reordered_or_replayed_traffic_does_not_open() {
        let svc = key();
        let (hs, hello) = ClientHandshake::start();
        let (mut s, answer) = answer_hello(&svc, &hello).unwrap();
        let mut c = hs.finish(&svc.verifying_key().to_bytes(), &answer).unwrap();
        let m1 = c.seal(b"one").unwrap();
        let m2 = c.seal(b"two").unwrap();
        let mut altered = m1.clone();
        altered[0] ^= 1;
        assert!(s.open(&altered).is_err());
        // The failed open used up counter 0: the channel is now dead, which is
        // what a broken session should be.
        assert!(s.open(&m2).is_err() || s.open(&m1).is_err());
        let (hs, hello) = ClientHandshake::start();
        let (mut s, answer) = answer_hello(&svc, &hello).unwrap();
        let mut c = hs.finish(&svc.verifying_key().to_bytes(), &answer).unwrap();
        let m1 = c.seal(b"one").unwrap();
        let m2 = c.seal(b"two").unwrap();
        assert!(s.open(&m2).is_err(), "out of order opened");
        let (hs, hello) = ClientHandshake::start();
        let (mut s, answer) = answer_hello(&svc, &hello).unwrap();
        let mut c = hs.finish(&svc.verifying_key().to_bytes(), &answer).unwrap();
        let m1b = c.seal(b"one").unwrap();
        assert_eq!(s.open(&m1b).unwrap(), b"one");
        assert!(s.open(&m1b).is_err(), "replay opened");
        let _ = (m1, m2);
    }

    #[test]
    fn the_service_refuses_a_session_without_the_challenge() {
        assert!(answer_hello(&key(), b"GET / HTTP/1.0\r\n\r\n").is_err());
        assert!(!is_hello(b"HSA1short"));
    }

    #[test]
    fn registration_needs_the_key_and_a_fresh_time() {
        let svc = key();
        let (pk, ts, sig) = registration_proof(&svc);
        let hash = service_hash_of(&pk);
        assert!(verify_registration(&hash, &pk, ts, &sig).is_ok());
        // Someone else's key for this address.
        let other = key().verifying_key().to_bytes();
        assert!(verify_registration(&hash, &other, ts, &sig).is_err());
        // The right key, signed by someone else.
        let (pk2, ts2, sig2) = registration_proof(&key());
        assert!(verify_registration(&hash, &pk, ts2, &sig2).is_err());
        let _ = pk2;
        // An old proof, replayed.
        let old = ts - REGISTRATION_MAX_SKEW_SECS - 5;
        let old_sig = svc
            .sign(&registration_bytes(&hash, old))
            .to_bytes()
            .to_vec();
        assert!(verify_registration(&hash, &pk, old, &old_sig).is_err());
        // A changed time under the same signature.
        assert!(verify_registration(&hash, &pk, ts + 1, &sig).is_err());
    }
}
