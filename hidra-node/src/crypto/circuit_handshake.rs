//! The handshake a client runs with each relay of a circuit, and that every
//! link between two nodes starts with.
//!
//! Noise NK with the same hybrid forward secrecy as the node handshake:
//!
//! ```text
//!   <- s
//!   ...
//!   -> e, e1, es
//!   <- e, ee, ekem1
//! ```
//!
//! Only the relay is authenticated. The client already holds the relay's
//! static key (from a descriptor the relay signed, or from a key its operator
//! pinned) and mixes it in before the first message, so the handshake
//! completes only with whoever holds the matching private key. The client has
//! no static key at all: each run starts from a fresh ephemeral X25519 key and
//! a fresh ML-KEM-1024 key, so two hops of one circuit, or two circuits, carry
//! nothing a relay could use to tell they came from the same client.
//!
//! The transport keys depend on `es`, `ee` and the ML-KEM secret. A later
//! compromise of the relay's static key exposes `es` only; a recording broken
//! with a quantum computer exposes the X25519 halves only.

use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::handshake::{
    DH_LEN, KEM_CT_LEN, KEM_EK_LEN, SymmetricState, TAG_LEN, TransportCipher,
};
use crate::error::{HidraError, Result};

const PROTOCOL_NAME: &[u8] = b"Noise_NKhfs_25519+MLKEM1024_ChaChaPoly_BLAKE3";

/// The initiator's message: its ephemeral key, its ML-KEM key, and the tag of
/// an empty payload sealed under `es`.
pub const MSG_A_LEN: usize = DH_LEN + KEM_EK_LEN + TAG_LEN;
/// The responder's answer: its ephemeral key, the ML-KEM ciphertext (sealed),
/// and the tag of an empty payload.
pub const MSG_B_LEN: usize = DH_LEN + KEM_CT_LEN + TAG_LEN + TAG_LEN;

/// Both directions of a finished handshake, from this side's point of view.
pub struct Keys {
    pub send: TransportCipher,
    pub recv: TransportCipher,
}

/// A DH output that is all zeros means the peer sent a low-order point: the
/// "shared" secret is then known to anyone. Refused rather than mixed in.
fn contributory(shared: SharedSecret) -> Result<SharedSecret> {
    if shared.was_contributory() {
        Ok(shared)
    } else {
        Err(HidraError::Handshake("peer sent a low-order key".into()))
    }
}

/// The client's half, between sending message A and reading message B.
pub struct Initiator {
    sym: SymmetricState,
    e: StaticSecret,
    e1: DecapsulationKey,
}

impl Initiator {
    /// Starts a handshake with the relay whose static key is `responder`, and
    /// returns message A to send to it.
    pub fn start(responder: &PublicKey) -> Result<(Self, Vec<u8>)> {
        let mut sym = SymmetricState::initialize_with(PROTOCOL_NAME);
        sym.mix_hash(responder.as_bytes());

        let e = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e);
        sym.mix_hash(e_pub.as_bytes());

        let (e1, ek) = MlKem1024::generate_keypair();
        let ek_bytes = ek.to_bytes();
        sym.mix_hash(&ek_bytes);

        let es = contributory(e.diffie_hellman(responder))?;
        sym.mix_key(es.as_bytes());
        let tag = sym.encrypt_and_hash(&[])?;

        let mut msg = Vec::with_capacity(MSG_A_LEN);
        msg.extend_from_slice(e_pub.as_bytes());
        msg.extend_from_slice(&ek_bytes);
        msg.extend_from_slice(&tag);
        Ok((Self { sym, e, e1 }, msg))
    }

    /// Reads message B. Fails unless it came from the holder of the static
    /// key `start` was given: the tag is under a key that depends on `es`.
    pub fn finish(mut self, msg_b: &[u8]) -> Result<Keys> {
        if msg_b.len() != MSG_B_LEN {
            return Err(HidraError::Handshake(format!(
                "message B is {} bytes, expected {MSG_B_LEN}",
                msg_b.len()
            )));
        }
        let mut re_bytes = [0u8; DH_LEN];
        re_bytes.copy_from_slice(&msg_b[..DH_LEN]);
        let re = PublicKey::from(re_bytes);
        self.sym.mix_hash(&re_bytes);

        let ee = contributory(self.e.diffie_hellman(&re))?;
        self.sym.mix_key(ee.as_bytes());

        let mut off = DH_LEN;
        let ct_bytes = self
            .sym
            .decrypt_and_hash(&msg_b[off..off + KEM_CT_LEN + TAG_LEN])?;
        off += KEM_CT_LEN + TAG_LEN;
        let ct = Ciphertext::try_from(ct_bytes.as_slice())
            .map_err(|_| HidraError::Handshake("ML-KEM ciphertext has the wrong length".into()))?;
        let mut ss = self.e1.decapsulate(&ct);
        self.sym.mix_key(&ss);
        ss.as_mut_slice().zeroize();

        self.sym.decrypt_and_hash(&msg_b[off..])?;
        let (c1, c2) = self.sym.split();
        Ok(Keys { send: c1, recv: c2 })
    }
}

/// The relay's half: reads message A with its static key and answers it.
/// Fails if the initiator used another static key than this relay's.
pub fn respond(static_secret: &StaticSecret, msg_a: &[u8]) -> Result<(Vec<u8>, Keys)> {
    if msg_a.len() != MSG_A_LEN {
        return Err(HidraError::Handshake(format!(
            "message A is {} bytes, expected {MSG_A_LEN}",
            msg_a.len()
        )));
    }
    let mut sym = SymmetricState::initialize_with(PROTOCOL_NAME);
    sym.mix_hash(PublicKey::from(static_secret).as_bytes());

    let mut re_bytes = [0u8; DH_LEN];
    re_bytes.copy_from_slice(&msg_a[..DH_LEN]);
    let re = PublicKey::from(re_bytes);
    sym.mix_hash(&re_bytes);
    let mut off = DH_LEN;

    let ek_bytes = &msg_a[off..off + KEM_EK_LEN];
    let ek = EncapsulationKey::new_from_slice(ek_bytes)
        .map_err(|_| HidraError::Handshake("ML-KEM encapsulation key rejected".into()))?;
    sym.mix_hash(ek_bytes);
    off += KEM_EK_LEN;

    let es = contributory(static_secret.diffie_hellman(&re))?;
    sym.mix_key(es.as_bytes());
    sym.decrypt_and_hash(&msg_a[off..])?;

    let e = StaticSecret::random_from_rng(OsRng);
    let e_pub = PublicKey::from(&e);
    sym.mix_hash(e_pub.as_bytes());
    let ee = contributory(e.diffie_hellman(&re))?;
    sym.mix_key(ee.as_bytes());

    let mut msg = Vec::with_capacity(MSG_B_LEN);
    msg.extend_from_slice(e_pub.as_bytes());
    let (ct, mut ss) = ek.encapsulate();
    let enc_ct = sym.encrypt_and_hash(&ct)?;
    msg.extend_from_slice(&enc_ct);
    sym.mix_key(&ss);
    ss.as_mut_slice().zeroize();
    let tag = sym.encrypt_and_hash(&[])?;
    msg.extend_from_slice(&tag);

    let (c1, c2) = sym.split();
    Ok((msg, Keys { send: c2, recv: c1 }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay() -> (StaticSecret, PublicKey) {
        let s = StaticSecret::random_from_rng(OsRng);
        let p = PublicKey::from(&s);
        (s, p)
    }

    #[test]
    fn both_sides_agree_and_the_messages_have_their_sizes() {
        let (s, p) = relay();
        let (init, a) = Initiator::start(&p).unwrap();
        assert_eq!(a.len(), MSG_A_LEN);
        let (b, mut r) = respond(&s, &a).unwrap();
        assert_eq!(b.len(), MSG_B_LEN);
        let mut i = init.finish(&b).unwrap();

        let ct = i.send.encrypt(b"forward").unwrap();
        assert_eq!(r.recv.decrypt(&ct).unwrap(), b"forward");
        let ct = r.send.encrypt(b"backward").unwrap();
        assert_eq!(i.recv.decrypt(&ct).unwrap(), b"backward");
    }

    /// The client aimed at one key; another relay answers. Neither side gets
    /// a session: the relay cannot open message A, and nothing it could send
    /// back would open at the client.
    #[test]
    fn a_relay_with_another_key_cannot_complete_it() {
        let (_, p) = relay();
        let (impostor, _) = relay();
        let (init, a) = Initiator::start(&p).unwrap();
        assert!(respond(&impostor, &a).is_err());

        // Even an impostor that skipped the check and answered anyway: the
        // answer does not open, because the client's keys depend on `es`.
        let (other_init, other_a) = Initiator::start(&PublicKey::from(&impostor)).unwrap();
        drop(other_init);
        let (b, _) = respond(&impostor, &other_a).unwrap();
        assert!(init.finish(&b).is_err());
    }

    /// Nothing in message A identifies the client: two handshakes by the same
    /// caller share no byte of key material.
    #[test]
    fn the_client_presents_nothing_that_repeats() {
        let (_, p) = relay();
        let (_, a1) = Initiator::start(&p).unwrap();
        let (_, a2) = Initiator::start(&p).unwrap();
        assert_ne!(a1[..DH_LEN], a2[..DH_LEN]);
        assert_ne!(
            a1[DH_LEN..DH_LEN + KEM_EK_LEN],
            a2[DH_LEN..DH_LEN + KEM_EK_LEN]
        );
    }

    #[test]
    fn a_tampered_ml_kem_ciphertext_breaks_it() {
        let (s, p) = relay();
        let (init, a) = Initiator::start(&p).unwrap();
        let (mut b, _) = respond(&s, &a).unwrap();
        b[DH_LEN + 7] ^= 1;
        assert!(init.finish(&b).is_err());
    }

    #[test]
    fn a_substituted_ml_kem_key_breaks_it() {
        let (s, p) = relay();
        let (_, mut a) = Initiator::start(&p).unwrap();
        let (_, theirs) = MlKem1024::generate_keypair();
        a[DH_LEN..DH_LEN + KEM_EK_LEN].copy_from_slice(&theirs.to_bytes());
        // The ML-KEM key is hashed before `es` seals the tag.
        assert!(respond(&s, &a).is_err());
    }

    #[test]
    fn a_low_order_ephemeral_is_refused() {
        let (s, p) = relay();
        let (_, mut a) = Initiator::start(&p).unwrap();
        a[..DH_LEN].copy_from_slice(&[0u8; DH_LEN]);
        assert!(respond(&s, &a).is_err());
    }

    #[test]
    fn short_messages_are_refused() {
        let (s, p) = relay();
        assert!(respond(&s, &[0u8; MSG_A_LEN - 1]).is_err());
        let (init, _) = Initiator::start(&p).unwrap();
        assert!(init.finish(&[0u8; MSG_B_LEN - 1]).is_err());
    }
}
