use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{HidraError, Result};

// "Noise_XX_25519_ChaChaPoly_BLAKE3" — exactly 32 bytes = HASHLEN
const PROTOCOL_NAME: &[u8; 32] = b"Noise_XX_25519_ChaChaPoly_BLAKE3";
const DH_LEN: usize = 32;
const TAG_LEN: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Initiator,
    Responder,
}

// ---------------------------------------------------------------------------
// CipherState — wraps ChaCha20-Poly1305 with Noise-spec nonce management
// ---------------------------------------------------------------------------
#[derive(Zeroize, ZeroizeOnDrop)]
struct CipherState {
    key: Option<[u8; 32]>,
    #[zeroize(skip)]
    nonce: u64,
}

impl CipherState {
    fn empty() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    fn from_key(key: [u8; 32]) -> Self {
        Self {
            key: Some(key),
            nonce: 0,
        }
    }

    fn has_key(&self) -> bool {
        self.key.is_some()
    }

    fn encrypt(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let key =
            self.key.ok_or_else(|| HidraError::Crypto("cipher not keyed".into()))?;
        if self.nonce == u64::MAX {
            return Err(HidraError::Crypto("nonce exhaustion".into()));
        }

        let nonce_bytes = Self::build_nonce(self.nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| HidraError::Crypto("invalid cipher key length".into()))?;

        let ciphertext = cipher
            .encrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: plaintext,
                    aad: ad,
                },
            )
            .map_err(|_| HidraError::Crypto("AEAD encryption failed".into()))?;

        self.nonce += 1;
        Ok(ciphertext)
    }

    fn decrypt(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key =
            self.key.ok_or_else(|| HidraError::Crypto("cipher not keyed".into()))?;
        if self.nonce == u64::MAX {
            return Err(HidraError::Crypto("nonce exhaustion".into()));
        }

        let nonce_bytes = Self::build_nonce(self.nonce);
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|_| HidraError::Crypto("invalid cipher key length".into()))?;

        let plaintext = cipher
            .decrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: ciphertext,
                    aad: ad,
                },
            )
            .map_err(|_| HidraError::Crypto("AEAD decryption failed".into()))?;

        self.nonce += 1;
        Ok(plaintext)
    }

    // Noise spec for ChaChaPoly: 4 zero bytes ‖ LE64(n)
    fn build_nonce(n: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&n.to_le_bytes());
        nonce
    }
}

// ---------------------------------------------------------------------------
// SymmetricState — manages chaining key, handshake hash, and cipher
// ---------------------------------------------------------------------------
struct SymmetricState {
    h: [u8; 32],
    ck: [u8; 32],
    cipher: CipherState,
}

impl SymmetricState {
    fn initialize() -> Self {
        let h = *PROTOCOL_NAME;
        Self {
            ck: h,
            h,
            cipher: CipherState::empty(),
        }
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, temp_k) = hkdf(&self.ck, ikm);
        self.ck = ck;
        self.cipher = CipherState::from_key(temp_k);
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = *hasher.finalize().as_bytes();
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let ciphertext = if self.cipher.has_key() {
            self.cipher.encrypt(&self.h, plaintext)?
        } else {
            plaintext.to_vec()
        };
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let plaintext = if self.cipher.has_key() {
            self.cipher.decrypt(&self.h, ciphertext)?
        } else {
            ciphertext.to_vec()
        };
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    fn split(mut self) -> (TransportCipher, TransportCipher) {
        let (k1, k2) = hkdf(&self.ck, &[]);
        self.h.zeroize();
        self.ck.zeroize();
        (
            TransportCipher(CipherState::from_key(k1)),
            TransportCipher(CipherState::from_key(k2)),
        )
    }
}

// HKDF using BLAKE3 keyed-hash as PRF
fn hkdf(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp_key = blake3::keyed_hash(ck, ikm);

    let output1 = blake3::keyed_hash(temp_key.as_bytes(), &[0x01]);

    let mut hasher = blake3::Hasher::new_keyed(temp_key.as_bytes());
    hasher.update(output1.as_bytes());
    hasher.update(&[0x02]);
    let output2 = hasher.finalize();

    (*output1.as_bytes(), *output2.as_bytes())
}

// ---------------------------------------------------------------------------
// TransportCipher — post-handshake encrypted channel (one direction)
// ---------------------------------------------------------------------------
pub struct TransportCipher(CipherState);

impl TransportCipher {
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.0.encrypt(&[], plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.0.decrypt(&[], ciphertext)
    }

    pub fn session_key(&self) -> Result<[u8; 32]> {
        self.0
            .key
            .ok_or_else(|| HidraError::Crypto("cipher not keyed".into()))
    }
}

// ---------------------------------------------------------------------------
// HandshakeState — Noise XX: -> e | <- e, ee, s, es | -> s, se
// ---------------------------------------------------------------------------
pub struct HandshakeState {
    symmetric: Option<SymmetricState>,
    s: StaticSecret,
    e: Option<StaticSecret>,
    rs: Option<PublicKey>,
    re: Option<PublicKey>,
    role: Role,
}

impl HandshakeState {
    pub fn new(role: Role, static_secret: StaticSecret) -> Self {
        Self {
            symmetric: Some(SymmetricState::initialize()),
            s: static_secret,
            e: None,
            rs: None,
            re: None,
            role,
        }
    }

    fn sym(&mut self) -> Result<&mut SymmetricState> {
        self.symmetric
            .as_mut()
            .ok_or_else(|| HidraError::Handshake("state already consumed".into()))
    }

    // -----------------------------------------------------------------------
    // Message A: -> e
    // -----------------------------------------------------------------------
    pub fn write_message_a(&mut self) -> Result<Vec<u8>> {
        let e = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e);
        self.e = Some(e);

        self.sym()?.mix_hash(e_pub.as_bytes());

        let mut msg = Vec::with_capacity(DH_LEN);
        msg.extend_from_slice(e_pub.as_bytes());

        let payload_ct = self.sym()?.encrypt_and_hash(&[])?;
        msg.extend_from_slice(&payload_ct);
        Ok(msg)
    }

    pub fn read_message_a(&mut self, message: &[u8]) -> Result<()> {
        if message.len() < DH_LEN {
            return Err(HidraError::Handshake("message A too short".into()));
        }

        let re_bytes: [u8; 32] = message[..DH_LEN]
            .try_into()
            .map_err(|_| HidraError::Handshake("invalid ephemeral key in A".into()))?;
        self.re = Some(PublicKey::from(re_bytes));

        self.sym()?.mix_hash(&re_bytes);
        self.sym()?.decrypt_and_hash(&message[DH_LEN..])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Message B: <- e, ee, s, es
    // -----------------------------------------------------------------------
    pub fn write_message_b(&mut self) -> Result<Vec<u8>> {
        // e — generate ephemeral
        let e = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e);
        self.e = Some(e);

        self.sym()?.mix_hash(e_pub.as_bytes());

        let mut msg = Vec::with_capacity(DH_LEN + DH_LEN + TAG_LEN + TAG_LEN);
        msg.extend_from_slice(e_pub.as_bytes());

        // ee — DH(local_e, remote_e)
        let re = self
            .re
            .ok_or_else(|| HidraError::Handshake("missing remote ephemeral for ee".into()))?;
        let ee = self
            .e
            .as_ref()
            .ok_or_else(|| HidraError::Handshake("missing local ephemeral for ee".into()))?
            .diffie_hellman(&re);
        self.sym()?.mix_key(ee.as_bytes());

        // s — encrypt & send static public key
        let s_pub = PublicKey::from(&self.s);
        let enc_s = self.sym()?.encrypt_and_hash(s_pub.as_bytes())?;
        msg.extend_from_slice(&enc_s);

        // es — responder: DH(s, re)  |  initiator: DH(e, rs)
        let es_dh = match self.role {
            Role::Responder => self.s.diffie_hellman(&re),
            Role::Initiator => {
                let rs = self.rs.ok_or_else(|| {
                    HidraError::Handshake("missing remote static for es".into())
                })?;
                self.e
                    .as_ref()
                    .ok_or_else(|| {
                        HidraError::Handshake("missing local ephemeral for es".into())
                    })?
                    .diffie_hellman(&rs)
            }
        };
        self.sym()?.mix_key(es_dh.as_bytes());

        let payload_ct = self.sym()?.encrypt_and_hash(&[])?;
        msg.extend_from_slice(&payload_ct);
        Ok(msg)
    }

    pub fn read_message_b(&mut self, message: &[u8]) -> Result<()> {
        let min = DH_LEN + DH_LEN + TAG_LEN + TAG_LEN;
        if message.len() < min {
            return Err(HidraError::Handshake(format!(
                "message B too short: {} < {min}",
                message.len()
            )));
        }

        let mut off = 0;

        // e
        let re_bytes: [u8; 32] = message[off..off + DH_LEN]
            .try_into()
            .map_err(|_| HidraError::Handshake("invalid ephemeral key in B".into()))?;
        self.re = Some(PublicKey::from(re_bytes));
        self.sym()?.mix_hash(&re_bytes);
        off += DH_LEN;

        // ee
        let re = self
            .re
            .ok_or_else(|| HidraError::Handshake("missing remote ephemeral for ee".into()))?;
        let ee = self
            .e
            .as_ref()
            .ok_or_else(|| HidraError::Handshake("missing local ephemeral for ee".into()))?
            .diffie_hellman(&re);
        self.sym()?.mix_key(ee.as_bytes());

        // s — decrypt remote static
        let enc_s = &message[off..off + DH_LEN + TAG_LEN];
        let rs_bytes = self.sym()?.decrypt_and_hash(enc_s)?;
        let rs_array: [u8; 32] = rs_bytes
            .try_into()
            .map_err(|_| HidraError::Handshake("invalid static key length in B".into()))?;
        self.rs = Some(PublicKey::from(rs_array));
        off += DH_LEN + TAG_LEN;

        // es — initiator: DH(e, rs)  |  responder: DH(s, re)
        let es_dh = match self.role {
            Role::Initiator => {
                let rs = self.rs.ok_or_else(|| {
                    HidraError::Handshake("missing remote static for es".into())
                })?;
                self.e
                    .as_ref()
                    .ok_or_else(|| {
                        HidraError::Handshake("missing local ephemeral for es".into())
                    })?
                    .diffie_hellman(&rs)
            }
            Role::Responder => self.s.diffie_hellman(&re),
        };
        self.sym()?.mix_key(es_dh.as_bytes());

        self.sym()?.decrypt_and_hash(&message[off..])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Message C: -> s, se
    // -----------------------------------------------------------------------
    pub fn write_message_c(&mut self) -> Result<Vec<u8>> {
        let mut msg = Vec::with_capacity(DH_LEN + TAG_LEN + TAG_LEN);

        // s — encrypt & send static
        let s_pub = PublicKey::from(&self.s);
        let enc_s = self.sym()?.encrypt_and_hash(s_pub.as_bytes())?;
        msg.extend_from_slice(&enc_s);

        // se — initiator: DH(s, re)  |  responder: DH(e, rs)
        let se_dh = match self.role {
            Role::Initiator => {
                let re = self.re.ok_or_else(|| {
                    HidraError::Handshake("missing remote ephemeral for se".into())
                })?;
                self.s.diffie_hellman(&re)
            }
            Role::Responder => {
                let rs = self.rs.ok_or_else(|| {
                    HidraError::Handshake("missing remote static for se".into())
                })?;
                self.e
                    .as_ref()
                    .ok_or_else(|| {
                        HidraError::Handshake("missing local ephemeral for se".into())
                    })?
                    .diffie_hellman(&rs)
            }
        };
        self.sym()?.mix_key(se_dh.as_bytes());

        let payload_ct = self.sym()?.encrypt_and_hash(&[])?;
        msg.extend_from_slice(&payload_ct);
        Ok(msg)
    }

    pub fn read_message_c(&mut self, message: &[u8]) -> Result<()> {
        let min = DH_LEN + TAG_LEN + TAG_LEN;
        if message.len() < min {
            return Err(HidraError::Handshake(format!(
                "message C too short: {} < {min}",
                message.len()
            )));
        }

        let mut off = 0;

        // s — decrypt remote static
        let enc_s = &message[off..off + DH_LEN + TAG_LEN];
        let rs_bytes = self.sym()?.decrypt_and_hash(enc_s)?;
        let rs_array: [u8; 32] = rs_bytes
            .try_into()
            .map_err(|_| HidraError::Handshake("invalid static key length in C".into()))?;
        self.rs = Some(PublicKey::from(rs_array));
        off += DH_LEN + TAG_LEN;

        // se — responder: DH(e, rs)  |  initiator: DH(s, re)
        let se_dh = match self.role {
            Role::Responder => {
                let rs = self.rs.ok_or_else(|| {
                    HidraError::Handshake("missing remote static for se".into())
                })?;
                self.e
                    .as_ref()
                    .ok_or_else(|| {
                        HidraError::Handshake("missing local ephemeral for se".into())
                    })?
                    .diffie_hellman(&rs)
            }
            Role::Initiator => {
                let re = self.re.ok_or_else(|| {
                    HidraError::Handshake("missing remote ephemeral for se".into())
                })?;
                self.s.diffie_hellman(&re)
            }
        };
        self.sym()?.mix_key(se_dh.as_bytes());

        self.sym()?.decrypt_and_hash(&message[off..])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Split — derive transport ciphers
    // -----------------------------------------------------------------------
    pub fn into_transport(mut self) -> Result<(TransportCipher, TransportCipher)> {
        let symmetric = self
            .symmetric
            .take()
            .ok_or_else(|| HidraError::Handshake("state already consumed".into()))?;
        let role = self.role;
        let (c1, c2) = symmetric.split();
        match role {
            Role::Initiator => Ok((c1, c2)),
            Role::Responder => Ok((c2, c1)),
        }
    }

    pub fn remote_static_public(&self) -> Option<&PublicKey> {
        self.rs.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_xx_handshake_produces_matching_transport_keys() {
        let i_static = StaticSecret::random_from_rng(OsRng);
        let r_static = StaticSecret::random_from_rng(OsRng);

        let mut initiator = HandshakeState::new(Role::Initiator, i_static);
        let mut responder = HandshakeState::new(Role::Responder, r_static);

        let msg_a = initiator.write_message_a().unwrap();
        responder.read_message_a(&msg_a).unwrap();

        let msg_b = responder.write_message_b().unwrap();
        initiator.read_message_b(&msg_b).unwrap();

        let msg_c = initiator.write_message_c().unwrap();
        responder.read_message_c(&msg_c).unwrap();

        let (mut i_send, mut i_recv) = initiator.into_transport().unwrap();
        let (mut r_send, mut r_recv) = responder.into_transport().unwrap();

        // Initiator → Responder
        let ct = i_send.encrypt(b"hello from initiator").unwrap();
        let pt = r_recv.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello from initiator");

        // Responder → Initiator
        let ct = r_send.encrypt(b"hello from responder").unwrap();
        let pt = i_recv.decrypt(&ct).unwrap();
        assert_eq!(pt, b"hello from responder");
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let i_s = StaticSecret::random_from_rng(OsRng);
        let r_s = StaticSecret::random_from_rng(OsRng);

        let mut init = HandshakeState::new(Role::Initiator, i_s);
        let mut resp = HandshakeState::new(Role::Responder, r_s);

        let a = init.write_message_a().unwrap();
        resp.read_message_a(&a).unwrap();
        let b = resp.write_message_b().unwrap();
        init.read_message_b(&b).unwrap();
        let c = init.write_message_c().unwrap();
        resp.read_message_c(&c).unwrap();

        let (mut i_send, _) = init.into_transport().unwrap();
        let (_, mut r_recv) = resp.into_transport().unwrap();

        let mut ct = i_send.encrypt(b"secret").unwrap();
        ct[0] ^= 0xFF; // flip a byte
        assert!(r_recv.decrypt(&ct).is_err());
    }
}
