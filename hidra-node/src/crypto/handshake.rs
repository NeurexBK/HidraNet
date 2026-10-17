use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::hybrid_sig::{HybridSignature, HybridSigningKey, HybridVerifyingKey};
use crate::error::{HidraError, Result};

// Noise XX with hybrid forward secrecy: the X25519 exchange is joined by an
// ML-KEM-1024 encapsulation, and the session key depends on both.
//
// This matters for one attack and one only: an adversary who records traffic
// today and decrypts it when a cryptographically relevant quantum computer
// exists. X25519 falls to Shor's algorithm; ML-KEM does not, as far as anyone
// knows. Against a classical attacker the X25519 half is still what carries
// the weight, which is why both are here rather than ML-KEM alone — a lattice
// break would otherwise take the whole thing with it.
//
// Longer than HASHLEN, so it is hashed rather than padded, per the Noise spec.
const PROTOCOL_NAME: &[u8] = b"Noise_XXhfs_25519+MLKEM1024_ChaChaPoly_BLAKE3";
const DH_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// ML-KEM-1024 encapsulation key, as it goes on the wire.
const KEM_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext.
const KEM_CT_LEN: usize = 1568;

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
        // Noise: a protocol name longer than HASHLEN is hashed; one that fits
        // is zero-padded. Ours is longer, so it is hashed.
        let h = *blake3::hash(PROTOCOL_NAME).as_bytes();
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

/// X25519 with the low-order points refused.
///
/// A peer who sends one of the eight low-order points on Curve25519 forces
/// the shared secret to all zeroes, whatever our private key is. The Noise
/// spec leaves checking for that optional, because the transcript hash still
/// differs; here it is done anyway, since a secret an attacker chose is not a
/// secret, and nothing legitimate ever sends such a point.
fn dh(secret: &StaticSecret, public: &PublicKey) -> Result<SharedSecret> {
    let shared = secret.diffie_hellman(public);
    if !shared.was_contributory() {
        return Err(HidraError::Handshake(
            "peer sent a low-order X25519 point".into(),
        ));
    }
    Ok(shared)
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
    /// Initiator only: the decapsulation key for the ephemeral ML-KEM keypair
    /// offered in message A. Ephemeral per handshake and never stored, so a
    /// later compromise of this node cannot unlock a recorded session.
    e1: Option<DecapsulationKey>,
    /// Responder only: the initiator's encapsulation key, read from message A
    /// and used in message B.
    re1: Option<EncapsulationKey>,
    /// Initiator only: the payload of message B, when the responder sent one.
    /// A responder that proves its identity puts the proof here; an older
    /// one sends nothing, and the field stays empty.
    peer_identity_proof: Option<Vec<u8>>,
    /// Initiator only: the transcript hash the proof was made over — the
    /// state just before message B's payload was mixed in.
    proof_transcript: Option<[u8; 32]>,
}

/// Domain separator for the identity proof. The signature covers the
/// transcript hash, which already commits to both ephemerals, the ML-KEM
/// material and the responder's encrypted static key.
const IDENTITY_PROOF_DOMAIN: &[u8] = b"HidraNet-noise-identity-proof-v1";
const IDENTITY_PROOF_VERSION: u8 = 0x01;

impl HandshakeState {
    pub fn new(role: Role, static_secret: StaticSecret) -> Self {
        Self {
            symmetric: Some(SymmetricState::initialize()),
            s: static_secret,
            e: None,
            rs: None,
            re: None,
            role,
            e1: None,
            re1: None,
            peer_identity_proof: None,
            proof_transcript: None,
        }
    }

    fn sym(&mut self) -> Result<&mut SymmetricState> {
        self.symmetric
            .as_mut()
            .ok_or_else(|| HidraError::Handshake("state already consumed".into()))
    }

    // -----------------------------------------------------------------------
    // Message A: -> e, e1
    //
    // e1 is a fresh ML-KEM-1024 encapsulation key. It is sent in the clear —
    // there is no key yet — and hashed into the transcript, so message B
    // cannot be answered with a substituted one without breaking the tag.
    // -----------------------------------------------------------------------
    pub fn write_message_a(&mut self) -> Result<Vec<u8>> {
        let e = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e);
        self.e = Some(e);

        let (dk, ek) = MlKem1024::generate_keypair();
        let ek_bytes = ek.to_bytes();
        self.e1 = Some(dk);

        self.sym()?.mix_hash(e_pub.as_bytes());
        self.sym()?.mix_hash(&ek_bytes);

        let mut msg = Vec::with_capacity(DH_LEN + KEM_EK_LEN);
        msg.extend_from_slice(e_pub.as_bytes());
        msg.extend_from_slice(&ek_bytes);

        let payload_ct = self.sym()?.encrypt_and_hash(&[])?;
        msg.extend_from_slice(&payload_ct);
        Ok(msg)
    }

    pub fn read_message_a(&mut self, message: &[u8]) -> Result<()> {
        // No tag: at message A there is no key yet, so Noise's
        // EncryptWithAd returns the payload unchanged.
        let min = DH_LEN + KEM_EK_LEN;
        if message.len() < min {
            return Err(HidraError::Handshake(format!(
                "message A too short: {} < {min} — a peer still speaking the \
                 X25519-only handshake sends {DH_LEN} bytes here",
                message.len()
            )));
        }

        let mut off = 0;

        let re_bytes: [u8; 32] = message[off..off + DH_LEN]
            .try_into()
            .map_err(|_| HidraError::Handshake("invalid ephemeral key in A".into()))?;
        self.re = Some(PublicKey::from(re_bytes));
        self.sym()?.mix_hash(&re_bytes);
        off += DH_LEN;

        let ek_bytes = &message[off..off + KEM_EK_LEN];
        // Rejects a malformed or non-canonical key rather than encapsulating
        // to it in message B.
        self.re1 = Some(EncapsulationKey::new_from_slice(ek_bytes).map_err(|_| {
            HidraError::Handshake("ML-KEM encapsulation key rejected in A".into())
        })?);
        self.sym()?.mix_hash(ek_bytes);
        off += KEM_EK_LEN;

        self.sym()?.decrypt_and_hash(&message[off..])?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Message B: <- e, ee, ekem1, s, es
    //
    // ekem1 goes in right after ee and before s, which is the point of putting
    // it here at all: by the time the responder's static key is encrypted, the
    // chaining key already depends on the ML-KEM secret. An adversary holding
    // a recording and a quantum computer breaks the X25519 halves and still
    // cannot read the static key, let alone the transport.
    // -----------------------------------------------------------------------
    pub fn write_message_b(&mut self) -> Result<Vec<u8>> {
        self.write_message_b_with(|_| Ok(Vec::new()))
    }

    /// Message B carrying a proof of who the responder is.
    ///
    /// Noise XX authenticates the responder's X25519 static key, and that is
    /// a key a quantum computer recovers from its public half. The proof is
    /// a hybrid signature (Ed25519 and ML-DSA-87, both required) over the
    /// transcript hash, which commits to that static key and to everything
    /// exchanged so far. An initiator that holds the responder's identity
    /// checks it with [`verify_remote_identity`](Self::verify_remote_identity).
    ///
    /// It rides in the payload Noise reserves for exactly this, which until
    /// now went empty. An initiator from before this decrypts the payload
    /// and ignores it, as Noise says to, so the two keep talking.
    pub fn write_message_b_proving(&mut self, identity: &HybridSigningKey) -> Result<Vec<u8>> {
        self.write_message_b_with(|h| identity_proof(identity, h))
    }

    fn write_message_b_with(
        &mut self,
        payload: impl FnOnce(&[u8; 32]) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        // e — generate ephemeral
        let e = StaticSecret::random_from_rng(OsRng);
        let e_pub = PublicKey::from(&e);
        self.e = Some(e);

        self.sym()?.mix_hash(e_pub.as_bytes());

        let mut msg = Vec::with_capacity(
            DH_LEN + KEM_CT_LEN + TAG_LEN + DH_LEN + TAG_LEN + TAG_LEN,
        );
        msg.extend_from_slice(e_pub.as_bytes());

        // ee — DH(local_e, remote_e)
        let re = self
            .re
            .ok_or_else(|| HidraError::Handshake("missing remote ephemeral for ee".into()))?;
        let ee = self
            .e
            .as_ref()
            .ok_or_else(|| HidraError::Handshake("missing local ephemeral for ee".into()))?;
        let ee = dh(ee, &re)?;
        self.sym()?.mix_key(ee.as_bytes());

        // ekem1 — encapsulate to the initiator's ML-KEM key and mix the secret
        let re1 = self
            .re1
            .as_ref()
            .ok_or_else(|| HidraError::Handshake("missing remote ML-KEM key for ekem1".into()))?;
        let (kem_ct, mut kem_ss) = re1.encapsulate();
        let enc_ct = self.sym()?.encrypt_and_hash(&kem_ct)?;
        msg.extend_from_slice(&enc_ct);
        self.sym()?.mix_key(&kem_ss);
        kem_ss.as_mut_slice().zeroize();

        // s — encrypt & send static public key
        let s_pub = PublicKey::from(&self.s);
        let enc_s = self.sym()?.encrypt_and_hash(s_pub.as_bytes())?;
        msg.extend_from_slice(&enc_s);

        // es — responder: DH(s, re)  |  initiator: DH(e, rs)
        let es_dh = match self.role {
            Role::Responder => dh(&self.s, &re)?,
            Role::Initiator => {
                let rs = self.rs.ok_or_else(|| {
                    HidraError::Handshake("missing remote static for es".into())
                })?;
                let e = self.e.as_ref().ok_or_else(|| {
                    HidraError::Handshake("missing local ephemeral for es".into())
                })?;
                dh(e, &rs)?
            }
        };
        self.sym()?.mix_key(es_dh.as_bytes());

        let h = self.sym()?.h;
        let payload = payload(&h)?;
        let payload_ct = self.sym()?.encrypt_and_hash(&payload)?;
        msg.extend_from_slice(&payload_ct);
        Ok(msg)
    }

    pub fn read_message_b(&mut self, message: &[u8]) -> Result<()> {
        let min = DH_LEN + KEM_CT_LEN + TAG_LEN + DH_LEN + TAG_LEN + TAG_LEN;
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
            .ok_or_else(|| HidraError::Handshake("missing local ephemeral for ee".into()))?;
        let ee = dh(ee, &re)?;
        self.sym()?.mix_key(ee.as_bytes());

        // ekem1 — decapsulate and mix the same secret in
        let enc_ct = &message[off..off + KEM_CT_LEN + TAG_LEN];
        let ct_bytes = self.sym()?.decrypt_and_hash(enc_ct)?;
        let kem_ct = Ciphertext::try_from(ct_bytes.as_slice())
            .map_err(|_| HidraError::Handshake("ML-KEM ciphertext has the wrong length".into()))?;
        let e1 = self
            .e1
            .as_ref()
            .ok_or_else(|| HidraError::Handshake("missing local ML-KEM key for ekem1".into()))?;
        // ML-KEM answers a tampered ciphertext with an unrelated key rather
        // than an error — implicit rejection. The mismatch surfaces at the
        // next tag, which is the whole point: there is no oracle here.
        let mut kem_ss = e1.decapsulate(&kem_ct);
        self.sym()?.mix_key(&kem_ss);
        kem_ss.as_mut_slice().zeroize();
        off += KEM_CT_LEN + TAG_LEN;

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
                let e = self.e.as_ref().ok_or_else(|| {
                    HidraError::Handshake("missing local ephemeral for es".into())
                })?;
                dh(e, &rs)?
            }
            Role::Responder => dh(&self.s, &re)?,
        };
        self.sym()?.mix_key(es_dh.as_bytes());

        // The payload, kept rather than dropped: a responder that proves
        // its identity puts the proof here. Its transcript is the hash
        // before the payload itself is mixed in, which is what was signed.
        let h = self.sym()?.h;
        let payload = self.sym()?.decrypt_and_hash(&message[off..])?;
        if !payload.is_empty() {
            self.peer_identity_proof = Some(payload);
            self.proof_transcript = Some(h);
        }
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
                dh(&self.s, &re)?
            }
            Role::Responder => {
                let rs = self.rs.ok_or_else(|| {
                    HidraError::Handshake("missing remote static for se".into())
                })?;
                let e = self.e.as_ref().ok_or_else(|| {
                    HidraError::Handshake("missing local ephemeral for se".into())
                })?;
                dh(e, &rs)?
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
                let e = self.e.as_ref().ok_or_else(|| {
                    HidraError::Handshake("missing local ephemeral for se".into())
                })?;
                dh(e, &rs)?
            }
            Role::Initiator => {
                let re = self.re.ok_or_else(|| {
                    HidraError::Handshake("missing remote ephemeral for se".into())
                })?;
                dh(&self.s, &re)?
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

    /// The peer's static public key, once the handshake has learned it.
    ///
    /// The binary goes through [`verify_remote_static`](Self::verify_remote_static)
    /// and never reads the key itself, hence the allow: the module is shared
    /// with the library, and the binary denies warnings.
    #[allow(dead_code)]
    pub fn remote_static_public(&self) -> Option<&PublicKey> {
        self.rs.as_ref()
    }

    /// Check that the peer is who we meant to talk to.
    ///
    /// Noise XX authenticates the static key it carries: after message B the
    /// initiator knows, for certain, which key the responder holds. What it
    /// does not know is whether that key belongs to the relay it wanted, and
    /// without this check anyone sitting between the client and the relay
    /// could answer the handshake with their own key and be accepted. The
    /// expected key is the base64 of the relay's `noise_static.public`, as
    /// listed in the config or, later, in its signed DHT descriptor.
    ///
    /// Comparison is constant-time: a mismatch is reported, never where it
    /// mismatched.
    pub fn verify_remote_static(&self, expected_b64: &str) -> Result<()> {
        let rs = self.rs.ok_or_else(|| {
            HidraError::Handshake(
                "remote static key is not known yet; verify after message B or C".into(),
            )
        })?;
        let expected = BASE64.decode(expected_b64.trim()).map_err(|_| {
            HidraError::Handshake("expected static key is not valid base64".into())
        })?;
        if expected.len() != DH_LEN {
            return Err(HidraError::Handshake(format!(
                "expected static key has {} bytes, not {DH_LEN}",
                expected.len()
            )));
        }
        if rs.as_bytes().ct_eq(&expected).into() {
            Ok(())
        } else {
            Err(HidraError::Handshake(
                "relay static key does not match the pinned key; refusing — \
                 this is what an interception looks like"
                    .into(),
            ))
        }
    }
}

impl HandshakeState {
    /// Whether the responder sent an identity proof in message B.
    pub fn remote_identity_proof_offered(&self) -> bool {
        self.peer_identity_proof.is_some()
    }

    /// Check the responder's identity proof against the identity expected.
    ///
    /// Refuses when no proof was sent: a caller that holds an expected
    /// identity is saying this peer must prove it, and an older responder
    /// cannot. Refuses on either half failing, without saying which.
    pub fn verify_remote_identity(&self, expected: &HybridVerifyingKey) -> Result<()> {
        let (proof, h) = match (&self.peer_identity_proof, &self.proof_transcript) {
            (Some(p), Some(h)) => (p, h),
            _ => {
                return Err(HidraError::Handshake(
                    "relay did not prove its identity; an identity is pinned for it, \
                     so this is either an older relay or an impostor"
                        .into(),
                ))
            }
        };
        let signature = parse_identity_proof(proof)?;
        expected
            .verify(&identity_proof_message(h), &signature)
            .map_err(|_| {
                HidraError::Handshake(
                    "relay identity proof does not match the pinned identity; refusing".into(),
                )
            })
    }
}

fn identity_proof_message(h: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(IDENTITY_PROOF_DOMAIN.len() + 32);
    m.extend_from_slice(IDENTITY_PROOF_DOMAIN);
    m.extend_from_slice(h);
    m
}

/// `version ‖ Ed25519 signature ‖ ML-DSA-87 signature`.
fn identity_proof(identity: &HybridSigningKey, h: &[u8; 32]) -> Result<Vec<u8>> {
    let sig = identity.sign(&identity_proof_message(h))?;
    let mut out = Vec::with_capacity(1 + sig.ed25519.len() + sig.mldsa.len());
    out.push(IDENTITY_PROOF_VERSION);
    out.extend_from_slice(&sig.ed25519);
    out.extend_from_slice(&sig.mldsa);
    Ok(out)
}

fn parse_identity_proof(proof: &[u8]) -> Result<HybridSignature> {
    match proof.first() {
        Some(&IDENTITY_PROOF_VERSION) => HybridSignature::from_bytes(&proof[1..]),
        Some(other) => Err(HidraError::Handshake(format!(
            "unknown identity proof version {other}"
        ))),
        None => Err(HidraError::Handshake("empty identity proof".into())),
    }
}

/// The key the onion layers use between a client and one relay.
///
/// The layers used to encrypt under the transport key itself — the same 32
/// bytes that the Noise transport uses with a counter nonce, reused with a
/// random nonce. Nothing was known to break, but one key in two AEAD uses is
/// the kind of thing that stops being fine the day one of the uses changes,
/// and an auditor is right to flag it. This derives a separate key.
///
/// A client uses it when the relay proved its identity in message B, which
/// is exactly when the relay is new enough to expect it; against an older
/// relay the client keeps the transport key, and a new relay still accepts
/// an older client by trying the transport key when the derived one does
/// not open the first cell. So the split lands without anyone being cut off.
pub fn onion_layer_key(transport_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("HidraNet onion layer key v1", transport_key)
}

/// Hold the relay to its post-quantum identity when one is pinned.
///
/// With nothing pinned there is nothing to compare against, so a proof the
/// relay offered is noted and the hop is otherwise treated as before. With
/// an identity pinned, the relay must prove it, both halves.
pub fn check_relay_pq_identity(handshake: &HandshakeState, expected_b64: &str) -> Result<()> {
    if expected_b64.trim().is_empty() {
        if handshake.remote_identity_proof_offered() {
            tracing::debug!(
                "relay offered a post-quantum identity proof, but none is pinned to check it \
                 against; set identity_pubkey in the relay's config entry"
            );
        }
        return Ok(());
    }
    let bytes = BASE64.decode(expected_b64.trim()).map_err(|_| {
        HidraError::Handshake("expected relay identity is not valid base64".into())
    })?;
    let expected = HybridVerifyingKey::from_bytes(&bytes)?;
    handshake.verify_remote_identity(&expected)
}

/// Pin the relay's key when one is known, and say so when it is not.
///
/// An empty expectation is the state every relay found through the DHT is in
/// today: the descriptor does not carry the Noise key yet, so the only
/// honest thing to do is connect and record that the hop is unverified. It
/// is said once per process at `warn` and afterwards at `debug`, so a proxy
/// building circuits all day does not fill the log with the same line.
pub fn check_relay_identity(handshake: &HandshakeState, expected_b64: &str) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SAID_ONCE: AtomicBool = AtomicBool::new(false);

    if expected_b64.trim().is_empty() {
        if !SAID_ONCE.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "relay static key is not pinned: the handshake is encrypted and \
                 authenticated, but nothing proves the far end is the relay that \
                 was meant. Set noise_pubkey in the relay's config entry to pin it."
            );
        } else {
            tracing::debug!("relay static key is not pinned");
        }
        return Ok(());
    }
    handshake.verify_remote_static(expected_b64)
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

    /// Runs the three messages and hands back the two states.
    fn complete() -> (HandshakeState, HandshakeState) {
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        let a = init.write_message_a().unwrap();
        resp.read_message_a(&a).unwrap();
        let b = resp.write_message_b().unwrap();
        init.read_message_b(&b).unwrap();
        let c = init.write_message_c().unwrap();
        resp.read_message_c(&c).unwrap();
        (init, resp)
    }

    /// The ML-KEM material is actually on the wire, not merely compiled in.
    ///
    /// This is the test that would have caught the state this code was in
    /// before: a post_quantum module that existed, compiled, passed its own
    /// tests, and was never reached by a single handshake.
    #[test]
    fn the_handshake_carries_ml_kem_material() {
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));

        let a = init.write_message_a().unwrap();
        assert_eq!(a.len(), DH_LEN + KEM_EK_LEN, "message A must carry an encapsulation key");

        resp.read_message_a(&a).unwrap();
        let b = resp.write_message_b().unwrap();
        assert_eq!(
            b.len(),
            DH_LEN + KEM_CT_LEN + TAG_LEN + DH_LEN + TAG_LEN + TAG_LEN,
            "message B must carry an ML-KEM ciphertext"
        );
    }

    /// Swapping the encapsulation key in flight breaks the handshake.
    ///
    /// Without this the key would be decoration: an attacker could replace it
    /// with one they hold the decapsulation key for and learn the secret that
    /// was supposed to be out of their reach.
    #[test]
    fn a_substituted_encapsulation_key_breaks_the_handshake() {
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));

        let mut a = init.write_message_a().unwrap();
        // The attacker's own key, in place of the initiator's.
        let (_, their_ek) = MlKem1024::generate_keypair();
        a[DH_LEN..DH_LEN + KEM_EK_LEN].copy_from_slice(&their_ek.to_bytes());

        resp.read_message_a(&a).unwrap(); // the responder cannot tell yet
        let b = resp.write_message_b().unwrap();
        // The initiator decapsulates with a key that does not match, so the
        // chaining keys diverge and the static key will not decrypt.
        assert!(
            init.read_message_b(&b).is_err(),
            "a swapped ML-KEM key must not produce a working session"
        );
    }

    /// Tampering with the ciphertext breaks it too, by implicit rejection:
    /// ML-KEM returns an unrelated key rather than an error, the chaining keys
    /// diverge, and the next tag fails. That is what denies an attacker the
    /// oracle a chosen-ciphertext attack needs.
    #[test]
    fn a_tampered_ml_kem_ciphertext_breaks_the_handshake() {
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));

        let a = init.write_message_a().unwrap();
        resp.read_message_a(&a).unwrap();
        let mut b = resp.write_message_b().unwrap();
        b[DH_LEN + 4] ^= 0x01;

        assert!(init.read_message_b(&b).is_err());
    }

    /// A peer still speaking the X25519-only handshake is refused outright
    /// rather than negotiated down to it. There is no downgrade path: the
    /// protocol name is hashed into the transcript, so the two cannot agree
    /// on a key even if the lengths happened to line up.
    #[test]
    fn an_x25519_only_peer_is_refused() {
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        let old_style_message_a = vec![0u8; DH_LEN];
        let err = resp.read_message_a(&old_style_message_a).unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    /// A low-order ephemeral point is refused rather than folded into a key
    /// the attacker already knows.
    #[test]
    fn a_low_order_ephemeral_point_is_refused() {
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));

        let mut a = init.write_message_a().unwrap();
        // The identity point: DH with it is all zeroes for every private key.
        a[..DH_LEN].copy_from_slice(&[0u8; DH_LEN]);
        resp.read_message_a(&a).unwrap();
        let err = resp.write_message_b().unwrap_err();
        assert!(format!("{err}").contains("low-order"), "{err}");
    }

    /// The initiator can pin the responder's static key, and a different key
    /// is refused even though the handshake itself succeeded.
    #[test]
    fn the_remote_static_key_can_be_pinned() {
        let r_static = StaticSecret::random_from_rng(OsRng);
        let r_public = PublicKey::from(&r_static);
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, r_static);

        // Before message B the key is unknown, and saying so is an error.
        assert!(init.verify_remote_static(&BASE64.encode([1u8; 32])).is_err());

        let a = init.write_message_a().unwrap();
        resp.read_message_a(&a).unwrap();
        let b = resp.write_message_b().unwrap();
        init.read_message_b(&b).unwrap();

        assert_eq!(init.remote_static_public(), Some(&r_public));
        init.verify_remote_static(&BASE64.encode(r_public.as_bytes())).unwrap();
        check_relay_identity(&init, &BASE64.encode(r_public.as_bytes())).unwrap();

        let other = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        assert!(init.verify_remote_static(&BASE64.encode(other.as_bytes())).is_err());
        assert!(check_relay_identity(&init, &BASE64.encode(other.as_bytes())).is_err());
        assert!(init.verify_remote_static("not base64!").is_err());
        assert!(init.verify_remote_static(&BASE64.encode([1u8; 16])).is_err());
    }

    fn run(init: &mut HandshakeState, resp: &mut HandshakeState, identity: Option<&HybridSigningKey>) {
        let a = init.write_message_a().unwrap();
        resp.read_message_a(&a).unwrap();
        let b = match identity {
            Some(id) => resp.write_message_b_proving(id).unwrap(),
            None => resp.write_message_b().unwrap(),
        };
        init.read_message_b(&b).unwrap();
        let c = init.write_message_c().unwrap();
        resp.read_message_c(&c).unwrap();
    }

    /// The responder proves its hybrid identity; the initiator checks it,
    /// and a different identity is refused even though the Noise handshake
    /// itself succeeded.
    #[test]
    fn the_responder_can_prove_a_post_quantum_identity() {
        let identity = HybridSigningKey::generate();
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        run(&mut init, &mut resp, Some(&identity));

        assert!(init.remote_identity_proof_offered());
        init.verify_remote_identity(&identity.verifying_key()).unwrap();
        let pinned = BASE64.encode(identity.verifying_key().to_bytes());
        check_relay_pq_identity(&init, &pinned).unwrap();

        let other = HybridSigningKey::generate();
        assert!(init.verify_remote_identity(&other.verifying_key()).is_err());
        assert!(check_relay_pq_identity(&init, &BASE64.encode(other.verifying_key().to_bytes())).is_err());

        // The session keys are unaffected by the proof: both sides agree.
        let (i_send, _) = init.into_transport().unwrap();
        let (_, r_recv) = resp.into_transport().unwrap();
        assert_eq!(i_send.session_key().unwrap(), r_recv.session_key().unwrap());
    }

    /// An older responder sends no proof. With nothing pinned that is fine;
    /// with an identity pinned it is refused, because the pin says this
    /// relay must prove itself.
    #[test]
    fn an_unproven_responder_passes_only_when_nothing_is_pinned() {
        let mut init = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        run(&mut init, &mut resp, None);
        assert!(!init.remote_identity_proof_offered());
        check_relay_pq_identity(&init, "").unwrap();
        let pinned = BASE64.encode(HybridSigningKey::generate().verifying_key().to_bytes());
        assert!(check_relay_pq_identity(&init, &pinned).is_err());
    }

    /// A proof that is not for this transcript is refused: the signature
    /// from one handshake cannot be replayed into another.
    #[test]
    fn a_proof_from_another_handshake_is_refused() {
        let identity = HybridSigningKey::generate();
        let mut init1 = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp1 = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        run(&mut init1, &mut resp1, Some(&identity));
        let stolen = init1.peer_identity_proof.clone().unwrap();

        let mut init2 = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp2 = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        run(&mut init2, &mut resp2, Some(&identity));
        init2.peer_identity_proof = Some(stolen);
        assert!(init2.verify_remote_identity(&identity.verifying_key()).is_err());

        // And a mangled proof is refused, never panicked on.
        let mut init3 = HandshakeState::new(Role::Initiator, StaticSecret::random_from_rng(OsRng));
        let mut resp3 = HandshakeState::new(Role::Responder, StaticSecret::random_from_rng(OsRng));
        run(&mut init3, &mut resp3, Some(&identity));
        for bad in [vec![], vec![0x09], vec![0x01, 0, 0], vec![0x01; 5000]] {
            init3.peer_identity_proof = Some(bad);
            assert!(init3.verify_remote_identity(&identity.verifying_key()).is_err());
        }
    }

    /// No pinned key means connect and warn, not refuse: refusing would take
    /// every DHT-discovered relay offline until the descriptor carries a key.
    #[test]
    fn an_unpinned_relay_is_allowed_through() {
        let (init, _) = complete();
        check_relay_identity(&init, "").unwrap();
        check_relay_identity(&init, "   ").unwrap();
    }

    /// Two handshakes never land on the same key.
    #[test]
    fn distinct_handshakes_produce_distinct_keys() {
        let (a_init, _) = complete();
        let (b_init, _) = complete();
        let (a_send, _) = a_init.into_transport().unwrap();
        let (b_send, _) = b_init.into_transport().unwrap();
        assert_ne!(a_send.session_key().unwrap(), b_send.session_key().unwrap());
    }

    /// Both sides agree on the same session key through the hybrid exchange.
    #[test]
    fn both_sides_agree_on_the_hybrid_session_key() {
        let (init, resp) = complete();
        let (i_send, _) = init.into_transport().unwrap();
        let (_, r_recv) = resp.into_transport().unwrap();
        assert_eq!(i_send.session_key().unwrap(), r_recv.session_key().unwrap());
    }
}
