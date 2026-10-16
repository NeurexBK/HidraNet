//! The post-quantum claims, checked against the code rather than the docs.
//!
//! Three things are claimed. The handshake between nodes is hybrid (X25519
//! and ML-KEM-1024); `hybrid_on_the_wire` already proves that one. A mail
//! body is sealed under both as well, so a mailbox copied today does not
//! open the day the curve falls. And an envelope is signed with Ed25519 and
//! ML-DSA-87, both required. This file holds the second and third to
//! account, and then reads the source for the mistake that would quietly
//! undo any of them: a new X25519 exchange, somewhere else, with no KEM
//! beside it.

use std::fs;
use std::path::{Path, PathBuf};

use hidra_node::apps::hidramail::crypto::{MailKeys, seal_message, seal_message_v2};
use hidra_node::apps::hidramail::protocol::MailEnvelope;
use hidra_node::apps::hidramail::server::envelope_pq_verified;
use hidra_node::crypto::hybrid_sig::{HybridSigningKey, MLDSA_SIGNATURE_LEN};

const KEM_CT_LEN: usize = 1568;

fn temp_keys() -> (PathBuf, MailKeys) {
    let dir = std::env::temp_dir().join(format!("hidra_pq_claims_{}", uuid::Uuid::new_v4()));
    let keys = MailKeys::load_or_generate(&dir).unwrap();
    (dir, keys)
}

/// A mail body sealed the new way carries an ML-KEM ciphertext, and opening
/// it needs the recipient's KEM key as well as the X25519 one.
#[test]
fn a_mail_body_is_sealed_under_x25519_and_ml_kem() {
    let (dir, keys) = temp_keys();
    let body = b"the body of a message";

    let (eph, sealed) = seal_message_v2(&keys.public_bytes, &keys.kem_public_bytes, body).unwrap();
    assert!(sealed.starts_with(b"HM2"), "a hybrid body is marked as one");
    assert!(
        sealed.len() >= 3 + KEM_CT_LEN + 12 + 16 + body.len(),
        "the body must carry a whole ML-KEM-1024 ciphertext"
    );
    assert_eq!(keys.open(&eph, &sealed).unwrap(), body);

    // Another mailbox, with a different KEM key, cannot open it even if it
    // somehow held the X25519 secret: both halves go into the key.
    let (other_dir, other) = temp_keys();
    assert!(other.open(&eph, &sealed).is_err());

    fs::remove_dir_all(dir).ok();
    fs::remove_dir_all(other_dir).ok();
}

/// Tampering with the KEM ciphertext is refused. ML-KEM answers a tampered
/// ciphertext with an unrelated key rather than an error (implicit
/// rejection); the AEAD tag is what says no, and it must.
#[test]
fn a_tampered_kem_ciphertext_does_not_open() {
    let (dir, keys) = temp_keys();
    let (eph, mut sealed) =
        seal_message_v2(&keys.public_bytes, &keys.kem_public_bytes, b"body").unwrap();
    sealed[3 + 7] ^= 0x01;
    assert!(keys.open(&eph, &sealed).is_err());

    // Nor does relabelling a hybrid body as a legacy one get anywhere.
    let (eph, mut sealed) =
        seal_message_v2(&keys.public_bytes, &keys.kem_public_bytes, b"body").unwrap();
    sealed[0] = b'X';
    assert!(keys.open(&eph, &sealed).is_err());
    fs::remove_dir_all(dir).ok();
}

/// Mail from a sender that predates the hybrid seal still opens. Refusing
/// it would lose mail; what changes is that the mailbox can tell.
#[test]
fn a_legacy_body_still_opens() {
    let (dir, keys) = temp_keys();
    let (eph, sealed) = seal_message(&keys.public_bytes, b"old style").unwrap();
    assert!(!sealed.starts_with(b"HM2"));
    assert_eq!(keys.open(&eph, &sealed).unwrap(), b"old style");
    fs::remove_dir_all(dir).ok();
}

/// The mailbox's keys survive a restart: the same KEM key comes back, so
/// mail sealed to it yesterday opens today.
#[test]
fn the_mailbox_kem_key_is_stable_across_reloads() {
    let (dir, keys) = temp_keys();
    let again = MailKeys::load_or_generate(&dir).unwrap();
    assert_eq!(keys.kem_public_bytes, again.kem_public_bytes);
    assert_eq!(keys.public_bytes, again.public_bytes);
    let (eph, sealed) =
        seal_message_v2(&keys.public_bytes, &keys.kem_public_bytes, b"persisted").unwrap();
    assert_eq!(again.open(&eph, &sealed).unwrap(), b"persisted");
    fs::remove_dir_all(dir).ok();
}

fn envelope() -> MailEnvelope {
    MailEnvelope {
        id: "id".into(),
        from_addr: "a@example.hidra".into(),
        to_addr: "b@example.hidra".into(),
        timestamp: 1,
        ephemeral_pubkey: vec![1; 32],
        sealed_body: vec![2; 64],
        sender_verifying_key: Vec::new(),
        signature: Vec::new(),
        sender_pq_verifying_key: Vec::new(),
        pq_signature: Vec::new(),
    }
}

/// An envelope signed with both halves verifies; one with the ML-DSA half
/// missing, or either half wrong, is not post-quantum verified.
#[test]
fn an_envelope_needs_both_signature_halves() {
    let key = HybridSigningKey::generate();
    let vk = key.verifying_key().to_bytes();
    let mut env = envelope();
    env.sender_verifying_key = vk[..32].to_vec();
    env.sender_pq_verifying_key = vk[32..].to_vec();
    let sig = key.sign(&env.signing_data()).unwrap();
    env.signature = sig.ed25519;
    env.pq_signature = sig.mldsa;
    assert_eq!(env.pq_signature.len(), MLDSA_SIGNATURE_LEN);
    assert!(envelope_pq_verified(&env));

    let mut legacy = env.clone();
    legacy.pq_signature.clear();
    legacy.sender_pq_verifying_key.clear();
    assert!(
        !envelope_pq_verified(&legacy),
        "Ed25519 alone is not post-quantum"
    );

    let mut bad_pq = env.clone();
    bad_pq.pq_signature[50] ^= 1;
    assert!(!envelope_pq_verified(&bad_pq));

    let mut bad_ed = env.clone();
    bad_ed.signature[5] ^= 1;
    assert!(!envelope_pq_verified(&bad_ed));

    let mut other_key = env.clone();
    other_key.sender_pq_verifying_key =
        HybridSigningKey::generate().verifying_key().to_bytes()[32..].to_vec();
    assert!(!envelope_pq_verified(&other_key));
}

/// The files that may do an X25519 exchange, because each pairs it with
/// ML-KEM. A `diffie_hellman(` anywhere else is a key exchange that a
/// recording and a quantum computer will open, and this test is the review
/// comment that says so before it ships.
const MAY_USE_X25519: &[&str] = &[
    // The hybrid handshake; every DH feeds a chaining key that already holds
    // the ML-KEM secret.
    "src/crypto/handshake.rs",
    // The hybrid mail seal (and the legacy opener, kept to read old mail).
    "src/apps/hidramail.rs",
    // A second hybrid KEM, not used by the binary; kept for its tests.
    "src/security/mod.rs",
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_x25519_exchange_exists_without_ml_kem_beside_it() {
    let mut files = Vec::new();
    rust_sources(Path::new("src"), &mut files);
    assert!(!files.is_empty());

    let mut offences = Vec::new();
    for path in &files {
        let shown = path.display().to_string().replace('\\', "/");
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let uses_dh = text.contains(".diffie_hellman(");
        if !uses_dh {
            continue;
        }
        let allowed = MAY_USE_X25519.iter().any(|ok| shown.ends_with(ok));
        if !allowed {
            offences.push(format!("{shown}: X25519 exchange with no ML-KEM beside it"));
            continue;
        }
        // The allowlisted files earn their place by actually using ML-KEM.
        if !text.contains("ml_kem") {
            offences.push(format!(
                "{shown}: allowlisted for X25519 but no longer uses ML-KEM"
            ));
        }
    }
    assert!(
        offences.is_empty(),
        "a key exchange that is not hybrid would be opened by a recording and a \
         quantum computer. Pair it with ML-KEM-1024, as the handshake and the mail \
         seal do:\n\n{}\n",
        offences.join("\n")
    );
}

/// The mail server seals to a recipient the hybrid way whenever it can.
/// A refactor that went back to the legacy call for every recipient would
/// pass every other test here; this one reads the send path.
#[test]
fn the_mail_send_path_prefers_the_hybrid_seal() {
    let text = fs::read_to_string("src/apps/hidramail.rs").unwrap();
    let send = text
        .split("async fn api_send_mail")
        .nth(1)
        .expect("the send handler exists");
    assert!(
        send.contains("seal_message_v2("),
        "the send path must seal under X25519 and ML-KEM when the recipient has a KEM key"
    );
}
