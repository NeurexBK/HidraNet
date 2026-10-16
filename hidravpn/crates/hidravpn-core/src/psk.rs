//! A WireGuard pre-shared key agreed through ML-KEM-1024, so the tunnel
//! survives a quantum computer.
//!
//! WireGuard's handshake is X25519. A recording of it, kept until a large
//! enough quantum computer exists, is opened then — every byte of every
//! session. WireGuard's own answer is the pre-shared key: 32 bytes mixed
//! into the handshake that the recording does not contain, so the session
//! keys stay out of reach for as long as the PSK does. What WireGuard does
//! not say is where the PSK comes from, and a PSK sent in the clear is no
//! PSK at all.
//!
//! Here it comes from ML-KEM-1024 (FIPS 203), run over the admission
//! exchange. The client makes a fresh KEM key pair and sends the public half
//! with its admission request; the node encapsulates to it and sends back
//! the ciphertext; both derive the PSK from the shared secret. An observer
//! of the exchange, quantum computer or not, learns the public key and the
//! ciphertext and nothing about the secret. An active attacker who swaps the
//! ciphertext only gives the client a PSK the node does not hold, and the
//! WireGuard handshake then fails — a denial of service, which the same
//! attacker could do by dropping packets, and not a compromise.
//!
//! For a client admitted by hand, the node draws a random PSK and puts it in
//! the invite. That invite now carries a secret and has to be handed over
//! privately — over SSH, which is itself post-quantum in current OpenSSH,
//! or in person — where before it carried nothing secret.
//!
//! The derivation binds the two WireGuard public keys, so a shared secret
//! from one admission cannot be worn by another pair of peers.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use ml_kem::ml_kem_1024::{Ciphertext, DecapsulationKey, EncapsulationKey};
use ml_kem::{Decapsulate, Encapsulate, Kem, KeyExport, MlKem1024, TryKeyInit};
use sha2::Sha256;
use zeroize::Zeroize;

const INFO: &[u8] = b"hidravpn-psk-v1";
/// ML-KEM-1024 encapsulation key and ciphertext, on the wire.
pub const KEM_PUBLIC_LEN: usize = 1568;
pub const KEM_CIPHERTEXT_LEN: usize = 1568;

/// The client's half of an agreement in progress: the decapsulation key it
/// keeps and the public key it sends.
pub struct Offer {
    dk: DecapsulationKey,
    /// Base64 of the encapsulation key, for the admission request.
    pub public_key: String,
}

impl Offer {
    pub fn new() -> Self {
        let (dk, ek) = MlKem1024::generate_keypair();
        let public_key = B64.encode(ek.to_bytes());
        Self { dk, public_key }
    }

    /// Turn the node's ciphertext into the PSK, base64 as WireGuard wants it.
    pub fn finish(
        self,
        ciphertext_b64: &str,
        node_public_key: &str,
        client_public_key: &str,
    ) -> Result<String> {
        let ct_bytes = B64
            .decode(ciphertext_b64.trim())
            .context("the node's KEM ciphertext is not base64")?;
        let ct = Ciphertext::try_from(ct_bytes.as_slice())
            .map_err(|_| anyhow!("the node's KEM ciphertext is not {KEM_CIPHERTEXT_LEN} bytes"))?;
        // Implicit rejection: a tampered ciphertext gives an unrelated
        // secret, never an error. The WireGuard handshake is what fails.
        let mut shared = self.dk.decapsulate(&ct);
        let psk = derive(&shared, node_public_key, client_public_key);
        shared.as_mut_slice().zeroize();
        Ok(encode(psk))
    }
}

impl Default for Offer {
    fn default() -> Self {
        Self::new()
    }
}

/// The node's half: from the client's public key, the ciphertext to send
/// back and the PSK to set on the peer.
pub fn answer(
    client_kem_public_b64: &str,
    node_public_key: &str,
    client_public_key: &str,
) -> Result<(String, String)> {
    let ek_bytes = B64
        .decode(client_kem_public_b64.trim())
        .context("kem_public_key is not base64")?;
    if ek_bytes.len() != KEM_PUBLIC_LEN {
        return Err(anyhow!("kem_public_key is not {KEM_PUBLIC_LEN} bytes"));
    }
    let ek = EncapsulationKey::new_from_slice(&ek_bytes)
        .map_err(|_| anyhow!("kem_public_key is not a valid ML-KEM-1024 key"))?;
    let (ct, mut shared) = ek.encapsulate();
    let psk = derive(&shared, node_public_key, client_public_key);
    shared.as_mut_slice().zeroize();
    Ok((B64.encode(ct), encode(psk)))
}

/// A PSK for a client admitted by hand, drawn at random.
pub fn random() -> Result<String> {
    let mut psk = [0u8; 32];
    getrandom::fill(&mut psk).map_err(|e| anyhow!("no randomness for a pre-shared key: {e}"))?;
    let out = encode(psk);
    psk.zeroize();
    Ok(out)
}

/// The 32 bytes WireGuard takes, from the base64 an invite or a lease holds.
pub fn decode(psk_b64: &str) -> Result<[u8; 32]> {
    let v = B64
        .decode(psk_b64.trim())
        .context("the pre-shared key is not base64")?;
    let arr: [u8; 32] = v
        .try_into()
        .map_err(|_| anyhow!("a pre-shared key is 32 bytes"))?;
    Ok(arr)
}

fn encode(mut psk: [u8; 32]) -> String {
    let s = B64.encode(psk);
    psk.zeroize();
    s
}

fn derive(shared: &[u8], node_public_key: &str, client_public_key: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut info = Vec::with_capacity(INFO.len() + 2 + 90);
    info.extend_from_slice(INFO);
    info.push(0);
    info.extend_from_slice(node_public_key.trim().as_bytes());
    info.push(0);
    info.extend_from_slice(client_public_key.trim().as_bytes());
    let mut psk = [0u8; 32];
    hk.expand(&info, &mut psk)
        .expect("32 bytes is within HKDF-SHA256's output length");
    psk
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "node-public-key";
    const CLIENT: &str = "client-public-key";

    #[test]
    fn both_sides_land_on_the_same_key() {
        let offer = Offer::new();
        assert_eq!(B64.decode(&offer.public_key).unwrap().len(), KEM_PUBLIC_LEN);
        let (ct, node_psk) = answer(&offer.public_key, NODE, CLIENT).unwrap();
        assert_eq!(B64.decode(&ct).unwrap().len(), KEM_CIPHERTEXT_LEN);
        let client_psk = offer.finish(&ct, NODE, CLIENT).unwrap();
        assert_eq!(node_psk, client_psk);
        assert_eq!(decode(&client_psk).unwrap().len(), 32);
    }

    /// The ciphertext on the wire is worth nothing without the key the
    /// client kept: another offer decapsulates it to a different PSK.
    #[test]
    fn the_ciphertext_alone_does_not_give_the_key() {
        let offer = Offer::new();
        let (ct, node_psk) = answer(&offer.public_key, NODE, CLIENT).unwrap();
        let other = Offer::new();
        assert_ne!(other.finish(&ct, NODE, CLIENT).unwrap(), node_psk);
    }

    /// A swapped ciphertext yields a key the node does not hold, so the
    /// WireGuard handshake fails rather than running on an attacker's key.
    #[test]
    fn a_tampered_ciphertext_diverges() {
        let offer = Offer::new();
        let (ct, node_psk) = answer(&offer.public_key, NODE, CLIENT).unwrap();
        let mut bytes = B64.decode(&ct).unwrap();
        bytes[10] ^= 1;
        let client_psk = offer.finish(&B64.encode(bytes), NODE, CLIENT).unwrap();
        assert_ne!(client_psk, node_psk);
    }

    #[test]
    fn the_key_is_bound_to_the_two_peers() {
        let offer = Offer::new();
        let (ct, node_psk) = answer(&offer.public_key, NODE, CLIENT).unwrap();
        assert_ne!(offer.finish(&ct, "another-node", CLIENT).unwrap(), node_psk);
    }

    #[test]
    fn two_agreements_differ_and_random_keys_differ() {
        let a = Offer::new();
        let b = Offer::new();
        let (_, pa) = answer(&a.public_key, NODE, CLIENT).unwrap();
        let (_, pb) = answer(&b.public_key, NODE, CLIENT).unwrap();
        assert_ne!(pa, pb);
        assert_ne!(random().unwrap(), random().unwrap());
    }

    #[test]
    fn malformed_input_is_refused_rather_than_panicked_on() {
        assert!(answer("not base64!", NODE, CLIENT).is_err());
        assert!(answer(&B64.encode([0u8; 10]), NODE, CLIENT).is_err());
        assert!(Offer::new().finish("not base64!", NODE, CLIENT).is_err());
        assert!(Offer::new()
            .finish(&B64.encode([0u8; 10]), NODE, CLIENT)
            .is_err());
        assert!(decode("short").is_err());
        assert!(decode(&B64.encode([0u8; 31])).is_err());
    }
}
