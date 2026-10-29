//! Sealed requests: how a client knows it is talking to the service.
//!
//! On Windows the control channel is a named pipe, and a pipe's name is not
//! proof of who serves it: a signed-in user can make `\\.\pipe\hidravpn`
//! while the service is stopped, or add an instance of it beside the
//! service's own. Whatever answers would then read the client's request,
//! token and all, and say whatever it liked about the tunnel.
//!
//! So the service makes a fresh X25519 key every time it starts, keeps the
//! private half in memory only, and writes the public half where only it
//! (root, SYSTEM, administrators) can write and those who may drive it can
//! read: beside the control token. A client seals its request to that key:
//! a key of its own for this one request, a shared secret from the two, and
//! the request encrypted and authenticated (AES-256-GCM) under a key derived
//! from it. Only the service can open it, and only the service can seal the
//! answer under the matching answer key; a client believes an answer only
//! when it opens. Something else on the pipe sees nothing it can read,
//! cannot answer in the service's place, and cannot pass the request on to
//! the real service and read either half on the way (it never holds either
//! key). Nothing in the browser needs native code for this: Node's crypto
//! has every piece.
//!
//! On the wire, each a single line of JSON as before:
//!
//! ```text
//! {"seal":"x25519-aes256gcm","from":"<the client's public key>","data":"<request>"}
//! {"seal":"x25519-aes256gcm","nonce":"<12 bytes>","data":"<answer>"}
//! ```
//!
//! base64, and the request and answer inside are the plain lines a client
//! that does not seal sends and gets (older clients; the scripts). Sealing is
//! the client's choice; the service reads both.
//!
//! The request key seals one request only (the client's key is new each
//! time), so the request's nonce is fixed. The answer's is not: a request
//! passed on to the service twice would have it seal two answers under the
//! same answer key, and the same nonce twice under one key would let
//! whoever saw both make a third that opens. So each answer has a random
//! nonce of its own, sent with it.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// The scheme, named in every sealed line.
pub const SCHEME: &str = "x25519-aes256gcm";
/// What the two keys are derived for: nothing else derives the same ones.
const INFO: &[u8] = b"hidravpn control channel v1";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The service's key: made at start, never written down.
pub struct ServiceKey {
    secret: StaticSecret,
    public: PublicKey,
}

impl ServiceKey {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness: {e}"))?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// The public half as the key file holds it.
    pub fn public_base64(&self) -> String {
        b64().encode(self.public.as_bytes())
    }

    /// Opens a sealed request: its plain line, and what seals the answer.
    pub fn open(&self, sealed: &SealedRequest) -> Result<(Vec<u8>, AnswerSealer)> {
        if sealed.seal != SCHEME {
            anyhow::bail!("a request sealed another way ({})", sealed.seal);
        }
        let from = public_from_base64(&sealed.from).context("the request's key")?;
        let shared = self.secret.diffie_hellman(&from);
        if !shared.was_contributory() {
            anyhow::bail!("a request sealed to no key at all");
        }
        let (request_key, answer_key) = derive(shared.as_bytes(), &from, &self.public);
        let mut data = b64()
            .decode(sealed.data.as_bytes())
            .map_err(|_| anyhow!("the request is not base64"))?;
        let plain = request_key
            .open_in_place(once(), Aad::empty(), &mut data)
            .map_err(|_| {
                anyhow!("the request was not sealed to this service's key (sealed before the service restarted?)")
            })?
            .to_vec();
        Ok((plain, AnswerSealer(answer_key)))
    }
}

/// A sealed request, as it is read from the line.
#[derive(Serialize, Deserialize)]
pub struct SealedRequest {
    pub seal: String,
    pub from: String,
    pub data: String,
}

/// A sealed answer, as it is read from the line.
#[derive(Serialize, Deserialize)]
pub struct SealedAnswer {
    pub seal: String,
    pub nonce: String,
    pub data: String,
}

/// Seals the one answer to the request it was opened from.
pub struct AnswerSealer(LessSafeKey);

impl AnswerSealer {
    /// The answer's line, without its newline.
    pub fn seal(self, answer: &[u8]) -> Result<String> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| anyhow!("no randomness: {e}"))?;
        self.seal_with(nonce, answer)
    }

    fn seal_with(self, nonce: [u8; NONCE_LEN], answer: &[u8]) -> Result<String> {
        let mut data = answer.to_vec();
        self.0
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
            .map_err(|_| anyhow!("could not seal the answer"))?;
        Ok(serde_json::to_string(&SealedAnswer {
            seal: SCHEME.into(),
            nonce: b64().encode(nonce),
            data: b64().encode(data),
        })?)
    }
}

/// Opens the one answer to a request this client sealed.
pub struct AnswerOpener(LessSafeKey);

impl AnswerOpener {
    /// The answer's plain line. An error when the line is not an answer
    /// sealed by the holder of the service's key: whatever said it, it was
    /// not the service.
    pub fn open(self, line: &str) -> Result<Vec<u8>> {
        let sealed: SealedAnswer =
            serde_json::from_str(line.trim()).map_err(|_| anyhow!("the answer is not sealed"))?;
        if sealed.seal != SCHEME {
            anyhow::bail!("the answer is sealed another way");
        }
        let nonce: [u8; NONCE_LEN] = b64()
            .decode(sealed.nonce.as_bytes())
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or_else(|| anyhow!("the answer's nonce is not 12 bytes of base64"))?;
        let mut data = b64()
            .decode(sealed.data.as_bytes())
            .map_err(|_| anyhow!("the answer is not base64"))?;
        let plain = self
            .0
            .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut data)
            .map_err(|_| anyhow!("the answer was not sealed by the service"))?;
        Ok(plain.to_vec())
    }
}

/// The service's public key, from the text of its key file.
pub fn public_from_base64(text: &str) -> Result<PublicKey> {
    let bytes = b64()
        .decode(text.trim().as_bytes())
        .map_err(|_| anyhow!("not base64"))?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("not a 32-byte key"))?;
    Ok(PublicKey::from(bytes))
}

/// Seals `request` (a plain request line, without its newline) to the
/// service's key. The line to send, without its newline, and what opens
/// the answer.
pub fn seal_request(service: &PublicKey, request: &[u8]) -> Result<(String, AnswerOpener)> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness: {e}"))?;
    seal_request_with(StaticSecret::from(bytes), service, request)
}

fn seal_request_with(
    mine: StaticSecret,
    service: &PublicKey,
    request: &[u8],
) -> Result<(String, AnswerOpener)> {
    let from = PublicKey::from(&mine);
    let shared = mine.diffie_hellman(service);
    if !shared.was_contributory() {
        anyhow::bail!("the service's key is not a usable key");
    }
    let (request_key, answer_key) = derive(shared.as_bytes(), &from, service);
    let mut data = request.to_vec();
    request_key
        .seal_in_place_append_tag(once(), Aad::empty(), &mut data)
        .map_err(|_| anyhow!("could not seal the request"))?;
    let line = serde_json::to_string(&SealedRequest {
        seal: SCHEME.into(),
        from: b64().encode(from.as_bytes()),
        data: b64().encode(data),
    })?;
    Ok((line, AnswerOpener(answer_key)))
}

/// The request key and the answer key, from the shared secret and both
/// public keys. The request key seals one request, under the fixed nonce;
/// the answer key seals each answer under a random one.
fn derive(
    shared: &[u8; 32],
    client: &PublicKey,
    service: &PublicKey,
) -> (LessSafeKey, LessSafeKey) {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client.as_bytes());
    salt[32..].copy_from_slice(service.as_bytes());
    let mut okm = [0u8; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(Some(&salt), shared)
        .expand(INFO, &mut okm)
        .expect("64 bytes is a valid HKDF-SHA256 length");
    let key = |k: &[u8]| {
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, k).expect("a 32-byte AES-256 key"))
    };
    (key(&okm[..32]), key(&okm[32..]))
}

/// The request's nonce: its key is used for that one request only.
fn once() -> Nonce {
    Nonce::assume_unique_for_key([0u8; NONCE_LEN])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_request_opens_only_with_the_service_key_and_its_answer_only_for_that_request() {
        let service = ServiceKey::generate().unwrap();
        let public = public_from_base64(&service.public_base64()).unwrap();
        let request = br#"{"token":"t","cmd":"status"}"#;
        let (line, opener) = seal_request(&public, request).unwrap();
        assert!(!line.contains("token"), "the request is readable: {line}");
        let sealed: SealedRequest = serde_json::from_str(&line).unwrap();
        let (plain, sealer) = service.open(&sealed).unwrap();
        assert_eq!(plain, request);
        let answer = sealer.seal(br#"{"ok":true}"#).unwrap();
        assert!(!answer.contains("ok"), "the answer is readable: {answer}");
        assert_eq!(opener.open(&answer).unwrap(), br#"{"ok":true}"#);

        // Another key (an impostor's, or the service's before a restart)
        // opens nothing.
        let other = ServiceKey::generate().unwrap();
        assert!(other.open(&sealed).is_err());

        // An answer that is not sealed, or sealed for another request, is
        // not believed.
        let (_, opener) = seal_request(&public, request).unwrap();
        assert!(opener.open(r#"{"ok":true}"#).is_err());
        let (_, opener) = seal_request(&public, request).unwrap();
        assert!(
            opener.open(&answer).is_err(),
            "an answer to another request was believed"
        );

        // A byte changed on the way is refused.
        let (line, _) = seal_request(&public, request).unwrap();
        let mut sealed: SealedRequest = serde_json::from_str(&line).unwrap();
        let mut data = b64().decode(&sealed.data).unwrap();
        data[0] ^= 1;
        sealed.data = b64().encode(data);
        assert!(service.open(&sealed).is_err());
    }

    #[test]
    fn a_relay_that_passes_the_request_on_learns_nothing_and_cannot_change_the_answer() {
        // Something on the pipe that forwards both lines between the client
        // and the real service: it holds neither key.
        let service = ServiceKey::generate().unwrap();
        let public = public_from_base64(&service.public_base64()).unwrap();
        let (line, opener) = seal_request(
            &public,
            br#"{"token":"t","cmd":"set_pass_token","pass_token":"acct"}"#,
        )
        .unwrap();
        assert!(!line.contains("acct"));
        let sealed: SealedRequest = serde_json::from_str(&line).unwrap();
        let (_, sealer) = service.open(&sealed).unwrap();
        let answer = sealer
            .seal(br#"{"ok":true,"status":{"connected":false}}"#)
            .unwrap();
        let mut forged: SealedAnswer = serde_json::from_str(&answer).unwrap();
        let mut data = b64().decode(&forged.data).unwrap();
        let last = data.len() - 1;
        data[last] ^= 1;
        forged.data = b64().encode(data);
        assert!(opener
            .open(&serde_json::to_string(&forged).unwrap())
            .is_err());
    }

    #[test]
    fn a_request_passed_on_twice_gets_two_answers_under_two_nonces() {
        // The same request line, sent to the service twice (by something
        // that relays it): the answer key is the same both times, so the
        // nonces must differ, or the two answers together would give away
        // what forges a third.
        let service = ServiceKey::generate().unwrap();
        let public = public_from_base64(&service.public_base64()).unwrap();
        let (line, opener) = seal_request(&public, br#"{"token":"t","cmd":"status"}"#).unwrap();
        let sealed: SealedRequest = serde_json::from_str(&line).unwrap();
        let answers: Vec<SealedAnswer> = (0..2)
            .map(|_| {
                let (_, sealer) = service.open(&sealed).unwrap();
                serde_json::from_str(&sealer.seal(br#"{"ok":true}"#).unwrap()).unwrap()
            })
            .collect();
        assert_ne!(answers[0].nonce, answers[1].nonce);
        assert_ne!(answers[0].data, answers[1].data);
        assert_eq!(
            opener
                .open(&serde_json::to_string(&answers[1]).unwrap())
                .unwrap(),
            br#"{"ok":true}"#
        );
        // An answer with its nonce changed does not open.
        let (line, opener) = seal_request(&public, br#"{"token":"t","cmd":"status"}"#).unwrap();
        let (_, sealer) = service.open(&serde_json::from_str(&line).unwrap()).unwrap();
        let mut moved: SealedAnswer =
            serde_json::from_str(&sealer.seal(br#"{"ok":true}"#).unwrap()).unwrap();
        moved.nonce = b64().encode([0u8; NONCE_LEN]);
        assert!(opener
            .open(&serde_json::to_string(&moved).unwrap())
            .is_err());
    }

    #[test]
    fn the_browser_and_the_service_seal_the_same_way() {
        // Fixed keys, so hidra-browser/test/vpn-manager.js can check its own
        // sealing against these very bytes.
        let service = StaticSecret::from([7u8; 32]);
        let mine = StaticSecret::from([9u8; 32]);
        let public = PublicKey::from(&service);
        assert_eq!(b64().encode(public.as_bytes()), VECTOR_SERVICE_PUBLIC);
        let (line, opener) = seal_request_with(mine, &public, VECTOR_REQUEST.as_bytes()).unwrap();
        assert_eq!(line, VECTOR_SEALED_REQUEST);
        let key = ServiceKey {
            public,
            secret: service,
        };
        let (plain, sealer) = key.open(&serde_json::from_str(&line).unwrap()).unwrap();
        assert_eq!(plain, VECTOR_REQUEST.as_bytes());
        let answer = sealer
            .seal_with([5u8; NONCE_LEN], VECTOR_ANSWER.as_bytes())
            .unwrap();
        assert_eq!(answer, VECTOR_SEALED_ANSWER);
        assert_eq!(opener.open(&answer).unwrap(), VECTOR_ANSWER.as_bytes());
    }

    // The same values are in hidra-browser/test/vpn-manager.js.
    const VECTOR_SERVICE_PUBLIC: &str = "E75P6uryBMf9M1j8nAByGIHRdCeBKCJ+xnTzf3/pe20=";
    const VECTOR_REQUEST: &str = r#"{"token":"t","cmd":"status"}"#;
    const VECTOR_ANSWER: &str = r#"{"ok":true}"#;
    const VECTOR_SEALED_REQUEST: &str = r#"{"seal":"x25519-aes256gcm","from":"V9tLNZ8jrl4Ubk4lEgVnBHIlBjSMFQwUdT0Mkz0E1CE=","data":"awoBadlwJgq10rVIMuDYG1hWWuZhyX67vbtV/7hSr+VWpZ/B/s2NbfDvrpE="}"#;
    /// Sealed under the nonce [5; 12].
    const VECTOR_SEALED_ANSWER: &str = r#"{"seal":"x25519-aes256gcm","nonce":"BQUFBQUFBQUFBQUF","data":"SV962O/AfproVzANwBCuZb+H3WsPk2hdKQYb"}"#;
}
