//! Passes: one connection's worth of admission on one node, signed blind by
//! an issuer (phase 5).
//!
//! RFC 9474 RSA blind signatures, `RSABSSA-SHA384-PSS-Randomized`, 2048-bit
//! keys. The client makes a fresh WireGuard key and a random nonce for a node
//! it chose, builds the pass message, blinds it and sends only the blinded
//! form to the issuer with its account token. The issuer signs what it cannot
//! read and counts one pass against the account. The client unblinds the
//! signature and holds a pass that verifies against the issuer's public key,
//! which the issuer cannot link to the request that made it. The node checks
//! the pass names it, that the signature holds under a current issuer key,
//! and that the nonce was never spent there; then it admits the key the pass
//! names.
//!
//! ```text
//! message = "HidraVPN pass v1\0" || issuer key id (8) || node public key (32)
//!           || client public key (32) || nonce (32)
//! ```
//!
//! What a pass binds, and why: the issuer key id, so a pass is checked under
//! the key it was made for; the node, so a pass spent on one node is not
//! spent again on another (a spent list per node is enough); the client key,
//! so a pass copied off the wire admits only the key its owner holds the
//! secret of; the nonce, so each pass is spent once.
//!
//! Nothing here logs a key, a nonce or a node.

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, KeyPairSha384PSSRandomized, MessageRandomizer,
    PublicKeySha384PSSRandomized, SecretKeySha384PSSRandomized, Signature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::{public_key_from_base64, ClientKey};

/// The first bytes of every pass message, so a signature over a pass can
/// never be mistaken for a signature over anything else.
pub const DOMAIN: &[u8] = b"HidraVPN pass v1\0";
/// How many passes one request to the issuer may ask for.
pub const MAX_PER_REQUEST: usize = 16;
/// The size of an issuer key, in bits.
pub const KEY_BITS: usize = 2048;

const KEY_ID_DOMAIN: &[u8] = b"HidraVPN pass key id v1\0";
const SPENT_DOMAIN: &[u8] = b"HidraVPN spent pass v1\0";

// ---- issuer keys -----------------------------------------------------------

/// An issuer's public key, and the short id passes name it by.
#[derive(Clone, Debug)]
pub struct IssuerKey {
    pk: PublicKeySha384PSSRandomized,
    spki: Vec<u8>,
    id: [u8; 8],
}

impl IssuerKey {
    /// From the base64 of its SubjectPublicKeyInfo, as `hidravpn-issuer
    /// keygen` prints it and the signed list carries it.
    pub fn from_spki_base64(s: &str) -> Result<IssuerKey> {
        let spki = B64
            .decode(s.trim())
            .context("the issuer key is not base64")?;
        let pk = PublicKeySha384PSSRandomized::from_spki(&spki)
            .map_err(|e| anyhow!("not an RSA public key: {e}"))?;
        let n = pk.components().n();
        let bytes = n.iter().skip_while(|b| **b == 0).count();
        if bytes != KEY_BITS / 8 {
            return Err(anyhow!(
                "an issuer key is {KEY_BITS} bits; this one is {} bits at most",
                bytes * 8
            ));
        }
        Ok(IssuerKey {
            id: key_id(&spki),
            pk,
            spki,
        })
    }

    pub fn to_spki_base64(&self) -> String {
        B64.encode(&self.spki)
    }

    /// The id passes carry, hex: the first 8 bytes of a hash of the key.
    pub fn id_hex(&self) -> String {
        hex::encode(self.id)
    }

    fn modulus_bytes(&self) -> usize {
        KEY_BITS / 8
    }
}

fn key_id(spki: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(KEY_ID_DOMAIN);
    h.update(spki);
    let d = h.finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&d[..8]);
    id
}

/// An issuer's secret key: what signs passes. It lives with the issuer
/// service and nowhere else; it is not the release key nor the list key.
pub struct IssuerSecret {
    sk: SecretKeySha384PSSRandomized,
    public: IssuerKey,
}

impl IssuerSecret {
    /// A new key pair, from the operating system's randomness.
    pub fn generate() -> Result<IssuerSecret> {
        let kp = KeyPairSha384PSSRandomized::generate(&mut DefaultRng, KEY_BITS)
            .map_err(|e| anyhow!("could not make an issuer key: {e}"))?;
        let spki = kp
            .pk
            .to_spki()
            .map_err(|e| anyhow!("could not encode the issuer key: {e}"))?;
        let public = IssuerKey::from_spki_base64(&B64.encode(spki))?;
        Ok(IssuerSecret { sk: kp.sk, public })
    }

    /// From the base64 of its DER encoding, as `keygen` wrote it.
    pub fn from_der_base64(s: &str) -> Result<IssuerSecret> {
        let der = B64
            .decode(s.trim())
            .context("the issuer secret is not base64")?;
        let sk = SecretKeySha384PSSRandomized::from_der(&der)
            .map_err(|e| anyhow!("not an issuer secret key: {e}"))?;
        let pk = sk
            .public_key()
            .map_err(|e| anyhow!("the issuer secret has no public half: {e}"))?;
        let spki = pk
            .to_spki()
            .map_err(|e| anyhow!("could not encode the issuer key: {e}"))?;
        let public = IssuerKey::from_spki_base64(&B64.encode(spki))?;
        Ok(IssuerSecret { sk, public })
    }

    pub fn to_der_base64(&self) -> Result<String> {
        Ok(B64.encode(
            self.sk
                .to_der()
                .map_err(|e| anyhow!("could not encode the issuer secret: {e}"))?,
        ))
    }

    pub fn public(&self) -> &IssuerKey {
        &self.public
    }

    /// Signs one blinded message. The issuer never learns what is inside.
    pub fn sign_blinded(&self, blinded_b64: &str) -> Result<String> {
        let blinded = B64
            .decode(blinded_b64.trim())
            .context("a blinded message is not base64")?;
        if blinded.len() != self.public.modulus_bytes() {
            return Err(anyhow!(
                "a blinded message is {} bytes",
                self.public.modulus_bytes()
            ));
        }
        let sig = self
            .sk
            .blind_sign(&blinded)
            .map_err(|e| anyhow!("could not sign: {e}"))?;
        Ok(B64.encode(sig.0))
    }
}

/// An issuer key as a list or a node's settings name it: the key, its id,
/// and when passes made under it stop being accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PassKeyRecord {
    /// `IssuerKey::id_hex`, checked against the key.
    pub id: String,
    /// The SubjectPublicKeyInfo, base64.
    pub key: String,
    /// RFC 3339. After this, a pass under this key is refused everywhere.
    pub not_after: String,
}

impl PassKeyRecord {
    pub fn issuer_key(&self) -> Result<IssuerKey> {
        let k = IssuerKey::from_spki_base64(&self.key)?;
        if k.id_hex() != self.id.trim() {
            return Err(anyhow!(
                "the pass key's id {} is not the id of its key",
                self.id
            ));
        }
        Ok(k)
    }

    pub fn validate(&self) -> Result<()> {
        self.issuer_key()?;
        crate::timefmt::rfc3339_to_unix(&self.not_after).context("the pass key's not_after")?;
        Ok(())
    }

    pub fn is_current(&self, now_unix: i64) -> bool {
        crate::timefmt::rfc3339_to_unix(&self.not_after)
            .map(|t| now_unix <= t)
            .unwrap_or(false)
    }
}

/// The current key among these that lasts longest: the one to ask passes
/// under.
pub fn newest_current(keys: &[PassKeyRecord], now_unix: i64) -> Option<&PassKeyRecord> {
    keys.iter()
        .filter(|k| k.is_current(now_unix) && k.validate().is_ok())
        .max_by_key(|k| crate::timefmt::rfc3339_to_unix(&k.not_after).unwrap_or(0))
}

// ---- the message ------------------------------------------------------------

fn message(key_id: &[u8; 8], node: &[u8; 32], client: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(DOMAIN.len() + 8 + 96);
    m.extend_from_slice(DOMAIN);
    m.extend_from_slice(key_id);
    m.extend_from_slice(node);
    m.extend_from_slice(client);
    m.extend_from_slice(nonce);
    m
}

fn decode_fixed<const N: usize>(what: &str, s: &str) -> Result<[u8; N]> {
    B64.decode(s.trim())
        .with_context(|| format!("the pass's {what} is not base64"))?
        .try_into()
        .map_err(|_| anyhow!("the pass's {what} is not {N} bytes"))
}

fn decode_id(s: &str) -> Result<[u8; 8]> {
    hex::decode(s.trim())
        .context("the pass's key id is not hex")?
        .try_into()
        .map_err(|_| anyhow!("the pass's key id is not 8 bytes"))
}

// ---- the client's side ------------------------------------------------------

/// A pass asked for and not yet signed: what the client keeps between
/// sending the blinded message and receiving the signature. In memory only.
pub struct PendingPass {
    result: BlindingResult,
    msg: Vec<u8>,
    key_id: [u8; 8],
    node_public_key: String,
    client: ClientKey,
    nonce: [u8; 32],
}

/// Prepares one pass for `node_public_b64` under `issuer`: a fresh client
/// key, a nonce, the message, blinded. Returns what goes to the issuer (the
/// blinded message, base64) and what stays here.
pub fn prepare(issuer: &IssuerKey, node_public_b64: &str) -> Result<(String, PendingPass)> {
    let node = public_key_from_base64(node_public_b64).context("the node's key")?;
    let client = ClientKey::generate()?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| anyhow!("no randomness available: {e}"))?;
    let msg = message(
        &issuer.id,
        node.as_bytes(),
        client.public().as_bytes(),
        &nonce,
    );
    let result = issuer
        .pk
        .blind(&mut DefaultRng, &msg)
        .map_err(|e| anyhow!("could not blind the pass: {e}"))?;
    let blinded = B64.encode(&result.blind_message.0);
    Ok((
        blinded,
        PendingPass {
            result,
            msg,
            key_id: issuer.id,
            node_public_key: node_public_b64.trim().to_string(),
            client,
            nonce,
        },
    ))
}

impl PendingPass {
    /// Unblinds the issuer's answer into a pass, checking it verifies.
    pub fn finalize(self, issuer: &IssuerKey, blind_sig_b64: &str) -> Result<Pass> {
        if issuer.id != self.key_id {
            return Err(anyhow!("the pass was asked under another issuer key"));
        }
        let blind = B64
            .decode(blind_sig_b64.trim())
            .context("the issuer's signature is not base64")?;
        let sig = issuer
            .pk
            .finalize(&BlindSignature(blind), &self.result, &self.msg)
            .map_err(|_| anyhow!("the issuer's signature does not verify; the pass is refused"))?;
        let randomizer = self
            .result
            .msg_randomizer
            .ok_or_else(|| anyhow!("a randomized pass has a randomizer"))?;
        Ok(Pass {
            key_id: hex::encode(self.key_id),
            node_public_key: self.node_public_key,
            client_secret: self.client.secret_base64(),
            nonce: B64.encode(self.nonce),
            randomizer: B64.encode(randomizer.0),
            signature: B64.encode(sig.0),
        })
    }
}

/// A pass, as the wallet keeps it: everything to redeem it, including the
/// secret half of the client key it admits. Never sent anywhere as it is;
/// `redemption` is what goes to the node.
#[derive(Clone, Serialize, Deserialize)]
pub struct Pass {
    pub key_id: String,
    pub node_public_key: String,
    /// The fresh WireGuard key this pass admits, secret half, base64.
    pub client_secret: String,
    pub nonce: String,
    pub randomizer: String,
    pub signature: String,
}

impl std::fmt::Debug for Pass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the secret, nor anything that identifies the pass.
        f.write_str("Pass(..)")
    }
}

impl Pass {
    pub fn client_key(&self) -> Result<ClientKey> {
        ClientKey::from_base64(&self.client_secret)
    }

    /// What the node is shown: the pass without the client's secret.
    pub fn redemption(&self) -> Result<Redemption> {
        Ok(Redemption {
            key_id: self.key_id.clone(),
            node_public_key: self.node_public_key.clone(),
            client_public_key: self.client_key()?.public_base64(),
            nonce: self.nonce.clone(),
            randomizer: self.randomizer.clone(),
            signature: self.signature.clone(),
        })
    }
}

// ---- the node's side --------------------------------------------------------

/// What `POST /redeem` carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redemption {
    pub key_id: String,
    pub node_public_key: String,
    pub client_public_key: String,
    pub nonce: String,
    pub randomizer: String,
    pub signature: String,
}

impl Redemption {
    /// Checks the pass for this node: a current issuer key it trusts, made
    /// for this node, and a signature that holds. Whether the nonce was spent
    /// is the caller's to check, with `spent_tag`.
    pub fn verify(&self, trusted: &[PassKeyRecord], this_node: &str, now_unix: i64) -> Result<()> {
        let id = decode_id(&self.key_id)?;
        let record = trusted
            .iter()
            .find(|k| k.id.trim().eq_ignore_ascii_case(self.key_id.trim()))
            .ok_or_else(|| anyhow!("this node does not accept passes under that issuer key"))?;
        if !record.is_current(now_unix) {
            return Err(anyhow!(
                "the issuer key of this pass expired; get passes under the current one"
            ));
        }
        let issuer = record.issuer_key()?;
        if self.node_public_key.trim() != this_node.trim() {
            return Err(anyhow!("this pass was made for another node"));
        }
        let node = public_key_from_base64(&self.node_public_key)?;
        let client = public_key_from_base64(&self.client_public_key)?;
        let nonce = decode_fixed::<32>("nonce", &self.nonce)?;
        let randomizer = decode_fixed::<32>("randomizer", &self.randomizer)?;
        let sig = B64
            .decode(self.signature.trim())
            .context("the pass's signature is not base64")?;
        if sig.len() != issuer.modulus_bytes() {
            return Err(anyhow!("the pass's signature has the wrong length"));
        }
        let msg = message(&id, node.as_bytes(), client.as_bytes(), &nonce);
        issuer
            .pk
            .verify(&Signature(sig), Some(MessageRandomizer(randomizer)), &msg)
            .map_err(|_| anyhow!("the pass's signature does not verify"))
    }

    /// What a node writes down to refuse this pass a second time. A hash, so
    /// the spent list holds no nonce in the clear.
    pub fn spent_tag(&self) -> String {
        let mut h = Sha256::new();
        h.update(SPENT_DOMAIN);
        h.update(self.key_id.trim().to_ascii_lowercase().as_bytes());
        h.update(self.nonce.trim().as_bytes());
        hex::encode(h.finalize())
    }
}

// ---- the issuer's wire -------------------------------------------------------

/// What a client sends to the issuer's `POST /issue`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRequest {
    pub token: String,
    pub key_id: String,
    pub blinded: Vec<String>,
}

/// What the issuer answers: one blind signature per blinded message, in
/// order, and how many the account has left today.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueResponse {
    pub signatures: Vec<String>,
    #[serde(default)]
    pub remaining_today: u32,
}

/// What a fetch brought back: the passes, how many the account has left
/// today, and, when it stopped before the end, why.
#[derive(Debug)]
pub struct Fetched {
    pub passes: Vec<Pass>,
    pub remaining_today: u32,
    pub stopped: Option<String>,
}

/// Asks the issuer at `issuer_url` for one pass per entry of `nodes` (node
/// public keys, base64; a node may appear more than once), under `key`, with
/// the account `token`, at most `MAX_PER_REQUEST` per request. The issuer key
/// comes from the signed list, never from the issuer: an issuer that answered
/// under another key would make passes nobody accepts, and is refused.
///
/// Every pass the issuer signed was counted against the account, so none is
/// dropped: if a later request fails (a refusal, a network error, an answer
/// that does not verify), the passes from the earlier ones come back with
/// `stopped` saying why. Only a failure before any pass is an error.
pub async fn fetch(
    issuer_url: &str,
    token: &str,
    key: &PassKeyRecord,
    nodes: &[String],
) -> Result<Fetched> {
    let issuer = key.issuer_key()?;
    let url = crate::http::Url::parse(issuer_url)
        .context("the pass issuer's address")?
        .with_path("/issue");
    url.check_for_token()?;
    let mut got = Fetched {
        passes: Vec::with_capacity(nodes.len()),
        remaining_today: 0,
        stopped: None,
    };
    for chunk in nodes.chunks(MAX_PER_REQUEST) {
        match fetch_one(&url, &issuer, token, chunk, &mut got.passes).await {
            Ok(left) => got.remaining_today = left,
            Err(e) if got.passes.is_empty() => return Err(e),
            Err(e) => {
                got.stopped = Some(format!("{e:#}"));
                break;
            }
        }
    }
    Ok(got)
}

/// One request: the passes it brings are appended as each one verifies.
async fn fetch_one(
    url: &crate::http::Url,
    issuer: &IssuerKey,
    token: &str,
    chunk: &[String],
    out: &mut Vec<Pass>,
) -> Result<u32> {
    let mut pending = Vec::with_capacity(chunk.len());
    let mut blinded = Vec::with_capacity(chunk.len());
    for n in chunk {
        let (b, p) = prepare(issuer, n)?;
        blinded.push(b);
        pending.push(p);
    }
    let body = serde_json::to_string(&IssueRequest {
        token: token.trim().to_string(),
        key_id: issuer.id_hex(),
        blinded,
    })?;
    let (status, answer) = crate::http::call(url, "POST", &body).await?;
    if status != 200 {
        let why = serde_json::from_str::<crate::admission::Refusal>(&answer)
            .map(|r| r.error)
            .unwrap_or_else(|_| answer.trim().chars().take(200).collect());
        return Err(anyhow!("the pass issuer refused ({status}): {why}"));
    }
    let resp: IssueResponse =
        serde_json::from_str(&answer).context("the pass issuer's answer is unreadable")?;
    if resp.signatures.len() != pending.len() {
        return Err(anyhow!(
            "the pass issuer answered {} signatures for {} passes",
            resp.signatures.len(),
            pending.len()
        ));
    }
    for (p, sig) in pending.into_iter().zip(resp.signatures) {
        out.push(p.finalize(issuer, &sig)?);
    }
    Ok(resp.remaining_today)
}

// ---- the wallet --------------------------------------------------------------

/// The passes this machine holds, by node. A JSON file only root reads.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Wallet {
    #[serde(default)]
    pub passes: Vec<Pass>,
}

impl Wallet {
    pub fn from_json(s: &str) -> Result<Wallet> {
        serde_json::from_str(s).context("the pass wallet is not valid JSON")
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a wallet always serialises")
    }

    pub fn count_for(&self, node_public: &str) -> usize {
        let n = node_public.trim();
        self.passes
            .iter()
            .filter(|p| p.node_public_key.trim() == n)
            .count()
    }

    /// Takes one pass for that node out of the wallet, if there is one.
    pub fn take_for(&mut self, node_public: &str) -> Option<Pass> {
        let n = node_public.trim();
        let i = self
            .passes
            .iter()
            .position(|p| p.node_public_key.trim() == n)?;
        Some(self.passes.remove(i))
    }

    /// Drops the passes whose issuer key is no longer among the current ones:
    /// no node would take them. Returns how many went.
    pub fn drop_expired(&mut self, keys: &[PassKeyRecord], now_unix: i64) -> usize {
        let before = self.passes.len();
        self.passes.retain(|p| {
            keys.iter().any(|k| {
                k.id.trim().eq_ignore_ascii_case(p.key_id.trim()) && k.is_current(now_unix)
            })
        });
        before - self.passes.len()
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::OnceLock;

    /// One issuer key for all tests: making an RSA key takes a moment.
    pub fn issuer() -> &'static IssuerSecret {
        static KEY: OnceLock<IssuerSecret> = OnceLock::new();
        KEY.get_or_init(|| IssuerSecret::generate().unwrap())
    }

    pub fn record(not_after: &str) -> PassKeyRecord {
        let k = issuer().public();
        PassKeyRecord {
            id: k.id_hex(),
            key: k.to_spki_base64(),
            not_after: not_after.into(),
        }
    }

    /// A pass for `node`, signed by the test issuer.
    pub fn pass_for(node: &str) -> Pass {
        let (blinded, pending) = prepare(issuer().public(), node).unwrap();
        let sig = issuer().sign_blinded(&blinded).unwrap();
        pending.finalize(issuer().public(), &sig).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    const NOW: i64 = 1_791_894_896; // 2026-10-13T12:34:56Z

    fn node() -> String {
        ClientKey::generate().unwrap().public_base64()
    }

    #[test]
    fn a_pass_made_for_a_node_is_accepted_there_and_names_its_fresh_key() {
        let n = node();
        let pass = pass_for(&n);
        let r = pass.redemption().unwrap();
        r.verify(&[record("2027-01-01T00:00:00Z")], &n, NOW)
            .unwrap();
        assert_eq!(
            r.client_public_key,
            pass.client_key().unwrap().public_base64()
        );
        // The redemption carries no secret.
        let wire = serde_json::to_string(&r).unwrap();
        assert!(!wire.contains(&pass.client_secret));
        assert_eq!(format!("{pass:?}"), "Pass(..)");
    }

    #[test]
    fn every_pass_has_its_own_key_and_nonce() {
        let n = node();
        let a = pass_for(&n).redemption().unwrap();
        let b = pass_for(&n).redemption().unwrap();
        assert_ne!(a.client_public_key, b.client_public_key);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.spent_tag(), b.spent_tag());
        // The same pass, twice, has the same tag: that is what refuses it.
        assert_eq!(a.spent_tag(), a.clone().spent_tag());
    }

    #[test]
    fn a_pass_is_refused_on_another_node_or_after_its_key_or_under_an_unknown_key() {
        let n = node();
        let r = pass_for(&n).redemption().unwrap();
        let keys = [record("2027-01-01T00:00:00Z")];
        let e = r.verify(&keys, &node(), NOW).unwrap_err().to_string();
        assert!(e.contains("another node"), "{e}");
        let e = r
            .verify(&[record("2026-01-01T00:00:00Z")], &n, NOW)
            .unwrap_err()
            .to_string();
        assert!(e.contains("expired"), "{e}");
        let e = r.verify(&[], &n, NOW).unwrap_err().to_string();
        assert!(e.contains("does not accept"), "{e}");
    }

    #[test]
    fn a_changed_pass_does_not_verify() {
        let n = node();
        let keys = [record("2027-01-01T00:00:00Z")];
        let good = pass_for(&n).redemption().unwrap();
        // Another client key: a stolen pass with the thief's key.
        let mut r = good.clone();
        r.client_public_key = node();
        assert!(r.verify(&keys, &n, NOW).is_err());
        // Another nonce: an attempt to spend it twice under a new name.
        let mut r = good.clone();
        r.nonce = B64.encode([7u8; 32]);
        assert!(r.verify(&keys, &n, NOW).is_err());
        let mut r = good.clone();
        r.randomizer = B64.encode([7u8; 32]);
        assert!(r.verify(&keys, &n, NOW).is_err());
        let mut r = good.clone();
        r.signature = B64.encode(vec![1u8; 256]);
        assert!(r.verify(&keys, &n, NOW).is_err());
        let mut r = good;
        r.signature = "short".into();
        assert!(r.verify(&keys, &n, NOW).is_err());
    }

    #[test]
    fn the_issuer_signs_only_what_has_the_size_of_a_blinded_message() {
        assert!(issuer().sign_blinded("AAAA").is_err());
        assert!(issuer().sign_blinded("not base64!").is_err());
        // A signature from another issuer key is refused when finalising.
        let other = IssuerSecret::generate().unwrap();
        let (blinded, pending) = prepare(issuer().public(), &node()).unwrap();
        // The other key either refuses (the blinded value is past its
        // modulus, about half the time) or signs something that does not
        // verify under ours: never a pass.
        if let Ok(wrong) = other.sign_blinded(&blinded) {
            assert!(pending.finalize(issuer().public(), &wrong).is_err());
        }
    }

    #[test]
    fn keys_round_trip_and_an_id_that_lies_is_refused() {
        let again = IssuerSecret::from_der_base64(&issuer().to_der_base64().unwrap()).unwrap();
        assert_eq!(again.public().id_hex(), issuer().public().id_hex());
        let mut rec = record("2027-01-01T00:00:00Z");
        rec.validate().unwrap();
        rec.id = "0011223344556677".into();
        assert!(rec.validate().is_err());
        assert!(IssuerKey::from_spki_base64("AAAA").is_err());
    }

    #[test]
    fn the_newest_current_key_is_the_one_to_ask_under() {
        let old = record("2026-11-01T00:00:00Z");
        let mut later = record("2026-12-01T00:00:00Z");
        later.not_after = "2026-12-01T00:00:00Z".into();
        let gone = record("2026-01-01T00:00:00Z");
        let keys = vec![gone, old, later.clone()];
        assert_eq!(newest_current(&keys, NOW), Some(&later));
        assert!(newest_current(&keys[..1], NOW).is_none());
    }

    #[tokio::test]
    async fn passes_paid_for_in_an_earlier_request_survive_a_later_one_failing() {
        use tokio::io::AsyncWriteExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            // The first request is signed; the second connection is dropped
            // without an answer, as a network failure would.
            let (mut s, _) = l.accept().await.unwrap();
            let req = crate::admission::read_request(&mut s).await.unwrap();
            let r: IssueRequest = serde_json::from_slice(&req.body).unwrap();
            let signatures = r
                .blinded
                .iter()
                .map(|b| issuer().sign_blinded(b).unwrap())
                .collect();
            let body = serde_json::to_string(&IssueResponse {
                signatures,
                remaining_today: 9,
            })
            .unwrap();
            s.write_all(&crate::admission::http_response(200, &body))
                .await
                .unwrap();
            drop(s);
            let (s2, _) = l.accept().await.unwrap();
            drop(s2);
        });
        let n = node();
        let wanted = vec![n.clone(); MAX_PER_REQUEST + 3];
        let rec = record("2100-01-01T00:00:00Z");
        let got = fetch(&format!("http://127.0.0.1:{port}"), "t", &rec, &wanted)
            .await
            .unwrap();
        assert_eq!(
            got.passes.len(),
            MAX_PER_REQUEST,
            "the first request's passes are kept"
        );
        assert_eq!(got.remaining_today, 9);
        assert!(got.stopped.is_some());
        for p in &got.passes {
            p.redemption()
                .unwrap()
                .verify(std::slice::from_ref(&rec), &n, NOW)
                .unwrap();
        }
    }

    #[test]
    fn the_wallet_hands_out_a_nodes_passes_once_and_drops_dead_ones() {
        let (a, b) = (node(), node());
        let mut w = Wallet::default();
        w.passes.push(pass_for(&a));
        w.passes.push(pass_for(&a));
        w.passes.push(pass_for(&b));
        assert_eq!(w.count_for(&a), 2);
        let first = w.take_for(&a).unwrap();
        assert_eq!(w.count_for(&a), 1);
        assert_eq!(first.node_public_key, a);
        let again = Wallet::from_json(&w.to_json()).unwrap();
        assert_eq!(again.passes.len(), 2);
        assert!(w.take_for(&node()).is_none());
        let live = [record("2027-01-01T00:00:00Z")];
        assert_eq!(w.drop_expired(&live, NOW), 0);
        let dead = [record("2026-01-01T00:00:00Z")];
        assert_eq!(w.drop_expired(&dead, NOW), 2);
        assert!(w.passes.is_empty());
    }
}
