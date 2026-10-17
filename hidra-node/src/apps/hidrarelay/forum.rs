//! The forum's rules, enforced by the relay.
//!
//! On a public broker the forum page had to check everything itself and
//! could only ever believe the first claim it happened to see. A relay the
//! project runs can decide: it keeps a claim on a name only if the name is
//! free or the same key is claiming it again, keeps a post only if it is
//! signed and under a name its key claimed, lets a post be replaced or
//! deleted only by the key that signed it, keeps a hide only from the
//! moderator, and keeps the registrar's list only from the registrar. The
//! page's own checks stay, and agree with these; they are the same
//! signatures over the same fields (hidra-browser/src/ui/hidrachat-crypto.js
//! and forum.html), verified here with the same curve and hash Web Crypto
//! uses, over the same bytes `JSON.stringify` produces.
//!
//! The work is in two halves. `prepare` parses and verifies signatures and
//! needs no state, so the relay runs it outside its lock; `admit` compares
//! the established facts with what is kept, under the lock, and is cheap.

use std::sync::Mutex;

use base64::Engine as _;
use p256::ecdsa::signature::Verifier;
use serde_json::Value;

use super::{Policy, Prepared, REGISTRY_TOPIC, Retained};

/// Caps on what the forum keeps, per kind. Past them, new entries of that
/// kind are refused and the log says so. Names are free to make, so these
/// bound the damage of a flood; the registrar's own caps (3000 names,
/// bursts refused) are what keeps a real forum far below them.
pub const MAX_CLAIMS: usize = 20_000;
pub const MAX_POSTS: usize = 100_000;
pub const MAX_HIDES: usize = 20_000;
pub const MAX_REPORTS: usize = 20_000;

/// The largest integer JavaScript represents exactly. A timestamp or a
/// sequence number above it would be read as a different number by the
/// pages, and a signature the relay accepts would fail there.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// What the operator tells the relay about the forum.
pub struct ForumPolicy {
    /// The registrar's public key, as the page carries it. Without it the
    /// relay keeps no registry list at all.
    registrar: Option<String>,
    /// The moderator's public key, when the operator names one on the
    /// command line; otherwise the registrar's list names the moderator.
    moderator: Option<String>,
    /// The admin named by the kept list, remembered by the identity of the
    /// kept bytes so the list is verified once, not on every hide.
    registry_admin: Mutex<Option<(usize, usize, Option<String>)>>,
}

/// What `prepare` established about a publish: everything that does not
/// depend on what is kept.
#[derive(Debug, PartialEq, Eq)]
pub enum Fact {
    Chat,
    Report,
    Claim {
        pk: String,
    },
    Post {
        id: String,
        pk: String,
        nick_norm: String,
    },
    Tombstone {
        pk: String,
    },
    Hide {
        pk: String,
    },
    Admin {
        pk: String,
    },
    Registry {
        seq: i64,
    },
}

fn b64(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// A public key in the one encoding the pages use: 88 characters of
/// base64 for a 65-byte uncompressed point that re-encodes to the same
/// string.
pub fn canonical_pub(pk: &str) -> Option<Vec<u8>> {
    if pk.len() != 88 {
        return None;
    }
    let raw = b64(pk)?;
    if raw.len() != 65 || raw[0] != 4 {
        return None;
    }
    if base64::engine::general_purpose::STANDARD.encode(&raw) != pk {
        return None;
    }
    Some(raw)
}

/// ECDSA P-256 with SHA-256 over `JSON.stringify(fields)`, the signature as
/// Web Crypto emits it: 64 raw bytes, r then s.
pub fn verify_fields(pk: &str, fields: &Value, sig: &str) -> bool {
    let Some(raw) = canonical_pub(pk) else {
        return false;
    };
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw) else {
        return false;
    };
    let Some(sig_bytes) = b64(sig) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_slice(&sig_bytes) else {
        return false;
    };
    let Ok(msg) = serde_json::to_vec(fields) else {
        return false;
    };
    key.verify(&msg, &signature).is_ok()
}

fn s<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k)?.as_str()
}

/// A timestamp is a non-negative integer the pages can represent exactly;
/// anything else is refused rather than re-serialised into something else.
fn ts(v: &Value, k: &str) -> Option<i64> {
    let n = v.get(k)?.as_i64()?;
    (0..=MAX_SAFE_INTEGER).contains(&n).then_some(n)
}

fn is_post_id(id: &str, kind: u8) -> bool {
    id.len() == 11
        && id.as_bytes()[0] == kind
        && id
            .bytes()
            .skip(1)
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

fn is_name(n: &str) -> bool {
    let b = n.as_bytes();
    (3..=24).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// The characters ECMAScript's `String.prototype.trim` removes. Rust's
/// `trim` differs at the edges (it strips U+0085 and keeps U+FEFF); the
/// page and the registrar use the JavaScript set, so the relay must too.
fn js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// `normalizeName` in hidrachat-crypto.js: trimmed and lower-cased.
fn normalize_name(n: &str) -> String {
    n.trim_matches(js_whitespace).to_lowercase()
}

/// Length as the page measures it (`maxlength`, `slice`): UTF-16 units.
fn units(s: &str) -> usize {
    s.encode_utf16().count()
}

fn parse(payload: &[u8]) -> Option<Value> {
    let v: Value = serde_json::from_slice(payload).ok()?;
    v.is_object().then_some(v)
}

/// The key a retained post, claim or tombstone carries, if it is one of ours.
fn retained_pk(retained: &Retained, topic: &str) -> Option<String> {
    let v = parse(retained.get(topic)?)?;
    Some(s(&v, "pk")?.to_string())
}

/// The fields the registrar signs, in the order the pages and the tool
/// use (hidrachat-crypto.js registryFields): `hides` only when present,
/// `admin` as the empty string when absent or null.
fn registry_fields(v: &Value) -> Option<(Value, &str)> {
    let seq = v.get("seq").and_then(Value::as_i64)?;
    let t = ts(v, "ts")?;
    let names = v.get("names")?;
    let sig = s(v, "sig")?;
    if v.get("v").and_then(Value::as_i64) != Some(1)
        || !names.is_array()
        || !(0..=MAX_SAFE_INTEGER).contains(&seq)
    {
        return None;
    }
    let admin = match v.get("admin") {
        None | Some(Value::Null) => Value::String(String::new()),
        Some(Value::String(a)) => Value::String(a.clone()),
        Some(_) => return None,
    };
    let mut fields = vec![
        Value::from("registry"),
        Value::from(seq),
        Value::from(t),
        names.clone(),
        admin,
    ];
    if let Some(h) = v.get("hides") {
        if !h.is_array() {
            return None;
        }
        fields.push(h.clone());
    }
    Some((Value::Array(fields), sig))
}

type Check = std::result::Result<Fact, &'static str>;

impl ForumPolicy {
    pub fn new(registrar: Option<String>, moderator: Option<String>) -> Self {
        Self {
            registrar,
            moderator,
            registry_admin: Mutex::new(None),
        }
    }

    /// The admin the kept list names, if the list verifies against the
    /// configured key. The relay only ever kept one that did; the re-check
    /// covers a data directory first filled with the rules off. Verified
    /// once per list: the result is remembered by the kept bytes' identity
    /// and forgotten when a newer list is admitted.
    fn registry_admin(&self, retained: &Retained) -> Option<String> {
        let key = self.registrar.as_ref()?;
        let bytes = retained.get(REGISTRY_TOPIC)?;
        let ident = (bytes.as_ptr() as usize, bytes.len());
        let mut cache = self
            .registry_admin
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some((p, l, admin)) = &*cache {
            if (*p, *l) == ident {
                return admin.clone();
            }
        }
        let admin = parse(bytes).and_then(|v| {
            let (fields, sig) = registry_fields(&v)?;
            if !verify_fields(key, &fields, sig) {
                return None;
            }
            let a = s(&v, "admin")?;
            (!a.is_empty()).then(|| a.to_string())
        });
        *cache = Some((ident.0, ident.1, admin.clone()));
        admin
    }

    /// The moderator as configured: the flag, or the admin in the
    /// registrar's list (the registrar's `set-admin`), so the operator
    /// names the moderator once.
    fn named_moderator(&self, retained: &Retained) -> Option<String> {
        if let Some(m) = &self.moderator {
            return Some(m.clone());
        }
        self.registry_admin(retained)
    }

    /// Who the operator named, else who made the first claim on
    /// `hforum/admin` that the relay kept.
    fn moderator_key(&self, retained: &Retained) -> Option<String> {
        self.named_moderator(retained).or_else(|| {
            let v = parse(retained.get("hforum/admin")?)?;
            if v.get("v")?.as_i64()? != 2 {
                return None;
            }
            Some(s(&v, "pk")?.to_string())
        })
    }

    fn check(&self, topic: &str, payload: &[u8], retain: bool) -> Check {
        if let Some(rest) = topic.strip_prefix("hidra/") {
            // Room traffic is opaque ciphertext; only the shape of the topic
            // is checked. The chat page retains nothing, so a retained
            // publish here is someone filling the store.
            let ok = rest == "presence/v1"
                || (rest.len() == 38
                    && rest.starts_with("hidra-")
                    && rest[6..]
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
            if !ok {
                return Err("chat: unknown topic");
            }
            if retain {
                return Err("chat: nothing is retained");
            }
            return Ok(Fact::Chat);
        }
        let Some(rest) = topic.strip_prefix("hforum/") else {
            return Err("unknown tree");
        };
        // The forum page retains everything it publishes. A live-only
        // message on these topics reaches the pages open now and leaves no
        // trace for the relay's rules to hold against.
        if !retain {
            return Err("forum: not retained");
        }
        let parts: Vec<&str> = rest.split('/').collect();
        match (parts[0], parts.len()) {
            ("u", 2) => self.claim(parts[1], payload),
            ("t", 2) => self.post(b't', parts[1], None, payload),
            ("r", 3) => self.post(b'r', parts[2], Some(parts[1]), payload),
            ("mod", 2) => self.hide(parts[1], payload),
            ("admin", 1) => self.admin(payload),
            ("registry", 1) => self.registry(payload),
            ("rep", 3) => {
                let by_ok = (1..=32).contains(&parts[2].len())
                    && parts[2]
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
                let id_ok = is_post_id(parts[1], b't') || is_post_id(parts[1], b'r');
                let payload_ok = payload.is_empty() || payload == b"1";
                if by_ok && id_ok && payload_ok {
                    Ok(Fact::Report)
                } else {
                    Err("report: malformed")
                }
            }
            _ => Err("forum: unknown topic"),
        }
    }

    fn claim(&self, norm: &str, payload: &[u8]) -> Check {
        if !is_name(norm) {
            return Err("claim: bad name");
        }
        if payload.is_empty() {
            return Err("claim: names are not deleted");
        }
        let v = parse(payload).ok_or("claim: not a JSON object")?;
        let (Some(name), Some(pk), Some(sig), Some(t)) =
            (s(&v, "name"), s(&v, "pk"), s(&v, "sig"), ts(&v, "ts"))
        else {
            return Err("claim: malformed");
        };
        if v.get("v").and_then(Value::as_i64) != Some(2)
            || normalize_name(name) != norm
            || units(name) > 24
        {
            return Err("claim: malformed");
        }
        if !verify_fields(pk, &serde_json::json!(["claim", norm, name, pk, t]), sig) {
            return Err("claim: bad signature");
        }
        Ok(Fact::Claim { pk: pk.to_string() })
    }

    fn post(&self, kind: u8, id: &str, tid: Option<&str>, payload: &[u8]) -> Check {
        if !is_post_id(id, kind) || tid.is_some_and(|t| !is_post_id(t, b't')) {
            return Err("post: bad id");
        }
        if payload.is_empty() {
            return Err("post: deletion is a signed tombstone, not an empty message");
        }
        let v = parse(payload).ok_or("post: not a JSON object")?;
        let (Some(pk), Some(sig), Some(t)) = (s(&v, "pk"), s(&v, "sig"), ts(&v, "ts")) else {
            return Err("post: unsigned");
        };
        if v.get("del").is_some() {
            if !verify_fields(pk, &serde_json::json!(["del", id, t]), sig) {
                return Err("tombstone: bad signature");
            }
            return Ok(Fact::Tombstone { pk: pk.to_string() });
        }
        if s(&v, "id") != Some(id) {
            return Err("post: id does not match the topic");
        }
        let Some(nick) = s(&v, "nick") else {
            return Err("post: malformed");
        };
        let fields = if kind == b't' {
            let (Some(cat), Some(title), Some(body)) =
                (s(&v, "cat"), s(&v, "title"), s(&v, "body"))
            else {
                return Err("post: malformed");
            };
            if units(cat) > 40 || units(title) > 140 || units(body) > 20_000 || units(nick) > 24 {
                return Err("post: over the page's limits");
            }
            serde_json::json!(["t", id, cat, title, body, nick, t])
        } else {
            let Some(body) = s(&v, "body") else {
                return Err("post: malformed");
            };
            if s(&v, "topicId") != tid || units(body) > 20_000 || units(nick) > 24 {
                return Err("post: malformed");
            }
            serde_json::json!(["r", id, tid.unwrap_or(""), body, nick, t])
        };
        if !verify_fields(pk, &fields, sig) {
            return Err("post: bad signature");
        }
        Ok(Fact::Post {
            id: id.to_string(),
            pk: pk.to_string(),
            nick_norm: normalize_name(nick),
        })
    }

    fn hide(&self, id: &str, payload: &[u8]) -> Check {
        if !(is_post_id(id, b't') || is_post_id(id, b'r')) {
            return Err("hide: bad id");
        }
        if payload.is_empty() || payload == b"1" {
            return Err("hide: must be signed");
        }
        let v = parse(payload).ok_or("hide: not a JSON object")?;
        let (Some(pk), Some(sig), Some(t)) = (s(&v, "pk"), s(&v, "sig"), ts(&v, "ts")) else {
            return Err("hide: malformed");
        };
        if s(&v, "id") != Some(id) {
            return Err("hide: malformed");
        }
        if !verify_fields(pk, &serde_json::json!(["hide", id, t]), sig) {
            return Err("hide: bad signature");
        }
        Ok(Fact::Hide { pk: pk.to_string() })
    }

    fn admin(&self, payload: &[u8]) -> Check {
        if payload.is_empty() {
            return Err("admin: not deleted");
        }
        let v = parse(payload).ok_or("admin: not a JSON object")?;
        let (Some(pk), Some(sig), Some(t)) = (s(&v, "pk"), s(&v, "sig"), ts(&v, "ts")) else {
            return Err("admin: malformed");
        };
        if v.get("v").and_then(Value::as_i64) != Some(2) {
            return Err("admin: malformed");
        }
        if !verify_fields(pk, &serde_json::json!(["admin", pk, t]), sig) {
            return Err("admin: bad signature");
        }
        Ok(Fact::Admin { pk: pk.to_string() })
    }

    fn registry(&self, payload: &[u8]) -> Check {
        let Some(key) = &self.registrar else {
            return Err("registry: no registrar key configured");
        };
        if payload.is_empty() {
            return Err("registry: not deleted");
        }
        let v = parse(payload).ok_or("registry: not a JSON object")?;
        let Some((fields, sig)) = registry_fields(&v) else {
            return Err("registry: malformed");
        };
        if !verify_fields(key, &fields, sig) {
            return Err("registry: bad signature");
        }
        Ok(Fact::Registry {
            seq: v.get("seq").and_then(Value::as_i64).unwrap_or(0),
        })
    }

    /// The stateful half: the fact against what is kept.
    fn weigh(&self, fact: &Fact, topic: &str, retained: &Retained) -> Option<&'static str> {
        let existing = retained.get(topic);
        let is_new = existing.is_none();
        let existing_pk = existing.and_then(parse).and_then(|e| {
            s(&e, "pk")
                .map(str::to_string)
                .map(|pk| (pk, e.get("del").is_some()))
        });
        match fact {
            Fact::Chat => None,
            Fact::Report => (is_new && retained.count("hforum/rep") >= MAX_REPORTS)
                .then_some("report: cap reached"),
            Fact::Claim { pk } => match existing_pk {
                Some((owner, _)) if owner != *pk => Some("claim: name taken"),
                Some(_) => None,
                None if retained.count("hforum/u") >= MAX_CLAIMS => Some("claim: cap reached"),
                None => None,
            },
            Fact::Tombstone { pk } => match existing_pk {
                Some((owner, _)) if owner == *pk => None,
                Some(_) => Some("tombstone: not the author"),
                None => Some("tombstone: nothing to delete"),
            },
            Fact::Post { id, pk, nick_norm } => {
                match &existing_pk {
                    Some((_, true)) => return Some("post: deleted"),
                    Some((owner, _)) if owner != pk => {
                        return Some("post: id belongs to another key");
                    }
                    _ => {}
                }
                // The page keeps replies by id alone: the same id under
                // another topic would shadow the first on a fresh load.
                if retained.topic_of_id(id).is_some_and(|t| t != topic) {
                    return Some("post: id already used under another topic");
                }
                if is_new && retained.count("hforum/t") + retained.count("hforum/r") >= MAX_POSTS {
                    return Some("post: cap reached");
                }
                // The page signs in before it posts, so a post's nickname is
                // a name its key has claimed. One signed with another key is
                // an impersonation; the page would flag it, the relay drops it.
                match retained_pk(retained, &format!("hforum/u/{nick_norm}")) {
                    Some(owner) if owner == *pk => None,
                    Some(_) => Some("post: nickname belongs to another key"),
                    None => Some("post: nickname not claimed"),
                }
            }
            Fact::Hide { pk } => {
                match self.moderator_key(retained) {
                    Some(m) if m == *pk => {}
                    Some(_) => return Some("hide: not the moderator"),
                    None => return Some("hide: no moderator yet"),
                }
                (is_new && retained.count("hforum/mod") >= MAX_HIDES).then_some("hide: cap reached")
            }
            Fact::Admin { pk } => {
                if let Some(m) = self.named_moderator(retained) {
                    (m != *pk).then_some("admin: not the moderator the operator named")
                } else if let Some((owner, _)) = existing_pk {
                    (owner != *pk).then_some("admin: already claimed")
                } else {
                    None
                }
            }
            Fact::Registry { seq } => {
                if let Some(existing) = existing.and_then(parse) {
                    if existing
                        .get("seq")
                        .and_then(Value::as_i64)
                        .is_some_and(|e| e >= *seq)
                    {
                        return Some("registry: not newer than the one kept");
                    }
                }
                // A newer list is about to be kept: whatever admin was
                // remembered from the old one is forgotten.
                *self
                    .registry_admin
                    .lock()
                    .unwrap_or_else(|p| p.into_inner()) = None;
                None
            }
        }
    }
}

impl Policy for ForumPolicy {
    fn prepare(
        &self,
        topic: &str,
        payload: &[u8],
        retain: bool,
    ) -> std::result::Result<Prepared, &'static str> {
        self.check(topic, payload, retain)
            .map(|f| Box::new(f) as Prepared)
    }

    fn admit(
        &self,
        prepared: &Prepared,
        topic: &str,
        _retain: bool,
        retained: &Retained,
    ) -> Option<&'static str> {
        let Some(fact) = prepared.downcast_ref::<Fact>() else {
            return Some("forum: not prepared here");
        };
        self.weigh(fact, topic, retained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Signed by the browser's own module (hidra-browser/src/ui/
    /// hidrachat-crypto.js) over fixed seeds; see forum_vectors.json.
    fn vectors() -> Value {
        serde_json::from_str(include_str!("forum_vectors.json")).unwrap()
    }

    fn bytes(v: &Value) -> Arc<[u8]> {
        serde_json::to_vec(v).unwrap().into()
    }

    fn policy(registrar: bool, moderator: Option<&str>) -> ForumPolicy {
        let v = vectors();
        ForumPolicy::new(
            registrar.then(|| v["R"].as_str().unwrap().to_string()),
            moderator.map(str::to_string),
        )
    }

    /// Both halves, as the relay runs them for a retained publish.
    fn refuse(
        pol: &ForumPolicy,
        topic: &str,
        payload: &[u8],
        retained: &Retained,
    ) -> Option<&'static str> {
        refuse_with(pol, topic, payload, true, retained)
    }

    fn refuse_with(
        pol: &ForumPolicy,
        topic: &str,
        payload: &[u8],
        retain: bool,
        retained: &Retained,
    ) -> Option<&'static str> {
        match pol.prepare(topic, payload, retain) {
            Err(reason) => Some(reason),
            Ok(p) => pol.admit(&p, topic, retain, retained),
        }
    }

    #[test]
    fn signatures_made_in_the_browser_verify_here() {
        let v = vectors();
        let a = v["A"].as_str().unwrap();
        let c = &v["claim_A_alice"];
        let fields = serde_json::json!(["claim", "alice", c["name"], a, c["ts"]]);
        assert!(verify_fields(a, &fields, c["sig"].as_str().unwrap()));
        assert!(!verify_fields(
            a,
            &serde_json::json!(["claim", "alice", "Alicia", a, c["ts"]]),
            c["sig"].as_str().unwrap()
        ));
        assert!(!verify_fields(
            v["B"].as_str().unwrap(),
            &fields,
            c["sig"].as_str().unwrap()
        ));
        // A title with quotes, angle brackets, a line separator, a newline
        // and an emoji: JSON.stringify and serde_json agree byte for byte.
        let p = &v["post_A"];
        let fields = serde_json::json!([
            "t", p["id"], p["cat"], p["title"], p["body"], p["nick"], p["ts"]
        ]);
        assert!(verify_fields(a, &fields, p["sig"].as_str().unwrap()));
    }

    #[test]
    fn a_name_belongs_to_the_first_key_that_claimed_it() {
        let v = vectors();
        let pol = policy(false, None);
        let mut retained = Retained::default();
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&v["claim_A_alice"]),
                &retained
            ),
            None
        );
        retained.insert("hforum/u/alice", bytes(&v["claim_A_alice"]));
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&v["claim_B_alice"]),
                &retained
            ),
            Some("claim: name taken")
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&v["claim_A_alice"]),
                &retained
            ),
            None,
            "the same key may claim again"
        );
        assert_eq!(
            refuse(&pol, "hforum/u/alice", b"", &retained),
            Some("claim: names are not deleted")
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/Alice",
                &bytes(&v["claim_A_alice"]),
                &retained
            ),
            Some("claim: bad name")
        );
        assert_eq!(
            refuse(&pol, "hforum/u/bob", &bytes(&v["claim_A_alice"]), &retained),
            Some("claim: malformed")
        );
        let mut tampered = v["claim_A_bob"].clone();
        tampered["name"] = Value::from("Bob!");
        assert_eq!(
            refuse(&pol, "hforum/u/bob", &bytes(&tampered), &retained),
            Some("claim: malformed")
        );
        tampered["name"] = Value::from("bob");
        assert_eq!(
            refuse(&pol, "hforum/u/bob", &bytes(&tampered), &retained),
            Some("claim: bad signature")
        );
        assert_eq!(
            refuse(&pol, "hforum/u/bob", &bytes(&v["claim_A_bob"]), &retained),
            None
        );
        // Not retained: the page never does that, and the relay would have
        // nothing to hold the name against.
        assert_eq!(
            refuse_with(
                &pol,
                "hforum/u/bob",
                &bytes(&v["claim_A_bob"]),
                false,
                &retained
            ),
            Some("forum: not retained")
        );
    }

    #[test]
    fn names_are_trimmed_as_javascript_trims_them() {
        let pol = policy(false, None);
        let retained = Retained::default();
        let (sk, pk) = local_key(3);
        let claim = |name: &str| {
            serde_json::json!({ "v": 2, "name": name, "pk": pk, "ts": 1,
                "sig": local_sign(&sk, &serde_json::json!(["claim", "alice", name, pk, 1])) })
        };
        // U+0085 is white space to Rust's trim and not to JavaScript's: the
        // page would compute another name, so the relay must not fold it.
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&claim("alice\u{0085}")),
                &retained
            ),
            Some("claim: malformed")
        );
        // U+FEFF is the other way round; both sides drop it.
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&claim("\u{FEFF}Alice ")),
                &retained
            ),
            None
        );
        // A timestamp JavaScript cannot represent would sign differently there.
        let big = serde_json::json!({ "v": 2, "name": "alice", "pk": pk, "ts": 9007199254740993i64,
            "sig": local_sign(&sk, &serde_json::json!(["claim", "alice", "alice", pk, 9007199254740993i64])) });
        assert_eq!(
            refuse(&pol, "hforum/u/alice", &bytes(&big), &retained),
            Some("claim: malformed")
        );
    }

    #[test]
    fn a_post_is_kept_only_signed_and_only_its_author_changes_it() {
        let v = vectors();
        let pol = policy(false, None);
        let mut retained = Retained::default();
        let topic = "hforum/t/tabcdefghij";
        assert_eq!(
            refuse(&pol, topic, &bytes(&v["post_A"]), &retained),
            Some("post: nickname not claimed")
        );
        retained.insert("hforum/u/alice", bytes(&v["claim_A_alice"]));
        assert_eq!(
            refuse(&pol, topic, &bytes(&v["post_B_same_id"]), &retained),
            Some("post: nickname not claimed")
        );
        retained.insert("hforum/u/bob", bytes(&v["claim_A_bob"]));
        assert_eq!(
            refuse(&pol, topic, &bytes(&v["post_B_same_id"]), &retained),
            Some("post: nickname belongs to another key"),
            "B signs as Bob, but bob is A's name"
        );
        assert_eq!(refuse(&pol, topic, b"{\"id\":\"tabcdefghij\",\"title\":\"x\",\"body\":\"y\",\"nick\":\"n\",\"cat\":\"c\",\"ts\":1}", &retained), Some("post: unsigned"));
        assert_eq!(
            refuse(&pol, topic, b"", &retained),
            Some("post: deletion is a signed tombstone, not an empty message")
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/x');alert(1)",
                &bytes(&v["post_A"]),
                &retained
            ),
            Some("post: bad id")
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/rabcdefghij",
                &bytes(&v["post_A"]),
                &retained
            ),
            Some("post: bad id")
        );
        assert_eq!(refuse(&pol, topic, &bytes(&v["post_A"]), &retained), None);
        retained.insert(topic, bytes(&v["post_A"]));
        assert_eq!(
            refuse(&pol, topic, &bytes(&v["post_B_same_id"]), &retained),
            Some("post: id belongs to another key")
        );
        assert_eq!(
            refuse(&pol, topic, &bytes(&v["tomb_B"]), &retained),
            Some("tombstone: not the author")
        );
        let mut tampered = v["post_A"].clone();
        tampered["title"] = Value::from("edited");
        assert_eq!(
            refuse(&pol, topic, &bytes(&tampered), &retained),
            Some("post: bad signature")
        );
        assert_eq!(refuse(&pol, topic, &bytes(&v["tomb_A"]), &retained), None);
        retained.insert(topic, bytes(&v["tomb_A"]));
        assert_eq!(
            refuse(&pol, topic, &bytes(&v["post_A"]), &retained),
            Some("post: deleted"),
            "the original bytes do not bring it back"
        );
        // A reply must sit under its topic, and its id is its own.
        assert_eq!(
            refuse(
                &pol,
                "hforum/r/tabcdefghij/rabcdefghij",
                &bytes(&v["reply_A"]),
                &retained
            ),
            None
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/r/tzzzzzzzzzz/rabcdefghij",
                &bytes(&v["reply_A"]),
                &retained
            ),
            Some("post: malformed")
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/r/tabcdefghij/tabcdefghij",
                &bytes(&v["reply_A"]),
                &retained
            ),
            Some("post: bad id")
        );
        retained.insert("hforum/r/tabcdefghij/rabcdefghij", bytes(&v["reply_A"]));
        let (sk, pk) = local_key(9);
        let claim = serde_json::json!({ "v": 2, "name": "eve", "pk": pk, "ts": 1,
            "sig": local_sign(&sk, &serde_json::json!(["claim", "eve", "eve", pk, 1])) });
        retained.insert("hforum/u/eve", bytes(&claim));
        let fields = serde_json::json!(["r", "rabcdefghij", "tzzzzzzzzzz", "x", "eve", 2]);
        let shadow = serde_json::json!({ "id": "rabcdefghij", "topicId": "tzzzzzzzzzz", "body": "x",
            "nick": "eve", "ts": 2, "pk": pk, "sig": local_sign(&sk, &fields) });
        assert_eq!(
            refuse(
                &pol,
                "hforum/r/tzzzzzzzzzz/rabcdefghij",
                &bytes(&shadow),
                &retained
            ),
            Some("post: id already used under another topic"),
            "the page keys replies by id; a second one elsewhere would shadow the first"
        );
    }

    #[test]
    fn hides_come_from_the_moderator_and_moderation_is_claimed_once() {
        let v = vectors();
        let pol = policy(false, None);
        let mut retained = Retained::default();
        assert_eq!(
            refuse(
                &pol,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_A"]),
                &retained
            ),
            Some("hide: no moderator yet")
        );
        assert_eq!(
            refuse(&pol, "hforum/mod/tabcdefghij", b"1", &retained),
            Some("hide: must be signed")
        );
        assert_eq!(
            refuse(&pol, "hforum/admin", &bytes(&v["admin_A"]), &retained),
            None
        );
        retained.insert("hforum/admin", bytes(&v["admin_A"]));
        assert_eq!(
            refuse(&pol, "hforum/admin", &bytes(&v["admin_B"]), &retained),
            Some("admin: already claimed")
        );
        assert_eq!(
            refuse(&pol, "hforum/admin", b"", &retained),
            Some("admin: not deleted")
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_A"]),
                &retained
            ),
            None
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_B"]),
                &retained
            ),
            Some("hide: not the moderator")
        );
        // With a moderator named by the operator, the relay's own word wins.
        let named = policy(false, Some(v["B"].as_str().unwrap()));
        assert_eq!(
            refuse(
                &named,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_A"]),
                &retained
            ),
            Some("hide: not the moderator")
        );
        assert_eq!(
            refuse(
                &named,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_B"]),
                &retained
            ),
            None
        );
        assert_eq!(
            refuse(
                &named,
                "hforum/admin",
                &bytes(&v["admin_A"]),
                &Retained::default()
            ),
            Some("admin: not the moderator the operator named")
        );
        assert_eq!(
            refuse(
                &named,
                "hforum/admin",
                &bytes(&v["admin_B"]),
                &Retained::default()
            ),
            None
        );
        // With no flag, the registrar's list names the moderator (its
        // set-admin): registry_2 carries A as admin.
        let by_list = policy(true, None);
        let mut retained = Retained::default();
        retained.insert("hforum/registry", bytes(&v["registry_2"]));
        assert_eq!(
            refuse(
                &by_list,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_A"]),
                &retained
            ),
            None
        );
        assert_eq!(
            refuse(
                &by_list,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_B"]),
                &retained
            ),
            Some("hide: not the moderator")
        );
        assert_eq!(
            refuse(&by_list, "hforum/admin", &bytes(&v["admin_B"]), &retained),
            Some("admin: not the moderator the operator named")
        );
        assert_eq!(
            refuse(&by_list, "hforum/admin", &bytes(&v["admin_A"]), &retained),
            None
        );
        // A list that does not verify (a data directory filled with the
        // rules off) names nobody; the cache keys on the kept bytes, so a
        // replaced list is re-read.
        let mut forged = v["registry_2"].clone();
        forged["admin"] = v["B"].clone();
        retained.insert("hforum/registry", bytes(&forged));
        assert_eq!(
            refuse(
                &by_list,
                "hforum/mod/tabcdefghij",
                &bytes(&v["hide_B"]),
                &retained
            ),
            Some("hide: no moderator yet")
        );
    }

    #[test]
    fn the_registry_comes_from_the_registrar_and_only_moves_forward() {
        let v = vectors();
        let pol = policy(true, None);
        let mut retained = Retained::default();
        assert_eq!(
            refuse(
                &policy(false, None),
                "hforum/registry",
                &bytes(&v["registry_1"]),
                &retained
            ),
            Some("registry: no registrar key configured")
        );
        assert_eq!(
            refuse(&pol, "hforum/registry", &bytes(&v["registry_1"]), &retained),
            None
        );
        retained.insert("hforum/registry", bytes(&v["registry_1"]));
        assert_eq!(
            refuse(&pol, "hforum/registry", &bytes(&v["registry_1"]), &retained),
            Some("registry: not newer than the one kept")
        );
        assert_eq!(
            refuse(&pol, "hforum/registry", &bytes(&v["registry_2"]), &retained),
            None,
            "with hides, a six-field signature"
        );
        let mut tampered = v["registry_2"].clone();
        tampered["admin"] = v["B"].clone();
        assert_eq!(
            refuse(&pol, "hforum/registry", &bytes(&tampered), &retained),
            Some("registry: bad signature")
        );
        assert_eq!(
            refuse(&pol, "hforum/registry", b"", &retained),
            Some("registry: not deleted")
        );
    }

    #[test]
    fn the_chat_trees_are_shaped_and_the_rest_is_refused() {
        let pol = policy(false, None);
        let r = Retained::default();
        let room = format!("hidra/hidra-{}", "a".repeat(32));
        assert_eq!(
            refuse_with(&pol, "hidra/presence/v1", b"{}", false, &r),
            None
        );
        assert_eq!(refuse_with(&pol, &room, b"ciphertext", false, &r), None);
        assert_eq!(
            refuse_with(&pol, &room, b"ciphertext", true, &r),
            Some("chat: nothing is retained")
        );
        assert_eq!(
            refuse_with(&pol, "hidra/other", b"x", false, &r),
            Some("chat: unknown topic")
        );
        assert_eq!(
            refuse_with(
                &pol,
                &format!("hidra/hidra-{}", "A".repeat(32)),
                b"x",
                false,
                &r
            ),
            Some("chat: unknown topic")
        );
        assert_eq!(
            refuse(&pol, "hforum/zzz/1", b"x", &r),
            Some("forum: unknown topic")
        );
        assert_eq!(
            refuse(&pol, "hforum/rep/tabcdefghij/e27a8bea", b"1", &r),
            None
        );
        assert_eq!(
            refuse(&pol, "hforum/rep/tabcdefghij/E27A", b"1", &r),
            Some("report: malformed")
        );
        assert_eq!(
            refuse(&pol, "hforum/rep/tabcdefghij/e27a8bea", b"2", &r),
            Some("report: malformed")
        );
    }

    #[test]
    fn each_kind_has_a_cap() {
        let pol = policy(false, None);
        let mut retained = Retained::default();
        for i in 0..MAX_REPORTS {
            retained.insert(&format!("hforum/rep/tabcdefghij/u{i}"), b"1"[..].into());
        }
        assert_eq!(
            refuse(&pol, "hforum/rep/tabcdefghij/u0", b"1", &retained),
            None,
            "a report already kept may be published again"
        );
        assert_eq!(
            refuse(&pol, "hforum/rep/tabcdefghij/more", b"1", &retained),
            Some("report: cap reached")
        );
        assert_eq!(retained.count("hforum/rep"), MAX_REPORTS);
        retained.remove("hforum/rep/tabcdefghij/u0");
        assert_eq!(retained.count("hforum/rep"), MAX_REPORTS - 1);
        assert_eq!(
            refuse(&pol, "hforum/rep/tabcdefghij/more", b"1", &retained),
            None
        );
    }

    /// A key made here, to sign what the vectors do not cover.
    fn local_key(seed: u8) -> (p256::ecdsa::SigningKey, String) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let pk = sk.verifying_key().to_encoded_point(false);
        let pk = base64::engine::general_purpose::STANDARD.encode(pk.as_bytes());
        (sk, pk)
    }

    fn local_sign(sk: &p256::ecdsa::SigningKey, fields: &Value) -> String {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = sk.sign(&serde_json::to_vec(fields).unwrap());
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    }

    #[test]
    fn limits_are_measured_as_the_page_measures_them() {
        let pol = policy(false, None);
        let (sk, pk) = local_key(7);
        let mut retained = Retained::default();
        let claim = serde_json::json!({ "v": 2, "name": "zoe", "pk": pk, "ts": 1,
            "sig": local_sign(&sk, &serde_json::json!(["claim", "zoe", "zoe", pk, 1])) });
        assert_eq!(
            refuse(&pol, "hforum/u/zoe", &bytes(&claim), &retained),
            None
        );
        retained.insert("hforum/u/zoe", bytes(&claim));
        let post = |title: &str, body: &str| {
            let id = "tlimitsabcd";
            let fields = serde_json::json!(["t", id, "General", title, body, "zoe", 2]);
            serde_json::json!({ "id": id, "cat": "General", "title": title, "body": body,
                "nick": "zoe", "ts": 2, "pk": pk, "sig": local_sign(&sk, &fields) })
        };
        // 140 accented characters are 280 bytes and 140 units: within the
        // page's maxlength, so kept. A 141st is refused.
        let title = "é".repeat(140);
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/tlimitsabcd",
                &bytes(&post(&title, "x")),
                &retained
            ),
            None
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/tlimitsabcd",
                &bytes(&post(&(title + "é"), "x")),
                &retained
            ),
            Some("post: over the page's limits")
        );
        // An emoji is two units: 10_000 of them fill the body exactly.
        let body = "😀".repeat(10_000);
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/tlimitsabcd",
                &bytes(&post("t", &body)),
                &retained
            ),
            None
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/tlimitsabcd",
                &bytes(&post("t", &(body + "a"))),
                &retained
            ),
            Some("post: over the page's limits")
        );
    }

    #[test]
    fn what_is_not_json_is_refused_everywhere() {
        let v = vectors();
        let pol = policy(true, Some(v["B"].as_str().unwrap()));
        let retained = Retained::default();
        for topic in [
            "hforum/u/alice",
            "hforum/t/tabcdefghij",
            "hforum/r/tabcdefghij/rabcdefghij",
            "hforum/mod/tabcdefghij",
            "hforum/admin",
            "hforum/registry",
        ] {
            for payload in [&b"not json"[..], b"[1,2]", b"\"s\"", b"42", b"{", b"null"] {
                assert!(
                    refuse(&pol, topic, payload, &retained).is_some(),
                    "{topic} accepted {payload:?}"
                );
            }
        }
    }
}
