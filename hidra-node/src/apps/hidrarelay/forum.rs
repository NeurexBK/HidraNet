//! The forum's rules, enforced by the relay.
//!
//! On a public broker the forum page had to check everything itself and
//! could only ever believe the first claim it happened to see. A relay the
//! project runs can decide: it keeps a claim on a name only if the name is
//! free or the same key is claiming it again, keeps a post only if it is
//! signed and under a name its key holds, lets a post be replaced or
//! deleted only by the key that signed it, keeps a hide only from the
//! moderator, and keeps the registrar's list only from the registrar. The
//! page's own checks stay, and agree with these; they are the same
//! signatures over the same fields (hidra-browser/src/ui/hidrachat-crypto.js
//! and forum.html), verified here with the same curve and hash Web Crypto
//! uses, over the same bytes `JSON.stringify` produces.
//!
//! On names, the registrar's list is the authority, as it is for the pages:
//! a name the list gives to a key is that key's here too, whether or not a
//! claim for it is kept. So a relay that starts empty (the move from the
//! public brokers, or a lost data directory) still knows every registered
//! name as soon as the registrar has published once.
//!
//! The work is in two halves. `prepare` parses and verifies signatures and
//! needs no state, so the relay runs it outside its lock; `admit` compares
//! the established facts with what is kept, under the lock, through the
//! metadata the relay remembers beside each payload, and parses nothing
//! but a newly kept registry list, once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use p256::ecdsa::signature::Verifier;
use serde_json::Value;

use super::{Meta, Policy, Prepared, REGISTRY_TOPIC, Retained};

/// Caps on what the forum keeps, per kind. Past them, new entries of that
/// kind are refused and the log says so. Names are free to make, so these
/// bound the damage of a flood; the registrar's own caps (3000 names,
/// bursts refused) are what keeps a real forum far below them. They add
/// up to the relay's cap on retained messages.
pub const MAX_CLAIMS: usize = 10_000;
pub const MAX_POSTS: usize = 30_000;
pub const MAX_HIDES: usize = 5_000;
pub const MAX_REPORTS: usize = 5_000;

/// Names are free to make, so they are metered for the relay as a whole:
/// this many new names an hour, with this much of a burst. A forum grows
/// by a few accounts a day; a flood is what this stops. The registrar
/// meters them again on its side.
pub const NEW_NAMES_PER_HOUR: f64 = 300.0;
pub const NEW_NAMES_BURST: f64 = 60.0;
/// A kept name the registrar's list does not carry, once a list published
/// this long after the name was kept has arrived, was refused by the
/// registrar (its caps, its burst rule) and is dropped from the store.
pub const UNLISTED_NAME_GRACE: Duration = Duration::from_secs(120);

/// The largest integer JavaScript represents exactly. A timestamp or a
/// sequence number above it would be read as a different number by the
/// pages, and a signature the relay accepts would fail there.
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// What the operator tells the relay about the forum.
pub struct ForumPolicy {
    /// The registrar's public key, as the page carries it. Without it the
    /// relay keeps no registry list at all.
    registrar: Option<String>,
    /// A moderator named directly, overriding the registrar's list. Not
    /// offered on the command line: the pages learn the moderator from the
    /// list, so naming one here that the list does not carry would leave
    /// them believing the wrong account. Kept for tests.
    moderator: Option<String>,
    /// What the kept list says, remembered by the identity of the kept
    /// bytes so the list is parsed and verified once, not on every post.
    registry: Mutex<Option<(usize, usize, Option<RegistryFacts>)>>,
    /// The meter on new names, relay-wide.
    names: Mutex<NameMeter>,
}

/// A token bucket for new names: `NEW_NAMES_PER_HOUR` sustained,
/// `NEW_NAMES_BURST` at once.
struct NameMeter {
    tokens: f64,
    last: Instant,
}

impl NameMeter {
    fn take(&mut self, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * NEW_NAMES_PER_HOUR / 3600.0).min(NEW_NAMES_BURST);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The parts of the registrar's list the rules use.
#[derive(Clone, Debug, Default)]
struct RegistryFacts {
    admin: Option<String>,
    /// Normalised name to the key that holds it.
    names: HashMap<String, String>,
}

/// What `prepare` established about a publish: everything that does not
/// depend on what is kept.
#[derive(Debug, PartialEq, Eq)]
pub enum Fact {
    Chat,
    Report,
    Claim {
        norm: String,
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

/// The fields the registrar signs, in the order the pages and the tool
/// use (hidrachat-crypto.js registryFields): `hides` only when present,
/// `admin` as the empty string when absent or null.
fn registry_fields(v: &Value) -> Option<(Value, &str)> {
    let seq = v.get("seq").and_then(Value::as_i64)?;
    let t = ts(v, "ts")?;
    let names = v.get("names")?;
    let sig = s(v, "sig")?;
    if v.get("v").and_then(Value::as_i64) != Some(1) || !(0..=MAX_SAFE_INTEGER).contains(&seq) {
        return None;
    }
    // Each entry is [norm, name, pk, ts] with a timestamp JavaScript prints
    // as serde_json does; anything else could re-serialise differently
    // here and fail a signature the pages accept, or the other way round.
    let entries = names.as_array()?;
    for e in entries {
        let e = e.as_array()?;
        if e.len() != 4
            || !e[0].is_string()
            || !e[1].is_string()
            || e[2].as_str().is_none_or(|pk| canonical_pub(pk).is_none())
            || !e[3]
                .as_i64()
                .is_some_and(|t| (0..=MAX_SAFE_INTEGER).contains(&t))
        {
            return None;
        }
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
            registry: Mutex::new(None),
            names: Mutex::new(NameMeter {
                tokens: NEW_NAMES_BURST,
                last: Instant::now(),
            }),
        }
    }

    /// What the kept list says, if it verifies against the configured key.
    /// The relay only ever kept one that did; the re-check covers a data
    /// directory first filled with the rules off. Parsed once per list:
    /// the result is remembered by the kept bytes' identity and forgotten
    /// when a newer list is admitted.
    fn registry_facts(&self, retained: &Retained) -> Option<RegistryFacts> {
        let key = self.registrar.as_ref()?;
        let bytes = retained.get(REGISTRY_TOPIC)?;
        let ident = (bytes.as_ptr() as usize, bytes.len());
        let mut cache = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((p, l, facts)) = &*cache {
            if (*p, *l) == ident {
                return facts.clone();
            }
        }
        let facts = parse(bytes).and_then(|v| {
            let (fields, sig) = registry_fields(&v)?;
            if !verify_fields(key, &fields, sig) {
                return None;
            }
            let admin = s(&v, "admin").filter(|a| !a.is_empty()).map(str::to_string);
            let mut names = HashMap::new();
            for e in v.get("names")?.as_array()? {
                // [norm, name, pk, ts], as the registrar builds it.
                if let (Some(norm), Some(pk)) = (
                    e.get(0).and_then(Value::as_str),
                    e.get(2).and_then(Value::as_str),
                ) {
                    names.insert(norm.to_string(), pk.to_string());
                }
            }
            Some(RegistryFacts { admin, names })
        });
        *cache = Some((ident.0, ident.1, facts.clone()));
        facts
    }

    /// The key a name belongs to: the registrar's word first, else the
    /// claim the relay keeps.
    fn name_owner(&self, norm: &str, retained: &Retained) -> Option<String> {
        if let Some(pk) = self
            .registry_facts(retained)
            .and_then(|f| f.names.get(norm).cloned())
        {
            return Some(pk);
        }
        retained
            .meta(&format!("hforum/u/{norm}"))
            .and_then(|m| m.pk.as_deref().map(str::to_string))
    }

    /// The moderator as configured: the override, or the admin in the
    /// registrar's list (the registrar's `set-admin`), so the operator
    /// names the moderator once.
    fn named_moderator(&self, retained: &Retained) -> Option<String> {
        if let Some(m) = &self.moderator {
            return Some(m.clone());
        }
        self.registry_facts(retained).and_then(|f| f.admin)
    }

    /// Who the operator named, else who made the first claim on
    /// `hforum/admin` that the relay kept.
    fn moderator_key(&self, retained: &Retained) -> Option<String> {
        self.named_moderator(retained).or_else(|| {
            retained
                .meta("hforum/admin")
                .and_then(|m| m.pk.as_deref().map(str::to_string))
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
        Ok(Fact::Claim {
            norm: norm.to_string(),
            pk: pk.to_string(),
        })
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

    /// The stateful half: the fact against what is kept, through the
    /// metadata beside each payload.
    fn weigh(&self, fact: &Fact, topic: &str, retained: &Retained) -> Option<&'static str> {
        let existing = retained.meta(topic);
        let is_new = existing.is_none();
        let existing_pk = existing.and_then(|m| m.pk.as_deref());
        match fact {
            Fact::Chat => None,
            Fact::Report => (is_new && retained.count("hforum/rep") >= MAX_REPORTS)
                .then_some("report: cap reached"),
            Fact::Claim { norm, pk } => {
                // The registrar's word on a name comes first.
                if let Some(owner) = self
                    .registry_facts(retained)
                    .and_then(|f| f.names.get(norm).cloned())
                {
                    return (owner != *pk)
                        .then_some("claim: the registry gives this name to another key");
                }
                match existing_pk {
                    Some(owner) if owner != pk => Some("claim: name taken"),
                    Some(_) => None,
                    None if retained.count("hforum/u") >= MAX_CLAIMS => Some("claim: cap reached"),
                    // An account is one key for one name (the key is derived
                    // from the name), so a key asking for a second name is
                    // not the page.
                    None if retained.claims_of(pk) >= 1 => {
                        Some("claim: this key already holds a name")
                    }
                    None => {
                        let mut meter = self.names.lock().unwrap_or_else(|p| p.into_inner());
                        (!meter.take(Instant::now()))
                            .then_some("claim: too many new names right now")
                    }
                }
            }
            Fact::Tombstone { pk } => match existing_pk {
                Some(owner) if owner == pk => None,
                Some(_) => Some("tombstone: not the author"),
                None => Some("tombstone: nothing to delete"),
            },
            Fact::Post { id, pk, nick_norm } => {
                if existing.is_some_and(|m| m.tombstone) {
                    return Some("post: deleted");
                }
                if existing_pk.is_some_and(|owner| owner != pk) {
                    return Some("post: id belongs to another key");
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
                // a name its key holds. One signed with another key is an
                // impersonation; the page would flag it, the relay drops it.
                match self.name_owner(nick_norm, retained) {
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
                } else if let Some(owner) = existing_pk {
                    (owner != pk).then_some("admin: already claimed")
                } else {
                    None
                }
            }
            Fact::Registry { seq } => {
                // Only a kept list that verifies under the current key holds
                // the sequence forward; one left by another key (a rotated
                // key, a data directory from before) does not lock out the
                // registrar.
                if self.registry_facts(retained).is_some()
                    && existing
                        .and_then(|m| m.seq)
                        .is_some_and(|kept| kept >= *seq)
                {
                    return Some("registry: not newer than the one kept");
                }
                // A newer list is about to be kept: what was remembered
                // from the old one is forgotten.
                *self.registry.lock().unwrap_or_else(|p| p.into_inner()) = None;
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

    /// Beside each kept forum payload: the key that signed it, whether it
    /// is a tombstone, and a list's sequence number. Computed off the lock,
    /// so `admit` never parses a kept payload.
    fn meta(&self, topic: &str, payload: &[u8]) -> Meta {
        if !topic.starts_with("hforum/") || topic.starts_with("hforum/rep/") {
            return Meta::default();
        }
        let Some(v) = parse(payload) else {
            return Meta::default();
        };
        Meta {
            pk: s(&v, "pk").map(Into::into),
            tombstone: v.get("del").is_some(),
            seq: v.get("seq").and_then(Value::as_i64),
        }
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

    /// Names the registrar did not take. A kept claim whose name the list
    /// does not carry, or gives to another key, once a list published well
    /// after the claim was kept has arrived, was refused on the registrar's
    /// side and goes; so the store never holds more names than the
    /// registrar's caps allow plus what is still pending there.
    fn sweep(&self, retained: &Retained) -> Vec<Arc<str>> {
        let (Some(facts), Some(list_since)) = (
            self.registry_facts(retained),
            retained.since(REGISTRY_TOPIC),
        ) else {
            return Vec::new();
        };
        retained
            .of_class("hforum/u")
            .into_iter()
            .filter(|(topic, since, meta)| {
                let norm = &topic["hforum/u/".len()..];
                let listed_to_this_key = facts
                    .names
                    .get(norm)
                    .is_some_and(|owner| meta.pk.as_deref() == Some(owner.as_str()));
                !listed_to_this_key && list_since > *since + UNLISTED_NAME_GRACE
            })
            .map(|(topic, _, _)| topic)
            .collect()
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

    /// Keeps a payload as the relay would: with the policy's metadata.
    fn keep(r: &mut Retained, pol: &ForumPolicy, topic: &str, payload: Arc<[u8]>) {
        let meta = pol.meta(topic, &payload);
        r.insert(topic, payload, meta);
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
        keep(
            &mut retained,
            &pol,
            "hforum/u/alice",
            bytes(&v["claim_A_alice"]),
        );
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
            Some("claim: this key already holds a name"),
            "A holds alice already; an account is one key for one name"
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
    fn the_registrars_list_decides_names_even_on_an_empty_store() {
        let v = vectors();
        let pol = policy(true, None);
        let mut retained = Retained::default();
        // Nothing kept but the list, which gives alice and bob to A.
        keep(
            &mut retained,
            &pol,
            "hforum/registry",
            bytes(&v["registry_2"]),
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&v["claim_B_alice"]),
                &retained
            ),
            Some("claim: the registry gives this name to another key"),
            "B cannot take alice on an empty store"
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&v["claim_A_alice"]),
                &retained
            ),
            None
        );
        // A posts as Alice with no claim kept: the list vouches for the name.
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/tabcdefghij",
                &bytes(&v["post_A"]),
                &retained
            ),
            None
        );
        // B, signing as Bob, is not bob's key according to the list.
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/tabcdefghij",
                &bytes(&v["post_B_same_id"]),
                &retained
            ),
            Some("post: nickname belongs to another key")
        );
        // A claim the relay kept before the list arrived yields to the list.
        keep(
            &mut retained,
            &pol,
            "hforum/u/alice",
            bytes(&v["claim_B_alice"]),
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/t/tabcdefghij",
                &bytes(&v["post_A"]),
                &retained
            ),
            None,
            "the list, not the kept claim, says whose name alice is"
        );
        // Without a registrar key there is no list to follow.
        let open = policy(false, None);
        assert_eq!(
            refuse(
                &open,
                "hforum/t/tabcdefghij",
                &bytes(&v["post_A"]),
                &retained
            ),
            Some("post: nickname belongs to another key")
        );
    }

    #[test]
    fn a_key_holds_one_name_and_new_names_are_metered() {
        let v = vectors();
        let pol = policy(false, None);
        let mut retained = Retained::default();
        keep(
            &mut retained,
            &pol,
            "hforum/u/alice",
            bytes(&v["claim_A_alice"]),
        );
        assert_eq!(
            refuse(&pol, "hforum/u/bob", &bytes(&v["claim_A_bob"]), &retained),
            Some("claim: this key already holds a name"),
            "A already holds alice"
        );
        assert_eq!(
            refuse(
                &pol,
                "hforum/u/alice",
                &bytes(&v["claim_A_alice"]),
                &retained
            ),
            None,
            "the name it holds, again, is fine"
        );
        // Fresh keys may register until the relay-wide burst is spent.
        let fresh = policy(false, None);
        let retained = Retained::default();
        let mut admitted = 0;
        for i in 0..(NEW_NAMES_BURST as u8 + 5) {
            let (sk, pk) = local_key(100 + i);
            let name = format!("user{i:03}");
            let claim = serde_json::json!({ "v": 2, "name": name, "pk": pk, "ts": 1,
                "sig": local_sign(&sk, &serde_json::json!(["claim", name, name, pk, 1])) });
            match refuse(
                &fresh,
                &format!("hforum/u/{name}"),
                &bytes(&claim),
                &retained,
            ) {
                None => admitted += 1,
                Some(r) => assert_eq!(r, "claim: too many new names right now"),
            }
        }
        assert_eq!(admitted, NEW_NAMES_BURST as usize);
    }

    #[test]
    fn names_the_registrar_did_not_take_are_swept() {
        let v = vectors();
        let pol = policy(true, None);
        let mut retained = Retained::default();
        let long_ago = Instant::now() - Duration::from_secs(3600);
        // alice (listed to A), eve (unlisted), and a claim on bob by B
        // (listed to A): all kept an hour ago.
        retained.insert_at(
            "hforum/u/alice",
            bytes(&v["claim_A_alice"]),
            pol.meta("hforum/u/alice", &bytes(&v["claim_A_alice"])),
            long_ago,
        );
        let (sk, pk) = local_key(5);
        let eve = serde_json::json!({ "v": 2, "name": "eve", "pk": pk, "ts": 1,
            "sig": local_sign(&sk, &serde_json::json!(["claim", "eve", "eve", pk, 1])) });
        retained.insert_at(
            "hforum/u/eve",
            bytes(&eve),
            pol.meta("hforum/u/eve", &bytes(&eve)),
            long_ago,
        );
        let b_as_bob =
            serde_json::json!({ "v": 2, "name": "bob", "pk": v["B"], "ts": 1, "sig": "x" });
        retained.insert_at(
            "hforum/u/bob",
            bytes(&b_as_bob),
            pol.meta("hforum/u/bob", &bytes(&b_as_bob)),
            long_ago,
        );
        assert!(
            pol.sweep(&retained).is_empty(),
            "no list, nothing to judge by"
        );
        // A list kept just now, published long after those claims: alice stays,
        // eve and the stray bob go.
        keep(
            &mut retained,
            &pol,
            "hforum/registry",
            bytes(&v["registry_2"]),
        );
        let mut gone: Vec<String> = pol.sweep(&retained).iter().map(|t| t.to_string()).collect();
        gone.sort();
        assert_eq!(gone, vec!["hforum/u/bob", "hforum/u/eve"]);
        // A name kept after the list was: still pending at the registrar, kept.
        let (sk2, pk2) = local_key(6);
        let zed = serde_json::json!({ "v": 2, "name": "zed", "pk": pk2, "ts": 1,
            "sig": local_sign(&sk2, &serde_json::json!(["claim", "zed", "zed", pk2, 1])) });
        keep(&mut retained, &pol, "hforum/u/zed", bytes(&zed));
        let gone = pol.sweep(&retained);
        assert!(!gone.iter().any(|t| &t[..] == "hforum/u/zed"));
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
        keep(
            &mut retained,
            &pol,
            "hforum/u/alice",
            bytes(&v["claim_A_alice"]),
        );
        assert_eq!(
            refuse(&pol, topic, &bytes(&v["post_B_same_id"]), &retained),
            Some("post: nickname not claimed")
        );
        keep(
            &mut retained,
            &pol,
            "hforum/u/bob",
            bytes(&v["claim_A_bob"]),
        );
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
        keep(&mut retained, &pol, topic, bytes(&v["post_A"]));
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
        keep(&mut retained, &pol, topic, bytes(&v["tomb_A"]));
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
        keep(
            &mut retained,
            &pol,
            "hforum/r/tabcdefghij/rabcdefghij",
            bytes(&v["reply_A"]),
        );
        let (sk, pk) = local_key(9);
        let claim = serde_json::json!({ "v": 2, "name": "eve", "pk": pk, "ts": 1,
            "sig": local_sign(&sk, &serde_json::json!(["claim", "eve", "eve", pk, 1])) });
        keep(&mut retained, &pol, "hforum/u/eve", bytes(&claim));
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
        keep(&mut retained, &pol, "hforum/admin", bytes(&v["admin_A"]));
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
        // With a moderator named directly, that word wins.
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
        // The registrar's list names the moderator (its set-admin):
        // registry_2 carries A as admin.
        let by_list = policy(true, None);
        let mut retained = Retained::default();
        keep(
            &mut retained,
            &by_list,
            "hforum/registry",
            bytes(&v["registry_2"]),
        );
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
        keep(&mut retained, &by_list, "hforum/registry", bytes(&forged));
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
        keep(
            &mut retained,
            &pol,
            "hforum/registry",
            bytes(&v["registry_1"]),
        );
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
        // A list left by another key does not hold the sequence: the
        // registrar whose key the relay has starts over without being
        // locked out.
        let mut retained = Retained::default();
        let foreign = serde_json::json!({ "v": 1, "seq": 500, "ts": 1, "names": [], "admin": null, "sig": "x" });
        keep(&mut retained, &pol, "hforum/registry", bytes(&foreign));
        assert_eq!(
            refuse(&pol, "hforum/registry", &bytes(&v["registry_1"]), &retained),
            None,
            "sequence 1 is kept over a sequence 500 nobody can verify"
        );
        // An entry with a timestamp JavaScript would print differently is
        // refused as malformed rather than accepted and re-serialised.
        let mut odd = v["registry_2"].clone();
        odd["names"][0][3] = Value::from(18_446_744_073_709_552_000.0_f64);
        assert_eq!(
            refuse(&pol, "hforum/registry", &bytes(&odd), &Retained::default()),
            Some("registry: malformed")
        );
        odd["names"][0] = serde_json::json!(["alice", "Alice", "not a key", 1]);
        assert_eq!(
            refuse(&pol, "hforum/registry", &bytes(&odd), &Retained::default()),
            Some("registry: malformed")
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
            keep(
                &mut retained,
                &pol,
                &format!("hforum/rep/tabcdefghij/u{i}"),
                b"1"[..].into(),
            );
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

    #[test]
    fn metadata_is_what_admit_reads() {
        let v = vectors();
        let pol = policy(true, None);
        let m = pol.meta("hforum/t/tabcdefghij", &bytes(&v["post_A"]));
        assert_eq!(m.pk.as_deref(), v["A"].as_str());
        assert!(!m.tombstone);
        let m = pol.meta("hforum/t/tabcdefghij", &bytes(&v["tomb_A"]));
        assert!(m.tombstone);
        let m = pol.meta("hforum/registry", &bytes(&v["registry_2"]));
        assert_eq!(m.seq, Some(2));
        assert_eq!(
            pol.meta("hforum/rep/tabcdefghij/e27a", b"1"),
            Meta::default()
        );
        assert_eq!(
            pol.meta("hforum/t/tabcdefghij", b"not json"),
            Meta::default()
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
        keep(&mut retained, &pol, "hforum/u/zoe", bytes(&claim));
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
