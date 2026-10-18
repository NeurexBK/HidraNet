//! A signed list of nodes: how a new client learns which nodes exist, and
//! who runs them, without meeting anyone — and the trust anchor for a node's
//! identity (its key and its endpoint).
//!
//! The maintainers build `nodes.json` (the shape below) from the records the
//! nodes print, with `scripts/make-node-list.sh`, which signs it with the
//! LIST key (`hidravpn-sign sign --key list.key nodes.json`), and publish the
//! two files. A client imports them with `hidravpn nodes import`, or through
//! the browser; either way the signature is checked against the embedded
//! list key BEFORE the JSON is even parsed, and only then are the nodes
//! written down as *known*. A list nobody signed, or that was changed after
//! signing, or that was signed with another key, or that expired, or that is
//! older than the one already held, goes nowhere; a node the list names
//! under `removed` is struck from the pocket. A list newer than the one held
//! (a higher `sequence`) also brings up to date what the pocket holds about
//! a node that kept its key — its endpoint, operator, role, contact,
//! admission — known or admitted, so a node that moves servers is followed
//! without anyone rotating its key.
//!
//! ```json
//! { "version": 1,
//!   "generated": "2026-10-13T00:00:00Z",
//!   "note": "the first nodes, run by the maintainers; see docs/business/16",
//!   "nodes": [ { "node_name": "node-1", "node_public_key": "...",
//!                "endpoint": "203.0.113.10:51820",
//!                "operator": "the maintainers", "contact": "nodes@example.org" } ] }
//! ```
//!
//! What a list does NOT do: admit anyone by itself. A known node is a node
//! to ask admission from — the invite is what connects, and it carries the
//! client's own tunnel address, which no list for everyone can. A node whose
//! record says `"admission": "open"` answers that request itself
//! (`admission.rs`, `hidravpn nodes join`); one that admits by hand needs its
//! operator (`hidravpn-node admit`), and `nodes list` says whom to ask.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use std::net::SocketAddr;

use crate::keys::public_key_from_base64;
use crate::pocket::Pocket;
use crate::release::ReleaseKey;

/// The one shape this version of the client reads.
pub const DIRECTORY_VERSION: u32 = 1;

/// One node as a list names it: its identity and where it is, never a
/// client's address — that is an invite's business.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub node_name: String,
    /// The node's WireGuard public key, base64. A client derives the key it
    /// will show this node from it (`hidravpn pubkey --node`).
    pub node_public_key: String,
    /// Where the node listens, `ip:port`.
    pub endpoint: String,
    /// Who runs it, for people. Two hops through one operator are one
    /// operator's view, and a client should be able to tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// How to ask that operator for admission: an address, a page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// "entry", "exit" or "both": what the node lets itself be used as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// "open": the node admits any client that asks (`admission.rs`);
    /// "manual" or absent: its operator admits by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
    /// The TCP port of its admission service, when not the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_port: Option<u16>,
    /// Where the node is, as two letters (ISO 3166-1 alpha-2, "FI", "DE"):
    /// what a person reads to see the route, and what a client could use to
    /// put two hops in two countries. Said by whoever signs the list, not
    /// measured: a list is only as right as its signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// What this node's software can do beyond phase 4 (`features`): a
    /// client never asks a node for something its record does not list, so
    /// a node not yet updated is passed over instead of failing a
    /// connection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
}

/// What a node can do, as its record lists it.
pub mod features {
    /// Admits a key for one connection only (`"session": true`), against a
    /// proof of work, and forgets it soon after the connection ends.
    pub const SESSIONS: &str = "sessions";
    /// As an entry, forwards a client's admission request to an exit
    /// (TCP 51821), so the exit is asked from the entry's address.
    pub const ADMISSION_RELAY: &str = "admission-relay";
}

/// A country as two ASCII letters, upper case; anything else is refused, so
/// what reaches a page is always two letters and never markup or a sentence.
pub fn normalise_country(c: &str) -> Result<String> {
    let c = c.trim();
    if c.len() == 2 && c.chars().all(|ch| ch.is_ascii_alphabetic()) {
        Ok(c.to_ascii_uppercase())
    } else {
        Err(anyhow!(
            "a country is two letters (ISO 3166-1 alpha-2, such as FI or DE), not {c:?}"
        ))
    }
}

impl NodeRecord {
    pub fn validate(&self) -> Result<()> {
        if self.node_name.trim().is_empty() {
            return Err(anyhow!("a node in the list has no name"));
        }
        let name = self.node_name.trim();
        if name.len() > 32
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(anyhow!(
                "the name of a node must be 1-32 letters, digits, '-', '_' or '.': {name:?}"
            ));
        }
        if self
            .operator
            .as_deref()
            .map(|o| o.chars().count() > 64)
            .unwrap_or(false)
        {
            return Err(anyhow!(
                "the operator of {} is longer than 64 characters",
                name
            ));
        }
        if self
            .contact
            .as_deref()
            .map(|c| c.chars().count() > 128)
            .unwrap_or(false)
        {
            return Err(anyhow!(
                "the contact of {} is longer than 128 characters",
                name
            ));
        }
        public_key_from_base64(&self.node_public_key)
            .with_context(|| format!("the key of {} in the list", self.node_name))?;
        let endpoint = self
            .endpoint
            .parse::<SocketAddr>()
            .with_context(|| format!("the endpoint of {} is not ip:port", self.node_name))?;
        if !endpoint.is_ipv4() {
            // A client routes all of IPv6 into the tunnel, so its own packets
            // to an IPv6 node would never reach it.
            return Err(anyhow!(
                "the endpoint of {} is an IPv6 address; a node is reached over IPv4 in this phase",
                self.node_name
            ));
        }
        if let Some(c) = self.country.as_deref() {
            normalise_country(c).with_context(|| format!("the country of {}", self.node_name))?;
        }
        if let Some(r) = self.role.as_deref() {
            if !matches!(
                r.trim().to_ascii_lowercase().as_str(),
                "entry" | "exit" | "both"
            ) {
                return Err(anyhow!(
                    "the role of {} must be entry, exit or both",
                    self.node_name
                ));
            }
        }
        if let Some(a) = self.admission.as_deref() {
            if !matches!(
                a.trim().to_ascii_lowercase().as_str(),
                "open" | "manual" | "pass"
            ) {
                return Err(anyhow!(
                    "the admission of {} must be open, manual or pass",
                    self.node_name
                ));
            }
        }
        if self.features.len() > 16
            || self.features.iter().any(|f| {
                f.is_empty()
                    || f.len() > 32
                    || !f.chars().all(|c| c.is_ascii_lowercase() || c == '-')
            })
        {
            return Err(anyhow!(
                "the features of {} must be at most 16 short lower-case words",
                self.node_name
            ));
        }
        Ok(())
    }

    /// Whether the record lists this feature.
    pub fn has(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    pub fn is_open(&self) -> bool {
        self.admission
            .as_deref()
            .map(|a| a.trim().eq_ignore_ascii_case("open"))
            == Some(true)
    }

    /// Whether the node admits a client that redeems a pass (phase 5).
    pub fn takes_passes(&self) -> bool {
        self.admission
            .as_deref()
            .map(|a| a.trim().eq_ignore_ascii_case("pass"))
            == Some(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directory {
    pub version: u32,
    /// When the list was made (RFC 3339), for people; nothing is decided by it.
    #[serde(default)]
    pub generated: String,
    /// Goes up with every list published. A client refuses a list older
    /// than the one it has, so a list kept from before a node was withdrawn
    /// cannot bring it back.
    #[serde(default)]
    pub sequence: u64,
    /// After this (RFC 3339) the list is not imported: a stale list is worse
    /// than none, because the nodes it names may be gone or taken over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Public keys of nodes withdrawn: compromised, retired, taken over. A
    /// client removes them, known or admitted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default)]
    pub nodes: Vec<NodeRecord>,
    /// Who issues passes, for nodes that admit with one (phase 5): where to
    /// ask, and the keys passes are signed under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_issuer: Option<PassIssuer>,
}

/// The pass issuer a list names.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PassIssuer {
    /// `https://...` (plain HTTP only on a private network).
    pub url: String,
    pub keys: Vec<crate::pass::PassKeyRecord>,
}

impl PassIssuer {
    pub fn validate(&self) -> Result<()> {
        crate::http::Url::parse(&self.url).context("the pass issuer's address")?;
        if self.keys.is_empty() {
            return Err(anyhow!("the pass issuer names no key"));
        }
        for k in &self.keys {
            k.validate()?;
        }
        Ok(())
    }
}

/// What an import did: which nodes went in, and which were left out and why
/// (already in the pocket, usually).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Merge {
    pub added: Vec<String>,
    pub skipped: Vec<(String, String)>,
    #[serde(default)]
    pub removed: Vec<String>,
    /// Nodes already in the pocket whose record a newer list brought up to
    /// date, and what changed about each.
    #[serde(default)]
    pub updated: Vec<(String, String)>,
}

impl Merge {
    pub fn summary(&self) -> String {
        let mut s = format!("added {} node(s)", self.added.len());
        if !self.updated.is_empty() {
            s.push_str(&format!(", updated {}", self.updated.len()));
        }
        if !self.skipped.is_empty() {
            s.push_str(&format!(", skipped {}", self.skipped.len()));
        }
        if !self.removed.is_empty() {
            s.push_str(&format!(", removed {}", self.removed.len()));
        }
        s
    }
}

impl Directory {
    /// Verifies the signature over the exact bytes, then parses and checks
    /// every invite. Nothing is read from the list before the signature holds.
    pub fn from_signed(list: &[u8], signature_b64: &str, key: &ReleaseKey) -> Result<Directory> {
        key.verify(list, signature_b64)
            .context("the node list is not accepted")?;
        let text = std::str::from_utf8(list).context("the node list is not UTF-8")?;
        Directory::from_json_unchecked(text)
    }

    /// Parses a list WITHOUT checking a signature. For the maintainers'
    /// tooling and for tests; everything a client does goes through
    /// `from_signed`.
    pub fn from_json_unchecked(text: &str) -> Result<Directory> {
        let d: Directory = serde_json::from_str(text).context("the node list is not valid JSON")?;
        if d.version != DIRECTORY_VERSION {
            return Err(anyhow!(
                "the node list is version {}; this client reads version {}",
                d.version,
                DIRECTORY_VERSION
            ));
        }
        if d.nodes.is_empty() && d.removed.is_empty() {
            return Err(anyhow!("the node list names no nodes"));
        }
        for n in &d.nodes {
            n.validate()?;
        }
        if let Some(e) = d.expires.as_deref() {
            crate::timefmt::rfc3339_to_unix(e).context("the list's expiry")?;
        }
        for k in &d.removed {
            public_key_from_base64(k).context("a removed key in the list")?;
        }
        if let Some(p) = &d.pass_issuer {
            p.validate()?;
        }
        Ok(d)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a directory always serialises")
    }

    /// Applies the list to the pocket: withdrawn nodes go, known or
    /// admitted; the rest are written down as known. A node this machine is
    /// already admitted on, or already knows, is brought up to date when the
    /// list is newer than the one the pocket holds (its sequence is higher)
    /// and its record changed, and skipped, with the reason, otherwise;
    /// nothing else is removed or reordered, so what the person added by
    /// hand stays. The pocket remembers the list's sequence.
    pub fn merge_into(&self, pocket: &mut Pocket) -> Merge {
        let mut m = Merge::default();
        let newer = self.sequence > pocket.list_sequence;
        for key in &self.removed {
            m.removed.extend(pocket.remove_by_key(key));
        }
        for n in &self.nodes {
            if self
                .removed
                .iter()
                .any(|k| k.trim() == n.node_public_key.trim())
            {
                continue;
            }
            match pocket.learn(n.clone()) {
                Ok(()) => m.added.push(n.node_name.clone()),
                Err(e) => {
                    let changed = if newer { pocket.refresh(n) } else { Vec::new() };
                    if changed.is_empty() {
                        m.skipped.push((n.node_name.clone(), e.to_string()));
                    } else {
                        m.updated.push((n.node_name.clone(), changed.join(", ")));
                    }
                }
            }
        }
        if self.sequence > pocket.list_sequence {
            pocket.list_sequence = self.sequence;
        }
        // The issuer comes with the newest list: a newer list without one
        // takes it away, an older one cannot bring an old one back.
        if newer || pocket.pass_issuer.is_none() {
            pocket.pass_issuer = self.pass_issuer.clone();
        }
        m
    }

    /// Why this list must not be applied now, if it must not: expired, or
    /// older than the one already imported.
    pub fn check_current(&self, pocket: &Pocket, now_unix: i64) -> Result<()> {
        if let Some(e) = self.expires.as_deref() {
            let until = crate::timefmt::rfc3339_to_unix(e)?;
            if now_unix > until {
                return Err(anyhow!(
                    "the node list expired on {e}; get a newer one, a stale list may name nodes that are gone or taken over"
                ));
            }
        }
        if self.sequence < pocket.list_sequence {
            return Err(anyhow!(
                "the node list is older (sequence {}) than the one already imported (sequence {}); refusing to go back",
                self.sequence,
                pocket.list_sequence
            ));
        }
        Ok(())
    }
}

/// The whole import, as the command line and the service both do it: with the
/// key given (the embedded list key, normally), verify, parse, check it is
/// current, merge. With no key there is no import, and the message says why.
pub fn import_signed(
    pocket: &mut Pocket,
    list: &[u8],
    signature_b64: &str,
    key: Option<&ReleaseKey>,
) -> Result<Merge> {
    import_signed_at(pocket, list, signature_b64, key, crate::timefmt::now_unix())
}

/// `import_signed` with the clock given, for tests.
pub fn import_signed_at(
    pocket: &mut Pocket,
    list: &[u8],
    signature_b64: &str,
    key: Option<&ReleaseKey>,
    now_unix: i64,
) -> Result<Merge> {
    let key = key.ok_or_else(|| {
        anyhow!(
            "this build carries no list key, so it cannot check a node list; a key given explicitly (`hidravpn nodes import --pubkey ...`) must have come to you by another channel than the list"
        )
    })?;
    let dir = Directory::from_signed(list, signature_b64, key)?;
    dir.check_current(pocket, now_unix)?;
    Ok(dir.merge_into(pocket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Invite;
    use crate::keys::ClientKey;
    use crate::pocket::Slot;
    use crate::release::testing::TestSigner;

    fn record(name: &str, endpoint: &str) -> NodeRecord {
        NodeRecord {
            node_name: name.into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: endpoint.into(),
            operator: Some("the maintainers".into()),
            contact: Some("nodes@example.org".into()),
            role: Some("both".into()),
            admission: Some("open".into()),
            admission_port: None,
            country: None,
            features: Vec::new(),
        }
    }

    fn invite_for(r: &NodeRecord) -> Invite {
        Invite {
            node_name: r.node_name.clone(),
            node_public_key: r.node_public_key.clone(),
            endpoint: r.endpoint.clone(),
            client_address: "10.77.0.2/16".into(),
            client_address6: None,
            dns: std::net::Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1420,
            keepalive: 25,
            operator: r.operator.clone(),
            role: r.role.clone(),
            pass: None,
            country: None,
            admission: None,
            admission_port: None,
            behind: false,
            features: Vec::new(),
        }
    }

    fn directory() -> Directory {
        Directory {
            version: 1,
            generated: "2026-10-13T00:00:00Z".into(),
            sequence: 3,
            expires: Some("2026-12-31T00:00:00Z".into()),
            removed: vec![],
            note: Some("the first nodes".into()),
            nodes: vec![
                record("node-1", "203.0.113.10:51820"),
                record("node-2", "203.0.113.11:51820"),
                record("node-3", "203.0.113.20:51820"),
            ],
            pass_issuer: None,
        }
    }

    #[test]
    fn a_country_is_two_letters_and_reaches_an_admitted_node_from_a_newer_list() {
        assert_eq!(normalise_country(" fi ").unwrap(), "FI");
        for bad in ["", "F", "FIN", "F1", "<b>", "🇫🇮"] {
            assert!(normalise_country(bad).is_err(), "{bad:?} must be refused");
        }
        let mut r = record("node-1", "203.0.113.10:51820");
        r.country = Some("Finland".into());
        assert!(r.validate().is_err(), "a country in words is refused");
        r.country = Some("fi".into());
        r.validate().unwrap();

        // Admitted without a country; a newer list says where the node is.
        let mut pocket = Pocket::default();
        let plain = record("node-1", "203.0.113.10:51820");
        pocket.add(Slot::Exit, invite_for(&plain)).unwrap();
        let mut placed = plain.clone();
        placed.country = Some("FI".into());
        let changed = pocket.refresh(&placed);
        assert!(changed.contains(&"country".to_string()), "{changed:?}");
        let (_, inv) = pocket.iter().next().unwrap();
        assert_eq!(inv.country.as_deref(), Some("FI"));
    }

    #[test]
    fn a_signed_list_makes_nodes_known_and_none_of_them_connectable() {
        let signer = TestSigner::new();
        let json = directory().to_json();
        let sig = signer.sign(json.as_bytes());
        let mut pocket = Pocket::default();
        let m = import_signed(&mut pocket, json.as_bytes(), &sig, Some(&signer.public())).unwrap();
        assert_eq!(m.added, vec!["node-1", "node-2", "node-3"]);
        assert!(m.skipped.is_empty());
        assert_eq!(pocket.known.len(), 3);
        assert!(pocket.is_empty(), "known nodes are not nodes to connect to");
        assert!(pocket.pick_rapido().is_err());
        assert_eq!(m.summary(), "added 3 node(s)");
        // The list never carried a client address, and the pocket file does
        // not grow one for a known node.
        assert!(!json.contains("client_address"));
        assert!(!pocket.to_json().contains("client_address"));
    }

    #[test]
    fn admission_turns_a_known_node_into_one_to_connect_to() {
        let dir = directory();
        let mut pocket = Pocket::default();
        dir.merge_into(&mut pocket);
        // The operator of node-1 admits this machine: the invite goes in, the
        // record goes away, and a second import does not bring it back.
        pocket.add(Slot::Exit, invite_for(&dir.nodes[0])).unwrap();
        assert_eq!(pocket.known.len(), 2);
        assert_eq!(pocket.exits.len(), 1);
        let again = dir.merge_into(&mut pocket);
        assert!(again.added.is_empty());
        assert_eq!(again.skipped.len(), 3);
        assert!(
            again.skipped[0].1.contains("already admitted"),
            "{}",
            again.skipped[0].1
        );
        assert!(
            again.skipped[1].1.contains("already known"),
            "{}",
            again.skipped[1].1
        );
        assert!(pocket.pick_rapido().is_ok());
        // Removing by name removes a known node too.
        assert_eq!(pocket.remove("node-2"), 1);
        assert_eq!(pocket.known.len(), 1);
    }

    #[test]
    fn a_changed_list_a_wrong_key_or_no_key_makes_nothing_known() {
        let signer = TestSigner::new();
        let json = directory().to_json();
        let sig = signer.sign(json.as_bytes());
        let mut pocket = Pocket::default();

        let tampered = json.replace("203.0.113.10", "198.51.100.99");
        let e = import_signed(
            &mut pocket,
            tampered.as_bytes(),
            &sig,
            Some(&signer.public()),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("not accepted"), "{e}");
        assert!(pocket.known.is_empty());

        let other = TestSigner::new();
        import_signed(&mut pocket, json.as_bytes(), &sig, Some(&other.public())).unwrap_err();
        assert!(pocket.known.is_empty());

        let e = import_signed(&mut pocket, json.as_bytes(), &sig, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains("no list key"), "{e}");
        assert!(pocket.known.is_empty());

        // The signature is checked before the JSON is parsed.
        let junk = b"{ not json";
        let e = Directory::from_signed(junk, &signer.sign(junk), &signer.public())
            .unwrap_err()
            .to_string();
        assert!(e.contains("not valid JSON"), "{e}");
        let e = Directory::from_signed(junk, &sig, &signer.public())
            .unwrap_err()
            .to_string();
        assert!(e.contains("not accepted"), "{e}");
    }

    #[test]
    fn another_version_an_empty_list_or_a_bad_record_is_refused() {
        let mut d = directory();
        d.version = 2;
        let e = Directory::from_json_unchecked(&d.to_json())
            .unwrap_err()
            .to_string();
        assert!(e.contains("version 2"), "{e}");
        let e = Directory::from_json_unchecked(r#"{"version":1}"#)
            .unwrap_err()
            .to_string();
        assert!(e.contains("names no nodes"), "{e}");
        let mut d = directory();
        d.nodes[0].role = Some("relay".into());
        assert!(Directory::from_json_unchecked(&d.to_json()).is_err());
        let mut d = directory();
        d.expires = Some("soon".into());
        assert!(Directory::from_json_unchecked(&d.to_json()).is_err());
        let mut d = directory();
        d.nodes[0].endpoint = "not-an-endpoint".into();
        let e = Directory::from_json_unchecked(&d.to_json())
            .unwrap_err()
            .to_string();
        assert!(e.contains("node-1"), "{e}");
        let mut d = directory();
        d.nodes[1].node_public_key = "short".into();
        assert!(Directory::from_json_unchecked(&d.to_json()).is_err());
        let mut d = directory();
        d.nodes[2].node_name = " ".into();
        assert!(Directory::from_json_unchecked(&d.to_json()).is_err());
        let mut d = directory();
        d.nodes[0].endpoint = "[2001:db8::10]:51820".into();
        let e = Directory::from_json_unchecked(&d.to_json())
            .unwrap_err()
            .to_string();
        assert!(e.contains("IPv6") && e.contains("node-1"), "{e}");
    }

    #[test]
    fn a_newer_list_follows_a_node_that_kept_its_key_and_the_same_list_does_not() {
        let signer = TestSigner::new();
        let dir = directory(); // sequence 3
        let json = dir.to_json();
        let now = crate::timefmt::rfc3339_to_unix("2026-10-13T12:00:00Z").unwrap();
        let mut pocket = Pocket::default();
        import_signed_at(
            &mut pocket,
            json.as_bytes(),
            &signer.sign(json.as_bytes()),
            Some(&signer.public()),
            now,
        )
        .unwrap();
        // node-2 admitted this machine: it is an exit now.
        pocket.add(Slot::Exit, invite_for(&dir.nodes[1])).unwrap();

        // The same sequence with a changed address is a maintainer's slip,
        // not a newer list: skipped, and the pocket keeps what it had.
        let mut same = directory();
        same.nodes = dir.nodes.clone();
        same.nodes[0].endpoint = "203.0.113.99:51820".into();
        let j = same.to_json();
        let m = import_signed_at(
            &mut pocket,
            j.as_bytes(),
            &signer.sign(j.as_bytes()),
            Some(&signer.public()),
            now,
        )
        .unwrap();
        assert!(m.updated.is_empty(), "{m:?}");
        assert_eq!(m.skipped.len(), 3);
        assert_eq!(pocket.known[0].endpoint, "203.0.113.10:51820");

        // A newer list: node-1 moved servers; node-2 moved too and is now an
        // entry only; node-3 is as it was.
        let mut next = directory();
        next.sequence = 4;
        next.nodes = dir.nodes.clone();
        next.nodes[0].endpoint = "203.0.113.99:51820".into();
        next.nodes[1].endpoint = "203.0.113.98:51820".into();
        next.nodes[1].role = Some("entry".into());
        let j = next.to_json();
        let m = import_signed_at(
            &mut pocket,
            j.as_bytes(),
            &signer.sign(j.as_bytes()),
            Some(&signer.public()),
            now,
        )
        .unwrap();
        assert!(m.added.is_empty());
        assert_eq!(m.skipped.len(), 1, "{m:?}");
        assert_eq!(m.updated.len(), 2, "{m:?}");
        assert_eq!(m.updated[0].0, "node-1");
        assert_eq!(m.updated[0].1, "endpoint");
        assert_eq!(m.updated[1].0, "node-2");
        assert!(
            m.updated[1].1.contains("endpoint") && m.updated[1].1.contains("role"),
            "{}",
            m.updated[1].1
        );
        assert!(
            m.updated[1].1.contains("no longer an exit")
                && m.updated[1].1.contains("now also an entry"),
            "{}",
            m.updated[1].1
        );
        assert!(m.summary().contains("updated 2"), "{}", m.summary());
        let known1 = pocket
            .known
            .iter()
            .find(|k| k.node_name == "node-1")
            .unwrap();
        assert_eq!(known1.endpoint, "203.0.113.99:51820");
        assert!(
            pocket.exits.is_empty(),
            "node-2 is no longer offered as an exit"
        );
        assert_eq!(pocket.entries.len(), 1);
        assert_eq!(pocket.entries[0].endpoint, "203.0.113.98:51820");
        assert_eq!(pocket.entries[0].role.as_deref(), Some("entry"));
        // What the node's admission gave stays.
        assert_eq!(pocket.entries[0].client_address, "10.77.0.2/16");
        assert_eq!(pocket.list_sequence, 4);
    }

    #[test]
    fn an_expired_or_older_list_is_refused_and_a_withdrawal_removes_the_node() {
        let signer = TestSigner::new();
        let dir = directory();
        let json = dir.to_json();
        let sig = signer.sign(json.as_bytes());
        let now = crate::timefmt::rfc3339_to_unix("2026-10-13T12:00:00Z").unwrap();
        let mut pocket = Pocket::default();
        import_signed_at(
            &mut pocket,
            json.as_bytes(),
            &sig,
            Some(&signer.public()),
            now,
        )
        .unwrap();
        assert_eq!(pocket.list_sequence, 3);
        assert_eq!(pocket.joinable().len(), 3, "all three admit openly");

        // After the expiry: refused, pocket untouched.
        let later = crate::timefmt::rfc3339_to_unix("2027-01-01T00:00:00Z").unwrap();
        let e = import_signed_at(
            &mut pocket,
            json.as_bytes(),
            &sig,
            Some(&signer.public()),
            later,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("expired"), "{e}");
        assert_eq!(pocket.known.len(), 3);

        // An older sequence: refused.
        let mut old = directory();
        old.sequence = 2;
        let old_json = old.to_json();
        let e = import_signed_at(
            &mut pocket,
            old_json.as_bytes(),
            &signer.sign(old_json.as_bytes()),
            Some(&signer.public()),
            now,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("older"), "{e}");

        // The next list withdraws node-2, which this machine had even been
        // admitted on: it goes, known or admitted, and does not come back.
        pocket.add(Slot::Exit, invite_for(&dir.nodes[1])).unwrap();
        let mut next = directory();
        next.sequence = 4;
        next.removed = vec![dir.nodes[1].node_public_key.clone()];
        next.nodes = dir.nodes.clone();
        let next_json = next.to_json();
        let m = import_signed_at(
            &mut pocket,
            next_json.as_bytes(),
            &signer.sign(next_json.as_bytes()),
            Some(&signer.public()),
            now,
        )
        .unwrap();
        assert_eq!(m.removed, vec!["node-2"]);
        assert!(pocket.exits.is_empty());
        assert!(!pocket.known.iter().any(|k| k.node_name == "node-2"));
        assert_eq!(pocket.list_sequence, 4);
        assert!(m.summary().contains("removed 1"));
    }
}
