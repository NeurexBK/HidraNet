//! The pocket: the entry and exit nodes a client holds invites for, so that
//! `up --privado` and `new-identity` can pick among them instead of being
//! handed one invite at a time.
//!
//! It is a JSON file the client manages (`hidravpn nodes add|list|remove`):
//!
//! ```json
//! { "entries": [ ...invites... ], "exits": [ ...invites... ] }
//! ```
//!
//! Choices are uniform, from the operating system's randomness, and never
//! logged. Listing a pocket names nodes and endpoints, never keys.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::Invite;
use crate::directory::NodeRecord;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pocket {
    #[serde(default)]
    pub entries: Vec<Invite>,
    #[serde(default)]
    pub exits: Vec<Invite>,
    /// Nodes this machine knows of but is not admitted on: what a signed
    /// node list brings. They cannot be connected to; once the node's
    /// operator admits this machine's key and the invite is added above, the
    /// record here goes away.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known: Vec<NodeRecord>,
    /// The sequence number of the last node list imported; an older list is
    /// refused, so a list someone kept from before a node was withdrawn
    /// cannot bring it back.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub list_sequence: u64,
    /// The pass issuer the newest list named (phase 5): where passes for the
    /// nodes that admit with one come from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass_issuer: Option<crate::directory::PassIssuer>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Which list of the pocket a node goes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Entry,
    Exit,
}

/// What `up --privado` or `up --rapido` picked: the exit, the entry (two
/// hops only), and the rest of each list, for `new-identity` to rotate to.
#[derive(Debug, Clone)]
pub struct Pick {
    pub exit: Invite,
    pub entry: Option<Invite>,
    pub other_exits: Vec<Invite>,
    pub other_entries: Vec<Invite>,
    /// Two hops: are both run by the same operator, as far as the invites
    /// say? `None` for one hop, or when either invite does not say.
    pub same_operator: Option<bool>,
}

impl Pocket {
    pub fn from_json(s: &str) -> Result<Self> {
        let p: Pocket = serde_json::from_str(s).context("the pocket is not valid JSON")?;
        // Shape only: an invite an older version accepted stays readable;
        // building a circuit with it checks it in full.
        for inv in p.entries.iter().chain(p.exits.iter()) {
            inv.validate_shape()
                .with_context(|| format!("the invite for {} in the pocket", inv.node_name))?;
        }
        Ok(p)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a pocket always serialises")
    }

    /// Adds an invite to one list. A name is the handle `remove` uses, so
    /// two different nodes cannot share one; the same node (same key) may be
    /// in both lists under its one name, but not twice in one list.
    pub fn add(&mut self, slot: Slot, invite: Invite) -> Result<()> {
        invite.validate()?;
        let name = invite.node_name.trim();
        if name.is_empty() {
            return Err(anyhow!("the invite has no node name"));
        }
        if self.iter().any(|(_, i)| {
            i.node_name.trim() == name && i.node_public_key.trim() != invite.node_public_key.trim()
        }) {
            return Err(anyhow!(
                "another node named \"{name}\" is already in the pocket; remove it first"
            ));
        }
        let list = self.list_mut(slot);
        if list
            .iter()
            .any(|i| i.node_public_key.trim() == invite.node_public_key.trim())
        {
            return Err(anyhow!(
                "that node is already in the pocket as an {} (same key)",
                slot_name(slot)
            ));
        }
        let key = invite.node_public_key.trim().to_string();
        list.push(invite);
        // Admitted now: no longer merely known.
        self.known.retain(|k| k.node_public_key.trim() != key);
        Ok(())
    }

    /// A node from a signed list, not yet admitted. Skipped, with the
    /// reason, when the machine is already admitted on it or already knows
    /// it.
    pub fn learn(&mut self, record: NodeRecord) -> Result<()> {
        record.validate()?;
        let key = record.node_public_key.trim();
        if self.iter().any(|(_, i)| i.node_public_key.trim() == key) {
            return Err(anyhow!("already admitted on this node"));
        }
        if self.known.iter().any(|k| k.node_public_key.trim() == key) {
            return Err(anyhow!("already known"));
        }
        self.known.push(record);
        Ok(())
    }

    /// Brings what the pocket holds about a node up to date with its record
    /// in a newer signed list: the same key, newer facts. A known record is
    /// replaced. An admitted invite keeps what the node's admission gave it
    /// (the client's address, the DNS, the MTU) and takes the list's
    /// endpoint, operator, role and name; its slots follow the role when the
    /// list gives one. Returns what changed, in words for a person; empty
    /// when nothing did, or when the key is not in the pocket at all.
    pub fn refresh(&mut self, record: &NodeRecord) -> Vec<String> {
        let key = record.node_public_key.trim();
        let mut changed: Vec<String> = Vec::new();
        if let Some(k) = self
            .known
            .iter_mut()
            .find(|k| k.node_public_key.trim() == key)
        {
            let fields = [
                ("name", k.node_name.trim() != record.node_name.trim()),
                ("endpoint", k.endpoint.trim() != record.endpoint.trim()),
                ("operator", k.operator != record.operator),
                ("contact", k.contact != record.contact),
                ("role", k.role != record.role),
                ("admission", k.admission != record.admission),
                ("admission port", k.admission_port != record.admission_port),
                ("country", k.country != record.country),
            ];
            changed.extend(
                fields
                    .iter()
                    .filter(|(_, differs)| *differs)
                    .map(|(name, _)| name.to_string()),
            );
            if !changed.is_empty() {
                *k = record.clone();
            }
            return changed;
        }
        if !self.iter().any(|(_, i)| i.node_public_key.trim() == key) {
            return changed;
        }
        // Another node may already carry the name the list gives this one;
        // then the name stays, since it is the handle `remove` uses.
        let name_taken = self.iter().any(|(_, i)| {
            i.node_name.trim() == record.node_name.trim() && i.node_public_key.trim() != key
        });
        for inv in self
            .entries
            .iter_mut()
            .chain(self.exits.iter_mut())
            .filter(|i| i.node_public_key.trim() == key)
        {
            if inv.endpoint.trim() != record.endpoint.trim() {
                inv.endpoint = record.endpoint.clone();
                changed.push("endpoint".into());
            }
            if inv.operator != record.operator {
                inv.operator = record.operator.clone();
                changed.push("operator".into());
            }
            if inv.role != record.role {
                inv.role = record.role.clone();
                changed.push("role".into());
            }
            if inv.country != record.country {
                inv.country = record.country.clone();
                changed.push("country".into());
            }
            if !name_taken && inv.node_name.trim() != record.node_name.trim() {
                inv.node_name = record.node_name.clone();
                changed.push("name".into());
            }
        }
        changed.sort();
        changed.dedup();
        // The slots follow the role the list gives, when it gives one: a
        // node that became an entry is no longer offered as an exit.
        if record.role.is_some() {
            let allowed = slots_for_role(record.role.as_deref());
            let copy = self
                .iter()
                .find(|(_, i)| i.node_public_key.trim() == key)
                .map(|(_, i)| i.clone());
            for slot in [Slot::Entry, Slot::Exit] {
                let has = self
                    .list_mut(slot)
                    .iter()
                    .any(|i| i.node_public_key.trim() == key);
                if allowed.contains(&slot) && !has {
                    if let Some(inv) = copy.clone() {
                        self.list_mut(slot).push(inv);
                        changed.push(format!("now also an {}", slot_name(slot)));
                    }
                } else if !allowed.contains(&slot) && has {
                    self.list_mut(slot)
                        .retain(|i| i.node_public_key.trim() != key);
                    changed.push(format!("no longer an {}", slot_name(slot)));
                }
            }
        }
        changed
    }

    /// Removes every node with that name, from both lists. Returns how many.
    pub fn remove(&mut self, name: &str) -> usize {
        let name = name.trim();
        let before = self.entries.len() + self.exits.len() + self.known.len();
        self.entries.retain(|i| i.node_name.trim() != name);
        self.exits.retain(|i| i.node_name.trim() != name);
        self.known.retain(|k| k.node_name.trim() != name);
        before - self.entries.len() - self.exits.len() - self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.exits.is_empty()
    }

    /// Removes every node with that key, admitted or known. Returns the
    /// names removed.
    pub fn remove_by_key(&mut self, key: &str) -> Vec<String> {
        let key = key.trim();
        let mut names = Vec::new();
        for i in self.iter().filter(|(_, i)| i.node_public_key.trim() == key) {
            names.push(i.1.node_name.clone());
        }
        for k in self
            .known
            .iter()
            .filter(|k| k.node_public_key.trim() == key)
        {
            names.push(k.node_name.clone());
        }
        self.entries.retain(|i| i.node_public_key.trim() != key);
        self.exits.retain(|i| i.node_public_key.trim() != key);
        self.known.retain(|k| k.node_public_key.trim() != key);
        names.sort();
        names.dedup();
        names
    }

    /// Known nodes this machine could ask admission from without meeting
    /// anyone: the ones whose record says admission is open.
    pub fn joinable(&self) -> Vec<&NodeRecord> {
        self.known
            .iter()
            .filter(|k| k.is_open() || k.takes_passes())
            .collect()
    }

    /// Puts a fresh invite for a node in place of the one it replaces (same
    /// key), in every list the old one was in, or in the slots its role
    /// allows when it was not there: what redeeming the next pass for a node
    /// does. The record goes from `known`, as with `add`.
    pub fn replace(&mut self, invite: Invite) -> Result<()> {
        invite.validate()?;
        let key = invite.node_public_key.trim().to_string();
        let mut placed = false;
        for inv in self
            .entries
            .iter_mut()
            .chain(self.exits.iter_mut())
            .filter(|i| i.node_public_key.trim() == key)
        {
            *inv = invite.clone();
            placed = true;
        }
        if !placed {
            for slot in slots_for_role(invite.role.as_deref()) {
                self.add(slot, invite.clone())?;
            }
        }
        self.known.retain(|k| k.node_public_key.trim() != key);
        Ok(())
    }

    /// Every node in the pocket with its slot, entries first.
    pub fn iter(&self) -> impl Iterator<Item = (Slot, &Invite)> {
        self.entries
            .iter()
            .map(|i| (Slot::Entry, i))
            .chain(self.exits.iter().map(|i| (Slot::Exit, i)))
    }

    /// One exit, at random. The other exits come along for rotation.
    pub fn pick_rapido(&self) -> Result<Pick> {
        if self.exits.is_empty() {
            return Err(anyhow!(
                "the pocket has no exit node; add one with `hidravpn nodes add --exit exit.json`"
            ));
        }
        let mut exits = self.exits.clone();
        let exit = exits.remove(crate::random::index(exits.len())?);
        Ok(Pick {
            exit,
            entry: None,
            other_exits: exits,
            other_entries: Vec::new(),
            same_operator: None,
        })
    }

    /// One exit and one entry, at random, that are two different nodes. The
    /// other exits and entries come along for rotation.
    pub fn pick_privado(&self) -> Result<Pick> {
        if self.exits.is_empty() {
            return Err(anyhow!(
                "the pocket has no exit node; add one with `hidravpn nodes add --exit exit.json`"
            ));
        }
        if self.entries.is_empty() {
            return Err(anyhow!(
                "the pocket has no entry node; add one with `hidravpn nodes add --entry entry.json`"
            ));
        }
        // Every (entry, exit) pair of two different nodes; among them, the
        // pairs run by two different operators when there are any, because
        // two hops under one operator are one operator's view. One of those
        // at random, so no pair is favoured.
        let pairs: Vec<(usize, usize)> = (0..self.entries.len())
            .flat_map(|e| (0..self.exits.len()).map(move |x| (e, x)))
            .filter(|&(e, x)| !same_node(&self.entries[e], &self.exits[x]))
            .collect();
        if pairs.is_empty() {
            return Err(anyhow!(
                "every entry in the pocket is the same node as every exit; two hops need two different nodes"
            ));
        }
        let different: Vec<(usize, usize)> = pairs
            .iter()
            .copied()
            .filter(|&(e, x)| same_operator(&self.entries[e], &self.exits[x]) == Some(false))
            .collect();
        let pairs = if different.is_empty() {
            pairs
        } else {
            different
        };
        let (e, x) = pairs[crate::random::index(pairs.len())?];
        let same_operator = same_operator(&self.entries[e], &self.exits[x]);
        let mut exits = self.exits.clone();
        let exit = exits.remove(x);
        let mut entries = self.entries.clone();
        let entry = entries.remove(e);
        Ok(Pick {
            exit,
            entry: Some(entry),
            other_exits: exits,
            other_entries: entries,
            same_operator,
        })
    }

    fn list_mut(&mut self, slot: Slot) -> &mut Vec<Invite> {
        match slot {
            Slot::Entry => &mut self.entries,
            Slot::Exit => &mut self.exits,
        }
    }
}

/// Two invites name the same node when they carry the same key or the same
/// endpoint — the same test `CircuitSpec::validate` makes.
pub fn same_node(a: &Invite, b: &Invite) -> bool {
    a.node_public_key.trim() == b.node_public_key.trim()
        || matches!((a.endpoint_addr(), b.endpoint_addr()), (Ok(x), Ok(y)) if x == y)
}

/// Whether two invites name the same operator: `Some(true)` or `Some(false)`
/// when both say who runs them, `None` when either does not.
pub fn same_operator(a: &Invite, b: &Invite) -> Option<bool> {
    match (a.operator.as_deref(), b.operator.as_deref()) {
        (Some(x), Some(y)) if !x.trim().is_empty() && !y.trim().is_empty() => {
            Some(x.trim().eq_ignore_ascii_case(y.trim()))
        }
        _ => None,
    }
}

/// The lists a node of a given role goes in: an entry in the entries, an
/// exit in the exits, a node that is both in both.
pub fn slots_for_role(role: Option<&str>) -> Vec<Slot> {
    match role.map(|r| r.trim().to_ascii_lowercase()).as_deref() {
        Some("entry") => vec![Slot::Entry],
        Some("exit") => vec![Slot::Exit],
        _ => vec![Slot::Entry, Slot::Exit],
    }
}

pub fn slot_name(slot: Slot) -> &'static str {
    match slot {
        Slot::Entry => "entry",
        Slot::Exit => "exit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ClientKey;
    use std::net::Ipv4Addr;

    fn invite(name: &str, endpoint: &str) -> Invite {
        Invite {
            node_name: name.into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: endpoint.into(),
            client_address: "10.77.0.2/16".into(),
            dns: Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1420,
            keepalive: 25,
            operator: None,
            role: None,
            pass: None,
            country: None,
        }
    }

    fn run_by(mut inv: Invite, op: &str) -> Invite {
        inv.operator = Some(op.into());
        inv
    }

    #[test]
    fn two_hops_prefer_two_operators_and_say_when_they_could_not() {
        let mut p = Pocket::default();
        p.add(
            Slot::Entry,
            run_by(invite("e-a", "203.0.113.20:51820"), "alice"),
        )
        .unwrap();
        p.add(
            Slot::Exit,
            run_by(invite("x-a", "203.0.113.10:51820"), "alice"),
        )
        .unwrap();
        p.add(
            Slot::Exit,
            run_by(invite("x-b", "203.0.113.11:51820"), "bob"),
        )
        .unwrap();
        for _ in 0..30 {
            let pick = p.pick_privado().unwrap();
            assert_eq!(
                pick.exit.node_name, "x-b",
                "the pair under two operators is the one taken"
            );
            assert_eq!(pick.same_operator, Some(false));
        }
        p.remove("x-b");
        let pick = p.pick_privado().unwrap();
        assert_eq!(
            pick.same_operator,
            Some(true),
            "with no other choice, it says so"
        );
        p.remove("x-a");
        p.add(Slot::Exit, invite("x-c", "203.0.113.12:51820"))
            .unwrap();
        assert_eq!(
            p.pick_privado().unwrap().same_operator,
            None,
            "an invite that does not say leaves it unknown"
        );
        assert_eq!(p.pick_rapido().unwrap().same_operator, None);
    }

    #[test]
    fn one_node_may_serve_as_entry_and_exit_under_its_one_name() {
        let mut p = Pocket::default();
        let both = invite("both", "203.0.113.30:51820");
        p.add(Slot::Exit, both.clone()).unwrap();
        p.add(Slot::Entry, both.clone()).unwrap();
        assert!(p.add(Slot::Entry, both).is_err(), "not twice in one list");
        let mut other = invite("both", "203.0.113.31:51820");
        other.node_name = "both".into();
        assert!(
            p.add(Slot::Exit, other).is_err(),
            "another node may not take the name"
        );
        assert_eq!(p.remove("both"), 2);
        assert_eq!(slots_for_role(Some("entry")), vec![Slot::Entry]);
        assert_eq!(slots_for_role(Some("Exit")), vec![Slot::Exit]);
        assert_eq!(slots_for_role(None), vec![Slot::Entry, Slot::Exit]);
    }

    #[test]
    fn a_pocket_from_an_older_version_still_reads_and_its_odd_invite_is_refused_at_use() {
        let mut p = Pocket::default();
        p.add(Slot::Exit, invite("x1", "198.51.100.2:51820"))
            .unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&p.to_json()).unwrap();
        // An invite written by hand, before the resolver had to be the node.
        json["exits"][0]["dns"] = "1.1.1.1".into();
        let again = Pocket::from_json(&json.to_string()).unwrap();
        assert_eq!(again.exits.len(), 1, "the pocket still reads");
        let e = crate::circuit::CircuitSpec {
            exit: again.exits[0].clone(),
            entry: None,
        }
        .validate()
        .unwrap_err();
        assert!(format!("{e:#}").contains("DNS"), "{e:#}");
    }

    #[test]
    fn a_pocket_round_trips_and_an_empty_file_reads() {
        let mut p = Pocket::default();
        p.add(Slot::Entry, invite("e1", "1.1.1.1:51820")).unwrap();
        p.add(Slot::Exit, invite("x1", "198.51.100.2:51820"))
            .unwrap();
        let again = Pocket::from_json(&p.to_json()).unwrap();
        assert_eq!(again.entries.len(), 1);
        assert_eq!(again.exits.len(), 1);
        let empty = Pocket::from_json("{}").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn names_are_unique_and_a_node_is_in_one_list_once() {
        let mut p = Pocket::default();
        let x = invite("x1", "198.51.100.2:51820");
        p.add(Slot::Exit, x.clone()).unwrap();
        assert!(p.add(Slot::Exit, x.clone()).is_err(), "same name");
        let mut same_key = x.clone();
        same_key.node_name = "other".into();
        assert!(
            p.add(Slot::Exit, same_key.clone()).is_err(),
            "same key, same list"
        );
        p.add(Slot::Entry, same_key).unwrap();
        assert_eq!(p.entries.len(), 1);
        assert_eq!(p.remove("other"), 1);
        assert_eq!(p.remove("nobody"), 0);
        assert_eq!(p.remove("x1"), 1);
        assert!(p.is_empty());
    }

    #[test]
    fn rapido_picks_an_exit_and_keeps_the_others() {
        let mut p = Pocket::default();
        assert!(p.pick_rapido().is_err());
        for (n, ep) in [
            ("x1", "198.51.100.1:51820"),
            ("x2", "198.51.100.2:51820"),
            ("x3", "198.51.100.3:51820"),
        ] {
            p.add(Slot::Exit, invite(n, ep)).unwrap();
        }
        for _ in 0..20 {
            let pick = p.pick_rapido().unwrap();
            assert!(pick.entry.is_none());
            assert_eq!(pick.other_exits.len(), 2);
            assert!(pick
                .other_exits
                .iter()
                .all(|i| i.node_name != pick.exit.node_name));
        }
    }

    #[test]
    fn privado_picks_two_different_nodes_and_every_pair_comes_up() {
        let mut p = Pocket::default();
        p.add(Slot::Exit, invite("x1", "198.51.100.1:51820"))
            .unwrap();
        assert!(p
            .pick_privado()
            .unwrap_err()
            .to_string()
            .contains("no entry"));
        p.add(Slot::Entry, invite("e1", "1.1.1.1:51820")).unwrap();
        p.add(Slot::Entry, invite("e2", "1.1.1.2:51820")).unwrap();
        p.add(Slot::Exit, invite("x2", "198.51.100.2:51820"))
            .unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let pick = p.pick_privado().unwrap();
            let entry = pick.entry.as_ref().unwrap();
            assert!(!same_node(entry, &pick.exit));
            assert_eq!(pick.other_exits.len(), 1);
            assert_eq!(pick.other_entries.len(), 1);
            seen.insert((entry.node_name.clone(), pick.exit.node_name.clone()));
        }
        assert_eq!(seen.len(), 4, "all four pairs should come up in 200 picks");
    }

    #[test]
    fn privado_never_pairs_a_node_with_itself() {
        let mut p = Pocket::default();
        let node = invite("both", "1.1.1.1:51820");
        p.add(Slot::Entry, node.clone()).unwrap();
        let mut as_exit = node.clone();
        as_exit.node_name = "both-as-exit".into();
        p.add(Slot::Exit, as_exit).unwrap();
        assert!(p
            .pick_privado()
            .unwrap_err()
            .to_string()
            .contains("same node"));
        p.add(Slot::Exit, invite("x2", "198.51.100.2:51820"))
            .unwrap();
        for _ in 0..20 {
            assert_eq!(p.pick_privado().unwrap().exit.node_name, "x2");
        }
    }

    #[test]
    fn a_node_that_admits_openly_is_joinable_however_the_list_spells_it() {
        let mut p = Pocket::default();
        for (name, admission) in [
            ("a", "open"),
            ("b", "Open"),
            ("c", " OPEN "),
            ("d", "manual"),
        ] {
            p.learn(NodeRecord {
                node_name: name.into(),
                node_public_key: ClientKey::generate().unwrap().public_base64(),
                endpoint: format!("203.0.113.{}:51820", 40 + p.known.len()),
                operator: None,
                contact: None,
                role: None,
                admission: Some(admission.into()),
                admission_port: None,
                country: None,
            })
            .unwrap();
        }
        let names: Vec<&str> = p.joinable().iter().map(|r| r.node_name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
