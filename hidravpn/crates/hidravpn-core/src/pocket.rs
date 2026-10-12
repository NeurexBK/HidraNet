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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pocket {
    #[serde(default)]
    pub entries: Vec<Invite>,
    #[serde(default)]
    pub exits: Vec<Invite>,
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
}

impl Pocket {
    pub fn from_json(s: &str) -> Result<Self> {
        let p: Pocket = serde_json::from_str(s).context("the pocket is not valid JSON")?;
        for inv in p.entries.iter().chain(p.exits.iter()) {
            inv.validate()
                .with_context(|| format!("the invite for {} in the pocket", inv.node_name))?;
        }
        Ok(p)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a pocket always serialises")
    }

    /// Adds an invite to one list. A name is the handle `remove` uses, so it
    /// must be unique in the pocket; the same node (same key) may be in both
    /// lists but not twice in one.
    pub fn add(&mut self, slot: Slot, invite: Invite) -> Result<()> {
        invite.validate()?;
        let name = invite.node_name.trim();
        if name.is_empty() {
            return Err(anyhow!("the invite has no node name"));
        }
        if self.iter().any(|(_, i)| i.node_name.trim() == name) {
            return Err(anyhow!(
                "a node named \"{name}\" is already in the pocket; remove it first"
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
        list.push(invite);
        Ok(())
    }

    /// Removes every node with that name, from both lists. Returns how many.
    pub fn remove(&mut self, name: &str) -> usize {
        let name = name.trim();
        let before = self.entries.len() + self.exits.len();
        self.entries.retain(|i| i.node_name.trim() != name);
        self.exits.retain(|i| i.node_name.trim() != name);
        before - self.entries.len() - self.exits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.exits.is_empty()
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
        // Every (entry, exit) pair of two different nodes; one of them at
        // random, so no pair is favoured.
        let pairs: Vec<(usize, usize)> = (0..self.entries.len())
            .flat_map(|e| (0..self.exits.len()).map(move |x| (e, x)))
            .filter(|&(e, x)| !same_node(&self.entries[e], &self.exits[x]))
            .collect();
        if pairs.is_empty() {
            return Err(anyhow!(
                "every entry in the pocket is the same node as every exit; two hops need two different nodes"
            ));
        }
        let (e, x) = pairs[crate::random::index(pairs.len())?];
        let mut exits = self.exits.clone();
        let exit = exits.remove(x);
        let mut entries = self.entries.clone();
        let entry = entries.remove(e);
        Ok(Pick {
            exit,
            entry: Some(entry),
            other_exits: exits,
            other_entries: entries,
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
        }
    }

    #[test]
    fn a_pocket_round_trips_and_an_empty_file_reads() {
        let mut p = Pocket::default();
        p.add(Slot::Entry, invite("e1", "1.1.1.1:51820")).unwrap();
        p.add(Slot::Exit, invite("x1", "2.2.2.2:51820")).unwrap();
        let again = Pocket::from_json(&p.to_json()).unwrap();
        assert_eq!(again.entries.len(), 1);
        assert_eq!(again.exits.len(), 1);
        let empty = Pocket::from_json("{}").unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn names_are_unique_and_a_node_is_in_one_list_once() {
        let mut p = Pocket::default();
        let x = invite("x1", "2.2.2.2:51820");
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
            ("x1", "2.2.2.1:51820"),
            ("x2", "2.2.2.2:51820"),
            ("x3", "2.2.2.3:51820"),
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
        p.add(Slot::Exit, invite("x1", "2.2.2.1:51820")).unwrap();
        assert!(p
            .pick_privado()
            .unwrap_err()
            .to_string()
            .contains("no entry"));
        p.add(Slot::Entry, invite("e1", "1.1.1.1:51820")).unwrap();
        p.add(Slot::Entry, invite("e2", "1.1.1.2:51820")).unwrap();
        p.add(Slot::Exit, invite("x2", "2.2.2.2:51820")).unwrap();
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
        p.add(Slot::Exit, invite("x2", "2.2.2.2:51820")).unwrap();
        for _ in 0..20 {
            assert_eq!(p.pick_privado().unwrap().exit.node_name, "x2");
        }
    }
}
