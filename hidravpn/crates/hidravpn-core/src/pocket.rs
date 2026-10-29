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
            if inv.admission != record.admission || inv.admission_port != record.admission_port {
                inv.admission = record.admission.clone();
                inv.admission_port = record.admission_port;
                changed.push("admission".into());
            }
            if inv.features != record.features {
                inv.features = record.features.clone();
                changed.push("features".into());
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
    ///
    /// An invite whose pass was redeemed through an entry never takes the
    /// place of one whose pass was redeemed from this machine's address: the
    /// one kept is the key a later one-hop connection may still show, and
    /// the other is never shown from here (nor, being spent, behind an entry
    /// again). One redeemed from here takes the place of either.
    pub fn replace(&mut self, invite: Invite) -> Result<()> {
        invite.validate()?;
        let key = invite.node_public_key.trim().to_string();
        let keeps_direct = invite.pass.is_some() && invite.direct_pass().is_none();
        let mut placed = false;
        for inv in self
            .entries
            .iter_mut()
            .chain(self.exits.iter_mut())
            .filter(|i| i.node_public_key.trim() == key)
        {
            if !(keeps_direct && inv.direct_pass().is_some()) {
                *inv = invite.clone();
            }
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

    /// The nodes that may fill a slot, for one connection.
    ///
    /// A node that admits openly is asked for a fresh key on every
    /// connection, whether this machine joined it once or only knows it from
    /// the signed list — so known records count, and a stable lease this
    /// machine may hold there is never used. Such a node is skipped when its
    /// record does not list `sessions`: its software is older than
    /// per-connection keys, and the stable key it would need is what lets a
    /// node recognise a person from one connection to the next. A node
    /// admitted by hand is used with its lease. `accept` says which leases
    /// suit the slot. Returns the nodes and how many were skipped as not
    /// updated.
    fn candidates(&self, slot: Slot, accept: impl Fn(&Invite) -> bool) -> (Vec<Invite>, usize) {
        let list = match slot {
            Slot::Entry => &self.entries,
            Slot::Exit => &self.exits,
        };
        let known = self
            .joinable()
            .into_iter()
            .filter(|r| slots_for_role(r.role.as_deref()).contains(&slot))
            .map(stand_in);
        let mut out: Vec<Invite> = Vec::new();
        let mut outdated = 0;
        for c in list.iter().filter(|i| accept(i)).cloned().chain(known) {
            if out
                .iter()
                .any(|o| o.node_public_key.trim() == c.node_public_key.trim())
            {
                continue;
            }
            if c.admits_openly() && !c.admits_sessions() {
                outdated += 1;
                continue;
            }
            out.push(c);
        }
        (out, outdated)
    }

    /// The nodes one hop may go through: open nodes (asked for a key for
    /// this connection), or a lease granted by hand for the one-hop key —
    /// never one for the key behind an entry.
    pub fn rapido_exits(&self) -> (Vec<Invite>, usize) {
        self.candidates(Slot::Exit, |i| !i.behind)
    }

    /// The nodes two hops may enter through.
    pub fn privado_entries(&self) -> (Vec<Invite>, usize) {
        self.candidates(Slot::Entry, |_| true)
    }

    /// The nodes that may be the exit of two hops: open nodes (asked through
    /// the entry for a key for this connection), or a lease an operator
    /// granted by hand to the key behind an entry. An exit admitted by hand
    /// for the one-hop key is not one: that key may have arrived from this
    /// machine's own address.
    pub fn privado_exits(&self) -> (Vec<Invite>, usize) {
        self.candidates(Slot::Exit, |i| {
            i.behind || i.admits_openly() || i.takes_passes()
        })
    }

    /// One exit, at random. The other exits come along for rotation.
    pub fn pick_rapido(&self) -> Result<Pick> {
        let (mut exits, outdated) = self.rapido_exits();
        if exits.is_empty() {
            return Err(anyhow!(
                "no node can carry one hop: {}",
                missing("exit", outdated, "`hidravpn nodes add --exit exit.json`")
            ));
        }
        let exit = exits.remove(crate::random::index(exits.len())?);
        Ok(Pick {
            exit,
            entry: None,
            other_exits: exits,
            other_entries: Vec::new(),
            same_operator: None,
        })
    }

    /// One exit and one entry, at random, that are two different nodes run
    /// by two different operators — unless `allow_same_operator`, the
    /// person's explicit yes to two hops one operator could watch together
    /// (or whose operators the list does not name). An exit asked through
    /// the entry needs an entry that relays the request. The other exits and
    /// entries come along for rotation.
    pub fn pick_privado(&self, allow_same_operator: bool) -> Result<Pick> {
        let (entries_all, entries_outdated) = self.privado_entries();
        if entries_all.is_empty() {
            return Err(anyhow!(
                "no node can be the entry of two hops: {}",
                missing(
                    "entry",
                    entries_outdated,
                    "`hidravpn nodes add --entry entry.json`"
                )
            ));
        }
        let (exits_all, exits_outdated) = self.privado_exits();
        if exits_all.is_empty() {
            let by_hand = self.exits.iter().any(|i| !i.behind && !i.admits_openly());
            return Err(anyhow!(
                "no node can be the exit of two hops: {}",
                if by_hand && exits_outdated == 0 {
                    "the exits in the pocket were admitted by hand for the one-hop key, which this machine shows from its own address. Ask the operator to admit `hidravpn pubkey --node <its key> --behind` and add that invite with `hidravpn nodes add --exit exit.json --behind`".to_string()
                } else {
                    missing("exit", exits_outdated, "a lease for the key behind an entry: `hidravpn pubkey --node <its key> --behind`, then `hidravpn nodes add --exit exit.json --behind`")
                }
            ));
        }
        let pairs: Vec<(usize, usize)> = (0..entries_all.len())
            .flat_map(|e| (0..exits_all.len()).map(move |x| (e, x)))
            .filter(|&(e, x)| !same_node(&entries_all[e], &exits_all[x]))
            .collect();
        if pairs.is_empty() {
            return Err(anyhow!(
                "every entry in the pocket is the same node as every exit; two hops need two different nodes"
            ));
        }
        let relayed: Vec<(usize, usize)> = pairs
            .iter()
            .copied()
            .filter(|&(e, x)| entry_can_reach(&entries_all[e], &exits_all[x]))
            .collect();
        if relayed.is_empty() {
            return Err(anyhow!(
                "no entry can carry this machine to an exit: the entries' software is older than relaying admission (no `admission-relay` in the node list), or the exits use other ports than WireGuard's {} and admission's {}, the ones an entry forwards; their operators need to update them",
                crate::admission::DEFAULT_WIREGUARD_PORT,
                crate::admission::DEFAULT_ADMISSION_PORT
            ));
        }
        let allowed: Vec<(usize, usize)> = relayed
            .into_iter()
            .filter(|&(e, x)| pair_allowed(&entries_all[e], &exits_all[x], allow_same_operator))
            .collect();
        if allowed.is_empty() {
            return Err(anyhow!("{}", SAME_OPERATOR_REFUSAL));
        }
        let (e, x) = allowed[crate::random::index(allowed.len())?];
        let same_operator = same_operator(&entries_all[e], &exits_all[x]);
        let mut exits = exits_all;
        let exit = exits.remove(x);
        let mut entries = entries_all;
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

/// Why two hops are refused when no pair has two operators.
pub const SAME_OPERATOR_REFUSAL: &str = "two hops refused: every entry and exit available is run by the same operator, or the node list does not say who runs them. One operator running both hops can see who you are and where you go, which is what two hops exist to prevent. Connect anyway only if you accept that: `--allow-same-operator` on the command line, or the box on the VPN page";

/// Whether two hops through `entry` and `exit` may be built: two operators,
/// or the person's explicit yes.
pub fn pair_allowed(entry: &Invite, exit: &Invite, allow_same_operator: bool) -> bool {
    allow_same_operator || same_operator(entry, exit) == Some(false)
}

/// Whether `entry` can carry the admission request `exit` needs: an exit
/// admitted by hand needs none; one asked for a key per connection, openly
/// or with a pass, needs an entry whose software relays the request, and
/// takes it on the standard admission port, the one port an entry relays
/// (an entry that forwarded any port would carry anything, not only
/// WireGuard and this request). An exit on another port is still used as
/// the only hop.
pub fn entry_can_reach(entry: &Invite, exit: &Invite) -> bool {
    on_forwarded_port(exit)
        && (!(exit.admits_openly() || exit.takes_passes())
            || (entry.has(crate::directory::features::ADMISSION_RELAY) && on_relayed_port(exit)))
}

fn on_relayed_port(exit: &Invite) -> bool {
    exit.admission_port
        .unwrap_or(crate::admission::DEFAULT_ADMISSION_PORT)
        == crate::admission::DEFAULT_ADMISSION_PORT
}

/// An entry forwards WireGuard to the standard port only, to any exit,
/// admitted openly, with a pass or by hand.
fn on_forwarded_port(exit: &Invite) -> bool {
    exit.endpoint_addr()
        .is_ok_and(|a| a.port() == crate::admission::DEFAULT_WIREGUARD_PORT)
}

/// Why `entry` cannot carry the admission request `exit` needs, when
/// `entry_can_reach` says so.
pub fn relay_refusal(entry: &Invite, exit: &Invite) -> String {
    if !on_forwarded_port(exit) {
        format!(
            "{} listens for WireGuard on another port than {}, the one an entry forwards to: it is used as the only hop, not as the exit of two hops",
            exit.node_name,
            crate::admission::DEFAULT_WIREGUARD_PORT
        )
    } else if on_relayed_port(exit) {
        format!(
            "{} cannot ask {} for admission on this machine's behalf: its software is older than that (no `admission-relay` in the node list)",
            entry.node_name, exit.node_name
        )
    } else {
        format!(
            "{} takes admission requests on TCP {}, and an entry relays them only to {}: it is used as the only hop, not as the exit of two hops",
            exit.node_name,
            exit.admission_port
                .unwrap_or(crate::admission::DEFAULT_ADMISSION_PORT),
            crate::admission::DEFAULT_ADMISSION_PORT
        )
    }
}

/// Why no node fills a slot, and what to do.
fn missing(slot: &str, outdated: usize, add: &str) -> String {
    if outdated > 0 {
        format!(
            "{outdated} {slot} node(s) that admit openly run software older than per-connection keys (no `sessions` in the node list) and are not used; their operators need to update them and publish the list again"
        )
    } else {
        format!("the pocket has no {slot} node; import the signed node list, or add one: {add}")
    }
}

/// What the pocket knows of an exit it has not joined: enough to pick it
/// and ask it for admission, never enough to connect (it has no lease).
fn stand_in(r: &NodeRecord) -> Invite {
    Invite {
        node_name: r.node_name.clone(),
        node_public_key: r.node_public_key.clone(),
        endpoint: r.endpoint.clone(),
        client_address: "0.0.0.0/32".into(),
        client_address6: None,
        dns: std::net::Ipv4Addr::UNSPECIFIED,
        allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
        mtu: 1420,
        keepalive: 25,
        operator: r.operator.clone(),
        role: r.role.clone(),
        country: r.country.clone(),
        admission: r.admission.clone(),
        admission_port: r.admission_port,
        behind: false,
        features: r.features.clone(),
        pass: None,
    }
}

/// Two invites name the same node when they carry the same key or the same
/// endpoint address (whatever the port: one machine) — the same test
/// `CircuitSpec::validate` makes.
pub fn same_node(a: &Invite, b: &Invite) -> bool {
    a.node_public_key.trim() == b.node_public_key.trim()
        || matches!((a.endpoint_ip(), b.endpoint_ip()), (Ok(x), Ok(y)) if x == y)
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
            client_address6: None,
            dns: Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1420,
            keepalive: 25,
            operator: None,
            role: None,
            pass: None,
            country: None,
            admission: None,
            admission_port: None,
            behind: false,
            features: Vec::new(),
        }
        .open()
    }

    fn with_pass(mut inv: Invite, behind: Option<bool>) -> Invite {
        inv.admission = Some("pass".into());
        inv.features = Vec::new();
        inv.pass = Some(crate::config::PassBinding {
            client_secret: ClientKey::generate().unwrap().secret_base64(),
            admission_port: None,
            redeemed_at: 1,
            used_at: 0,
            behind,
        });
        inv
    }

    #[test]
    fn a_pass_key_redeemed_through_an_entry_never_takes_the_place_of_one_redeemed_from_here() {
        let base = invite("q", "203.0.113.10:51820");
        let direct = with_pass(base.clone(), Some(false));
        let behind = with_pass(base.clone(), Some(true));
        let secret = |p: &Pocket| p.exits[0].pass.as_ref().unwrap().client_secret.clone();
        let mut p = Pocket::default();
        p.add(Slot::Exit, direct.clone()).unwrap();
        p.replace(behind.clone()).unwrap();
        assert_eq!(p.exits.len(), 1);
        assert_eq!(
            secret(&p),
            direct.pass.as_ref().unwrap().client_secret,
            "the key a later one-hop connection may show stays"
        );
        // A key redeemed from here takes the place of either.
        let direct2 = with_pass(base.clone(), Some(false));
        p.replace(direct2.clone()).unwrap();
        assert_eq!(secret(&p), direct2.pass.as_ref().unwrap().client_secret);
        let mut q = Pocket::default();
        q.add(Slot::Exit, behind.clone()).unwrap();
        q.replace(direct.clone()).unwrap();
        assert_eq!(secret(&q), direct.pass.as_ref().unwrap().client_secret);
        // Through an entry, in place of one redeemed through an entry or of
        // unknown origin (an older pocket): neither is shown from here.
        let behind2 = with_pass(base.clone(), Some(true));
        let mut b = Pocket::default();
        b.add(Slot::Exit, behind.clone()).unwrap();
        b.replace(behind2.clone()).unwrap();
        assert_eq!(secret(&b), behind2.pass.as_ref().unwrap().client_secret);
        let mut r = Pocket::default();
        r.add(Slot::Exit, with_pass(base.clone(), None)).unwrap();
        r.replace(behind.clone()).unwrap();
        assert_eq!(secret(&r), behind.pass.as_ref().unwrap().client_secret);
        // A node not in the pocket yet goes in, whatever its key.
        let mut e = Pocket::default();
        e.replace(behind.clone()).unwrap();
        assert_eq!(e.exits.len() + e.entries.len(), 2, "no role: both slots");
    }

    impl Invite {
        /// A node that admits openly, with today's software.
        fn open(mut self) -> Self {
            self.admission = Some("open".into());
            self.features = vec![
                crate::directory::features::SESSIONS.into(),
                crate::directory::features::ADMISSION_RELAY.into(),
            ];
            self
        }
    }

    #[test]
    fn an_exit_on_another_admission_port_is_never_the_exit_of_two_hops() {
        let entry = run_by(invite("e", "203.0.113.20:51820"), "a");
        let mut odd = run_by(invite("x-odd", "203.0.113.10:51820"), "b");
        odd.admission_port = Some(51900);
        assert!(!entry_can_reach(&entry, &odd));
        let why = relay_refusal(&entry, &odd);
        assert!(
            why.contains("TCP 51900") && why.contains("only hop"),
            "{why}"
        );
        let mut std_port = run_by(invite("x-std", "203.0.113.11:51820"), "b");
        std_port.admission_port = Some(crate::admission::DEFAULT_ADMISSION_PORT);
        assert!(entry_can_reach(&entry, &std_port));
        assert!(relay_refusal(&entry, &std_port).contains("admission-relay"));
        // WireGuard on another port: an entry forwards only the standard
        // one, to any exit, even one admitted by hand.
        let mut wg_odd = run_by(invite("x-wg", "203.0.113.12:51900"), "b");
        assert!(!entry_can_reach(&entry, &wg_odd));
        assert!(relay_refusal(&entry, &wg_odd).contains("another port than 51820"));
        wg_odd.admission = Some("manual".into());
        assert!(!entry_can_reach(&entry, &wg_odd));

        let mut p = Pocket::default();
        p.add(Slot::Entry, entry.clone()).unwrap();
        p.add(Slot::Exit, odd.clone()).unwrap();
        let e = p.pick_privado(false).unwrap_err().to_string();
        assert!(e.contains("admission's 51821"), "{e}");
        p.add(Slot::Exit, std_port).unwrap();
        for _ in 0..20 {
            assert_eq!(p.pick_privado(false).unwrap().exit.node_name, "x-std");
        }
        // As the only hop it is asked directly, on its own port: still used.
        let mut q = Pocket::default();
        q.add(Slot::Exit, odd).unwrap();
        assert_eq!(q.pick_rapido().unwrap().exit.node_name, "x-odd");
    }

    #[test]
    fn a_node_older_than_per_connection_keys_is_passed_over_and_said_so() {
        let mut p = Pocket::default();
        let mut old_entry = run_by(invite("e-old", "203.0.113.20:51820"), "a");
        old_entry.features.clear();
        p.add(Slot::Entry, old_entry).unwrap();
        p.add(Slot::Exit, run_by(invite("x", "203.0.113.10:51820"), "b"))
            .unwrap();
        let e = p.pick_privado(false).unwrap_err().to_string();
        assert!(e.contains("older than per-connection keys"), "{e}");
        // An entry that takes session keys but does not relay admission
        // cannot carry an exit that is asked through it.
        let mut no_relay = run_by(invite("e-norelay", "203.0.113.21:51820"), "a");
        no_relay.features = vec![crate::directory::features::SESSIONS.into()];
        p.add(Slot::Entry, no_relay).unwrap();
        let e = p.pick_privado(false).unwrap_err().to_string();
        assert!(e.contains("admission-relay"), "{e}");
        p.add(
            Slot::Entry,
            run_by(invite("e-new", "203.0.113.22:51820"), "a"),
        )
        .unwrap();
        for _ in 0..20 {
            assert_eq!(
                p.pick_privado(false).unwrap().entry.unwrap().node_name,
                "e-new"
            );
        }
        // One hop through an old open exit: passed over too.
        let mut q = Pocket::default();
        let mut old_exit = invite("x-old", "203.0.113.30:51820");
        old_exit.features.clear();
        q.add(Slot::Exit, old_exit).unwrap();
        assert!(q
            .pick_rapido()
            .unwrap_err()
            .to_string()
            .contains("older than per-connection keys"));
    }

    fn run_by(mut inv: Invite, op: &str) -> Invite {
        inv.operator = Some(op.into());
        inv
    }

    #[test]
    fn two_hops_need_two_operators_or_the_persons_yes() {
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
            let pick = p.pick_privado(false).unwrap();
            assert_eq!(
                pick.exit.node_name, "x-b",
                "the pair under two operators is the only one taken"
            );
            assert_eq!(pick.same_operator, Some(false));
        }
        p.remove("x-b");
        let e = p.pick_privado(false).unwrap_err().to_string();
        assert!(
            e.contains("same operator") && e.contains("--allow-same-operator"),
            "{e}"
        );
        let pick = p.pick_privado(true).unwrap();
        assert_eq!(
            pick.same_operator,
            Some(true),
            "with the person's yes, and said"
        );
        p.remove("x-a");
        p.add(Slot::Exit, invite("x-c", "203.0.113.12:51820"))
            .unwrap();
        assert!(
            p.pick_privado(false).is_err(),
            "an operator nobody named could be the entry's: refused too"
        );
        assert_eq!(p.pick_privado(true).unwrap().same_operator, None);
        assert_eq!(p.pick_rapido().unwrap().same_operator, None);
    }

    #[test]
    fn only_an_open_exit_or_one_admitted_for_the_key_behind_an_entry_is_a_privado_exit() {
        let mut p = Pocket::default();
        p.add(Slot::Entry, run_by(invite("e", "203.0.113.20:51820"), "a"))
            .unwrap();
        let mut by_hand = run_by(invite("x-hand", "203.0.113.10:51820"), "b");
        by_hand.admission = Some("manual".into());
        p.add(Slot::Exit, by_hand).unwrap();
        let e = p.pick_privado(false).unwrap_err().to_string();
        assert!(e.contains("--behind"), "{e}");
        assert_eq!(p.pick_rapido().unwrap().exit.node_name, "x-hand");
        let mut behind = run_by(invite("x-behind", "203.0.113.11:51820"), "b");
        behind.admission = Some("manual".into());
        behind.behind = true;
        p.add(Slot::Exit, behind).unwrap();
        for _ in 0..20 {
            assert_eq!(p.pick_privado(false).unwrap().exit.node_name, "x-behind");
            assert_eq!(
                p.pick_rapido().unwrap().exit.node_name,
                "x-hand",
                "a lease for the key behind an entry is never used for one hop"
            );
        }
        // A known exit that admits openly is a candidate before it is joined.
        p.remove("x-behind");
        p.learn(NodeRecord {
            node_name: "x-known".into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: "203.0.113.12:51820".into(),
            operator: Some("c".into()),
            contact: None,
            role: Some("exit".into()),
            admission: Some("open".into()),
            admission_port: None,
            country: None,
            features: vec![crate::directory::features::SESSIONS.into()],
        })
        .unwrap();
        let pick = p.pick_privado(false).unwrap();
        assert_eq!(pick.exit.node_name, "x-known");
        assert!(pick.exit.admits_openly());
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
        json["exits"][0]["dns"] = "198.51.100.53".into();
        let again = Pocket::from_json(&json.to_string()).unwrap();
        assert_eq!(again.exits.len(), 1, "the pocket still reads");
        let e = crate::circuit::CircuitSpec::new(again.exits[0].clone(), None)
            .validate()
            .unwrap_err();
        assert!(format!("{e:#}").contains("DNS"), "{e:#}");
    }

    #[test]
    fn a_pocket_round_trips_and_an_empty_file_reads() {
        let mut p = Pocket::default();
        p.add(Slot::Entry, invite("e1", "192.0.2.1:51820")).unwrap();
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
            .pick_privado(true)
            .unwrap_err()
            .to_string()
            .contains("no entry"));
        p.add(Slot::Entry, invite("e1", "192.0.2.1:51820")).unwrap();
        p.add(Slot::Entry, invite("e2", "192.0.2.2:51820")).unwrap();
        p.add(Slot::Exit, invite("x2", "198.51.100.2:51820"))
            .unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let pick = p.pick_privado(true).unwrap();
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
        let node = invite("both", "192.0.2.1:51820");
        p.add(Slot::Entry, node.clone()).unwrap();
        let mut as_exit = node.clone();
        as_exit.node_name = "both-as-exit".into();
        p.add(Slot::Exit, as_exit).unwrap();
        assert!(p
            .pick_privado(true)
            .unwrap_err()
            .to_string()
            .contains("same node"));
        p.add(Slot::Exit, invite("x2", "198.51.100.2:51820"))
            .unwrap();
        for _ in 0..20 {
            assert_eq!(p.pick_privado(true).unwrap().exit.node_name, "x2");
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
                features: Vec::new(),
            })
            .unwrap();
        }
        let names: Vec<&str> = p.joinable().iter().map(|r| r.node_name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }
}
