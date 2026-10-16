//! The descriptors a node holds: its own, the ones it looked up, and the ones
//! other nodes pushed to it because it is close to the service's address.
//!
//! Keys are free, so services are too; a store with no rules is a store any
//! one node can fill. The rules:
//!
//! - A descriptor must verify (the service signed it for this address), must
//!   not be dated more than MAX_CLOCK_SKEW_SECS ahead, and expires
//!   DESCRIPTOR_TTL_SECS after it was signed. Services republish well inside
//!   that window (`DhtNode` does it for the services it announced).
//! - A newer revision replaces an older one; nothing else replaces anything.
//! - A node that pushes descriptors may introduce at most
//!   MAX_NEW_PER_PUSHER_PER_HOUR new addresses per hour here.
//! - When the store is full: expired entries go first, then looked-up copies
//!   (oldest first), then the entries of whichever pusher has the most
//!   (oldest first). This node's own services are never evicted.

use std::collections::{HashMap, VecDeque};

use crate::p2p::dht::descriptor::ServiceDescriptor;
use crate::p2p::dht::node::NodeId;

pub const MAX_STORED_SERVICES: usize = 4096;
pub const DESCRIPTOR_TTL_SECS: u64 = 3600;
pub const MAX_CLOCK_SKEW_SECS: u64 = 600;
pub const MAX_NEW_PER_PUSHER_PER_HOUR: usize = 32;
const MAX_TRACKED_PUSHERS: usize = 8192;
const HOUR: u64 = 3600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// This node announced it (it holds the service's key).
    Own,
    /// This node looked it up over disjoint paths and kept the newest.
    Fetched,
    /// Another node pushed it here, because this node is near its address.
    Pushed(NodeId),
}

#[derive(Debug, Clone)]
pub struct Stored {
    pub descriptor: ServiceDescriptor,
    pub origin: Origin,
    /// The nodes that have delivered this service here (at most
    /// MAX_DELIVERERS). An entry more than one node delivered is nobody's
    /// to have evicted as "the heaviest pusher's".
    pub delivered_by: Vec<NodeId>,
}

const MAX_DELIVERERS: usize = 4;

fn note_delivery(delivered_by: &mut Vec<NodeId>, origin: Origin) {
    if let Origin::Pushed(by) = origin
        && !delivered_by.contains(&by)
        && delivered_by.len() < MAX_DELIVERERS
    {
        delivered_by.push(by);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    NotSigned,
    FromTheFuture,
    Expired,
    NotNewer,
    PusherOverQuota,
    Full,
}

#[derive(Debug, Default)]
pub struct ServiceStore {
    entries: HashMap<[u8; 20], Stored>,
    introduced: HashMap<NodeId, VecDeque<u64>>,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn expired(d: &ServiceDescriptor, now: u64) -> bool {
    d.revision.saturating_add(DESCRIPTOR_TTL_SECS) <= now
}

impl ServiceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The descriptor held for this address, unless it has expired.
    pub fn get(&self, service_hash: &[u8; 20], now: u64) -> Option<&Stored> {
        self.entries
            .get(service_hash)
            .filter(|s| !expired(&s.descriptor, now))
    }

    /// Drops this node's own copy of a service it no longer publishes.
    pub fn forget_own(&mut self, service_hash: &[u8; 20]) {
        if self
            .entries
            .get(service_hash)
            .is_some_and(|s| s.origin == Origin::Own)
        {
            self.entries.remove(service_hash);
        }
    }

    /// Keeps `descriptor` under the rules in the module documentation.
    pub fn put(
        &mut self,
        service_hash: [u8; 20],
        descriptor: ServiceDescriptor,
        origin: Origin,
        now: u64,
    ) -> Result<(), Refused> {
        if descriptor.verify(&service_hash).is_err() {
            return Err(Refused::NotSigned);
        }
        if descriptor.revision > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
            return Err(Refused::FromTheFuture);
        }
        if expired(&descriptor, now) {
            return Err(Refused::Expired);
        }
        if let Some(held) = self.entries.get_mut(&service_hash) {
            if !expired(&held.descriptor, now) && held.descriptor.revision >= descriptor.revision {
                // Not newer, but another node delivering the same service is
                // still worth knowing: it makes the entry nobody's alone.
                if held.descriptor.revision == descriptor.revision {
                    note_delivery(&mut held.delivered_by, origin);
                }
                return Err(Refused::NotNewer);
            }
            // A newer revision of a service already held: an update, which
            // costs the pusher nothing and keeps the stronger origin. An
            // entry stays attributed to whoever pushed it first, so a node
            // that relays updates faster cannot take an honest service's
            // entry over and get it evicted as its own.
            let origin = match (held.origin, origin) {
                (Origin::Own, _) | (_, Origin::Own) => Origin::Own,
                (Origin::Pushed(first), Origin::Pushed(_)) => Origin::Pushed(first),
                (Origin::Fetched, Origin::Pushed(_)) => Origin::Fetched,
                (_, o) => o,
            };
            let mut delivered_by = std::mem::take(&mut held.delivered_by);
            note_delivery(&mut delivered_by, origin);
            *held = Stored {
                descriptor,
                origin,
                delivered_by,
            };
            return Ok(());
        }
        if let Origin::Pushed(by) = origin {
            let window = self.introduced.entry(by).or_default();
            while window
                .front()
                .is_some_and(|t| now.saturating_sub(*t) >= HOUR)
            {
                window.pop_front();
            }
            if window.len() >= MAX_NEW_PER_PUSHER_PER_HOUR {
                return Err(Refused::PusherOverQuota);
            }
        }
        if self.entries.len() >= MAX_STORED_SERVICES && !self.evict_one(now, origin) {
            return Err(Refused::Full);
        }
        if let Origin::Pushed(by) = origin {
            if self.introduced.len() >= MAX_TRACKED_PUSHERS && !self.introduced.contains_key(&by) {
                self.introduced
                    .retain(|_, w| w.back().is_some_and(|t| now.saturating_sub(*t) < HOUR));
            }
            self.introduced.entry(by).or_default().push_back(now);
        }
        self.entries.insert(service_hash, {
            let mut delivered_by = Vec::new();
            note_delivery(&mut delivered_by, origin);
            Stored {
                descriptor,
                origin,
                delivered_by,
            }
        });
        Ok(())
    }

    /// Makes room for one entry of `incoming` origin; false if none can go.
    fn evict_one(&mut self, now: u64, incoming: Origin) -> bool {
        // Expired entries first, all of them.
        let before = self.entries.len();
        self.entries.retain(|_, s| !expired(&s.descriptor, now));
        if self.entries.len() < before {
            return true;
        }
        // Then looked-up copies, oldest first.
        let oldest_fetched = self
            .entries
            .iter()
            .filter(|(_, s)| s.origin == Origin::Fetched)
            .min_by_key(|(_, s)| s.descriptor.revision)
            .map(|(h, _)| *h);
        if let Some(h) = oldest_fetched {
            self.entries.remove(&h);
            return true;
        }
        // Then the heaviest pusher's oldest entry, unless the newcomer comes
        // from that same pusher: one pusher cannot evict its way past quota.
        // Counted only where that pusher is the entry's sole deliverer.
        let sole = |s: &Stored| match s.origin {
            Origin::Pushed(by) if s.delivered_by.len() <= 1 => Some(by),
            _ => None,
        };
        let mut counts: HashMap<NodeId, usize> = HashMap::new();
        for s in self.entries.values() {
            if let Some(by) = sole(s) {
                *counts.entry(by).or_default() += 1;
            }
        }
        let Some((&heaviest, _)) = counts.iter().max_by_key(|(_, c)| **c) else {
            return false;
        };
        if incoming == Origin::Pushed(heaviest) {
            return false;
        }
        let victim = self
            .entries
            .iter()
            .filter(|(_, s)| sole(s) == Some(heaviest))
            .min_by_key(|(_, s)| s.descriptor.revision)
            .map(|(h, _)| *h);
        match victim {
            Some(h) => {
                self.entries.remove(&h);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::dht::node::ID_LEN;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn intro() -> Vec<std::net::SocketAddr> {
        vec!["198.51.100.7:9001".parse().unwrap()]
    }

    fn pusher(b: u8) -> Origin {
        Origin::Pushed(NodeId([b; ID_LEN]))
    }

    fn fresh(now: u64) -> (SigningKey, ServiceDescriptor) {
        let k = SigningKey::generate(&mut OsRng);
        let d = ServiceDescriptor::sign(&k, intro(), now);
        (k, d)
    }

    #[test]
    fn only_signed_current_newer_descriptors_are_kept() {
        let now = 1_000_000;
        let mut s = ServiceStore::new();
        let key = SigningKey::generate(&mut OsRng);
        let old = ServiceDescriptor::sign(&key, intro(), now - 100);
        let new = ServiceDescriptor::sign(&key, intro(), now - 10);
        let hash = old.service_hash();
        assert_eq!(s.put(hash, new.clone(), pusher(1), now), Ok(()));
        assert_eq!(s.put(hash, old, pusher(1), now), Err(Refused::NotNewer));
        let forged = ServiceDescriptor::sign(&SigningKey::generate(&mut OsRng), intro(), now);
        assert_eq!(s.put(hash, forged, pusher(1), now), Err(Refused::NotSigned));
        let future = ServiceDescriptor::sign(&key, intro(), now + MAX_CLOCK_SKEW_SECS + 1);
        assert_eq!(
            s.put(hash, future, pusher(1), now),
            Err(Refused::FromTheFuture)
        );
        let stale = ServiceDescriptor::sign(&key, intro(), now - DESCRIPTOR_TTL_SECS);
        assert_eq!(s.put(hash, stale, pusher(1), now), Err(Refused::Expired));
        assert_eq!(s.get(&hash, now).map(|x| x.descriptor.clone()), Some(new));
        // An hour after it was signed, it is gone.
        assert!(s.get(&hash, now - 10 + DESCRIPTOR_TTL_SECS).is_none());
    }

    #[test]
    fn one_pusher_introduces_a_few_services_an_hour() {
        let now = 1_000_000;
        let mut s = ServiceStore::new();
        for _ in 0..MAX_NEW_PER_PUSHER_PER_HOUR {
            let (_, d) = fresh(now);
            assert_eq!(s.put(d.service_hash(), d, pusher(7), now), Ok(()));
        }
        let (k, d) = fresh(now);
        assert_eq!(
            s.put(d.service_hash(), d, pusher(7), now),
            Err(Refused::PusherOverQuota)
        );
        // Another pusher is not affected, and an update to a held service
        // costs nothing.
        let (_, d) = fresh(now);
        assert_eq!(s.put(d.service_hash(), d, pusher(8), now), Ok(()));
        let held_key = k;
        let first = ServiceDescriptor::sign(&held_key, intro(), now);
        assert_eq!(
            s.put(first.service_hash(), first.clone(), pusher(9), now),
            Ok(())
        );
        let update = ServiceDescriptor::sign(&held_key, intro(), now + 5);
        assert_eq!(
            s.put(update.service_hash(), update.clone(), pusher(7), now + 5),
            Ok(())
        );
        assert_eq!(
            s.get(&update.service_hash(), now + 5).map(|x| x.origin),
            Some(pusher(9)),
            "an update stays attributed to its first pusher"
        );
        // An hour later the window has moved.
        let (_, d) = fresh(now + HOUR);
        assert_eq!(s.put(d.service_hash(), d, pusher(7), now + HOUR), Ok(()));
    }

    #[test]
    fn a_full_store_evicts_the_heaviest_pusher_and_never_its_own() {
        let now = 1_000_000;
        let nid = |p: u32| {
            let mut id = [0xAAu8; ID_LEN];
            id[..4].copy_from_slice(&p.to_le_bytes());
            NodeId(id)
        };
        let mut s = ServiceStore::new();
        let (_, own) = fresh(now);
        assert_eq!(
            s.put(own.service_hash(), own.clone(), Origin::Own, now),
            Ok(())
        );
        let (_, honest) = fresh(now);
        assert_eq!(
            s.put(honest.service_hash(), honest.clone(), pusher(1), now),
            Ok(())
        );
        // Pushers at their full quota fill the rest.
        let mut p = 0u32;
        'fill: loop {
            for _ in 0..MAX_NEW_PER_PUSHER_PER_HOUR {
                if s.len() >= MAX_STORED_SERVICES {
                    break 'fill;
                }
                let (_, d) = fresh(now);
                assert_eq!(
                    s.put(d.service_hash(), d, Origin::Pushed(nid(p)), now),
                    Ok(())
                );
            }
            p += 1;
        }
        assert_eq!(s.len(), MAX_STORED_SERVICES);
        // A newcomer from a pusher with nothing here still gets in: an entry
        // of a pusher holding the most goes, not the one-service pusher's and
        // never this node's own.
        let (_, newcomer) = fresh(now);
        assert_eq!(
            s.put(newcomer.service_hash(), newcomer.clone(), pusher(250), now),
            Ok(())
        );
        assert_eq!(s.len(), MAX_STORED_SERVICES);
        assert!(s.get(&newcomer.service_hash(), now).is_some());
        assert!(
            s.get(&own.service_hash(), now).is_some(),
            "its own service is never evicted"
        );
        assert!(
            s.get(&honest.service_hash(), now).is_some(),
            "a one-service pusher is not the first to go"
        );
        // Expired entries make room before anything else.
        let later = now + DESCRIPTOR_TTL_SECS;
        let (_, after) = fresh(later);
        assert_eq!(
            s.put(after.service_hash(), after, pusher(251), later),
            Ok(())
        );
        assert!(
            s.len() < 10,
            "everything signed an hour ago has gone ({} left)",
            s.len()
        );
    }

    #[test]
    fn an_entry_two_nodes_delivered_is_not_one_pushers_to_lose() {
        let now = 1_000_000;
        let nid = |p: u32| {
            let mut id = [0xBBu8; ID_LEN];
            id[..4].copy_from_slice(&p.to_le_bytes());
            NodeId(id)
        };
        let mut s = ServiceStore::new();
        // An attacker (nid 0) relays an honest service before its publisher
        // (nid 999) delivers the same revision.
        let honest = ServiceDescriptor::sign(&SigningKey::generate(&mut OsRng), intro(), now - 10);
        assert_eq!(
            s.put(
                honest.service_hash(),
                honest.clone(),
                Origin::Pushed(nid(0)),
                now
            ),
            Ok(())
        );
        assert_eq!(
            s.put(
                honest.service_hash(),
                honest.clone(),
                Origin::Pushed(nid(999)),
                now
            ),
            Err(Refused::NotNewer)
        );
        // The attacker makes itself the heaviest pusher: a full quota of its
        // own, while everyone else filling the store pushes one fewer.
        for _ in 1..MAX_NEW_PER_PUSHER_PER_HOUR {
            let (_, d) = fresh(now);
            assert_eq!(
                s.put(d.service_hash(), d, Origin::Pushed(nid(0)), now),
                Ok(())
            );
        }
        let mut p = 1u32;
        'fill: loop {
            for _ in 0..MAX_NEW_PER_PUSHER_PER_HOUR - 1 {
                if s.len() >= MAX_STORED_SERVICES {
                    break 'fill;
                }
                let (_, d) = fresh(now);
                assert_eq!(
                    s.put(d.service_hash(), d, Origin::Pushed(nid(p)), now),
                    Ok(())
                );
            }
            p += 1;
        }
        // A second identity then pushes new services, each forcing an
        // eviction of the heaviest pusher's oldest entry, which the honest
        // service would be if it counted as the attacker's alone.
        for i in 0..5u32 {
            let (_, d) = fresh(now);
            assert_eq!(
                s.put(d.service_hash(), d, Origin::Pushed(nid(100_000 + i)), now),
                Ok(())
            );
        }
        assert!(
            s.get(&honest.service_hash(), now).is_some(),
            "the service two nodes delivered survived the evictions"
        );
    }
}
