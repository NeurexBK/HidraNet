//! Entry guards: the few relays a client uses as the first hop of every
//! circuit, kept for weeks.
//!
//! A client that picks a new entry for each circuit will, sooner or later,
//! pick a relay run by someone watching; if that someone also runs the exit
//! of the same circuit, they see both ends. With a fresh entry every time,
//! that is a question of when. With a guard kept for weeks it is a question
//! of whether: the guard is either honest, and the client is safe from this
//! attack for as long as it keeps it, or it is not, and nothing else changes.
//!
//! So the guard set is chosen once, saved, and kept until it expires. A
//! guard that fails is not replaced: that would let anyone who can break a
//! connection push the client from guard to guard until it lands on theirs.
//! The second guard is there for when the first is down. A guard is replaced
//! only when it expires or when the client no longer knows it as a relay.

use std::net::SocketAddr;
use std::path::PathBuf;

use rand::Rng;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::client::path::same_network;
use crate::p2p::dht::descriptor::VerifiedRelay;

/// Guards kept at a time: one in use, one for when it is down.
pub const GUARDS: usize = 2;
const DAY: u64 = 24 * 60 * 60;
/// A guard is kept for a random time in this range, so the moment a client
/// changes guards does not line up with the moment it chose them.
const LIFETIME_DAYS: std::ops::Range<u64> = 30..61;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Guard {
    addr: SocketAddr,
    transport_key: [u8; 32],
    expires: u64,
}

impl Guard {
    fn is(&self, r: &VerifiedRelay) -> bool {
        self.addr == r.addr() && &self.transport_key == r.transport_key()
    }
}

pub struct GuardSet {
    guards: Vec<Guard>,
    /// Where they are kept between runs; `None` keeps them in memory.
    file: Option<PathBuf>,
}

impl GuardSet {
    #[allow(dead_code)] // the binary always keeps its guards on disk
    pub fn in_memory() -> Self {
        Self {
            guards: Vec::new(),
            file: None,
        }
    }

    /// The guards saved at `file`, or none if there is no such file. A file
    /// that does not parse is replaced, with a warning.
    pub fn load(file: PathBuf) -> Self {
        let guards = match std::fs::read(&file) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                warn!(error = %e, "guard file is unreadable; choosing new guards");
                Vec::new()
            }),
            Err(_) => Vec::new(),
        };
        Self {
            guards,
            file: Some(file),
        }
    }

    /// Drops guards that expired or that are no longer among `known`, and
    /// picks new ones from `known` until there are GUARDS, each in a network
    /// none of the others is in. Saves the set if it changed.
    pub fn update(&mut self, known: &[VerifiedRelay], now: u64) {
        let before = self.guards.clone();
        self.guards
            .retain(|g| g.expires > now && known.iter().any(|r| g.is(r)));
        let mut rng = rand::thread_rng();
        let mut candidates: Vec<&VerifiedRelay> = known
            .iter()
            .filter(|r| !self.guards.iter().any(|g| g.is(r)))
            .collect();
        candidates.shuffle(&mut rng);
        for r in candidates {
            if self.guards.len() >= GUARDS {
                break;
            }
            if self.guards.iter().any(|g| same_network(&g.addr, &r.addr())) {
                continue;
            }
            self.guards.push(Guard {
                addr: r.addr(),
                transport_key: *r.transport_key(),
                expires: now + rng.gen_range(LIFETIME_DAYS) * DAY,
            });
        }
        if self.guards != before {
            info!(guards = self.guards.len(), "entry guards chosen");
            self.save();
        }
    }

    /// The guards, the one to use first first.
    pub fn guards(&self) -> Vec<VerifiedRelay> {
        self.guards
            .iter()
            .map(|g| VerifiedRelay::pinned(g.addr, g.transport_key))
            .collect()
    }

    /// Written readable by this user only: it says which relays this user
    /// enters the network through.
    fn save(&self) {
        let Some(file) = &self.file else { return };
        let result = serde_json::to_vec(&self.guards)
            .map_err(|e| crate::error::HidraError::Protocol(e.to_string()))
            .and_then(|bytes| crate::crypto::keys::write_private_file(file, &bytes));
        if let Err(e) = result {
            warn!(error = %e, "could not save the entry guards");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(addr: &str, key: u8) -> VerifiedRelay {
        VerifiedRelay::pinned(addr.parse().unwrap(), [key; 32])
    }

    fn known() -> Vec<VerifiedRelay> {
        vec![
            relay("198.51.100.1:9001", 1),
            relay("198.51.100.2:9001", 2),
            relay("203.0.113.1:9001", 3),
            relay("192.0.2.1:9001", 4),
        ]
    }

    #[test]
    fn guards_are_chosen_once_and_kept() {
        let mut set = GuardSet::in_memory();
        set.update(&known(), 1000);
        let first = set.guards();
        assert_eq!(first.len(), GUARDS);
        assert!(!same_network(&first[0].addr(), &first[1].addr()));
        for t in 0..50 {
            set.update(&known(), 1000 + t * DAY / 2);
            assert_eq!(set.guards(), first, "kept within their lifetime");
        }
    }

    #[test]
    fn a_guard_is_replaced_only_when_it_expires_or_is_no_longer_known() {
        // Expired: both replaced by guards that have not.
        let mut set = GuardSet::in_memory();
        set.update(&known(), 0);
        set.update(&known(), 61 * DAY);
        assert_eq!(set.guards().len(), GUARDS);
        assert!(set.guards.iter().all(|g| g.expires > 61 * DAY));

        // No longer known: that one is replaced, the other kept.
        let mut set = GuardSet::in_memory();
        set.update(&known(), 0);
        let gone = set.guards()[0].clone();
        let kept = set.guards()[1].clone();
        let without: Vec<_> = known().into_iter().filter(|r| *r != gone).collect();
        set.update(&without, 1);
        assert!(set.guards().contains(&kept));
        assert!(!set.guards().contains(&gone));
        assert_eq!(set.guards().len(), GUARDS);
    }

    #[test]
    fn guards_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("hidra-guards-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("guards.json");
        let mut set = GuardSet::load(file.clone());
        set.update(&known(), 0);
        let first = set.guards();
        let mut again = GuardSet::load(file.clone());
        again.update(&known(), 10);
        assert_eq!(again.guards(), first);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
