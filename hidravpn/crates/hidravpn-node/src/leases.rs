//! Who is admitted and which tunnel address they hold.
//!
//! Kept in /var/lib/hidravpn, so a reboot keeps every client: a lease is a
//! public key and a tunnel address, exactly what a WireGuard configuration
//! holds, and a kernel update on a rented server must not throw everyone out.
//! In phase 5 admission comes from a pass and a lease lives as long as the
//! connection; this file is the phase-1 stand-in, written by an
//! administrator's `admit`.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use wireguard_control::Key;

use crate::config::TunnelNet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub name: String,
    pub public_key: String,
    pub ip: Ipv4Addr,
    /// Seconds since the epoch when admitted; 0 for leases from before this
    /// was recorded.
    #[serde(default)]
    pub admitted_at: u64,
    /// "manual" (the operator's `admit`) or "open" (the admission service).
    #[serde(default = "manual")]
    pub source: String,
    /// Seconds since the epoch of the last handshake the node wrote down
    /// (every reaper tick and at shutdown); 0 when none was ever seen. It is
    /// what makes a restart not count as idleness.
    #[serde(default)]
    pub last_seen: u64,
    /// The bytes received from this key when last looked at, in memory only:
    /// more than that since means the client is still there, even between
    /// handshakes (WireGuard shakes hands only every two minutes).
    #[serde(skip)]
    rx_seen: u64,
}

fn manual() -> String {
    "manual".into()
}

/// How long an openly admitted lease with no handshake ever is kept.
pub const NEVER_CAME_SECS: u64 = 900;

/// How long a session lease — a key made for one connection, asked for
/// through an entry — outlives its last handshake. A live WireGuard session
/// shakes hands every two minutes, so ten minutes of silence means the
/// connection is over; the node then forgets the key and its address.
pub const SESSION_IDLE_SECS: u64 = 600;

/// A session lease whose key never shook hands is gone after this: the
/// client that asked for it connects within seconds, or never.
pub const SESSION_NEVER_CAME_SECS: u64 = 120;

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Leases {
    leases: Vec<Lease>,
}

fn path() -> PathBuf {
    // HIDRAVPN_RUN_DIR lets two nodes share one machine (the multi-hop test
    // runs an entry and an exit side by side); the default is /run, RAM.
    let dir = std::env::var_os("HIDRAVPN_RUN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/hidravpn"));
    dir.join("peers.json")
}

impl Leases {
    pub fn load() -> Result<Self> {
        match std::fs::read(path()) {
            Ok(b) => Ok(serde_json::from_slice(&b).context("the leases file is unreadable")?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        let p = path();
        std::fs::create_dir_all(p.parent().unwrap())?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Lease> {
        self.leases.iter()
    }

    pub fn find(&self, public_key: &str) -> Option<&Lease> {
        let k = public_key.trim();
        self.leases.iter().find(|l| l.public_key == k)
    }

    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// Admits a key through the admission service, or returns the lease it
    /// already has. `session` marks a key made for one connection: its lease
    /// lapses soon after the connection ends (`expire_idle`).
    pub fn admit_open(
        &mut self,
        name: &str,
        public_key: &str,
        net: &TunnelNet,
        session: bool,
    ) -> Result<Lease> {
        let had = self.find(public_key).is_some();
        let mut lease = self.admit(name, public_key, net)?;
        if !had {
            let source = if session { "session" } else { "open" };
            lease.source = source.into();
            if let Some(l) = self
                .leases
                .iter_mut()
                .find(|l| l.public_key == lease.public_key)
            {
                l.source = source.into();
            }
        }
        Ok(lease)
    }

    /// Writes down, for every lease with a handshake, when that handshake
    /// was (`handshake_age` is per key, as the tunnel reports it). Returns
    /// whether anything advanced, so the caller knows to save.
    pub fn note_handshakes(
        &mut self,
        now: u64,
        handshake_age: &std::collections::HashMap<String, Option<std::time::Duration>>,
    ) -> bool {
        let mut touched = false;
        for l in self.leases.iter_mut() {
            if let Some(Some(age)) = handshake_age.get(&l.public_key) {
                let seen = now.saturating_sub(age.as_secs());
                if seen > l.last_seen {
                    l.last_seen = seen;
                    touched = true;
                }
            }
        }
        touched
    }

    /// Writes down `now` as the last sign of life of every lease that has
    /// received bytes since the last look (`rx_bytes` is per key, as the
    /// tunnel counts it). Returns whether anything advanced.
    pub fn note_traffic(
        &mut self,
        now: u64,
        rx_bytes: &std::collections::HashMap<String, u64>,
    ) -> bool {
        let mut touched = false;
        for l in self.leases.iter_mut() {
            if let Some(&rx) = rx_bytes.get(&l.public_key) {
                if rx > l.rx_seen {
                    l.rx_seen = rx;
                    if now > l.last_seen {
                        l.last_seen = now;
                        touched = true;
                    }
                }
            }
        }
        touched
    }

    /// Drops openly admitted leases that have been idle for `idle_secs`:
    /// nothing from the client since it was admitted or since the last
    /// handshake written down (`note_handshakes` first). Manual leases never
    /// expire. Returns what was dropped.
    pub fn expire_idle(&mut self, now: u64, idle_secs: u64, session_secs: u64) -> Vec<Lease> {
        // A lease whose client never completed a handshake is a request, not
        // a client: it lapses after NEVER_CAME_SECS (or the idle window, if
        // that is shorter), so admissions cost tunnels, not HTTP requests.
        // A session lease lapses `session_secs` after its last sign of life,
        // whatever the idle window: it was made for one connection.
        let lapsed = |l: &Lease, window: u64, never_came: u64| {
            let quiet = now.saturating_sub(l.admitted_at.max(l.last_seen));
            quiet >= window
                || (l.last_seen == 0 && now.saturating_sub(l.admitted_at) >= window.min(never_came))
        };
        let (gone, kept): (Vec<Lease>, Vec<Lease>) =
            self.leases
                .drain(..)
                .partition(|l| match l.source.as_str() {
                    "open" => idle_secs > 0 && lapsed(l, idle_secs, NEVER_CAME_SECS),
                    "session" => lapsed(l, session_secs.max(1), SESSION_NEVER_CAME_SECS),
                    _ => false,
                });
        self.leases = kept;
        gone
    }

    /// Admits a key, or returns the lease it already has.
    pub fn admit(&mut self, name: &str, public_key: &str, net: &TunnelNet) -> Result<Lease> {
        let key = public_key.trim();
        Key::from_base64(key).map_err(|_| anyhow!("that is not a valid WireGuard public key"))?;
        if let Some(l) = self.find(key) {
            return Ok(l.clone());
        }
        let name = name.trim();
        if name.is_empty()
            || name.len() > 32
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("the name must be 1-32 letters, digits, - or _"));
        }
        let ip = self.next_free(net)?;
        let lease = Lease {
            name: name.to_string(),
            public_key: key.to_string(),
            ip,
            admitted_at: now_unix(),
            source: manual(),
            last_seen: 0,
            rx_seen: 0,
        };
        self.leases.push(lease.clone());
        Ok(lease)
    }

    pub fn revoke(&mut self, public_key: &str) -> bool {
        let before = self.leases.len();
        let k = public_key.trim();
        self.leases.retain(|l| l.public_key != k);
        self.leases.len() != before
    }

    /// The lowest unused address after the node's own.
    fn next_free(&self, net: &TunnelNet) -> Result<Ipv4Addr> {
        let hosts = 1u32 << (32 - net.prefix);
        let base = u32::from(net.network);
        for off in 2..hosts - 1 {
            let ip = Ipv4Addr::from(base + off);
            if !self.leases.iter().any(|l| l.ip == ip) {
                return Ok(ip);
            }
        }
        Err(anyhow!("the tunnel subnet is full"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> TunnelNet {
        TunnelNet {
            cidr: "10.77.0.0/16".into(),
            network: Ipv4Addr::new(10, 77, 0, 0),
            prefix: 16,
            node_ip: Ipv4Addr::new(10, 77, 0, 1),
        }
    }

    #[test]
    fn addresses_are_handed_out_in_order_and_kept() {
        let mut l = Leases::default();
        let a = Key::generate_private().get_public().to_base64();
        let b = Key::generate_private().get_public().to_base64();
        assert_eq!(
            l.admit("a", &a, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 2)
        );
        assert_eq!(
            l.admit("b", &b, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 3)
        );
        // Admitting the same key again changes nothing.
        assert_eq!(
            l.admit("a-again", &a, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 2)
        );
        assert!(l.revoke(&a));
        assert!(!l.revoke(&a));
        // The freed address is reused.
        let c = Key::generate_private().get_public().to_base64();
        assert_eq!(
            l.admit("c", &c, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 2)
        );
    }

    #[test]
    fn idle_open_leases_expire_and_manual_ones_never_do() {
        let mut l = Leases::default();
        let open_quiet = Key::generate_private().get_public().to_base64();
        let open_active = Key::generate_private().get_public().to_base64();
        let open_new = Key::generate_private().get_public().to_base64();
        let manual_quiet = Key::generate_private().get_public().to_base64();
        l.admit_open("q", &open_quiet, &net(), false).unwrap();
        l.admit_open("a", &open_active, &net(), false).unwrap();
        l.admit_open("n", &open_new, &net(), false).unwrap();
        l.admit("m", &manual_quiet, &net()).unwrap();
        let t0 = now_unix();
        // Pretend the first three were admitted long ago, except the new one.
        for lease in l.leases.iter_mut() {
            if lease.public_key != open_new {
                lease.admitted_at = t0 - 100;
            }
        }
        let mut age = std::collections::HashMap::new();
        age.insert(open_quiet.clone(), Some(std::time::Duration::from_secs(90)));
        age.insert(open_active.clone(), Some(std::time::Duration::from_secs(5)));
        age.insert(manual_quiet.clone(), None);
        assert!(l.note_handshakes(t0, &age), "handshakes were written down");
        let gone = l.expire_idle(t0, 60, SESSION_IDLE_SECS);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].public_key, open_quiet);
        assert!(l.find(&open_active).is_some(), "an active one stays");
        assert!(
            l.find(&open_new).is_some(),
            "one admitted a moment ago stays, handshake or not"
        );
        assert!(
            l.find(&manual_quiet).is_some(),
            "a manual lease never expires"
        );
        assert!(
            l.expire_idle(t0, 0, SESSION_IDLE_SECS).is_empty(),
            "0 means never"
        );

        // A restart: the tunnel knows no handshake for anyone. What was
        // written down decides — each lease goes once it has been quiet for
        // the whole window, counted from its admission or its last handshake,
        // whichever is later.
        let nothing = std::collections::HashMap::new();
        assert!(!l.note_handshakes(t0 + 30, &nothing));
        let gone = l.expire_idle(t0 + 30, 60, SESSION_IDLE_SECS);
        assert!(gone.is_empty(), "nothing is 60 s idle yet: {gone:?}");
        let gone = l.expire_idle(t0 + 56, 60, SESSION_IDLE_SECS);
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(
            gone[0].public_key, open_active,
            "last seen 5 s before t0: 61 s quiet"
        );
        assert!(
            l.find(&open_new).is_some(),
            "admitted at t0: 56 s quiet only"
        );
        let gone = l.expire_idle(t0 + 61, 60, SESSION_IDLE_SECS);
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(gone[0].public_key, open_new, "never seen since admission");
        assert!(
            l.find(&manual_quiet).is_some(),
            "a manual lease never expires"
        );
    }

    #[test]
    fn a_lease_that_never_shook_hands_lapses_long_before_the_idle_window() {
        let mut l = Leases::default();
        let never = Key::generate_private().get_public().to_base64();
        let came = Key::generate_private().get_public().to_base64();
        let by_hand = Key::generate_private().get_public().to_base64();
        l.admit_open("never", &never, &net(), false).unwrap();
        l.admit_open("came", &came, &net(), false).unwrap();
        l.admit("hand", &by_hand, &net()).unwrap();
        let t0 = now_unix();
        for lease in l.leases.iter_mut() {
            lease.admitted_at = t0 - 1000; // all admitted a while ago
        }
        let mut age = std::collections::HashMap::new();
        age.insert(came.clone(), Some(std::time::Duration::from_secs(10)));
        l.note_handshakes(t0, &age);
        // Thirty days of idle window; the one that never came is gone after
        // NEVER_CAME_SECS, the one that came stays, the manual one stays.
        let gone = l.expire_idle(t0, 30 * 86_400, SESSION_IDLE_SECS);
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(gone[0].public_key, never);
        assert!(l.find(&came).is_some());
        assert!(l.find(&by_hand).is_some());
        // Shorter idle windows keep working as before.
        assert!(l.expire_idle(t0, 60, SESSION_IDLE_SECS).is_empty());
    }

    #[test]
    fn bad_input_is_refused() {
        let mut l = Leases::default();
        assert!(l.admit("x", "not-a-key", &net()).is_err());
        let k = Key::generate_private().get_public().to_base64();
        assert!(l.admit("has space", &k, &net()).is_err());
    }

    #[test]
    fn a_session_lease_lapses_soon_after_its_connection_whatever_the_idle_window() {
        let mut l = Leases::default();
        let k = || {
            wireguard_control::Key::generate_private()
                .get_public()
                .to_base64()
        };
        let (session, kept_open) = (k(), k());
        l.admit_open("client", &session, &net(), true).unwrap();
        l.admit_open("client", &kept_open, &net(), false).unwrap();
        assert_eq!(l.find(&session).unwrap().source, "session");
        let t0 = l.find(&session).unwrap().admitted_at;
        let mut ages = std::collections::HashMap::new();
        ages.insert(session.clone(), Some(std::time::Duration::from_secs(0)));
        ages.insert(kept_open.clone(), Some(std::time::Duration::from_secs(0)));
        l.note_handshakes(t0 + 100, &ages);
        // Alive: nothing goes.
        assert!(l.expire_idle(t0 + 100 + 30, 30 * 86_400, 60).is_empty());
        // Quiet for the session window: the session lease goes, the
        // ordinary open one (thirty days) stays.
        let gone = l.expire_idle(t0 + 100 + 60, 30 * 86_400, 60);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].public_key, session);
        assert!(l.find(&kept_open).is_some());
        // Even with idle expiry off for open leases, a session lease lapses.
        let s2 = k();
        l.admit_open("client", &s2, &net(), true).unwrap();
        let t = l.find(&s2).unwrap().admitted_at;
        assert_eq!(l.expire_idle(t + 61, 0, 60).len(), 1);
    }

    #[test]
    fn traffic_between_handshakes_keeps_a_session_alive() {
        let mut l = Leases::default();
        let k = wireguard_control::Key::generate_private()
            .get_public()
            .to_base64();
        l.admit_open("client", &k, &net(), true).unwrap();
        let t0 = l.find(&k).unwrap().admitted_at;
        let mut rx = std::collections::HashMap::new();
        rx.insert(k.clone(), 500u64);
        assert!(l.note_traffic(t0 + 50, &rx));
        assert!(
            !l.note_traffic(t0 + 70, &rx),
            "no new bytes, no new sign of life"
        );
        assert!(
            l.expire_idle(t0 + 100, 0, 60).is_empty(),
            "50 s quiet of 60"
        );
        rx.insert(k.clone(), 900);
        assert!(l.note_traffic(t0 + 105, &rx));
        assert!(l.expire_idle(t0 + 160, 0, 60).is_empty());
        assert_eq!(l.expire_idle(t0 + 166, 0, 60).len(), 1);
    }
}
