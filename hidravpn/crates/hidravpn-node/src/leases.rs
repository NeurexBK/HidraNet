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
}

fn manual() -> String {
    "manual".into()
}

/// How long an openly admitted lease with no handshake ever is kept.
pub const NEVER_CAME_SECS: u64 = 900;

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
    /// already has.
    pub fn admit_open(&mut self, name: &str, public_key: &str, net: &TunnelNet) -> Result<Lease> {
        self.admit_as(name, public_key, net, "open")
    }

    /// Admits the fresh key a redeemed pass names. Such a lease lapses soon
    /// after it is no longer used: the next connection brings its own pass.
    pub fn admit_pass(&mut self, name: &str, public_key: &str, net: &TunnelNet) -> Result<Lease> {
        self.admit_as(name, public_key, net, "pass")
    }

    fn admit_as(
        &mut self,
        name: &str,
        public_key: &str,
        net: &TunnelNet,
        source: &str,
    ) -> Result<Lease> {
        let had = self.find(public_key).is_some();
        let mut lease = self.admit(name, public_key, net)?;
        if !had {
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

    /// Drops openly admitted leases that have been idle for `idle_secs`:
    /// nothing from the client since it was admitted or since the last
    /// handshake written down (`note_handshakes` first). Manual leases never
    /// expire. Returns what was dropped.
    #[cfg(test)]
    pub fn expire_idle(&mut self, now: u64, idle_secs: u64) -> Vec<Lease> {
        self.expire_idle_with_passes(now, idle_secs, 0)
    }

    /// `expire_idle`, and leases won with a pass after `pass_idle_secs`
    /// without a handshake (or `NEVER_CAME_SECS` when they never had one);
    /// 0 keeps them.
    pub fn expire_idle_with_passes(
        &mut self,
        now: u64,
        idle_secs: u64,
        pass_idle_secs: u64,
    ) -> Vec<Lease> {
        let mut gone = self.expire_source(now, pass_idle_secs, "pass");
        gone.extend(self.expire_source(now, idle_secs, "open"));
        gone
    }

    fn expire_source(&mut self, now: u64, idle_secs: u64, source: &str) -> Vec<Lease> {
        if idle_secs == 0 {
            return Vec::new();
        }
        // A lease whose client never completed a handshake is a request, not
        // a client: it lapses after NEVER_CAME_SECS (or the idle window, if
        // that is shorter), so admissions cost tunnels, not HTTP requests.
        let never_came = idle_secs.min(NEVER_CAME_SECS);
        let (gone, kept): (Vec<Lease>, Vec<Lease>) = self.leases.drain(..).partition(|l| {
            l.source == source
                && (now.saturating_sub(l.admitted_at.max(l.last_seen)) >= idle_secs
                    || (l.last_seen == 0 && now.saturating_sub(l.admitted_at) >= never_came))
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

/// The passes this node has taken, by tag (`Redemption::spent_tag`, a hash:
/// no nonce in the clear), each with the end of its issuer key's validity,
/// after which no node takes it anyway and the tag can go. Kept beside the
/// leases, so a restart does not let a pass be spent twice.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SpentPasses {
    #[serde(default)]
    tags: std::collections::BTreeMap<String, i64>,
}

fn spent_path() -> PathBuf {
    path().with_file_name("spent.json")
}

impl SpentPasses {
    pub fn load() -> Result<Self> {
        match std::fs::read(spent_path()) {
            Ok(b) => Ok(serde_json::from_slice(&b).context("the spent-pass file is unreadable")?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Written beside, flushed to disk, renamed over, and the directory
    /// flushed too: after a power cut the file is the old list or the new
    /// one, never an empty one. Root only.
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let p = spent_path();
        let dir = p.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        let tmp = p.with_extension("json.tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&serde_json::to_vec(self)?)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p)?;
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.tags.contains_key(tag)
    }

    pub fn insert(&mut self, tag: String, valid_until: i64) {
        self.tags.insert(tag, valid_until);
    }

    /// Forgets the tags of passes no node would take any more.
    pub fn prune(&mut self, now_unix: i64) -> usize {
        let before = self.tags.len();
        self.tags.retain(|_, until| *until >= now_unix);
        before - self.tags.len()
    }

    pub fn len(&self) -> usize {
        self.tags.len()
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
        l.admit_open("q", &open_quiet, &net()).unwrap();
        l.admit_open("a", &open_active, &net()).unwrap();
        l.admit_open("n", &open_new, &net()).unwrap();
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
        let gone = l.expire_idle(t0, 60);
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
        assert!(l.expire_idle(t0, 0).is_empty(), "0 means never");

        // A restart: the tunnel knows no handshake for anyone. What was
        // written down decides — each lease goes once it has been quiet for
        // the whole window, counted from its admission or its last handshake,
        // whichever is later.
        let nothing = std::collections::HashMap::new();
        assert!(!l.note_handshakes(t0 + 30, &nothing));
        let gone = l.expire_idle(t0 + 30, 60);
        assert!(gone.is_empty(), "nothing is 60 s idle yet: {gone:?}");
        let gone = l.expire_idle(t0 + 56, 60);
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(
            gone[0].public_key, open_active,
            "last seen 5 s before t0: 61 s quiet"
        );
        assert!(
            l.find(&open_new).is_some(),
            "admitted at t0: 56 s quiet only"
        );
        let gone = l.expire_idle(t0 + 61, 60);
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
        l.admit_open("never", &never, &net()).unwrap();
        l.admit_open("came", &came, &net()).unwrap();
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
        let gone = l.expire_idle(t0, 30 * 86_400);
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(gone[0].public_key, never);
        assert!(l.find(&came).is_some());
        assert!(l.find(&by_hand).is_some());
        // Shorter idle windows keep working as before.
        assert!(l.expire_idle(t0, 60).is_empty());
    }

    #[test]
    fn a_pass_lease_lapses_on_its_own_clock_and_a_spent_tag_is_kept_until_its_key_ends() {
        let mut l = Leases::default();
        let pass = Key::generate_private().get_public().to_base64();
        let open = Key::generate_private().get_public().to_base64();
        l.admit_pass("pass-1", &pass, &net()).unwrap();
        l.admit_open("open-1", &open, &net()).unwrap();
        assert_eq!(l.find(&pass).unwrap().source, "pass");
        let t0 = now_unix();
        let mut age = std::collections::HashMap::new();
        age.insert(pass.clone(), Some(std::time::Duration::from_secs(1)));
        age.insert(open.clone(), Some(std::time::Duration::from_secs(1)));
        l.note_handshakes(t0, &age);
        // An hour later: the pass lease (a 30-minute window) goes, the open
        // one (a day) stays.
        let gone = l.expire_idle_with_passes(t0 + 3600, 86_400, 1800);
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].public_key, pass);
        assert!(l.find(&open).is_some());
        // 0 keeps pass leases.
        l.admit_pass("pass-2", &pass, &net()).unwrap();
        assert!(l.expire_idle_with_passes(t0 + 10 * 86_400, 0, 0).is_empty());

        let mut s = SpentPasses::default();
        s.insert("a".into(), 100);
        s.insert("b".into(), 200);
        assert!(s.contains("a"));
        assert_eq!(s.prune(150), 1);
        assert!(!s.contains("a") && s.contains("b"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn bad_input_is_refused() {
        let mut l = Leases::default();
        assert!(l.admit("x", "not-a-key", &net()).is_err());
        let k = Key::generate_private().get_public().to_base64();
        assert!(l.admit("has space", &k, &net()).is_err());
    }
}
