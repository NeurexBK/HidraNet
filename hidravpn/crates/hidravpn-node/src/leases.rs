//! Who is admitted and which tunnel address they hold.
//!
//! Kept in /var/lib/hidravpn, so a reboot keeps every client: a lease is a
//! public key and a tunnel address, exactly what a WireGuard configuration
//! holds, and a kernel update on a rented server must not throw everyone out.
//! Written by the operator's `admit` and `revoke` and by the running node
//! (open admission, redeemed passes, idle expiry), always under one lock
//! (`Leases::update`).

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

/// The keys of the session leases in `gone` that never completed a
/// handshake: requests, not clients, whose places in the admission window
/// of new sessions are given back.
pub fn never_came_sessions(gone: &[Lease]) -> Vec<[u8; 32]> {
    gone.iter()
        .filter(|l| l.source == "session" && l.last_seen == 0)
        .filter_map(|l| hidravpn_core::keys::public_key_from_base64(&l.public_key).ok())
        .map(|k| *k.as_bytes())
        .collect()
}

/// How long an openly admitted lease with no handshake ever is kept.
pub const NEVER_CAME_SECS: u64 = 900;

/// How long each kind of lease outlives its last sign of life, in seconds;
/// 0 keeps it (sessions always lapse).
#[derive(Debug, Clone, Copy, Default)]
pub struct IdleWindows {
    /// Leases won through open admission and kept (a join).
    pub open: u64,
    /// Keys made for one connection (`"session": true`).
    pub session: u64,
    /// Keys a redeemed pass admitted.
    pub pass: u64,
}

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
    // runs an entry and an exit side by side).
    let dir = std::env::var_os("HIDRAVPN_RUN_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/hidravpn"));
    dir.join("peers.json")
}

/// The lock `Leases::update` holds, on a file beside the leases.
fn lock() -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = path().with_file_name("peers.lock");
    std::fs::create_dir_all(p.parent().unwrap())?;
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&p)
        .with_context(|| format!("opening {}", p.display()))?;
    f.lock().context("locking the leases")?;
    Ok(f)
}

impl Leases {
    pub fn load() -> Result<Self> {
        match std::fs::read(path()) {
            Ok(b) => Ok(serde_json::from_slice(&b).context("the leases file is unreadable")?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads the leases, lets `f` change them, and writes them back when it
    /// says so — all under a lock on the file system. The running node and
    /// the operator's `admit` and `revoke` both change this file: without
    /// the lock, and without reading it afresh each time, the node would
    /// hand out an address `admit` had just given someone, or write a
    /// revoked lease back. `f` returns its result and whether to save.
    pub fn update<T>(f: impl FnOnce(&mut Self) -> (T, bool)) -> Result<T> {
        let _lock = lock()?;
        let mut leases = Self::load()?;
        let (out, save) = f(&mut leases);
        if save {
            leases.save()?;
        }
        Ok(out)
    }

    /// Written beside, flushed, renamed over, the directory flushed: after a
    /// power cut the file is the old one or the new one, never an empty one
    /// that would keep the node from starting. Root only. Callers hold the
    /// lock (`update`).
    fn save(&self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let p = path();
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
            f.write_all(&serde_json::to_vec_pretty(self)?)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p)?;
        if let Ok(d) = std::fs::File::open(&dir) {
            let _ = d.sync_all();
        }
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
        let source = if session { "session" } else { "open" };
        self.admit_as(name, public_key, net, source)
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

    /// Writes down `now` as the last sign of life of every lease whose key
    /// received bytes since the last look (`active`): the client is still
    /// there, even between handshakes, which WireGuard makes only every two
    /// minutes. Returns whether anything advanced.
    pub fn note_traffic(&mut self, now: u64, active: &std::collections::HashSet<String>) -> bool {
        let mut touched = false;
        for l in self.leases.iter_mut() {
            if active.contains(&l.public_key) && now > l.last_seen {
                l.last_seen = now;
                touched = true;
            }
        }
        touched
    }

    /// Drops the leases that have been idle past their window (`w`): nothing
    /// from the client since it was admitted or since the last sign of life
    /// written down (`note_handshakes`, `note_traffic` first). Manual leases
    /// never expire. Returns what was dropped.
    pub fn expire_idle(&mut self, now: u64, w: &IdleWindows) -> Vec<Lease> {
        // A lease whose client never completed a handshake is a request, not
        // a client: it lapses after a short while (or the idle window, if
        // that is shorter), so admissions cost tunnels, not HTTP requests.
        // A session or pass lease was made for one connection: it lapses its
        // own window after its last sign of life, whatever the open window.
        let lapsed = |l: &Lease, window: u64, never_came: u64| {
            window > 0 && {
                let quiet = now.saturating_sub(l.admitted_at.max(l.last_seen));
                quiet >= window
                    || (l.last_seen == 0
                        && now.saturating_sub(l.admitted_at) >= window.min(never_came))
            }
        };
        let (gone, kept): (Vec<Lease>, Vec<Lease>) =
            self.leases
                .drain(..)
                .partition(|l| match l.source.as_str() {
                    "open" => lapsed(l, w.open, NEVER_CAME_SECS),
                    "session" => lapsed(l, w.session.max(1), SESSION_NEVER_CAME_SECS),
                    "pass" => lapsed(l, w.pass, NEVER_CAME_SECS),
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

    /// Whether a new client would get an address.
    pub fn has_room(&self, net: &TunnelNet) -> bool {
        self.next_free(net).is_ok()
    }

    /// How many leases came from `source` ("open", "session", ...).
    pub fn count_source(&self, source: &str) -> usize {
        self.leases.iter().filter(|l| l.source == source).count()
    }

    /// Why `public_key` cannot be given a new lease now, if it cannot: the
    /// node holds `max_clients`, or its subnet is used up, or — for a
    /// lasting lease won openly, whose cap `lasting_open` then is — the
    /// share kept for those is taken. Lasting leases cost no work, so they
    /// get a share and the rest of the places stay for sessions. A key that
    /// already has a lease is given it again.
    pub fn refusal_for_room(
        &self,
        public_key: &str,
        net: &TunnelNet,
        max_clients: u32,
        lasting_open: Option<usize>,
    ) -> Option<String> {
        if self.find(public_key).is_some() {
            return None;
        }
        if self.leases.len() as u64 >= u64::from(max_clients) || !self.has_room(net) {
            return Some("this node is full; try another".into());
        }
        match lasting_open {
            Some(cap) if self.count_source("open") >= cap => Some(
                "this node keeps its other places for keys made for one connection: no room for another lasting lease; connect without joining, or try another node".into(),
            ),
            _ => None,
        }
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
///
/// On disk it is a snapshot (`spent.json`) and a journal beside it
/// (`spent.log`, one `tag until` line per pass taken since the snapshot).
/// Taking a pass appends one line and flushes it: the same small write
/// whether the node remembers a hundred passes or a million, where
/// rewriting the whole list each time took close to a second at a million.
/// The snapshot is rewritten, and the journal emptied, when old tags are
/// pruned or the journal has grown (`needs_compacting`).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SpentPasses {
    #[serde(default)]
    tags: std::collections::BTreeMap<String, i64>,
    /// Lines in the journal now.
    #[serde(skip)]
    journal: usize,
    /// A write to the journal failed partway: the next pass rewrites the
    /// snapshot instead of appending after a torn line.
    #[serde(skip)]
    journal_torn: bool,
    /// Where both files live: beside the leases.
    #[serde(skip)]
    dir: PathBuf,
}

/// Journal lines after which the snapshot is rewritten.
const COMPACT_AFTER: usize = 4096;

impl SpentPasses {
    pub fn load() -> Result<Self> {
        Self::load_from(path().parent().unwrap())
    }

    fn spent_path(&self) -> PathBuf {
        self.dir.join("spent.json")
    }

    fn journal_path(&self) -> PathBuf {
        self.dir.join("spent.log")
    }

    fn load_from(dir: &std::path::Path) -> Result<Self> {
        let mut s: Self = match std::fs::read(dir.join("spent.json")) {
            Ok(b) => serde_json::from_slice(&b).context("the spent-pass file is unreadable")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e.into()),
        };
        s.dir = dir.to_path_buf();
        match std::fs::read(s.journal_path()) {
            Ok(b) => {
                // A line cut short by a power cut is the one pass that was
                // never admitted (its line is flushed before the admission);
                // anything that does not read as a line is skipped.
                for line in b.split(|c| *c == b'\n') {
                    let line = String::from_utf8_lossy(line);
                    let mut w = line.split_whitespace();
                    if let (Some(tag), Some(until), None) = (w.next(), w.next(), w.next()) {
                        if let Ok(until) = until.parse::<i64>() {
                            if tag.len() == 64 && tag.bytes().all(|c| c.is_ascii_hexdigit()) {
                                s.tags.insert(tag.to_string(), until);
                                s.journal += 1;
                            }
                        }
                    }
                }
                // The last line cut short: append nothing after it.
                if !b.is_empty() && !b.ends_with(b"\n") {
                    s.journal_torn = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(s)
    }

    /// Writes a pass down as spent, on disk before in memory: flushed
    /// before the caller admits its key.
    pub fn record(&mut self, tag: String, valid_until: i64) -> Result<()> {
        if self.journal_torn {
            self.tags.insert(tag, valid_until);
            return self.save();
        }
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let p = self.journal_path();
        let dir = self.dir.clone();
        std::fs::create_dir_all(&dir)?;
        let new = !p.exists();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&p)?;
        if let Err(e) = f
            .write_all(format!("{tag} {valid_until}\n").as_bytes())
            .and_then(|()| f.sync_data())
        {
            self.journal_torn = true;
            return Err(e.into());
        }
        if new {
            if let Ok(d) = std::fs::File::open(&dir) {
                let _ = d.sync_all();
            }
        }
        self.tags.insert(tag, valid_until);
        self.journal += 1;
        Ok(())
    }

    /// Takes back a pass written down as spent whose admission then failed,
    /// so the client may use it again. On disk first: if that fails the
    /// pass stays spent, which never lets it be spent twice.
    pub fn forget(&mut self, tag: &str) -> Result<()> {
        let Some(until) = self.tags.remove(tag) else {
            return Ok(());
        };
        if let Err(e) = self.save() {
            self.tags.insert(tag.to_string(), until);
            return Err(e);
        }
        Ok(())
    }

    /// Whether the journal has grown enough to fold into the snapshot.
    pub fn needs_compacting(&self) -> bool {
        self.journal >= COMPACT_AFTER || self.journal_torn
    }

    /// The whole list as a new snapshot — written beside, flushed to disk,
    /// renamed over, the directory flushed too, so after a power cut it is
    /// the old one or the new one, never an empty one — and then the journal
    /// emptied: a cut in between leaves tags in both, which is harmless.
    /// Root only.
    pub fn save(&mut self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let p = self.spent_path();
        let dir = self.dir.clone();
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
        match std::fs::OpenOptions::new()
            .write(true)
            .open(self.journal_path())
        {
            Ok(j) => {
                j.set_len(0)?;
                j.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        self.journal = 0;
        self.journal_torn = false;
        Ok(())
    }

    pub fn contains(&self, tag: &str) -> bool {
        self.tags.contains_key(tag)
    }

    #[cfg(test)]
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
    fn lasting_leases_fill_their_share_and_sessions_still_find_room() {
        let mut l = Leases::default();
        let key = || Key::generate_private().get_public().to_base64();
        let (max, cap) = (40, 10);
        // One source, or many, piles up lasting leases: it gets the share.
        let mut lasting = 0;
        for _ in 0..100 {
            let k = key();
            if l.refusal_for_room(&k, &net(), max, Some(cap)).is_none() {
                l.admit_open("x", &k, &net(), false).unwrap();
                lasting += 1;
            }
        }
        assert_eq!(lasting, cap, "lasting leases stop at their share");
        let why = l.refusal_for_room(&key(), &net(), max, Some(cap)).unwrap();
        assert!(why.contains("lasting"), "{why}");
        // A key that already holds one is given it again.
        let held = l.iter().next().unwrap().public_key.clone();
        assert!(l.refusal_for_room(&held, &net(), max, Some(cap)).is_none());
        // Sessions still find the other places, and then the node is full.
        let mut sessions = 0;
        loop {
            let k = key();
            if l.refusal_for_room(&k, &net(), max, None).is_some() {
                break;
            }
            l.admit_open("s", &k, &net(), true).unwrap();
            sessions += 1;
        }
        assert_eq!(sessions, max as usize - cap);
        assert_eq!(l.count_source("session"), max as usize - cap);
        assert!(l
            .refusal_for_room(&key(), &net(), max, None)
            .unwrap()
            .contains("full"));
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
        let gone = l.expire_idle(
            t0,
            &IdleWindows {
                open: 60,
                session: SESSION_IDLE_SECS,
                pass: 0,
            },
        );
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
            l.expire_idle(
                t0,
                &IdleWindows {
                    open: 0,
                    session: SESSION_IDLE_SECS,
                    pass: 0
                }
            )
            .is_empty(),
            "0 means never"
        );

        // A restart: the tunnel knows no handshake for anyone. What was
        // written down decides — each lease goes once it has been quiet for
        // the whole window, counted from its admission or its last handshake,
        // whichever is later.
        let nothing = std::collections::HashMap::new();
        assert!(!l.note_handshakes(t0 + 30, &nothing));
        let gone = l.expire_idle(
            t0 + 30,
            &IdleWindows {
                open: 60,
                session: SESSION_IDLE_SECS,
                pass: 0,
            },
        );
        assert!(gone.is_empty(), "nothing is 60 s idle yet: {gone:?}");
        let gone = l.expire_idle(
            t0 + 56,
            &IdleWindows {
                open: 60,
                session: SESSION_IDLE_SECS,
                pass: 0,
            },
        );
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(
            gone[0].public_key, open_active,
            "last seen 5 s before t0: 61 s quiet"
        );
        assert!(
            l.find(&open_new).is_some(),
            "admitted at t0: 56 s quiet only"
        );
        let gone = l.expire_idle(
            t0 + 61,
            &IdleWindows {
                open: 60,
                session: SESSION_IDLE_SECS,
                pass: 0,
            },
        );
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
        let gone = l.expire_idle(
            t0,
            &IdleWindows {
                open: 30 * 86_400,
                session: SESSION_IDLE_SECS,
                pass: 0,
            },
        );
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert_eq!(gone[0].public_key, never);
        assert!(l.find(&came).is_some());
        assert!(l.find(&by_hand).is_some());
        // Shorter idle windows keep working as before.
        assert!(l
            .expire_idle(
                t0,
                &IdleWindows {
                    open: 60,
                    session: SESSION_IDLE_SECS,
                    pass: 0
                }
            )
            .is_empty());
    }

    #[test]
    fn a_pass_lease_lapses_on_its_own_clock_and_a_spent_tag_is_kept_until_its_key_ends() {
        let mut l = Leases::default();
        let pass = Key::generate_private().get_public().to_base64();
        let open = Key::generate_private().get_public().to_base64();
        l.admit_pass("pass-1", &pass, &net()).unwrap();
        l.admit_open("open-1", &open, &net(), false).unwrap();
        assert_eq!(l.find(&pass).unwrap().source, "pass");
        let t0 = now_unix();
        let mut age = std::collections::HashMap::new();
        age.insert(pass.clone(), Some(std::time::Duration::from_secs(1)));
        age.insert(open.clone(), Some(std::time::Duration::from_secs(1)));
        l.note_handshakes(t0, &age);
        // An hour later: the pass lease (a 30-minute window) goes, the open
        // one (a day) stays.
        let gone = l.expire_idle(
            t0 + 3600,
            &IdleWindows {
                open: 86_400,
                session: SESSION_IDLE_SECS,
                pass: 1800,
            },
        );
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].public_key, pass);
        assert!(l.find(&open).is_some());
        // 0 keeps pass leases.
        l.admit_pass("pass-2", &pass, &net()).unwrap();
        assert!(l
            .expire_idle(
                t0 + 10 * 86_400,
                &IdleWindows {
                    open: 0,
                    session: SESSION_IDLE_SECS,
                    pass: 0
                }
            )
            .is_empty());

        let mut s = SpentPasses::default();
        s.insert("a".into(), 100);
        s.insert("b".into(), 200);
        assert!(s.contains("a"));
        assert_eq!(s.prune(150), 1);
        assert!(!s.contains("a") && s.contains("b"));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn spent_passes_survive_a_restart_from_the_journal_and_a_torn_line_is_skipped() {
        let dir = std::env::temp_dir().join(format!("hv-spent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let tag = |i: u8| format!("{:064x}", i);

        let mut s = SpentPasses::load_from(&dir).unwrap();
        s.record(tag(1), 100).unwrap();
        s.record(tag(2), 200).unwrap();
        assert!(
            !dir.join("spent.json").exists(),
            "a pass is a line, not a rewrite"
        );
        let s2 = SpentPasses::load_from(&dir).unwrap();
        assert!(s2.contains(&tag(1)) && s2.contains(&tag(2)));

        // A power cut halfway through a line: that line is skipped, the
        // ones before it kept, and nothing is appended after it.
        use std::io::Write;
        let mut j = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join("spent.log"))
            .unwrap();
        j.write_all(&tag(3).as_bytes()[..20]).unwrap();
        let mut s3 = SpentPasses::load_from(&dir).unwrap();
        assert_eq!(s3.len(), 2);
        assert!(s3.needs_compacting());
        s3.record(tag(4), 400).unwrap();
        assert_eq!(std::fs::metadata(dir.join("spent.log")).unwrap().len(), 0);
        let s4 = SpentPasses::load_from(&dir).unwrap();
        assert!(s4.contains(&tag(1)) && s4.contains(&tag(4)) && !s4.contains(&tag(3)));

        // Compacting folds the journal into the snapshot.
        let mut s5 = SpentPasses::load_from(&dir).unwrap();
        s5.record(tag(5), 500).unwrap();
        assert_eq!(s5.prune(150), 1);
        s5.save().unwrap();
        let s6 = SpentPasses::load_from(&dir).unwrap();
        assert_eq!(s6.len(), 3);
        assert!(!s6.contains(&tag(1)) && s6.contains(&tag(5)));

        // A pass taken back (its admission failed) is gone after a restart
        // too, whether it was in the journal or the snapshot; the others
        // stay.
        let mut s7 = SpentPasses::load_from(&dir).unwrap();
        s7.record(tag(6), 600).unwrap();
        s7.forget(&tag(6)).unwrap();
        s7.forget(&tag(5)).unwrap();
        s7.forget(&tag(9)).unwrap();
        let s8 = SpentPasses::load_from(&dir).unwrap();
        assert!(!s8.contains(&tag(6)) && !s8.contains(&tag(5)));
        assert!(s8.contains(&tag(4)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bad_input_is_refused() {
        let mut l = Leases::default();
        assert!(l.admit("x", "not-a-key", &net()).is_err());
        let k = Key::generate_private().get_public().to_base64();
        assert!(l.admit("has space", &k, &net()).is_err());
    }

    #[test]
    fn only_a_session_that_never_shook_hands_gives_its_place_back() {
        let mut l = Leases::default();
        let k = || {
            wireguard_control::Key::generate_private()
                .get_public()
                .to_base64()
        };
        let (never, came, open) = (k(), k(), k());
        l.admit_open("client", &never, &net(), true).unwrap();
        l.admit_open("client", &came, &net(), true).unwrap();
        l.admit_open("client", &open, &net(), false).unwrap();
        let t0 = l.find(&never).unwrap().admitted_at;
        let mut ages = std::collections::HashMap::new();
        ages.insert(came.clone(), Some(std::time::Duration::from_secs(0)));
        l.note_handshakes(t0 + 10, &ages);
        let windows = IdleWindows {
            open: 60,
            session: 60,
            pass: 0,
        };
        let gone = l.expire_idle(t0 + 10 + 3600, &windows);
        assert_eq!(gone.len(), 3, "all three lapsed");
        let back = never_came_sessions(&gone);
        let want = *hidravpn_core::keys::public_key_from_base64(&never)
            .unwrap()
            .as_bytes();
        assert_eq!(
            back,
            vec![want],
            "only the session key that never shook hands"
        );
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
        assert!(l
            .expire_idle(
                t0 + 100 + 30,
                &IdleWindows {
                    open: 30 * 86_400,
                    session: 60,
                    pass: 0
                }
            )
            .is_empty());
        // Quiet for the session window: the session lease goes, the
        // ordinary open one (thirty days) stays.
        let gone = l.expire_idle(
            t0 + 100 + 60,
            &IdleWindows {
                open: 30 * 86_400,
                session: 60,
                pass: 0,
            },
        );
        assert_eq!(gone.len(), 1);
        assert_eq!(gone[0].public_key, session);
        assert!(l.find(&kept_open).is_some());
        // Even with idle expiry off for open leases, a session lease lapses.
        let s2 = k();
        l.admit_open("client", &s2, &net(), true).unwrap();
        let t = l.find(&s2).unwrap().admitted_at;
        assert_eq!(
            l.expire_idle(
                t + 61,
                &IdleWindows {
                    open: 0,
                    session: 60,
                    pass: 0
                }
            )
            .len(),
            1
        );
    }

    #[test]
    fn traffic_between_handshakes_keeps_a_session_alive() {
        let mut l = Leases::default();
        let k = wireguard_control::Key::generate_private()
            .get_public()
            .to_base64();
        l.admit_open("client", &k, &net(), true).unwrap();
        let t0 = l.find(&k).unwrap().admitted_at;
        let w = IdleWindows {
            open: 0,
            session: 60,
            pass: 0,
        };
        let active: std::collections::HashSet<String> = [k.clone()].into();
        let quiet = std::collections::HashSet::new();
        assert!(l.note_traffic(t0 + 50, &active));
        assert!(
            !l.note_traffic(t0 + 70, &quiet),
            "no new bytes, no new sign of life"
        );
        assert!(l.expire_idle(t0 + 100, &w).is_empty(), "50 s quiet of 60");
        assert!(l.note_traffic(t0 + 105, &active));
        assert!(l.expire_idle(t0 + 160, &w).is_empty());
        assert_eq!(l.expire_idle(t0 + 166, &w).len(), 1);
    }
}
