//! Passes on the client (phase 5): the wallet, asking the issuer for passes,
//! and redeeming one on a node, the command line and the service alike.
//!
//! A node that admits with a pass is joined by redeeming one: the invite it
//! answers carries the pass's fresh key, which the tunnel then shows. Every
//! connection through such a node redeems the next pass when the wallet has
//! one (`circuit::prepare`; the exit of two hops through the entry), so the
//! node sees an unrelated key each time. Nothing here logs a node, a key or
//! a token.

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use hidravpn_core::admission::PassRefused;
use hidravpn_core::pass::{self, Wallet};
use hidravpn_core::{Invite, NodeRecord, Pocket};

/// An exclusive lock on the pocket's folder, shared by the command line and
/// the service: whoever loads, changes and saves the pocket or the wallet
/// holds it, so neither overwrites passes or invites the other just wrote.
/// Released when the returned file is dropped.
pub fn lock_beside(pocket_path: &Path) -> Result<std::fs::File> {
    let f = open_lock(pocket_path)?;
    f.lock().with_context(|| {
        format!(
            "locking {}",
            pocket_path.with_file_name("hidravpn.lock").display()
        )
    })?;
    Ok(f)
}

/// The lock file beside the pocket, root only, not yet locked.
fn open_lock(pocket_path: &Path) -> Result<std::fs::File> {
    if let Some(d) = pocket_path.parent() {
        std::fs::create_dir_all(d).with_context(|| format!("creating {}", d.display()))?;
    }
    let lock = pocket_path.with_file_name("hidravpn.lock");
    let mut o = std::fs::OpenOptions::new();
    o.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(&lock)
        .with_context(|| format!("opening {}", lock.display()))
}

fn now() -> u64 {
    hidravpn_core::timefmt::now_unix().max(0) as u64
}

/// Whether a circuit can be built with this invite now, as a first hop: any
/// invite not won with a pass and not for a node that takes them; one that
/// takes passes when the wallet has the next pass for it, or when its lease
/// is likely still standing.
pub fn usable(inv: &Invite, wallet: &Wallet, now_unix: u64) -> bool {
    let left = wallet.count_for(&inv.node_public_key) > 0;
    match &inv.pass {
        None => !inv.takes_passes() || left,
        Some(p) => left || p.lease_likely_alive(now_unix),
    }
}

/// Whether this invite can be the exit of two hops now: one that takes
/// passes is only ever shown a key redeemed through the entry, so it needs
/// a pass in the wallet; a standing lease from before is not enough.
pub fn usable_behind(inv: &Invite, wallet: &Wallet) -> bool {
    !inv.takes_passes() || wallet.count_for(&inv.node_public_key) > 0
}

/// The pocket without the invites `usable` (or, for the exit of two hops,
/// `usable_behind`) rules out, so a pick never lands on a node for which
/// there is no pass to show it a fresh key. When that would leave nothing
/// for the mode, the pocket as it is, and the connection says why.
pub fn without_dead(
    pocket: &Pocket,
    wallet: &Wallet,
    mode: &str,
    allow_same_operator: bool,
) -> Pocket {
    let t = now();
    let privado = mode.trim().eq_ignore_ascii_case("privado");
    let mut p = pocket.clone();
    p.entries.retain(|i| usable(i, wallet, t));
    if privado {
        p.exits.retain(|i| usable_behind(i, wallet));
    } else {
        p.exits.retain(|i| usable(i, wallet, t));
    }
    // A node only known from the list, that takes passes, and for which
    // there is no pass, cannot be joined either.
    p.known
        .retain(|r| !r.takes_passes() || wallet.count_for(&r.node_public_key) > 0);
    let enough = if privado {
        p.pick_privado(allow_same_operator).is_ok()
    } else {
        p.pick_rapido().is_ok()
    };
    if enough {
        p
    } else {
        pocket.clone()
    }
}

/// Writes down that a circuit went up or down with these keys' invites, in
/// the pocket at `path`.
///
/// It waits a second at most for the lock (someone may be fetching passes
/// over the network with it held) and otherwise leaves the times as they
/// are: they only steer which node is picked, they never decide a spend.
pub fn mark_used(pocket_path: &Path, node_keys: &[String]) -> Result<()> {
    let f = open_lock(pocket_path)?;
    let mut held = false;
    for _ in 0..20 {
        if f.try_lock().is_ok() {
            held = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !held {
        return Ok(());
    }
    let mut pocket = crate::daemon::load_pocket(pocket_path)?;
    if mark_used_in(&mut pocket, node_keys) {
        crate::daemon::save_pocket(pocket_path, &pocket)?;
    }
    Ok(())
}

/// `mark_used` on a pocket already loaded, by whoever holds the lock.
/// Returns whether anything changed.
pub fn mark_used_in(pocket: &mut Pocket, node_keys: &[String]) -> bool {
    let t = now();
    let mut changed = false;
    for inv in pocket.entries.iter_mut().chain(pocket.exits.iter_mut()) {
        if let Some(p) = inv.pass.as_mut() {
            if node_keys
                .iter()
                .any(|k| k.trim() == inv.node_public_key.trim())
            {
                p.used_at = t;
                changed = true;
            }
        }
    }
    changed
}

/// An invite won with a pass as the pocket keeps it now, which may say the
/// key was used since, or hold a newer one; any other invite as it is.
pub fn as_kept(pocket: &Pocket, inv: &Invite) -> Invite {
    if inv.pass.is_none() {
        return inv.clone();
    }
    pocket
        .entries
        .iter()
        .chain(pocket.exits.iter())
        .find(|p| p.pass.is_some() && p.node_public_key.trim() == inv.node_public_key.trim())
        .cloned()
        .unwrap_or_else(|| inv.clone())
}

/// The wallet at a path. A file that is not there is an empty wallet.
pub fn load_wallet(path: &Path) -> Result<Wallet> {
    match std::fs::read_to_string(path) {
        Ok(s) => Wallet::from_json(&s).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Wallet::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Writes the wallet atomically, readable by root only: it holds the secret
/// halves of the keys its passes admit.
pub fn save_wallet(path: &Path, wallet: &Wallet) -> Result<()> {
    crate::daemon::write_private_atomic(path, wallet.to_json().as_bytes())
}

/// The account token, from a file (trimmed).
pub fn read_token(path: &Path) -> Result<String> {
    let t = std::fs::read_to_string(path).with_context(|| {
        format!(
            "no pass account token at {} — `hidravpn passes token <file>` keeps one",
            path.display()
        )
    })?;
    parse_token(&t).with_context(|| format!("{}", path.display()))
}

/// An account token as typed or pasted: one word, trimmed.
pub fn parse_token(text: &str) -> Result<String> {
    let t = text.trim().to_string();
    if t.is_empty() || t.len() > 512 || t.chars().any(|c| c.is_whitespace()) {
        return Err(anyhow!(
            "that is not an account token (one word, no spaces)"
        ));
    }
    Ok(t)
}

/// Topping the wallet up by itself: when a pass node has fewer than `low`
/// passes left, the service asks for enough to bring it back to `count` —
/// only while connected, so the request goes through the tunnel and the
/// issuer sees an exit's address, not this machine's. Kept beside the
/// pocket (`refill.json`); with no file, on, 3 and 10.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Refill {
    pub enabled: bool,
    pub low: usize,
    pub count: usize,
}

impl Default for Refill {
    fn default() -> Self {
        Self {
            enabled: true,
            low: 3,
            count: 10,
        }
    }
}

impl Refill {
    /// `low` below `count`, `count` from 1 to 100 (what one fetch allows).
    pub fn check(&self) -> Result<()> {
        if self.count == 0 || self.count > 100 {
            return Err(anyhow!("--count is 1 to 100"));
        }
        if self.low >= self.count {
            return Err(anyhow!("--low must be below --count"));
        }
        Ok(())
    }

    /// Changes what is given and keeps the rest; says whether anything was
    /// given. Checked: a setting that does not make sense is refused, and
    /// nothing is changed.
    pub fn apply(
        &mut self,
        enabled: Option<bool>,
        low: Option<usize>,
        count: Option<usize>,
    ) -> Result<bool> {
        let mut next = self.clone();
        if let Some(e) = enabled {
            next.enabled = e;
        }
        if let Some(n) = low {
            next.low = n;
        }
        if let Some(n) = count {
            next.count = n;
        }
        next.check()?;
        *self = next;
        Ok(enabled.is_some() || low.is_some() || count.is_some())
    }

    pub fn describe(&self) -> String {
        if self.enabled {
            format!(
                "automatic passes on: a pass node with fewer than {} left gets topped up to {}, only while connected (through the tunnel)",
                self.low, self.count
            )
        } else {
            "automatic passes off: `hidravpn passes get` fetches them".into()
        }
    }
}

pub fn refill_path(pocket_path: &Path) -> std::path::PathBuf {
    pocket_path.with_file_name("refill.json")
}

/// The refill settings beside the pocket; the defaults (on) when there are
/// none. A file that is there but cannot be read, or says nothing that
/// makes sense, is taken as **off**: whoever wrote one may have switched
/// the spending off, and it is never switched back on behind their back.
pub fn load_refill(pocket_path: &Path) -> Refill {
    let path = refill_path(pocket_path);
    match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Refill::default(),
        read => read
            .ok()
            .and_then(|s| serde_json::from_str::<Refill>(&s).ok())
            .filter(|r| r.check().is_ok())
            .unwrap_or_else(|| {
                tracing::warn!("the automatic-passes settings cannot be read; taken as off");
                Refill {
                    enabled: false,
                    ..Refill::default()
                }
            }),
    }
}

pub fn save_refill(pocket_path: &Path, r: &Refill) -> Result<()> {
    r.check()?;
    crate::daemon::write_private_atomic(
        &refill_path(pocket_path),
        serde_json::to_string(r)?.as_bytes(),
    )
}

/// What a refill would ask for: each pass node of the pocket with fewer than
/// `low` passes, and how many bring it to `count`.
pub fn refill_wants(pocket: &Pocket, wallet: &Wallet, r: &Refill) -> Vec<(String, usize)> {
    pass_nodes(pocket)
        .into_iter()
        .filter_map(|(_, k)| {
            let have = wallet.count_for(&k);
            (have < r.low).then(|| (k, r.count - have))
        })
        .collect()
}

/// Tops the wallet up as `refill_wants` says, after throwing away the
/// passes no node takes any more (a pass under an expired key is not one
/// left). Ok(None) when the wallet is as it was; otherwise it was changed
/// and is to be saved.
pub async fn refill(
    pocket: &Pocket,
    wallet: &mut Wallet,
    token: &str,
    r: &Refill,
) -> Result<Option<String>> {
    let dropped = match &pocket.pass_issuer {
        Some(i) => wallet.drop_expired(&i.keys, hidravpn_core::timefmt::now_unix()),
        None => 0,
    };
    let wants = refill_wants(pocket, wallet, r);
    if wants.is_empty() {
        return Ok((dropped > 0).then(|| format!("{dropped} expired pass(es) thrown away")));
    }
    fetch_for(pocket, wallet, token, &wants).await.map(Some)
}

/// The public keys of the nodes in the pocket that admit with a pass: known
/// ones the list says take passes, and admitted ones joined with a pass.
pub fn pass_nodes(pocket: &Pocket) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = pocket
        .known
        .iter()
        .filter(|k| k.takes_passes())
        .map(|k| (k.node_name.clone(), k.node_public_key.clone()))
        .collect();
    for (_, inv) in pocket.iter() {
        if inv.pass.is_some()
            && !v
                .iter()
                .any(|(_, k)| k.trim() == inv.node_public_key.trim())
        {
            v.push((inv.node_name.clone(), inv.node_public_key.clone()));
        }
    }
    v
}

/// Asks the issuer the pocket's list names for `count` passes for each pass
/// node (or the one named), and puts them in the wallet. Returns a line for
/// the person: how many came, how many the account has left today.
pub async fn get_passes(
    pocket: &Pocket,
    wallet: &mut Wallet,
    token: &str,
    node: Option<&str>,
    count: usize,
) -> Result<String> {
    let issuer = pocket.pass_issuer.as_ref().ok_or_else(|| {
        anyhow!("the node list this machine holds names no pass issuer; import a newer list")
    })?;
    // Said first, before which node: without an issuer, none would do.
    pass::newest_current(&issuer.keys, hidravpn_core::timefmt::now_unix()).ok_or_else(|| {
        anyhow!("every pass key the node list names has expired; import a newer list")
    })?;
    let nodes: Vec<(String, String)> = pass_nodes(pocket)
        .into_iter()
        .filter(|(name, _)| {
            node.map(|n| n.trim().eq_ignore_ascii_case(name.trim()))
                .unwrap_or(true)
        })
        .collect();
    if nodes.is_empty() {
        return Err(anyhow!(match node {
            Some(n) => format!("no node named \"{n}\" in the pocket admits with a pass"),
            None => "no node in the pocket admits with a pass".to_string(),
        }));
    }
    if count == 0 || count > 100 {
        return Err(anyhow!("ask for 1 to 100 passes per node"));
    }
    let wants: Vec<(String, usize)> = nodes.into_iter().map(|(_, k)| (k, count)).collect();
    fetch_for(pocket, wallet, token, &wants).await
}

/// Asks the issuer for `n` passes for each node key in `wants`, and puts
/// them in the wallet; returns the line that says how it went.
async fn fetch_for(
    pocket: &Pocket,
    wallet: &mut Wallet,
    token: &str,
    wants: &[(String, usize)],
) -> Result<String> {
    let issuer = pocket.pass_issuer.as_ref().ok_or_else(|| {
        anyhow!("the node list this machine holds names no pass issuer; import a newer list")
    })?;
    let now = hidravpn_core::timefmt::now_unix();
    let key = pass::newest_current(&issuer.keys, now).ok_or_else(|| {
        anyhow!("every pass key the node list names has expired; import a newer list")
    })?;
    // Order the requests so the issuer cannot tell which node a pass is for
    // from where it sits in a batch: one per node, round and round.
    let rounds = wants.iter().map(|(_, n)| *n).max().unwrap_or(0);
    let mut wanted = Vec::new();
    for round in 0..rounds {
        for (k, n) in wants {
            if round < *n {
                wanted.push(k.clone());
            }
        }
    }
    let dropped = wallet.drop_expired(&issuer.keys, now);
    let got = pass::fetch(&issuer.url, token, key, &wanted).await?;
    let n = got.passes.len();
    wallet.passes.extend(got.passes);
    let mut line = format!(
        "{n} pass(es) for {} node(s); the account has {} left today",
        wants.len(),
        got.remaining_today
    );
    if let Some(why) = got.stopped {
        line.push_str(&format!(
            "; asked for {}, and the rest stopped: {why}",
            wanted.len()
        ));
    }
    if dropped > 0 {
        line.push_str(&format!("; {dropped} expired pass(es) thrown away"));
    }
    Ok(line)
}

/// Redeems one of the wallet's passes for this node and puts the invite in
/// the pocket. A pass the node refused is thrown away; one that never reached
/// it goes back in the wallet.
pub async fn redeem_into(
    pocket: &mut Pocket,
    wallet: &mut Wallet,
    record: &NodeRecord,
) -> Result<Invite> {
    let pass = wallet.take_for(&record.node_public_key).ok_or_else(|| {
        anyhow!(
            "no pass left for {}: `hidravpn passes get` asks the issuer for more",
            record.node_name
        )
    })?;
    match hidravpn_core::admission::redeem_pass(record, &pass).await {
        Ok(invite) => {
            pocket.replace(invite.clone())?;
            Ok(invite)
        }
        Err(e) => {
            if e.downcast_ref::<PassRefused>().is_none() {
                wallet.passes.push(pass);
            }
            Err(e)
        }
    }
}

/// The record to redeem the next pass against, rebuilt from an invite won
/// with a pass: the invite was checked against the list's record when it was
/// won, and carries what is needed of it.
pub fn record_of(invite: &Invite) -> Option<NodeRecord> {
    let p = invite.pass.as_ref()?;
    Some(NodeRecord {
        node_name: invite.node_name.clone(),
        node_public_key: invite.node_public_key.clone(),
        endpoint: invite.endpoint.clone(),
        operator: invite.operator.clone(),
        contact: None,
        role: invite.role.clone(),
        admission: Some("pass".into()),
        admission_port: p.admission_port,
        country: invite.country.clone(),
        features: invite.features.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hidravpn_core::{ClientKey, PassBinding, Slot};

    fn record(name: &str, admission: &str) -> NodeRecord {
        NodeRecord {
            node_name: name.into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: "203.0.113.10:51820".into(),
            operator: Some("the maintainers".into()),
            contact: None,
            role: Some("exit".into()),
            admission: Some(admission.into()),
            admission_port: Some(51999),
            country: None,
            features: Vec::new(),
        }
    }

    #[test]
    fn pass_nodes_are_the_known_ones_that_take_passes_and_the_ones_joined_with_one() {
        let mut p = Pocket::default();
        let a = record("a", "pass");
        p.learn(a.clone()).unwrap();
        p.learn(record("b", "open")).unwrap();
        let mut inv = Invite::from_json(&format!(
            r#"{{"node_name":"c","node_public_key":"{}","endpoint":"203.0.113.11:51820","client_address":"10.77.0.2/16","dns":"10.77.0.1"}}"#,
            ClientKey::generate().unwrap().public_base64()
        ))
        .unwrap();
        inv.pass = Some(PassBinding {
            client_secret: ClientKey::generate().unwrap().secret_base64(),
            admission_port: Some(51999),
            redeemed_at: 0,
            used_at: 0,
        });
        p.add(Slot::Exit, inv.clone()).unwrap();
        let names: Vec<String> = pass_nodes(&p).into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, vec!["a", "c"]);
        let rec = record_of(&inv).unwrap();
        assert!(rec.takes_passes());
        assert_eq!(rec.admission_port, Some(51999));
        rec.validate().unwrap();
        // The pocket on disk keeps the pass's key with the invite, and an
        // invite without a pass has none.
        let json = p.to_json();
        assert!(json.contains(&inv.pass.as_ref().unwrap().client_secret));
        assert!(record_of(&p.exits[0]).is_some());
        let plain: Invite = serde_json::from_str(&format!(
            r#"{{"node_name":"d","node_public_key":"{}","endpoint":"203.0.113.12:51820","client_address":"10.77.0.2/16","dns":"10.77.0.1"}}"#,
            ClientKey::generate().unwrap().public_base64()
        ))
        .unwrap();
        assert!(record_of(&plain).is_none());
    }

    #[test]
    fn an_invite_whose_lease_is_likely_gone_is_left_out_when_another_will_do() {
        let t = now();
        let mk = |name: &str, ep: &str, redeemed_at: u64, used_at: u64| {
            let mut inv = Invite::from_json(&format!(
                r#"{{"node_name":"{name}","node_public_key":"{}","endpoint":"{ep}","client_address":"10.77.0.2/16","dns":"10.77.0.1"}}"#,
                ClientKey::generate().unwrap().public_base64()
            ))
            .unwrap();
            inv.pass = Some(PassBinding {
                client_secret: ClientKey::generate().unwrap().secret_base64(),
                admission_port: None,
                redeemed_at,
                used_at,
            });
            inv
        };
        let fresh = mk("fresh", "203.0.113.1:51820", t - 60, 0);
        let lapsed = mk("lapsed", "203.0.113.2:51820", t - 3600, 0);
        let recent = mk("recent", "203.0.113.3:51820", t - 90_000, t - 600);
        let old = mk("old", "203.0.113.4:51820", t - 90_000, t - 80_000);
        let w = Wallet::default();
        assert!(usable(&fresh, &w, t) && usable(&recent, &w, t));
        assert!(!usable(&lapsed, &w, t) && !usable(&old, &w, t));
        let mut p = Pocket::default();
        for i in [&fresh, &lapsed, &recent, &old] {
            p.add(Slot::Exit, i.clone()).unwrap();
        }
        let names: Vec<String> = without_dead(&p, &w, "rapido", false)
            .exits
            .iter()
            .map(|i| i.node_name.clone())
            .collect();
        assert_eq!(names, vec!["fresh", "recent"]);
        // With nothing usable, the pocket as it is: better a try than none.
        let mut only_dead = Pocket::default();
        only_dead.add(Slot::Exit, old.clone()).unwrap();
        assert_eq!(without_dead(&only_dead, &w, "rapido", false).exits.len(), 1);
        // A pass in the wallet makes a lapsed one usable again.
        let mut w2 = Wallet::default();
        w2.passes.push(hidravpn_core::pass::Pass {
            key_id: "00".into(),
            node_public_key: lapsed.node_public_key.clone(),
            client_secret: String::new(),
            nonce: String::new(),
            randomizer: String::new(),
            signature: String::new(),
        });
        assert!(usable(&lapsed, &w2, t));
    }

    fn blank_pass(node: &str) -> hidravpn_core::pass::Pass {
        hidravpn_core::pass::Pass {
            key_id: "00".into(),
            node_public_key: node.into(),
            client_secret: String::new(),
            nonce: String::new(),
            randomizer: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn a_refill_tops_up_only_the_pass_nodes_that_run_low_and_back_to_count() {
        let mut p = Pocket::default();
        let (a, b) = (record("a", "pass"), record("b", "pass"));
        p.learn(a.clone()).unwrap();
        p.learn(b.clone()).unwrap();
        p.learn(record("c", "open")).unwrap();
        let mut w = Wallet::default();
        w.passes.push(blank_pass(&a.node_public_key));
        for _ in 0..5 {
            w.passes.push(blank_pass(&b.node_public_key));
        }
        let r = Refill::default();
        // a has 1 (< 3): 9 more brings it to 10; b has 5: left alone; c
        // takes no passes.
        assert_eq!(
            refill_wants(&p, &w, &r),
            vec![(a.node_public_key.clone(), 9)]
        );
        let off = Refill {
            low: 0,
            ..r.clone()
        };
        assert!(refill_wants(&p, &w, &off).is_empty(), "low 0 never tops up");
        assert!(Refill {
            low: 10,
            count: 10,
            enabled: true
        }
        .check()
        .is_err());
        assert!(Refill {
            low: 1,
            count: 101,
            enabled: true
        }
        .check()
        .is_err());
        let mut a = Refill::default();
        assert!(
            a.apply(None, Some(20), None).is_err(),
            "low 20 is not below 10"
        );
        assert_eq!(a, Refill::default(), "and nothing changed");
        assert!(a.apply(Some(false), None, Some(30)).unwrap());
        assert!(!a.enabled && a.low == 3 && a.count == 30);
        assert!(
            !a.apply(None, None, None).unwrap(),
            "nothing given, nothing changed"
        );
    }

    #[tokio::test]
    async fn expired_passes_are_not_counted_as_left() {
        let mut p = Pocket::default();
        let a = record("a", "pass");
        p.learn(a.clone()).unwrap();
        p.pass_issuer = Some(hidravpn_core::directory::PassIssuer {
            url: "https://passes.example.org".into(),
            keys: vec![pass::PassKeyRecord {
                id: "00".into(),
                key: String::new(),
                not_after: "2000-01-01T00:00:00Z".into(),
            }],
        });
        let mut w = Wallet::default();
        for _ in 0..5 {
            w.passes.push(blank_pass(&a.node_public_key));
        }
        // Five passes, all under a key that has expired: none is left, so
        // the node is to be topped up (the fetch fails here: no current key).
        let r = Refill::default();
        let out = refill(&p, &mut w, "token", &r).await;
        assert!(w.passes.is_empty(), "the expired passes are thrown away");
        assert!(out.is_err(), "and a fetch is attempted for the node");
        assert_eq!(
            refill_wants(&p, &w, &r),
            vec![(a.node_public_key.clone(), 10)]
        );
    }

    #[test]
    fn refill_settings_default_to_on_and_a_bad_file_is_off() {
        let dir = std::env::temp_dir().join(format!("hidravpn-refill-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pocket = dir.join("circuit.json");
        assert_eq!(load_refill(&pocket), Refill::default());
        let mine = Refill {
            enabled: false,
            low: 2,
            count: 20,
        };
        save_refill(&pocket, &mine).unwrap();
        assert_eq!(load_refill(&pocket), mine);
        assert!(save_refill(
            &pocket,
            &Refill {
                enabled: true,
                low: 5,
                count: 5
            }
        )
        .is_err());
        std::fs::write(
            refill_path(&pocket),
            "{\"enabled\":true,\"low\":9,\"count\":3}",
        )
        .unwrap();
        assert!(
            !load_refill(&pocket).enabled,
            "a file that makes no sense is off, never on"
        );
        std::fs::write(refill_path(&pocket), "not json").unwrap();
        assert!(!load_refill(&pocket).enabled);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wallet_file_that_is_not_there_is_empty_and_one_that_is_is_root_only() {
        let dir = std::env::temp_dir().join(format!("hidravpn-wallet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("passes.json");
        let _ = std::fs::remove_file(&path);
        assert!(load_wallet(&path).unwrap().passes.is_empty());
        save_wallet(&path, &Wallet::default()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let tok = dir.join("token");
        std::fs::write(&tok, "  abc-DEF_123\n").unwrap();
        assert_eq!(read_token(&tok).unwrap(), "abc-DEF_123");
        std::fs::write(&tok, "two words").unwrap();
        assert!(read_token(&tok).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
