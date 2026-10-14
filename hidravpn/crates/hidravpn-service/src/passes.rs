//! Passes on the client (phase 5): the wallet, asking the issuer for passes,
//! and redeeming one on a node, the command line and the service alike.
//!
//! A node that admits with a pass is joined by redeeming one: the invite it
//! answers carries the pass's fresh key, which the tunnel then shows. Every
//! connection through such a node redeems the next pass when the wallet has
//! one, so the node sees an unrelated key each time. Nothing here logs a
//! node, a key or a token.

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
    let f = o
        .open(&lock)
        .with_context(|| format!("opening {}", lock.display()))?;
    f.lock()
        .with_context(|| format!("locking {}", lock.display()))?;
    Ok(f)
}

fn now() -> u64 {
    hidravpn_core::timefmt::now_unix().max(0) as u64
}

/// Whether a circuit can be built with this invite now: any invite not won
/// with a pass; one won with a pass when the wallet has the next pass for
/// it, or when its lease is likely still standing.
pub fn usable(inv: &Invite, wallet: &Wallet, now_unix: u64) -> bool {
    match &inv.pass {
        None => true,
        Some(p) => wallet.count_for(&inv.node_public_key) > 0 || p.lease_likely_alive(now_unix),
    }
}

/// The pocket without the invites `usable` rules out, so a pick never lands
/// on a node whose lease is gone and for which there is no pass. When that
/// would leave nothing for the mode, the pocket as it is.
pub fn without_dead(pocket: &Pocket, wallet: &Wallet, mode: &str) -> Pocket {
    let t = now();
    let mut p = pocket.clone();
    p.entries.retain(|i| usable(i, wallet, t));
    p.exits.retain(|i| usable(i, wallet, t));
    let enough = match mode.trim().to_ascii_lowercase().as_str() {
        "privado" => p.pick_privado().is_ok(),
        _ => !p.exits.is_empty(),
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
    let lock = pocket_path.with_file_name("hidravpn.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock)
        .with_context(|| format!("opening {}", lock.display()))?;
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
    if changed {
        crate::daemon::save_pocket(pocket_path, &pocket)?;
    }
    Ok(())
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
    let now = hidravpn_core::timefmt::now_unix();
    let key = pass::newest_current(&issuer.keys, now).ok_or_else(|| {
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
    // Order the requests so the issuer cannot tell which node a pass is for
    // from where it sits in a batch: one per node, round and round.
    let mut wanted = Vec::with_capacity(nodes.len() * count);
    for _ in 0..count {
        for (_, k) in &nodes {
            wanted.push(k.clone());
        }
    }
    let dropped = wallet.drop_expired(&issuer.keys, now);
    let got = pass::fetch(&issuer.url, token, key, &wanted).await?;
    let n = got.passes.len();
    wallet.passes.extend(got.passes);
    let mut line = format!(
        "{n} pass(es) for {} node(s); the account has {} left today",
        nodes.len(),
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
    })
}

/// Before a connection: for each of these invites won with a pass, redeem the
/// next pass if the wallet has one, so the node is shown a key it has never
/// seen; the invite is replaced in place and in the pocket. With no pass
/// left, the invite stays as it is (its lease may still be alive) and a note
/// says so. Returns the notes.
pub async fn refresh(
    pocket: &mut Pocket,
    wallet: &mut Wallet,
    invites: &mut [&mut Invite],
) -> Vec<String> {
    let mut notes = Vec::new();
    let t = now();
    for inv in invites.iter_mut() {
        let Some(rec) = record_of(inv) else { continue };
        // Redeemed and not used yet: already a key the node has never seen
        // in use, and a lease that stands. Spending another pass buys nothing.
        if inv.pass.as_ref().is_some_and(|p| p.fresh(t)) {
            continue;
        }
        if wallet.count_for(&rec.node_public_key) == 0 {
            notes.push(format!(
                "no pass left for {}: connecting with the last one's key; `hidravpn passes get` for more",
                rec.node_name
            ));
            continue;
        }
        match redeem_into(pocket, wallet, &rec).await {
            Ok(fresh) => **inv = fresh,
            Err(e) => notes.push(format!("{e:#}; connecting with the last pass's key")),
        }
    }
    notes
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
        let names: Vec<String> = without_dead(&p, &w, "rapido")
            .exits
            .iter()
            .map(|i| i.node_name.clone())
            .collect();
        assert_eq!(names, vec!["fresh", "recent"]);
        // With nothing usable, the pocket as it is: better a try than none.
        let mut only_dead = Pocket::default();
        only_dead.add(Slot::Exit, old.clone()).unwrap();
        assert_eq!(without_dead(&only_dead, &w, "rapido").exits.len(), 1);
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
