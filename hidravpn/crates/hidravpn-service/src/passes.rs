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
use hidravpn_core::directory::PassIssuer;
use hidravpn_core::pass::{self, Wallet};
use hidravpn_core::{Invite, NodeRecord, Pocket};

/// An exclusive lock on the pocket's folder, shared by the command line and
/// the service: whoever loads, changes and saves the pocket or the wallet
/// holds it, so neither overwrites passes or invites the other just wrote.
/// Released when the returned file is dropped. Waited for without holding a
/// thread: the command line may hold it across a fetch over the network,
/// and the service's other requests (`status`, `down`) must not stall
/// behind that.
pub async fn lock_beside(pocket_path: &Path) -> Result<std::fs::File> {
    let f = open_lock(pocket_path)?;
    loop {
        match f.try_lock() {
            Ok(()) => return Ok(f),
            Err(std::fs::TryLockError::WouldBlock) => {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).with_context(|| {
                    format!(
                        "locking {}",
                        pocket_path.with_file_name("hidravpn.lock").display()
                    )
                });
            }
        }
    }
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
/// takes passes when the wallet has the next pass for it, or when the lease
/// of its last pass, redeemed from this machine's address, is likely still
/// standing. A pass redeemed through an entry counts for nothing here: its
/// key is never shown from this machine's address.
pub fn usable(inv: &Invite, wallet: &Wallet, now_unix: u64) -> bool {
    let left = wallet.count_for(&inv.node_public_key) > 0;
    match inv.direct_pass() {
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

/// Writes down that a circuit went up or down with these invites won with a
/// pass, in the pocket at `path`.
///
/// It waits a second at most for the lock (someone may be fetching passes
/// over the network with it held) and otherwise leaves the times as they
/// are: they only steer which node is picked, they never decide a spend.
pub async fn mark_used(pocket_path: &Path, used: &[Invite]) -> Result<()> {
    let f = open_lock(pocket_path)?;
    let mut held = false;
    for _ in 0..20 {
        if f.try_lock().is_ok() {
            held = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    if !held {
        return Ok(());
    }
    let mut pocket = crate::daemon::load_pocket(pocket_path)?;
    if mark_used_in(&mut pocket, used) {
        crate::daemon::save_pocket(pocket_path, &pocket)?;
    }
    Ok(())
}

/// `mark_used` on a pocket already loaded, by whoever holds the lock.
/// Only the pass key the circuit used is marked: the pocket may keep
/// another key for the same node (one redeemed from this machine's address,
/// when the circuit's was redeemed through an entry), whose lease this says
/// nothing about. Returns whether anything changed.
pub fn mark_used_in(pocket: &mut Pocket, used: &[Invite]) -> bool {
    let t = now();
    let mut changed = false;
    for inv in pocket.entries.iter_mut().chain(pocket.exits.iter_mut()) {
        let key = inv.node_public_key.trim().to_string();
        if let Some(p) = inv.pass.as_mut() {
            if used.iter().any(|u| {
                u.node_public_key.trim() == key
                    && u.pass
                        .as_ref()
                        .is_some_and(|q| q.client_secret == p.client_secret)
            }) {
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

/// Where the account tokens new ones replaced are kept: beside it, with
/// `.previous` after its name, then `.previous.1`, `.previous.2` and on, so
/// that none is ever written over. This is the `n`th of those names.
pub fn previous_token_path(token_path: &Path, n: u32) -> std::path::PathBuf {
    let mut name = token_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "pass.token".into());
    name.push(".previous");
    if n > 0 {
        name.push(format!(".{n}"));
    }
    token_path.with_file_name(name)
}

/// The tokens kept beside the one at `token_path` (`previous_token_path`)
/// that are there, oldest first.
pub fn kept_tokens(token_path: &Path) -> Vec<std::path::PathBuf> {
    let base = previous_token_path(token_path, 0);
    let (Some(dir), Some(stem)) = (base.parent(), base.file_name().and_then(|n| n.to_str())) else {
        return Vec::new();
    };
    let Ok(read) = std::fs::read_dir(if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    }) else {
        return Vec::new();
    };
    let mut found: Vec<(u32, std::path::PathBuf)> = read
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let rest = name.to_str()?.strip_prefix(stem)?;
            let n = match rest {
                "" => 0,
                r => r
                    .strip_prefix('.')?
                    .parse::<u32>()
                    .ok()
                    .filter(|&n| n > 0)?,
            };
            Some((n, previous_token_path(token_path, n)))
        })
        .collect();
    found.sort();
    found.into_iter().map(|(_, p)| p).collect()
}

/// Keeps `token` (as `parse_token` gives it) as the account token at
/// `token_path`, root only. The token it replaces, when it is another one,
/// is kept first beside it, root only too, under a name no kept token holds
/// yet (`previous_token_path`): any of them may be the only copy of an
/// account's paid balance, since the issuer keeps only its hash, so none is
/// ever written over. One kept already is not kept twice. A token there
/// that cannot be read is not replaced. Returns where the one replaced is
/// kept, if one was.
pub fn keep_token(token_path: &Path, token: &str) -> Result<Option<std::path::PathBuf>> {
    let before = match std::fs::read(token_path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "reading the account token already at {}, which is not replaced unread",
                    token_path.display()
                )
            })
        }
    };
    let mut kept = None;
    if let Some(old) = before {
        let text = String::from_utf8_lossy(&old);
        let old_token = text.trim();
        if !old_token.is_empty() && old_token != token {
            let already = kept_tokens(token_path).into_iter().find(|p| {
                std::fs::read(p).is_ok_and(|b| String::from_utf8_lossy(&b).trim() == old_token)
            });
            kept = Some(match already {
                Some(p) => p,
                None => {
                    let free = (0..)
                        .map(|n| previous_token_path(token_path, n))
                        .find(|p| {
                            std::fs::symlink_metadata(p)
                                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                        })
                        .expect("a free name");
                    crate::daemon::write_private_atomic(&free, &old)?;
                    free
                }
            });
        }
    }
    crate::daemon::write_private_atomic(token_path, token.as_bytes())?;
    Ok(kept)
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

/// Whether the issuer may be asked for passes, with the account token,
/// through a circuit in this mode. In rapido the one node already sees this
/// machine's address, and the issuer sees the node's. In privado the request
/// would leave through the exit that carries the session: the exit sees a
/// flow to the issuer leave from the session's own tunnel address, and at
/// that moment the issuer gets this account's request from the exit's
/// address, so the two together tie the two-hop session to the account, and
/// through it to how its passes were paid for. That holds whenever the exit's
/// operator also runs the issuer, or shares its logs with it. The signed
/// list does not say who runs the issuer; the maintainers run it and the
/// exits, so no exit is taken as another operator's: never in privado.
pub fn refills_through(mode: hidravpn_core::circuit::Mode) -> bool {
    mode == hidravpn_core::circuit::Mode::Rapido
}

/// Why a request that carries the account token is not sent while two hops
/// are up (`refills_through`).
pub const NOT_THROUGH_TWO_HOPS: &str = "not while two hops (privado) are up: the request carries the pass account token and would leave through the exit, and the issuer, run by the same maintainers as the exits, could then tie this two-hop session to the account and to how it was paid for. Get passes while disconnected or connected in rapido, then connect in privado";

/// Why no node is joined while two hops are up: the request for admission
/// would leave through the exit, and the key it admits would later be shown
/// to that node from this machine's own address.
pub const JOIN_NOT_THROUGH_TWO_HOPS: &str = "not while two hops (privado) are up: the node would be asked for admission through the exit, and the key it admitted this machine with would later be shown to it from this machine's own address, which ties the two-hop session to this machine. Join nodes while disconnected or connected in rapido, then connect in privado";

/// What is not sent while two hops are up (`not_through_two_hops`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoHopsRefuse {
    /// A request that carries the pass account token (`NOT_THROUGH_TWO_HOPS`).
    AccountToken,
    /// A request for admission to a node, open or with a pass
    /// (`JOIN_NOT_THROUGH_TWO_HOPS`).
    Join,
}

impl TwoHopsRefuse {
    pub fn why(self) -> &'static str {
        match self {
            Self::AccountToken => NOT_THROUGH_TWO_HOPS,
            Self::Join => JOIN_NOT_THROUGH_TWO_HOPS,
        }
    }

    fn not_sent(self) -> &'static str {
        match self {
            Self::AccountToken => "a request with the pass account token is not sent",
            Self::Join => "no node is joined",
        }
    }
}

/// Whether the command line may send such a request now (`TwoHopsRefuse`),
/// from what tells whether two hops are up: the service's answer to
/// `status` (None with no service; the hops it reports, or None when it
/// gave no status), and the network plan in place (`netcfg::load_plan`),
/// which a circuit held by the command line itself writes too. Anything
/// that cannot say for sure refuses: a service that does not answer, a plan
/// that cannot be read, or one from an older version that does not say how
/// many hops it routes through.
pub fn not_through_two_hops(
    service: Option<Result<Option<u8>>>,
    plan: Result<Option<hidravpn_core::netcfg::RevertPlan>>,
    what: TwoHopsRefuse,
) -> Result<()> {
    let (why, not_sent) = (what.why(), what.not_sent());
    match service {
        None => {}
        Some(Ok(Some(hops))) if hops < 2 => {}
        Some(Ok(Some(_))) => return Err(anyhow!("{why}")),
        Some(Ok(None)) => {
            return Err(anyhow!(
                "the service did not say whether two hops are up, and {not_sent} while they may be"
            ))
        }
        Some(Err(e)) => {
            return Err(anyhow!(
                "the service did not say whether two hops are up ({e:#}), and {not_sent} while they may be"
            ))
        }
    }
    match plan {
        Ok(None) => Ok(()),
        Ok(Some(p)) => match p.two_hops() {
            Some(false) => Ok(()),
            Some(true) => Err(anyhow!(
                "{why} (a connection through two hops holds the network; if none is up, `hidravpn down` undoes what it left)"
            )),
            None => Err(anyhow!(
                "a connection's network changes are in place and do not say whether they go through two hops, so {not_sent}; `hidravpn down` first"
            )),
        },
        Err(e) => Err(anyhow!(
            "could not tell whether two hops are up ({e:#}), so {not_sent}"
        )),
    }
}

/// Topping the wallet up by itself: when a pass node has fewer than `low`
/// passes left, the service asks for enough to bring it back to `count` —
/// only while connected in rapido, so the request goes through the tunnel
/// and the issuer sees the node's address, not this machine's; never in
/// privado (`refills_through`). Kept beside the pocket (`refill.json`); with
/// no file, on, 3 and 10.
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
                "automatic passes on: a pass node with fewer than {} left gets topped up to {}, only while connected in rapido (through the tunnel); never in privado, where the request would leave through the exit and the issuer, run by the same maintainers, could tie the two-hop session to the account: `hidravpn passes get` before connecting in privado",
                self.low, self.count
            )
        } else {
            "automatic passes off: `hidravpn passes get` fetches them (not while connected in privado)".into()
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
    go_on: &(dyn Fn() -> bool + Sync),
) -> Result<Option<String>> {
    let dropped = match &pocket.pass_issuer {
        Some(i) => wallet.drop_expired(&i.keys, hidravpn_core::timefmt::now_unix()),
        None => 0,
    };
    let wants = refill_wants(pocket, wallet, r);
    if wants.is_empty() {
        return Ok((dropped > 0).then(|| format!("{dropped} expired pass(es) thrown away")));
    }
    fetch_for(pocket, wallet, token, &wants, go_on)
        .await
        .map(Some)
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
    fetch_for(pocket, wallet, token, &wants, &|| true).await
}

/// Asks the issuer for `n` passes for each node key in `wants`, and puts
/// them in the wallet; returns the line that says how it went.
async fn fetch_for(
    pocket: &Pocket,
    wallet: &mut Wallet,
    token: &str,
    wants: &[(String, usize)],
    go_on: &(dyn Fn() -> bool + Sync),
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
    let got = pass::fetch(&issuer.url, token, key, &wanted, go_on).await?;
    let n = got.passes.len();
    wallet.passes.extend(got.passes);
    let mut line = format!(
        "{n} pass(es) for {} node(s); the account has {} left{}",
        wants.len(),
        got.remaining_today,
        if got.prepaid { "" } else { " today" }
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
    match hidravpn_core::admission::redeem_pass(record, &pass, false).await {
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
            behind: Some(false),
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
                behind: Some(false),
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

    fn pass_invite(name: &str, ep: &str, behind: Option<bool>, used_at: u64) -> Invite {
        let mut inv = Invite::from_json(&format!(
            r#"{{"node_name":"{name}","node_public_key":"{}","endpoint":"{ep}","client_address":"10.77.0.2/16","dns":"10.77.0.1","role":"exit","admission":"pass"}}"#,
            ClientKey::generate().unwrap().public_base64()
        ))
        .unwrap();
        inv.pass = Some(PassBinding {
            client_secret: ClientKey::generate().unwrap().secret_base64(),
            admission_port: None,
            redeemed_at: now() - 60,
            used_at,
            behind,
        });
        inv
    }

    #[test]
    fn a_pass_key_redeemed_through_an_entry_never_makes_a_node_usable_for_one_hop() {
        let t = now();
        let direct = pass_invite("direct", "203.0.113.1:51820", Some(false), t - 600);
        let behind_used = pass_invite("behind", "203.0.113.2:51820", Some(true), t - 600);
        let behind_fresh = pass_invite("fresh", "203.0.113.3:51820", Some(true), 0);
        let unknown = pass_invite("unknown", "203.0.113.4:51820", None, t - 600);
        let w = Wallet::default();
        assert!(
            usable(&direct, &w, t),
            "a key shown from here, its lease standing"
        );
        for i in [&behind_used, &behind_fresh, &unknown] {
            assert!(
                !usable(i, &w, t),
                "{}: a key the node saw through an entry (or from an older pocket) is not one to show it from here",
                i.node_name
            );
        }
        // A pass in the wallet is a fresh key: that node is usable again.
        let mut w2 = Wallet::default();
        w2.passes.push(blank_pass(&behind_used.node_public_key));
        assert!(usable(&behind_used, &w2, t));
        // In rapido, with no pass left, only the node whose key was shown
        // from here is picked; as the exit of two hops none is, without a pass.
        let mut p = Pocket::default();
        for i in [&direct, &behind_used, &behind_fresh, &unknown] {
            p.add(Slot::Exit, i.clone()).unwrap();
        }
        let names: Vec<String> = without_dead(&p, &w, "rapido", false)
            .exits
            .iter()
            .map(|i| i.node_name.clone())
            .collect();
        assert_eq!(names, vec!["direct"]);
        assert!(!usable_behind(&direct, &w));
    }

    #[test]
    fn a_circuit_marks_only_the_pass_key_it_used() {
        let t = now();
        let direct = pass_invite("q", "203.0.113.1:51820", Some(false), t - 7200);
        let mut behind = direct.clone();
        behind.pass = Some(PassBinding {
            client_secret: ClientKey::generate().unwrap().secret_base64(),
            admission_port: None,
            redeemed_at: t,
            used_at: 0,
            behind: Some(true),
        });
        let mut p = Pocket::default();
        p.add(Slot::Exit, direct.clone()).unwrap();
        // Two hops through the node: the pocket keeps the key shown from
        // here, and the circuit's key, redeemed through the entry, is not it.
        p.replace(behind.clone()).unwrap();
        assert!(p.exits[0].direct_pass().is_some());
        assert!(!mark_used_in(&mut p, std::slice::from_ref(&behind)));
        assert_eq!(
            p.exits[0].pass.as_ref().unwrap().used_at,
            t - 7200,
            "the two-hop circuit says nothing about the lease of the key shown from here"
        );
        assert!(mark_used_in(&mut p, std::slice::from_ref(&direct)));
        assert!(p.exits[0].pass.as_ref().unwrap().used_at >= t);
    }

    #[test]
    fn automatic_passes_go_out_through_one_hop_only() {
        use hidravpn_core::circuit::Mode;
        assert!(refills_through(Mode::Rapido));
        assert!(
            !refills_through(Mode::Privado),
            "never through the exit of two hops, whose operator runs the issuer"
        );
        let on = Refill::default().describe();
        assert!(
            on.contains("only while connected in rapido") && on.contains("never in privado"),
            "{on}"
        );
        assert!(NOT_THROUGH_TWO_HOPS.contains("privado"));
    }

    #[test]
    fn a_new_account_token_keeps_every_one_it_replaces() {
        let dir =
            std::env::temp_dir().join(format!("hidravpn-token-{}-{}", std::process::id(), now()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pass.token");
        let previous = previous_token_path(&path, 0);
        assert_eq!(previous, dir.join("pass.token.previous"));
        assert_eq!(
            previous_token_path(&path, 2),
            dir.join("pass.token.previous.2")
        );
        assert_eq!(
            keep_token(&path, "first").unwrap(),
            None,
            "nothing to keep aside"
        );
        assert_eq!(
            keep_token(&path, "first").unwrap(),
            None,
            "the same token: nothing replaced"
        );
        assert!(!previous.exists());
        assert_eq!(keep_token(&path, "second").unwrap(), Some(previous.clone()));
        assert_eq!(read_token(&path).unwrap(), "second");
        assert_eq!(std::fs::read_to_string(&previous).unwrap(), "first");
        // A second replacement right after (a wrong token corrected, say):
        // the first one kept stays as it is, the second goes beside it.
        let next = dir.join("pass.token.previous.1");
        assert_eq!(keep_token(&path, "third").unwrap(), Some(next.clone()));
        assert_eq!(read_token(&path).unwrap(), "third");
        assert_eq!(std::fs::read_to_string(&previous).unwrap(), "first");
        assert_eq!(std::fs::read_to_string(&next).unwrap(), "second");
        // Back to a token kept already: the one it replaces goes beside the
        // others, and one replaced that is kept already is not kept twice.
        let last = dir.join("pass.token.previous.2");
        assert_eq!(keep_token(&path, "second").unwrap(), Some(last.clone()));
        assert_eq!(std::fs::read_to_string(&last).unwrap(), "third");
        assert_eq!(keep_token(&path, "third").unwrap(), Some(next.clone()));
        assert_eq!(std::fs::read_to_string(&next).unwrap(), "second");
        // Leftovers of a write cut short are not kept tokens.
        std::fs::write(dir.join("pass.token.previous.1.tmp"), "x").unwrap();
        std::fs::write(dir.join("pass.token.previously"), "x").unwrap();
        assert_eq!(
            kept_tokens(&path),
            vec![previous.clone(), next.clone(), last.clone()]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in [&path, &previous, &next, &last] {
                assert_eq!(
                    std::fs::metadata(f).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_command_line_sends_the_account_token_or_joins_only_when_two_hops_are_surely_down() {
        use hidravpn_core::netcfg::RevertPlan;
        const TOKEN: TwoHopsRefuse = TwoHopsRefuse::AccountToken;
        let plan = |hops: Option<u8>| {
            Ok(Some(RevertPlan {
                interface: "hvpn0".into(),
                hops,
                ..Default::default()
            }))
        };
        let refused = |r: Result<()>, why: &str| {
            let e = format!("{:#}", r.expect_err(why));
            assert!(
                e.contains("not sent") || e.contains("not while two hops"),
                "{why}: {e}"
            );
        };
        // Nothing up, or one hop: allowed.
        assert!(not_through_two_hops(None, Ok(None), TOKEN).is_ok());
        assert!(not_through_two_hops(Some(Ok(Some(0))), Ok(None), TOKEN).is_ok());
        assert!(not_through_two_hops(Some(Ok(Some(1))), plan(Some(1)), TOKEN).is_ok());
        assert!(not_through_two_hops(None, plan(Some(1)), TOKEN).is_ok());
        // Two hops held by the service, or by the command line itself.
        refused(
            not_through_two_hops(Some(Ok(Some(2))), Ok(None), TOKEN),
            "the service has two hops",
        );
        refused(
            not_through_two_hops(None, plan(Some(2)), TOKEN),
            "a foreground circuit of two hops",
        );
        refused(
            not_through_two_hops(Some(Ok(Some(0))), plan(Some(2)), TOKEN),
            "the service has none, but the command line holds two",
        );
        // What cannot say for sure refuses.
        refused(
            not_through_two_hops(Some(Err(anyhow!("timed out"))), Ok(None), TOKEN),
            "a service that did not answer",
        );
        refused(
            not_through_two_hops(Some(Ok(None)), Ok(None), TOKEN),
            "a service with no status",
        );
        refused(
            not_through_two_hops(None, plan(None), TOKEN),
            "an older plan that does not say",
        );
        refused(
            not_through_two_hops(None, Err(anyhow!("permission denied")), TOKEN),
            "a plan that cannot be read",
        );
        // Joining a node is refused the same way, and says why.
        let join = |service: Option<Result<Option<u8>>>, plan| {
            not_through_two_hops(service, plan, TwoHopsRefuse::Join)
        };
        assert!(join(None, Ok(None)).is_ok());
        assert!(join(Some(Ok(Some(1))), plan(Some(1))).is_ok());
        for (r, why) in [
            (
                join(Some(Ok(Some(2))), Ok(None)),
                "the service has two hops",
            ),
            (
                join(None, plan(Some(2))),
                "a foreground circuit of two hops",
            ),
        ] {
            let e = format!("{:#}", r.expect_err(why));
            assert!(e.contains(JOIN_NOT_THROUGH_TWO_HOPS), "{why}: {e}");
        }
        for (r, why) in [
            (
                join(Some(Err(anyhow!("timed out"))), Ok(None)),
                "a service that did not answer",
            ),
            (join(None, plan(None)), "an older plan that does not say"),
        ] {
            let e = format!("{:#}", r.expect_err(why));
            assert!(e.contains("no node is joined"), "{why}: {e}");
        }
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
        p.pass_issuer = Some(PassIssuer {
            url: "https://passes.example.org".into(),
            keys: vec![pass::PassKeyRecord {
                id: "00".into(),
                key: String::new(),
                not_after: "2000-01-01T00:00:00Z".into(),
            }],
            wallet: None,
            mint: None,
        });
        let mut w = Wallet::default();
        for _ in 0..5 {
            w.passes.push(blank_pass(&a.node_public_key));
        }
        // Five passes, all under a key that has expired: none is left, so
        // the node is to be topped up (the fetch fails here: no current key).
        let r = Refill::default();
        let out = refill(&p, &mut w, "token", &r, &|| true).await;
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

    #[test]
    fn a_claim_turned_away_for_now_says_the_order_is_still_open() {
        use hidravpn_core::admission::refusal;
        use hidravpn_core::payment::{Rejected, CLAIMS_BUSY, CLAIM_PACED, TOO_MANY_TRIES};
        let open = "up to 24 hours from when it was made";
        let busy = "busy: try the same claim again in a minute";
        // The payment not yet final, or the issuer busy just then: the
        // claim reached the order.
        for (status, e) in [
            (404, Rejected::NotFound.to_string()),
            (429, CLAIM_PACED.to_string()),
            (429, CLAIMS_BUSY.to_string()),
        ] {
            let why = claim_refused(status, &refusal(e.clone()));
            assert!(why.contains(&e) && why.contains(open), "{why}");
        }
        // No order, tried too often, a failed payment: nothing says it is
        // still open, nor to try again.
        for (status, body) in [
            (
                404,
                refusal("no open order for this token (none made, or it lapsed)"),
            ),
            (429, refusal(TOO_MANY_TRIES)),
            (402, refusal(Rejected::Failed.to_string())),
        ] {
            let why = claim_refused(status, &body);
            assert!(!why.contains(open) && !why.contains(busy), "{why}");
        }
        // Any other 429 (a proxy's rate limit in front of the issuer, with
        // its own words or none) never reached the order: busy, try the
        // same claim again, and not that the order is held open.
        for body in [
            String::new(),
            "rate limit exceeded".into(),
            refusal("this order was tried too many times; make a new one"),
        ] {
            let why = claim_refused(429, &body);
            assert!(why.contains(busy) && !why.contains(open), "{why}");
        }
    }

    const WALLET: &str = "So11111111111111111111111111111111111111112";
    const OTHER_WALLET: &str = "ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc";
    const OTHER_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

    fn selling(url: &str, wallet: Option<&str>, mint: Option<&str>) -> Pocket {
        Pocket {
            pass_issuer: Some(PassIssuer {
                url: url.into(),
                keys: Vec::new(),
                wallet: wallet.map(String::from),
                mint: mint.map(String::from),
            }),
            ..Pocket::default()
        }
    }

    fn quote(wallet: &str, mint: &str, decimals: u8) -> hidravpn_core::payment::QuoteResponse {
        hidravpn_core::payment::QuoteResponse {
            passes: 10,
            amount: "50.004213".into(),
            amount_raw: 50_004_213,
            decimals,
            mint: mint.into(),
            wallet: wallet.into(),
            expires: "2026-11-01T12:00:00Z".into(),
            usd: None,
            rate: None,
        }
    }

    #[test]
    fn an_order_is_paid_only_to_the_wallet_and_in_the_token_the_signed_list_names() {
        use hidravpn_core::payment::HNET_MINT;
        let p = selling("https://passes.example.org", Some(WALLET), None);
        let refused = |p: &Pocket, q| order_from_quote(p, q, 10).unwrap_err().to_string();

        // The list's wallet, and HNET for a list that names no mint.
        let o = order_from_quote(&p, quote(&format!(" {WALLET} "), HNET_MINT, 6), 10).unwrap();
        assert_eq!((o.wallet.as_str(), o.mint.as_str()), (WALLET, HNET_MINT));
        assert_eq!(o.issuer, "https://passes.example.org");
        let told = describe_order(&o);
        assert!(
            told.contains(&format!(
                "Send exactly this amount of HNET, every decimal:\n  50.004213\nto this wallet, from any Solana wallet, by 2026-11-01T12:00:00Z (UTC):\n  {WALLET}\n"
            )),
            "{told}"
        );
        // The amount alone on its line, digits only, so it is copied whole.
        assert!(told.lines().any(|l| l == "  50.004213"), "{told}");
        assert!(
            told.contains("choose HNET as what you send, not dollars"),
            "{told}"
        );
        // No dollars without a dollar pack; with one, after the amount, as
        // a reference that is not to be typed into the wallet.
        assert!(!told.contains("USD"), "{told}");
        let mut in_usd = o.clone();
        in_usd.usd = Some("5.99".into());
        in_usd.rate = Some("0.00012686".into());
        let told = describe_order(&in_usd);
        let (amount_at, usd_at) = (
            told.find("  50.004213\n").unwrap(),
            told.find("5.99 USD").unwrap(),
        );
        assert!(amount_at < usd_at, "{told}");
        assert!(
            told.contains("For reference only: 5.99 USD at 0.00012686 USD for one HNET, fixed for this order. Do not type 5.99 into the wallet."),
            "{told}"
        );
        assert!(
            !told
                .lines()
                .any(|l| l.contains("50.004213") && l.contains("USD")),
            "{told}"
        );
        // A pack's listed price, without the zeros after its last decimal.
        assert_eq!(price_to_string(50_000_000, 6), "50");
        assert_eq!(price_to_string(47_217_500_000, 6), "47217.5");
        assert_eq!(price_to_string(100, 0), "100");

        // Another wallet, another token, decimals past any amount read: no
        // order, and the person is told to pay nothing.
        for (q, says) in [
            (quote(OTHER_WALLET, HNET_MINT, 6), "to a wallet"),
            (quote(WALLET, OTHER_MINT, 6), "in a token"),
        ] {
            let e = refused(&p, q);
            assert!(
                e.contains(says)
                    && e.contains("signed node list does not name")
                    && e.contains("pay it nothing")
                    && e.contains("import a newer node list"),
                "{e}"
            );
            assert!(!e.contains(OTHER_WALLET) && !e.contains(OTHER_MINT), "{e}");
        }
        for decimals in [19, 20, u8::MAX] {
            let e = refused(&p, quote(WALLET, HNET_MINT, decimals));
            assert!(
                e.contains("decimals") && e.contains("pay it nothing"),
                "{e}"
            );
        }
        let mut q = quote(WALLET, HNET_MINT, 6);
        q.amount_raw += 1;
        assert!(refused(&p, q).contains("does not add up"));

        // A list that names no wallet, or no issuer: nothing is bought, and
        // the person is told to import a newer list.
        let e = refused(
            &selling("https://passes.example.org", None, None),
            quote(WALLET, HNET_MINT, 6),
        );
        assert!(
            e.contains("does not name the wallet") && e.contains("import a newer node list"),
            "{e}"
        );
        assert!(selling_issuer(&Pocket::default())
            .unwrap_err()
            .to_string()
            .contains("names no pass issuer"));

        // A list that names another token: that one, labelled by its mint,
        // and HNET is then refused like any other.
        let p = selling("https://passes.example.org", Some(WALLET), Some(OTHER_MINT));
        let o = order_from_quote(&p, quote(WALLET, OTHER_MINT, 6), 10).unwrap();
        assert_eq!(o.mint, OTHER_MINT);
        assert!(describe_order(&o).contains(&format!(
            "Send exactly this amount of the token {OTHER_MINT}, every decimal:\n  50.004213\n"
        )));
        assert!(refused(&p, quote(WALLET, HNET_MINT, 6)).contains("in a token"));
        assert_eq!(token_name(HNET_MINT), "HNET");

        // The packs are held to the same: the wallet they say to pay.
        assert!(check_answer(&p, WALLET, OTHER_MINT, 6).is_ok());
        assert!(check_answer(&p, OTHER_WALLET, OTHER_MINT, 6).is_err());
        assert!(check_answer(&p, WALLET, OTHER_MINT, 19).is_err());
    }

    #[tokio::test]
    async fn an_open_order_the_list_does_not_name_is_not_paid_nor_claimed() {
        use hidravpn_core::payment::HNET_MINT;
        let p = selling("http://127.0.0.1:9", Some(WALLET), None);
        let mut o = order_from_quote(&p, quote(WALLET, HNET_MINT, 6), 10).unwrap();
        check_order(&p, &o).unwrap();
        // Under a newer list with another wallet, or another token, or
        // under a list with none: not to be paid, and not claimed. Nothing
        // is sent: the issuer here is a port nobody answers on.
        let path = std::env::temp_dir()
            .join(format!("hidravpn-order-{}", std::process::id()))
            .join("pocket.json");
        let sig = hidravpn_core::payment::base58_encode(&[7u8; 64]);
        for (list, says) in [
            (
                selling("http://127.0.0.1:9", Some(OTHER_WALLET), None),
                "to a wallet",
            ),
            (
                selling("http://127.0.0.1:9", Some(WALLET), Some(OTHER_MINT)),
                "in a token",
            ),
            (
                selling("http://127.0.0.1:9", None, None),
                "import a newer node list",
            ),
        ] {
            let e = check_order(&list, &o).unwrap_err().to_string();
            assert!(e.contains(says), "{e}");
            let e = claim(&list, &path, &o, "token", &sig)
                .await
                .unwrap_err()
                .to_string();
            assert!(e.contains("not claimed") && e.contains(says), "{e}");
        }
        o.wallet = OTHER_WALLET.into();
        let e = check_order(&p, &o).unwrap_err().to_string();
        assert!(e.contains("passes buy 10 --replace"), "{e}");
    }

    #[tokio::test]
    async fn buy_keeps_no_order_the_signed_list_does_not_name() {
        use hidravpn_core::payment::HNET_MINT;
        use tokio::io::AsyncWriteExt;
        // An issuer on this machine that answers each quote with the next
        // of these.
        let answers = vec![
            quote(OTHER_WALLET, HNET_MINT, 6),
            quote(WALLET, OTHER_MINT, 6),
            quote(WALLET, HNET_MINT, 6),
        ];
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        tokio::spawn(async move {
            for q in answers {
                let (mut s, _) = l.accept().await.unwrap();
                hidravpn_core::admission::read_request(&mut s)
                    .await
                    .unwrap();
                let body = serde_json::to_string(&q).unwrap();
                s.write_all(&hidravpn_core::admission::http_response(200, &body))
                    .await
                    .unwrap();
            }
        });
        let dir = std::env::temp_dir().join(format!("hidravpn-buy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pocket.json");
        let _ = std::fs::remove_file(order_path(&path));
        let p = selling(&url, Some(WALLET), None);
        for says in ["to a wallet", "in a token"] {
            let e = buy(&p, &path, "token", 10).await.unwrap_err().to_string();
            assert!(e.contains(says), "{e}");
            assert!(!order_path(&path).exists(), "no order is kept");
        }
        let o = buy(&p, &path, "token", 10).await.unwrap();
        assert_eq!(load_order(&path).unwrap(), Some(o.clone()));
        // It keeps which account token it was opened for, as a hash only.
        use sha2::Digest;
        assert_eq!(
            o.token_sha256.as_deref(),
            Some(hex::encode(sha2::Sha256::digest(b"token")).as_str())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An issuer on this machine that answers each request with the next of
    /// `answers`, and gives back the bodies it was sent.
    async fn answering(
        answers: Vec<(u16, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        use tokio::io::AsyncWriteExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
        let served = tokio::spawn(async move {
            let mut bodies = Vec::new();
            for (status, body) in answers {
                let (mut s, _) = l.accept().await.unwrap();
                let r = hidravpn_core::admission::read_request(&mut s)
                    .await
                    .unwrap();
                bodies.push(String::from_utf8_lossy(&r.body).into_owned());
                s.write_all(&hidravpn_core::admission::http_response(status, &body))
                    .await
                    .unwrap();
            }
            bodies
        });
        (url, served)
    }

    fn credited() -> String {
        r#"{"passes":10,"balance":10,"amount_raw":50004213,"already_claimed":false}"#.into()
    }

    #[tokio::test]
    async fn a_claim_goes_only_to_the_issuer_the_signed_list_names() {
        use hidravpn_core::payment::HNET_MINT;
        // The order was opened with an issuer that would credit the claim;
        // the list now names another one. The order is not to be paid, and
        // the claim, which carries the account token, goes nowhere.
        let (old_url, served) = answering(vec![(200, credited())]).await;
        let o = order_from_quote(
            &selling(&old_url, Some(WALLET), None),
            quote(WALLET, HNET_MINT, 6),
            10,
        )
        .unwrap();
        let now = selling("http://127.0.0.1:9", Some(WALLET), None);
        let e = check_order(&now, &o).unwrap_err().to_string();
        assert!(
            e.contains("opened with a pass issuer the signed node list does not name")
                && e.contains("passes buy 10 --replace"),
            "{e}"
        );
        let path = std::env::temp_dir()
            .join(format!("hidravpn-other-issuer-{}", std::process::id()))
            .join("pocket.json");
        let sig = hidravpn_core::payment::base58_encode(&[7u8; 64]);
        let e = claim(&now, &path, &o, "token", &sig)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("not claimed") && e.contains("pass issuer"),
            "{e}"
        );
        // The same issuer, written with spaces around it: the same one, and
        // the claim goes to the list's address.
        let mut spaced = o.clone();
        spaced.issuer = format!(" {old_url} ");
        let listed = selling(&old_url, Some(WALLET), None);
        check_order(&listed, &spaced).unwrap();
        let c = claim(&listed, &path, &spaced, "token", &sig).await.unwrap();
        assert_eq!(
            c,
            Claimed::Credited {
                passes: 10,
                balance: 10
            }
        );
        let bodies = served.await.unwrap();
        assert_eq!(bodies.len(), 1, "only the claim to the listed issuer");
    }

    #[test]
    fn hnet_is_read_with_hnets_six_decimals() {
        use hidravpn_core::payment::HNET_MINT;
        let p = selling("https://passes.example.org", Some(WALLET), None);
        // An answer that reads HNET with other decimals: a quote or packs
        // in it are refused, whatever the amount says.
        for decimals in [0, 5, 7, 9, 18] {
            let mut q = quote(WALLET, HNET_MINT, decimals);
            q.amount = hidravpn_core::payment::amount_to_string(q.amount_raw, decimals);
            let e = order_from_quote(&p, q, 10).unwrap_err().to_string();
            assert!(
                e.contains("not HNET's 6") && e.contains("pay it nothing"),
                "{decimals}: {e}"
            );
            assert!(check_answer(&p, WALLET, HNET_MINT, decimals).is_err());
        }
        assert!(check_answer(&p, WALLET, HNET_MINT, 6).is_ok());
        // An order kept with other decimals is not to be paid.
        let mut o = order_from_quote(&p, quote(WALLET, HNET_MINT, 6), 10).unwrap();
        check_order(&p, &o).unwrap();
        o.decimals = 9;
        o.amount = hidravpn_core::payment::amount_to_string(o.amount_raw, 9);
        let e = check_order(&p, &o).unwrap_err().to_string();
        assert!(e.contains("HNET's decimals"), "{e}");
        // Another token the list names is read with what its issuer says.
        let other = selling("https://passes.example.org", Some(WALLET), Some(OTHER_MINT));
        let o = order_from_quote(&other, quote(WALLET, OTHER_MINT, 9), 10);
        assert!(o.is_err_and(|e| !e.to_string().contains("HNET")));
        let mut q = quote(WALLET, OTHER_MINT, 9);
        q.amount = "0.050004213".into();
        let o = order_from_quote(&other, q, 10).unwrap();
        check_order(&other, &o).unwrap();
    }

    #[test]
    fn the_command_line_prints_the_issuer_s_figures_only_when_they_read_as_such() {
        use hidravpn_core::payment::HNET_MINT;
        let p = selling("https://passes.example.org", Some(WALLET), None);
        let mut o = order_from_quote(&p, quote(WALLET, HNET_MINT, 6), 10).unwrap();
        o.usd =
            Some("5.99 USD, or pay 5.99 to ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc".into());
        o.rate = Some("0.00012686".into());
        o.expires =
            "2026-11-01T12:00:00Z; send it to ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc".into();
        let told = describe_order(&o);
        assert!(
            !told.contains(OTHER_WALLET) && !told.contains("USD"),
            "{told}"
        );
        assert!(
            told.contains("from any Solana wallet:\n")
                && told.contains("Then: hidravpn passes claim"),
            "{told}"
        );
        o.usd = Some("5.99".into());
        o.rate =
            Some("one HNET for 0.0001 USD at ExYv4idyqxmuodpoZtxyGxeTGi6oYrqFAshAgCsRissc".into());
        o.expires = "2026-11-01T12:00:00Z".into();
        let told = describe_order(&o);
        assert!(
            !told.contains(OTHER_WALLET) && !told.contains("USD"),
            "{told}"
        );
        assert!(
            told.contains("by 2026-11-01T12:00:00Z (UTC):")
                && told.contains("Then, by the same time:"),
            "{told}"
        );
        for (raw, shown) in [
            ("5.99", Some("5.99")),
            (" 0.00004005 ", Some("0.00004005")),
            ("5.99 USD", None),
            ("-1", None),
            ("1e9", None),
        ] {
            assert_eq!(plain_number(raw).as_deref(), shown, "{raw}");
        }
        assert_eq!(
            plain_time(" 2026-11-01T12:00:00Z ").as_deref(),
            Some("2026-11-01T12:00:00Z")
        );
        for bad in ["", "tomorrow", "2026-11-01T12:00:00Z pay me", "2026-11-01"] {
            assert_eq!(plain_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_claim_goes_with_the_token_the_order_was_opened_for() {
        use sha2::Digest;
        let dir = std::env::temp_dir().join(format!("hidravpn-order-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pass.token");
        let hash = |t: &str| hex::encode(sha2::Sha256::digest(t.as_bytes()));
        keep_token(&path, "first-token").unwrap();
        let mut o = order_from_quote(
            &selling("https://passes.example.org", Some(WALLET), None),
            quote(WALLET, hidravpn_core::payment::HNET_MINT, 6),
            10,
        )
        .unwrap();
        o.token_sha256 = Some(hash("first-token"));
        assert_eq!(token_for_order(&path, &o).unwrap(), "first-token");
        // Another token replaces it: the order still goes with its own,
        // kept beside the new one.
        keep_token(&path, "second-token").unwrap();
        assert_eq!(token_for_order(&path, &o).unwrap(), "first-token");
        keep_token(&path, "third-token").unwrap();
        assert_eq!(token_for_order(&path, &o).unwrap(), "first-token");
        // An order kept before orders said which: the token kept now.
        let mut older = o.clone();
        older.token_sha256 = None;
        assert_eq!(token_for_order(&path, &older).unwrap(), "third-token");
        // Its own token no longer kept: not claimed with another one, and
        // the reason names no token and no hash.
        for p in kept_tokens(&path) {
            std::fs::remove_file(p).unwrap();
        }
        let e = token_for_order(&path, &o).unwrap_err();
        assert!(e.is::<TokenNotKept>(), "{e:#}");
        let said = format!("{e:#}");
        assert!(said.contains("no longer keeps"), "{said}");
        for secret in ["first-token", "third-token", &hash("first-token")] {
            assert!(!said.contains(secret), "{said}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn get_passes_says_by_a_code_when_this_machine_has_no_passes_on_its_account() {
        // An issuer under a current key, a node that takes passes, and the
        // service asked for passes: with no account token kept, and with
        // one the issuer holds no passes for.
        let secret = hidravpn_core::pass::IssuerSecret::generate().unwrap();
        let k = secret.public();
        let key = hidravpn_core::pass::PassKeyRecord {
            id: k.id_hex(),
            key: k.to_spki_base64(),
            not_after: "2099-01-01T00:00:00Z".into(),
        };
        let (url, served) = answering(vec![
            (
                403,
                hidravpn_core::admission::refusal(hidravpn_core::pass::NOT_AN_ACCOUNT),
            ),
            (
                402,
                hidravpn_core::admission::refusal(hidravpn_core::pass::too_few_left(3, 10)),
            ),
        ])
        .await;
        let mut p = selling(&url, Some(WALLET), None);
        p.pass_issuer.as_mut().unwrap().keys.push(key);
        p.learn(record("node-p", "pass")).unwrap();
        let dir = std::env::temp_dir().join(format!("hidravpn-no-passes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("circuit.json");
        crate::daemon::save_pocket(&path, &p).unwrap();
        let daemon = crate::daemon::Daemon::with_pocket("control".into(), path.clone());
        let ask = || async {
            let req: crate::ipc::Request = serde_json::from_value(
                serde_json::json!({"token": "control", "cmd": "get_passes", "count": 10}),
            )
            .unwrap();
            daemon.handle(req, Some(1000)).await
        };
        let r = ask().await;
        assert!(!r.ok && r.code.as_deref() == Some("no_passes"), "{r:?}");
        std::fs::write(dir.join("pass.token"), "kept-token").unwrap();
        let r = ask().await;
        assert!(!r.ok && r.code.as_deref() == Some("no_passes"), "{r:?}");
        // Some left, if too few: said as it is, with no code.
        let r = ask().await;
        assert!(!r.ok && r.code.is_none(), "{r:?}");
        assert!(r.error.unwrap().contains("3 pass(es) left"));
        assert_eq!(served.await.unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ---- buying passes with HNET (phase 7) ---------------------------------------------

/// An order the client opened and has not claimed: what to pay, where, and
/// by when. Kept beside the pocket (`order.json`, root only) until claimed.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Order {
    pub passes: u32,
    pub amount: String,
    pub amount_raw: u64,
    pub decimals: u8,
    pub mint: String,
    pub wallet: String,
    pub expires: String,
    pub issuer: String,
    /// For a pack priced in dollars: the price and the rate it was turned
    /// into tokens at, fixed for this order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    /// The SHA-256 (hex) of the account token the order was opened for: the
    /// claim goes with that token, wherever it is kept now
    /// (`token_for_order`). None in an order kept before this was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_sha256: Option<String>,
}

pub fn order_path(pocket_path: &Path) -> std::path::PathBuf {
    pocket_path.with_file_name("order.json")
}

/// The open order, if there is one.
pub fn load_order(pocket_path: &Path) -> Result<Option<Order>> {
    match std::fs::read_to_string(order_path(pocket_path)) {
        Ok(s) => serde_json::from_str(&s)
            .map(Some)
            .context("the order file beside the pocket is unreadable"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("reading the order beside the pocket"),
    }
}

/// What a token is called to the person: HNET for HNET's mint, any other
/// by its mint.
pub fn token_name(mint: &str) -> String {
    if mint == hidravpn_core::payment::HNET_MINT {
        "HNET".to_string()
    } else {
        format!("the token {mint}")
    }
}

/// A pack's price as it is listed: the amount without the zeros after its
/// last decimal ("50", "47217.5"). Not an amount to send: an order adds a
/// tag to it, and says that amount whole (`describe_order`).
pub fn price_to_string(raw: u64, decimals: u8) -> String {
    let s = hidravpn_core::payment::amount_to_string(raw, decimals);
    if s.contains('.') {
        s.trim_end_matches('0').trim_end_matches('.').to_string()
    } else {
        s
    }
}

/// How an order reads to the person: what to send, where, by when, and
/// what comes next. The wallet and the token are the ones the signed list
/// named when the order was made (`order_from_quote`). The amount is on a
/// line of its own, digits only, so it is copied whole; a pack priced in
/// dollars says the dollars after it, as a reference only: a buyer once
/// typed the dollar price into the wallet instead of the amount.
pub fn describe_order(o: &Order) -> String {
    let token = token_name(&o.mint);
    // The issuer's own figures, only when they read as a number and a time
    // (`plain_number`, `plain_time`): anything else is left out.
    let usd = o.usd.as_deref().and_then(plain_number);
    let rate = o.rate.as_deref().and_then(plain_number);
    let in_dollars = match (usd, rate) {
        (Some(usd), Some(rate)) => format!(
            "For reference only: {usd} USD at {rate} USD for one {token}, fixed for this order. \
             Do not type {usd} into the wallet.\n"
        ),
        _ => String::new(),
    };
    let (by, then) = match plain_time(&o.expires) {
        Some(t) => (format!(", by {t} (UTC)"), "Then, by the same time:"),
        None => (String::new(), "Then:"),
    };
    format!(
        "Send exactly this amount of {token}, every decimal:\n  {amount}\n\
         to this wallet, from any Solana wallet{by}:\n  {wallet}\n\
         The amount must match to the last digit: it is what tells your payment apart.\n\
         In the wallet, choose {token} as what you send, not dollars.\n\
         {in_dollars}\
         {then} hidravpn passes claim <transaction signature>\n\
         (the signature is in the wallet's transaction details, or on a Solana explorer).\n\
         Payments on Solana are public. To keep this one apart from the rest of what you do,\n\
         pay from a wallet you use for nothing else.",
        amount = o.amount,
        wallet = o.wallet,
    )
}

/// A figure from the issuer (dollars, a rate) only when it reads as a
/// plain decimal number, digits and at most one point: anything else is
/// not shown, by the command line or the browser's checkout.
pub fn plain_number(s: &str) -> Option<String> {
    let s = s.trim();
    let digits = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    let plain = match s.split_once('.') {
        Some((whole, frac)) => digits(whole) && digits(frac),
        None => digits(s),
    };
    (plain && s.len() <= 32).then(|| s.to_string())
}

/// A time from the issuer (an order's deadline) only when it reads as one
/// (RFC 3339, UTC): anything else is not shown.
pub fn plain_time(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() <= 40 && hidravpn_core::timefmt::rfc3339_to_unix(s).is_ok()).then(|| s.to_string())
}

/// The pass issuer the pocket's list names, and the wallet that list says
/// it is paid to. A purchase is paid to that wallet or not at all: from a
/// list that names none (one made before lists named it), nothing is
/// bought until a newer one is imported.
pub fn selling_issuer(pocket: &Pocket) -> Result<(&PassIssuer, &str)> {
    let issuer = pocket.pass_issuer.as_ref().ok_or_else(|| {
        PayRefused::error(
            "the node list this machine holds names no pass issuer; import a newer list",
        )
    })?;
    let wallet = issuer.pay_wallet().ok_or_else(|| {
        PayRefused::error(
            "the node list this machine holds does not name the wallet passes are paid to; import a newer node list",
        )
    })?;
    Ok((issuer, wallet))
}

/// Where the issuer's answer (`/quote` or `/packs`) says to pay, against the
/// signed list, before anyone is told to pay: the wallet and the token must
/// be the list's, whatever the answer says, and the decimals no more than an
/// amount is read with.
fn check_answer<'a>(
    pocket: &'a Pocket,
    wallet: &str,
    mint: &str,
    decimals: u8,
) -> Result<(&'a PassIssuer, &'a str)> {
    let (issuer, listed) = selling_issuer(pocket)?;
    if wallet.trim() != listed {
        return Err(PayRefused::error(
            "the pass issuer asks for payment to a wallet the signed node list does not name; pay it nothing. If the wallet changed, import a newer node list",
        ));
    }
    if mint.trim() != issuer.pay_mint() {
        return Err(PayRefused::error(
            "the pass issuer asks for payment in a token the signed node list does not name; pay it nothing. If the token changed, import a newer node list",
        ));
    }
    if decimals > hidravpn_core::payment::MAX_DECIMALS {
        return Err(PayRefused::error(format!(
            "the pass issuer names a token with {decimals} decimals, more than an amount is read with; pay it nothing"
        )));
    }
    if !hnet_decimals_hold(issuer.pay_mint(), decimals) {
        return Err(PayRefused::error(format!(
            "the pass issuer reads HNET with {decimals} decimals, not HNET's {}; pay it nothing",
            hidravpn_core::payment::HNET_DECIMALS
        )));
    }
    Ok((issuer, listed))
}

/// HNET is read with HNET's decimals: an amount in any other would be off
/// by a power of ten. Another token is read with what its issuer says.
fn hnet_decimals_hold(mint: &str, decimals: u8) -> bool {
    mint.trim() != hidravpn_core::payment::HNET_MINT
        || decimals == hidravpn_core::payment::HNET_DECIMALS
}

/// The order an issuer's answer to a quote makes, checked before anyone is
/// told to pay: where to pay is the signed list's (`check_answer`), the
/// amount is written the way it is read back, the pack is the one asked
/// for. The order keeps the list's wallet and mint, not the answer's.
fn order_from_quote(
    pocket: &Pocket,
    q: hidravpn_core::payment::QuoteResponse,
    passes: u32,
) -> Result<Order> {
    let (issuer, wallet) = check_answer(pocket, &q.wallet, &q.mint, q.decimals)?;
    if hidravpn_core::payment::amount_from_string(&q.amount, q.decimals)? != q.amount_raw
        || q.passes != passes
    {
        return Err(PayRefused::error(
            "the issuer's order does not add up; nothing to pay",
        ));
    }
    Ok(Order {
        passes: q.passes,
        amount: q.amount,
        amount_raw: q.amount_raw,
        decimals: q.decimals,
        mint: issuer.pay_mint().to_string(),
        wallet: wallet.to_string(),
        expires: q.expires,
        issuer: issuer.url.clone(),
        usd: q.usd,
        rate: q.rate,
        token_sha256: None,
    })
}

/// Whether the open order may be paid: only when it asks for payment to
/// the wallet, and in the token, the signed node list names, was opened
/// with the issuer that list names (the one a claim goes to), and reads
/// HNET with HNET's decimals. An order kept from under an older list is not
/// to be paid, nor claimed.
pub fn check_order(pocket: &Pocket, o: &Order) -> Result<()> {
    let (issuer, wallet) = selling_issuer(pocket)?;
    let other = if o.wallet.trim() != wallet {
        "asks for payment to a wallet the signed node list does not name"
    } else if o.mint.trim() != issuer.pay_mint() {
        "asks for payment in a token the signed node list does not name"
    } else if o.issuer.trim() != issuer.url.trim() {
        "was opened with a pass issuer the signed node list does not name"
    } else if !hnet_decimals_hold(&o.mint, o.decimals) {
        "does not read HNET with HNET's decimals"
    } else {
        return Ok(());
    };
    Err(anyhow!(
        "it {other}; `hidravpn passes buy {} --replace` makes a new order",
        o.passes
    ))
}

/// The account token for purchases: the one kept, or a new one made and
/// kept now (32 random bytes, as the issuer's own `account add` makes
/// them). Says whether it was made.
pub fn token_for_purchase(token_path: &Path) -> Result<(String, bool)> {
    match read_token(token_path) {
        Ok(t) => Ok((t, false)),
        Err(_) if !token_path.exists() => {
            let mut raw = [0u8; 32];
            getrandom::fill(&mut raw).map_err(|e| anyhow!("no randomness available: {e}"))?;
            let token =
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);
            crate::daemon::write_private_atomic(token_path, token.as_bytes())?;
            Ok((token, true))
        }
        Err(e) => Err(e),
    }
}

/// What the issuer sells, once its answer asks for payment where the
/// signed list says.
pub async fn packs(pocket: &Pocket) -> Result<hidravpn_core::payment::PacksResponse> {
    let (issuer, _) = selling_issuer(pocket)?;
    let url = hidravpn_core::http::Url::parse(&issuer.url)
        .context("the pass issuer's address")?
        .with_path("/packs");
    let (status, answer) = hidravpn_core::http::call(&url, "GET", "").await?;
    if status != 200 {
        return Err(IssuerRefused::error(
            status,
            &answer,
            refused("sells no passes", status, &answer),
        ));
    }
    let p: hidravpn_core::payment::PacksResponse =
        serde_json::from_str(&answer).context("the pass issuer's answer is unreadable")?;
    check_answer(pocket, &p.wallet, &p.mint, p.decimals)?;
    Ok(p)
}

/// Opens an order for `passes` with the issuer the pocket's list names,
/// for the account `token`, and keeps it beside the pocket.
pub async fn buy(pocket: &Pocket, pocket_path: &Path, token: &str, passes: u32) -> Result<Order> {
    buy_checked(pocket, pocket_path, token, passes, |_| Ok(())).await
}

/// `buy`, with what the caller also holds the order to (`validate`), said
/// before the order is written: an order it refuses replaces none kept.
pub(crate) async fn buy_checked(
    pocket: &Pocket,
    pocket_path: &Path,
    token: &str,
    passes: u32,
    validate: impl FnOnce(&Order) -> Result<()>,
) -> Result<Order> {
    use sha2::Digest;
    let (issuer, _) = selling_issuer(pocket)?;
    let url = hidravpn_core::http::Url::parse(&issuer.url)
        .context("the pass issuer's address")?
        .with_path("/quote");
    // Only the token's hash goes: the token itself travels at the claim,
    // over TLS or to this machine, as `check_for_token` sees to.
    url.check_for_token()?;
    let token_sha256 = hex::encode(sha2::Sha256::digest(token.trim().as_bytes()));
    let body = serde_json::to_string(&hidravpn_core::payment::QuoteRequest {
        token_sha256: token_sha256.clone(),
        passes,
    })?;
    let (status, answer) = hidravpn_core::http::call(&url, "POST", &body).await?;
    if status != 200 {
        return Err(IssuerRefused::error(
            status,
            &answer,
            refused("did not open the order", status, &answer),
        ));
    }
    let q: hidravpn_core::payment::QuoteResponse =
        serde_json::from_str(&answer).context("the pass issuer's answer is unreadable")?;
    let mut order = order_from_quote(pocket, q, passes)?;
    order.token_sha256 = Some(token_sha256);
    validate(&order)?;
    crate::daemon::write_private_atomic(
        &order_path(pocket_path),
        serde_json::to_string_pretty(&order)?.as_bytes(),
    )?;
    Ok(order)
}

/// What a claim did.
#[derive(Debug, Clone, PartialEq)]
pub enum Claimed {
    /// The open order is paid: the pack is on the account, the order file
    /// is gone.
    Credited { passes: u32, balance: u32 },
    /// The open order had been paid by this transaction already (a claim
    /// that was cut off before it was written down): nothing credited
    /// twice, the order file is gone.
    AlreadyCredited { balance: u32 },
    /// The transaction paid an earlier order of this token, not the open
    /// one, which stays open; `already` says whether that earlier claim
    /// was made before.
    EarlierOrder {
        passes: u32,
        balance: u32,
        already: bool,
    },
}

/// Claims the open order with the transaction that paid it. An order the
/// signed list does not stand behind (`check_order`) is not claimed: a
/// claim carries the account token.
pub async fn claim(
    pocket: &Pocket,
    pocket_path: &Path,
    order: &Order,
    token: &str,
    signature: &str,
) -> Result<Claimed> {
    check_order(pocket, order)
        .map_err(|e| anyhow!("the open order is not claimed, and not to be paid: {e}"))?;
    let signature = hidravpn_core::payment::check_signature(signature)?;
    // The issuer the signed list names, which `check_order` found the
    // order was opened with: a claim carries the account token.
    let (issuer, _) = selling_issuer(pocket)?;
    let url = hidravpn_core::http::Url::parse(issuer.url.trim())
        .context("the pass issuer's address")?
        .with_path("/claim");
    url.check_for_token()?;
    let body = serde_json::to_string(&hidravpn_core::payment::ClaimRequest {
        token: token.trim().to_string(),
        signature,
    })?;
    let (status, answer) = hidravpn_core::http::call(&url, "POST", &body).await?;
    if status != 200 {
        return Err(IssuerRefused::error(
            status,
            &answer,
            claim_refused(status, &answer),
        ));
    }
    let c: hidravpn_core::payment::ClaimResponse =
        serde_json::from_str(&answer).context("the pass issuer's answer is unreadable")?;
    if c.amount_raw != order.amount_raw {
        return Ok(Claimed::EarlierOrder {
            passes: c.passes,
            balance: c.balance,
            already: c.already_claimed,
        });
    }
    std::fs::remove_file(order_path(pocket_path))
        .or_else(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(e)
            }
        })
        .context("the order is paid, but its file beside the pocket could not be removed")?;
    Ok(if c.already_claimed {
        Claimed::AlreadyCredited { balance: c.balance }
    } else {
        Claimed::Credited {
            passes: c.passes,
            balance: c.balance,
        }
    })
}

/// The account token to claim `order` with: the one it was opened for
/// (`Order::token_sha256`), whether that is the token kept at `token_path`
/// or one a newer token replaced and that is kept beside it
/// (`kept_tokens`). An order kept before orders said which is claimed with
/// the token kept now, as before. When none here is that token, the error
/// is `TokenNotKept`. Neither a token nor its hash is ever said.
pub fn token_for_order(token_path: &Path, order: &Order) -> Result<String> {
    use sha2::Digest;
    let Some(want) = order.token_sha256.as_deref() else {
        return read_token(token_path);
    };
    let want = want.trim().to_ascii_lowercase();
    std::iter::once(token_path.to_path_buf())
        .chain(kept_tokens(token_path))
        .filter_map(|p| read_token(&p).ok())
        .find(|t| hex::encode(sha2::Sha256::digest(t.trim().as_bytes())) == want)
        .ok_or_else(|| anyhow::Error::new(TokenNotKept))
}

/// The order was opened for an account token this machine no longer keeps
/// (`token_for_order`): it can only be claimed with that token.
#[derive(Debug)]
pub struct TokenNotKept;

impl std::fmt::Display for TokenNotKept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the open order was made for an account token this machine no longer keeps, and only that token can claim it: `hidravpn passes token <file>` keeps it again (the token kept now is kept beside it), then claim")
    }
}

impl std::error::Error for TokenNotKept {}

/// Why the issuer did not take a claim. A claim it turned away only for now
/// (the payment not yet final on chain, or too many claims just then) has
/// reached the order, and a claim from the order's own token keeps it open
/// longer than the quote said: the person is told so, so they try again
/// rather than give up on a payment. The issuer's answer does not carry the
/// new time, so this says what holds as a rule.
fn claim_refused(status: u16, answer: &str) -> String {
    use hidravpn_core::payment::{
        Rejected, CLAIMS_BUSY, CLAIM_PACED, ORDER_LIFETIME, TOO_MANY_TRIES,
    };
    let error = serde_json::from_str::<hidravpn_core::admission::Refusal>(answer)
        .map(|r| r.error)
        .unwrap_or_default();
    let for_now = match status {
        404 => error == Rejected::NotFound.to_string(),
        429 => error == CLAIM_PACED || error == CLAIMS_BUSY,
        _ => false,
    };
    let why = refused("did not take the claim", status, answer);
    if status == 429 && !for_now && error != TOO_MANY_TRIES {
        // Only the issuer's own reason says the order can take no more
        // claims; any other 429 (a proxy's rate limit in front of it)
        // turned this claim away before it reached the order.
        return format!(
            "{why}\nThe issuer, or a proxy in front of it, is busy: try the same claim again in a minute."
        );
    }
    if !for_now {
        return why;
    }
    format!(
        "{why}\nThe order stays open past the time it shows: a claim that reaches the issuer \
         normally keeps it open up to {} hours from when it was made, so try the claim again later.",
        ORDER_LIFETIME / 3600
    )
}

/// A refusal worked out on this machine, from the signed node list, before
/// anything is paid: the wallet or the token the issuer asks for is not the
/// list's, the list names none, or the issuer's order does not add up. Its
/// text is this program's own, never the issuer's, so the browser's
/// checkout may show it as it is (`checkout`).
#[derive(Debug)]
pub struct PayRefused(String);

impl PayRefused {
    pub(crate) fn error(text: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(Self(text.into()))
    }
}

impl std::fmt::Display for PayRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PayRefused {}

/// The pass issuer answered a request for packs, an order or a claim with
/// an error status. Said as before (`refused`, `claim_refused`); the status
/// and the reason the issuer gave are kept apart for the browser's checkout,
/// which only compares that reason with the ones this program knows and
/// never repeats the issuer's words.
#[derive(Debug)]
pub struct IssuerRefused {
    pub status: u16,
    /// The `error` of the issuer's answer, empty when it gave none.
    pub reason: String,
    said: String,
}

impl IssuerRefused {
    fn error(status: u16, answer: &str, said: String) -> anyhow::Error {
        let reason = serde_json::from_str::<hidravpn_core::admission::Refusal>(answer)
            .map(|r| r.error)
            .unwrap_or_default();
        anyhow::Error::new(Self {
            status,
            reason,
            said,
        })
    }
}

impl std::fmt::Display for IssuerRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.said)
    }
}

impl std::error::Error for IssuerRefused {}

fn refused(what: &str, status: u16, answer: &str) -> String {
    let why = serde_json::from_str::<hidravpn_core::admission::Refusal>(answer)
        .map(|r| r.error)
        .unwrap_or_else(|_| answer.trim().chars().take(200).collect());
    format!("the pass issuer {what} ({status}): {why}")
}
