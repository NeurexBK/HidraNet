//! The daemon: it holds the circuit while it is up, arms the kill switch, and
//! puts everything back when it is told to disconnect or when it is stopped.
//!
//! Only one circuit at a time. Bringing a second one up replaces the first. If
//! the kill switch cannot be armed, the connection is refused and undone — the
//! service never routes the machine through a tunnel it cannot protect.
//!
//! It keeps what it needs to rebuild: the pool of entry nodes and the pool of
//! exit nodes it was given, and which of each is in use, so `new_identity`
//! can rotate to another exit — and another entry, when it has more than one.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hidravpn_core::killswitch;
use hidravpn_core::netcfg;
use hidravpn_core::{
    random, Circuit, CircuitOptions, CircuitSpec, ClientKey, Invite, Merge, Pocket, ReleaseKey,
    Role,
};
use tokio::sync::Mutex;

use crate::ipc::{Command, HopReport, NodeReport, Request, Response, StatusReport};
use crate::paths;

struct Active {
    /// The account that switched the circuit on (a uid, 0 for root or an
    /// elevated prompt; None for a non-elevated caller on Windows, where all
    /// of them are one), so another account cannot switch it off. A circuit
    /// root switched on is root's: a member of the group cannot take it down.
    owner: Option<u32>,
    circuit: Circuit,
    /// The entry nodes, when there are two hops; `current_entry` is the one
    /// in use. Empty for one hop.
    entries: Vec<Invite>,
    current_entry: usize,
    /// The exit nodes, in the order given; `current` is the one in use.
    pool: Vec<Invite>,
    current: usize,
    opts: CircuitOptions,
}

pub struct Daemon {
    token: String,
    state: Mutex<Option<Active>>,
    /// The pocket `connect` picks from (`hidravpn nodes`), normally the one
    /// next to the key; a test gives its own.
    pocket_path: PathBuf,
    /// The LIST key a signed node list is checked against: the one this
    /// build embeds (not the release key, which signs release files). None
    /// means no list is ever accepted.
    release_key: Option<ReleaseKey>,
    /// One import at a time: load, merge and write back are one step.
    pocket_lock: Mutex<()>,
}

/// What a person is told when a circuit could not be built while the kill
/// switch was held across a change: the machine is blocked, not open.
const HELD: &str = "the kill switch stays armed: nothing leaves this machine until `hidravpn down` or another connect";

/// The same bytes, compared without a short cut: the comparison takes the
/// same time whether the first byte or the last one differs.
fn same_token(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Daemon {
    pub fn new(token: String) -> Arc<Self> {
        Self::with_pocket(token, paths::circuit_pocket())
    }

    pub fn with_pocket(token: String, pocket_path: PathBuf) -> Arc<Self> {
        Self::with_pocket_and_key(token, pocket_path, ReleaseKey::embedded_list_key())
    }

    /// The key this daemon checks node lists against, for tests.
    pub fn list_key_base64(&self) -> Option<String> {
        self.release_key.as_ref().map(|k| k.to_base64())
    }

    /// A daemon with a given list key, for tests; the service itself only
    /// ever trusts the embedded one.
    pub fn with_pocket_and_key(
        token: String,
        pocket_path: PathBuf,
        release_key: Option<ReleaseKey>,
    ) -> Arc<Self> {
        Arc::new(Self {
            token,
            state: Mutex::new(None),
            pocket_path,
            release_key,
            pocket_lock: Mutex::new(()),
        })
    }

    /// `caller` is the account asking: `Some(0)` for root (an elevated
    /// process on Windows), another uid for a member of the group, `None`
    /// when the channel cannot tell. The channel is shared with the group,
    /// whose members may connect through the pocket, disconnect what they
    /// switched on, rotate, join, and import a signed list — but never hand
    /// the service an invite of their own, which would route the whole
    /// machine through a node nobody vetted, and never switch off what
    /// another account switched on.
    pub async fn handle(&self, req: Request, caller: Option<u32>) -> Response {
        let privileged = caller == Some(0);
        // The token is compared in full, in constant time, before anything else.
        if !same_token(req.token.as_bytes(), self.token.as_bytes()) {
            return Response::err("unauthorised: wrong or missing control token");
        }
        match req.cmd {
            Command::Ping => Response::ok(),
            Command::Status => self.status().await,
            Command::Up { .. } if !privileged => Response::err(
                "`up` with an invite needs root (an administrator prompt on Windows): only root may hand the service a node to route the machine through. Members of the hidravpn group use `connect`, which picks from the pocket root filled.",
            ),
            Command::Up {
                invite,
                allow_lan,
                keep_ipv6,
                via,
                alternates,
                alternate_entries,
            } => {
                let opts = CircuitOptions {
                    route_ipv6: !keep_ipv6,
                    allow_lan,
                    ..CircuitOptions::default()
                };
                match self
                    .up(invite, via, alternates, alternate_entries, opts, caller)
                    .await
                {
                    Ok(()) => self.status().await,
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::Connect {
                mode,
                allow_lan,
                keep_ipv6,
            } => {
                // Connecting replaces the circuit that is up: that is a
                // `down` of it, so the same rule applies.
                if let Err(e) = self.owned_by(caller).await {
                    return Response::err(format!("{e:#}"));
                }
                let opts = CircuitOptions {
                    route_ipv6: !keep_ipv6,
                    allow_lan,
                    ..CircuitOptions::default()
                };
                match self.connect_from_pocket(&mode, opts, caller).await {
                    Ok(joined) => {
                        let s = self.status().await;
                        match joined {
                            Some(note) => s.noting(note),
                            None => s,
                        }
                    }
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::Join { name } => match self.join(name.as_deref()).await {
                Ok((pocket, outcome)) => Response::with_nodes(self.reports(&pocket)).noting(outcome),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::GetPasses { name, count } => match self
                .get_passes(name.as_deref(), count.unwrap_or(10) as usize)
                .await
            {
                Ok((pocket, line)) => Response::with_nodes(self.reports(&pocket)).noting(line),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::SetPassToken { pass_token } => match self.set_pass_token(&pass_token) {
                Ok(()) => Response::ok().noting("the account token is kept on this machine, readable by root only"),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::Nodes => match load_pocket(&self.pocket_path) {
                Ok(p) => Response::with_nodes(self.reports(&p)),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::ImportNodes { list, signature } => {
                match self.import_nodes(&list, &signature).await {
                    Ok((pocket, merge)) => {
                        Response::with_nodes(self.reports(&pocket)).noting(merge.summary())
                    }
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::Down => {
                if let Err(e) = self.owned_by(caller).await {
                    return Response::err(format!("{e:#}"));
                }
                match self.down().await {
                    Ok(_) => Response::ok(),
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::NewIdentity => {
                if let Err(e) = self.owned_by(caller).await {
                    return Response::err(format!("{e:#}"));
                }
                match self.new_identity().await {
                    Ok(note) => self.status().await.noting(note),
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
        }
    }

    /// Root, or the account that switched the circuit on, or nobody has it
    /// on: otherwise this caller may not switch it off or rotate it.
    async fn owned_by(&self, caller: Option<u32>) -> Result<()> {
        if caller == Some(0) {
            return Ok(());
        }
        let guard = self.state.lock().await;
        match guard.as_ref().and_then(|a| a.owner) {
            Some(owner) if Some(owner) != caller => Err(anyhow!(
                "the VPN was switched on by another account on this computer; only that account or root may switch it off"
            )),
            _ => Ok(()),
        }
    }

    async fn up(
        &self,
        exit: Invite,
        entry: Option<Invite>,
        alternates: Vec<Invite>,
        alternate_entries: Vec<Invite>,
        opts: CircuitOptions,
        caller: Option<u32>,
    ) -> Result<()> {
        // Everything is checked before anything is touched: every exit with
        // every entry, since any pair may be built later.
        let mut pool = Vec::with_capacity(1 + alternates.len());
        pool.push(exit);
        pool.extend(alternates);
        let mut entries = Vec::new();
        if let Some(e) = entry {
            entries.push(e);
            entries.extend(alternate_entries);
        }
        for exit in &pool {
            if entries.is_empty() {
                CircuitSpec {
                    exit: exit.clone(),
                    entry: None,
                }
                .validate()?;
            }
            for entry in &entries {
                CircuitSpec {
                    exit: exit.clone(),
                    entry: Some(entry.clone()),
                }
                .validate()?;
            }
        }

        let next_first_hop = CircuitSpec {
            exit: pool[0].clone(),
            entry: entries.first().cloned(),
        }
        .first_hop_endpoint()?;

        let mut guard = self.state.lock().await;
        // Replacing a running circuit: the kill switch is held across the
        // change — only the old and the new first hop may be reached — before
        // the old circuit comes down, and the new circuit's own rules replace
        // the hold once it is up. There is no moment on the open network; if
        // the new circuit cannot be built, the machine stays blocked until
        // `down`, never open.
        let held = match guard.take() {
            Some(old) => {
                let mut allowed = vec![next_first_hop];
                if let Ok(current) = old.circuit.spec().first_hop_endpoint() {
                    allowed.push(current);
                }
                if let Err(e) = killswitch::hold(&allowed) {
                    *guard = Some(old);
                    return Err(e.context(
                        "could not hold the kill switch across the change; staying on the current circuit",
                    ));
                }
                self.note_used(old.circuit.spec());
                let _ = old.circuit.down_with(false).await;
                true
            }
            None => false,
        };
        let circuit = match connect(&pool[0], entries.first(), &opts, held).await {
            Ok(c) => c,
            Err(e) if held => return Err(e.context(HELD)),
            Err(e) => return Err(e),
        };
        self.note_used(circuit.spec());
        *guard = Some(Active {
            owner: caller,
            circuit,
            entries,
            current_entry: 0,
            pool,
            current: 0,
            opts,
        });
        tracing::info!("connected");
        Ok(())
    }

    /// Writes down, for the invites won with a pass that this circuit uses,
    /// that they were used now: what tells later picks their lease stands.
    fn note_used(&self, spec: &CircuitSpec) {
        let keys: Vec<String> = std::iter::once(&spec.exit)
            .chain(spec.entry.as_ref())
            .filter(|i| i.pass.is_some())
            .map(|i| i.node_public_key.clone())
            .collect();
        if !keys.is_empty() {
            if let Err(e) = crate::passes::mark_used(&self.pocket_path, &keys) {
                tracing::warn!("could not note a pass key's use: {e:#}");
            }
        }
    }

    /// Connects through nodes picked from the pocket: one exit for Rápido, an
    /// entry and an exit for Privado, each at random, the rest kept for
    /// `new_identity` to rotate to. The caller never sees an invite. With no
    /// admitted node but known nodes that admit openly, it asks them first:
    /// that is how a machine that only imported the list connects at all.
    /// Returns a note about what it joined, if it joined anything.
    async fn connect_from_pocket(
        &self,
        mode: &str,
        opts: CircuitOptions,
        caller: Option<u32>,
    ) -> Result<Option<String>> {
        let mut pocket = load_pocket(&self.pocket_path)?;
        let mut joined_note = None;
        if pocket.is_empty() && !pocket.joinable().is_empty() {
            let (p, note) = self.join(None).await?;
            pocket = p;
            joined_note = Some(note);
        }
        // A node joined with a pass whose lease is likely gone, and for which
        // the wallet holds no pass, is not picked while another will do.
        let wallet = crate::passes::load_wallet(&self.wallet_path()).unwrap_or_default();
        let mut plan = plan_connect(&crate::passes::without_dead(&pocket, &wallet, mode), mode)?;
        // Nodes joined with a pass are shown a fresh key every connection:
        // the next pass is redeemed now, if the wallet has one — unless the
        // join above just redeemed one, which is fresh already.
        if joined_note.is_none()
            && (plan.exit.pass.is_some() || plan.entry.as_ref().is_some_and(|e| e.pass.is_some()))
        {
            let in_use: Vec<String> = match self.state.lock().await.as_ref() {
                Some(a) => {
                    let spec = a.circuit.spec();
                    std::iter::once(&spec.exit)
                        .chain(spec.entry.as_ref())
                        .map(|i| i.node_public_key.clone())
                        .collect()
                }
                None => Vec::new(),
            };
            let notes = self
                .refresh_passes(&mut plan.exit, plan.entry.as_mut(), &in_use)
                .await;
            if !notes.is_empty() {
                let n = notes.join("; ");
                joined_note = Some(match joined_note {
                    Some(j) => format!("{j}; {n}"),
                    None => n,
                });
            }
        }
        self.up(
            plan.exit,
            plan.entry,
            plan.alternates,
            plan.alternate_entries,
            opts,
            caller,
        )
        .await?;
        Ok(joined_note)
    }

    /// Asks admission from the known nodes that admit openly (one by name,
    /// or all), with the key derived for each; a node that admits goes into
    /// the pocket under the role it declares. One node's refusal does not
    /// stop the others. Returns the pocket and a line per node.
    async fn join(&self, name: Option<&str>) -> Result<(Pocket, String)> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path)?;
        let mut pocket = load_pocket(&self.pocket_path)?;
        let targets: Vec<hidravpn_core::NodeRecord> = pocket
            .joinable()
            .into_iter()
            .filter(|r| {
                name.map(|n| n.trim().eq_ignore_ascii_case(r.node_name.trim()))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if targets.is_empty() {
            return Err(anyhow!(match name {
                Some(n) => format!("no known node named \"{n}\" admits openly or with a pass; `nodes list` says whom to ask"),
                None => "no known node admits openly or with a pass; import a node list, or ask an operator for an invite".to_string(),
            }));
        }
        let key = load_key()?;
        let mut wallet = crate::passes::load_wallet(&self.wallet_path())?;
        let wallet_before = wallet.passes.len();
        // The name a node files the lease under is a label for its operator,
        // not this machine's name: nothing identifying leaves here.
        let host = "client".to_string();
        let mut lines = Vec::new();
        let mut joined = 0;
        for rec in targets {
            if rec.takes_passes() {
                match crate::passes::redeem_into(&mut pocket, &mut wallet, &rec).await {
                    Ok(_) => {
                        joined += 1;
                        lines.push(format!(
                            "{}: admitted with a pass as {}",
                            rec.node_name,
                            rec.role.as_deref().unwrap_or("both")
                        ));
                    }
                    Err(e) => lines.push(format!("{}: {e:#}", rec.node_name)),
                }
                continue;
            }
            let shown = key.for_node_base64(&rec.node_public_key)?.public_base64();
            match hidravpn_core::admission::request_admission(&rec, &shown, &host).await {
                Ok(invite) => {
                    let mut added = 0;
                    for slot in hidravpn_core::pocket::slots_for_role(rec.role.as_deref()) {
                        if pocket.add(slot, invite.clone()).is_ok() {
                            added += 1;
                        }
                    }
                    joined += 1;
                    lines.push(format!(
                        "{}: admitted as {}",
                        rec.node_name,
                        rec.role.as_deref().unwrap_or("both")
                    ));
                    let _ = added;
                }
                Err(e) => lines.push(format!("{}: {e:#}", rec.node_name)),
            }
        }
        if joined > 0 {
            save_pocket(&self.pocket_path, &pocket)?;
            tracing::info!(joined, "joined node(s) through open admission or a pass");
        }
        if wallet.passes.len() != wallet_before {
            crate::passes::save_wallet(&self.wallet_path(), &wallet)?;
        }
        Ok((pocket, lines.join("; ")))
    }

    /// Redeems the next pass for these invites where they were won with one,
    /// updating them, the pocket and the wallet. Never fails: a node that
    /// cannot be given a fresh pass keeps its last key, and a note says why.
    async fn refresh_passes(
        &self,
        exit: &mut Invite,
        entry: Option<&mut Invite>,
        in_use: &[String],
    ) -> Vec<String> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = match crate::passes::lock_beside(&self.pocket_path) {
            Ok(f) => f,
            Err(e) => return vec![format!("passes not refreshed: {e:#}")],
        };
        let (mut pocket, mut wallet) = match (
            load_pocket(&self.pocket_path),
            crate::passes::load_wallet(&self.wallet_path()),
        ) {
            (Ok(p), Ok(w)) => (p, w),
            (Err(e), _) | (_, Err(e)) => {
                return vec![format!("passes not refreshed: {e:#}")];
            }
        };
        let before = wallet.passes.len();
        let mut notes = Vec::new();
        // A node the running circuit goes through cannot be asked for a
        // fresh admission while it does: the kill switch lets only the
        // tunnel's packets reach it, and the node answers nothing from inside
        // its tunnel. It keeps its key until the next connection from cold.
        let mut invites: Vec<&mut Invite> = Vec::new();
        for inv in std::iter::once(exit).chain(entry) {
            if inv.pass.is_some()
                && in_use
                    .iter()
                    .any(|k| k.trim() == inv.node_public_key.trim())
            {
                notes.push(format!(
                    "{} is part of the circuit in use, so it keeps its key this time",
                    inv.node_name
                ));
            } else {
                invites.push(inv);
            }
        }
        notes.extend(crate::passes::refresh(&mut pocket, &mut wallet, &mut invites).await);
        if wallet.passes.len() != before {
            if let Err(e) = save_pocket(&self.pocket_path, &pocket)
                .and_then(|_| crate::passes::save_wallet(&self.wallet_path(), &wallet))
            {
                notes.push(format!("could not write the pocket or the wallet: {e:#}"));
            }
        }
        notes
    }

    /// Keeps the account token passes are asked for with, root only. The
    /// token is checked for shape and never repeated in an answer.
    fn set_pass_token(&self, token: &str) -> Result<()> {
        let t = crate::passes::parse_token(token)?;
        write_private_atomic(&self.token_path(), t.as_bytes())?;
        tracing::info!("pass account token replaced");
        Ok(())
    }

    /// The pass wallet and the account token sit beside the pocket.
    fn wallet_path(&self) -> PathBuf {
        self.pocket_path.with_file_name("passes.json")
    }

    fn token_path(&self) -> PathBuf {
        self.pocket_path.with_file_name("pass.token")
    }

    /// Asks the issuer for passes with the token this machine keeps, `count`
    /// for each pass node or the one named. Only the account's quota is at
    /// stake, and the token never leaves the service.
    async fn get_passes(&self, name: Option<&str>, count: usize) -> Result<(Pocket, String)> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path)?;
        let pocket = load_pocket(&self.pocket_path)?;
        let token = crate::passes::read_token(&self.token_path())?;
        let mut wallet = crate::passes::load_wallet(&self.wallet_path())?;
        let line = crate::passes::get_passes(&pocket, &mut wallet, &token, name, count).await?;
        crate::passes::save_wallet(&self.wallet_path(), &wallet)?;
        tracing::info!("passes fetched from the issuer");
        Ok((pocket, line))
    }

    fn reports(&self, pocket: &Pocket) -> Vec<NodeReport> {
        let wallet = crate::passes::load_wallet(&self.wallet_path()).unwrap_or_default();
        node_reports_with_passes(pocket, &wallet)
    }

    /// Checks a signed node list against the embedded release key, and only
    /// then puts its nodes into the pocket and writes the pocket back. The
    /// pocket on disk is untouched by a list that is refused.
    async fn import_nodes(&self, list: &str, signature: &str) -> Result<(Pocket, Merge)> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path)?;
        let mut pocket = load_pocket(&self.pocket_path)?;
        let merge = hidravpn_core::directory::import_signed(
            &mut pocket,
            list.as_bytes(),
            signature,
            self.release_key.as_ref(),
        )?;
        save_pocket(&self.pocket_path, &pocket)?;
        tracing::info!(
            added = merge.added.len(),
            updated = merge.updated.len(),
            skipped = merge.skipped.len(),
            "node list imported"
        );
        Ok((pocket, merge))
    }

    /// Rebuilds the circuit through another exit of the pool, chosen at
    /// random among the others, and through another entry when there is
    /// more than one. Returns the note for the person: which nodes it got,
    /// or that there was no other to choose.
    async fn new_identity(&self) -> Result<String> {
        // 1. Under the state lock, only to read: which exit and entry come
        //    next. Among the others, the ones a circuit can be built with
        //    (`passes::usable`) are preferred, so a rotation does not land on
        //    a node whose pass lease is gone and for which no pass is left.
        let wallet = crate::passes::load_wallet(&self.wallet_path()).unwrap_or_default();
        let t = hidravpn_core::timefmt::now_unix().max(0) as u64;
        let (next, next_entry, mut next_exit, mut next_entry_inv, in_use, current, current_entry) = {
            let guard = self.state.lock().await;
            let a = guard
                .as_ref()
                .ok_or_else(|| anyhow!("not connected; nothing to rotate"))?;
            let ok_exit: Vec<bool> = a
                .pool
                .iter()
                .map(|i| crate::passes::usable(i, &wallet, t))
                .collect();
            let ok_entry: Vec<bool> = a
                .entries
                .iter()
                .map(|i| crate::passes::usable(i, &wallet, t))
                .collect();
            let next = pick_other(&ok_exit, a.current)?;
            let next_entry = pick_other(&ok_entry, a.current_entry)?;
            let spec = a.circuit.spec();
            let in_use: Vec<String> = std::iter::once(&spec.exit)
                .chain(spec.entry.as_ref())
                .map(|i| i.node_public_key.clone())
                .collect();
            (
                next,
                next_entry,
                a.pool[next].clone(),
                a.entries.get(next_entry).cloned(),
                in_use,
                a.current,
                a.current_entry,
            )
        };

        // 2. Without the lock — so `down` and `status` are never kept
        //    waiting on the network — a node joined with a pass gets the next
        //    pass redeemed, while the old circuit still carries traffic (the
        //    request goes through it, so the node sees the old exit, not this
        //    machine), before the kill switch is held to the tunnels' own
        //    packets.
        // The circuit's copies of the invites go back to the connect; the
        // pocket has them as they are now (when each key was last used, or a
        // newer one redeemed by the command line), and that is what decides.
        if let Ok(pocket) = load_pocket(&self.pocket_path) {
            if let Some(i) = pocket
                .exits
                .iter()
                .find(|i| i.node_public_key == next_exit.node_public_key)
            {
                next_exit = i.clone();
            }
            if let Some(e) = next_entry_inv.as_mut() {
                if let Some(i) = pocket
                    .entries
                    .iter()
                    .find(|i| i.node_public_key == e.node_public_key)
                {
                    *e = i.clone();
                }
            }
        }
        let mut pass_notes = Vec::new();
        if next_exit.pass.is_some() || next_entry_inv.as_ref().is_some_and(|e| e.pass.is_some()) {
            pass_notes = self
                .refresh_passes(&mut next_exit, next_entry_inv.as_mut(), &in_use)
                .await;
        }

        // 3. The lock again, and the circuit taken: it must be the one the
        //    choice was made on.
        let mut guard = self.state.lock().await;
        let mut active = guard
            .take()
            .ok_or_else(|| anyhow!("disconnected meanwhile; nothing to rotate"))?;
        let same = active.current == current
            && active.current_entry == current_entry
            && active
                .pool
                .get(next)
                .is_some_and(|i| i.node_public_key == next_exit.node_public_key)
            && match (&next_entry_inv, active.entries.get(next_entry)) {
                (Some(a), Some(b)) => a.node_public_key == b.node_public_key,
                (None, None) => true,
                _ => false,
            };
        if !same {
            *guard = Some(active);
            return Err(anyhow!(
                "the circuit changed while the new identity was prepared; ask again"
            ));
        }
        active.pool[next] = next_exit;
        if let (Some(e), Some(slot)) = (next_entry_inv, active.entries.get_mut(next_entry)) {
            *slot = e;
        }

        // The kill switch is held across the change: before the old circuit
        // comes down, the rules allow only the old and the new first hop, so
        // nothing else leaves while the new circuit is built; its own rules
        // replace the hold once it is up. A rotation that fails leaves the
        // machine blocked, never open.
        let mut allowed = Vec::with_capacity(2);
        if let Ok(current) = active.circuit.spec().first_hop_endpoint() {
            allowed.push(current);
        }
        match (CircuitSpec {
            exit: active.pool[next].clone(),
            entry: active.entries.get(next_entry).cloned(),
        })
        .first_hop_endpoint()
        {
            Ok(a) => allowed.push(a),
            Err(e) => {
                *guard = Some(active);
                return Err(e);
            }
        }
        if let Err(e) = killswitch::hold(&allowed) {
            *guard = Some(active);
            return Err(e.context(
                "could not hold the kill switch across the rotation; staying on the current circuit",
            ));
        }
        let Active {
            owner: active_owner,
            circuit,
            entries,
            current_entry,
            pool,
            current,
            opts,
        } = active;

        // The old circuit goes down completely before the new one comes up:
        // the exit's session and its routes belong to the old identity. The
        // kill switch stays, as the hold.
        self.note_used(circuit.spec());
        let _ = circuit.down_with(false).await;
        match connect(&pool[next], entries.get(next_entry), &opts, true).await {
            Ok(circuit) => {
                self.note_used(circuit.spec());
                let exit_note = if pool.len() == 1 {
                    "only one exit node is configured; reconnected to the same one, so the address the internet sees has not changed".to_string()
                } else {
                    format!(
                        "new identity: the exit is now {} (was {})",
                        pool[next].node_name, pool[current].node_name
                    )
                };
                let entry_note = match entries.len() {
                    0 => String::new(),
                    1 => format!(
                        "; the entry stays {} (only one entry node is configured)",
                        entries[0].node_name
                    ),
                    _ => format!(
                        "; the entry is now {} (was {})",
                        entries[next_entry].node_name, entries[current_entry].node_name
                    ),
                };
                *guard = Some(Active {
                    owner: active_owner,
                    circuit,
                    entries,
                    current_entry: next_entry,
                    pool,
                    current: next,
                    opts,
                });
                tracing::info!("new identity");
                let passes_note = if pass_notes.is_empty() {
                    String::new()
                } else {
                    format!("; {}", pass_notes.join("; "))
                };
                Ok(format!("{exit_note}{entry_note}{passes_note}"))
            }
            Err(e) => {
                // Nothing is up, and the hold still blocks the machine: say
                // so rather than pretend a circuit is up, or that it is open.
                Err(e.context(format!(
                    "the new circuit could not be built; disconnected, and {HELD}"
                )))
            }
        }
    }

    pub async fn down(&self) -> Result<&'static str> {
        let mut guard = self.state.lock().await;
        let active = match guard.take() {
            None => {
                // Even with nothing running, make sure nothing is left armed.
                let _ = killswitch::remove();
                if let Ok(Some(old)) = netcfg::load_plan() {
                    let _ = netcfg::revert(&old);
                }
                return Ok("already disconnected");
            }
            Some(a) => a,
        };
        // The circuit takes itself down in order: the firewall and the routing
        // first, then the tunnels, waiting for their tasks to let go of the
        // interfaces so the kernel interfaces are gone before we report
        // "disconnected".
        self.note_used(active.circuit.spec());
        let r = active.circuit.down().await;
        tracing::info!("disconnected");
        r.map(|_| "disconnected")
    }

    async fn status(&self) -> Response {
        let guard = self.state.lock().await;
        let killswitch = killswitch::is_active();
        match guard.as_ref() {
            None => Response::with_status(StatusReport {
                connected: false,
                node_name: None,
                endpoint: None,
                last_handshake_secs: None,
                tx_bytes: 0,
                rx_bytes: 0,
                killswitch,
                hops: 0,
                mode: String::new(),
                entry_name: None,
                hops_detail: Vec::new(),
                same_operator: None,
            }),
            Some(a) => {
                let s = a.circuit.status();
                let exit = s.exit();
                let same_operator = a.entries.get(a.current_entry).and_then(|entry| {
                    hidravpn_core::pocket::same_operator(entry, &a.pool[a.current])
                });
                Response::with_status(StatusReport {
                    connected: s.connected,
                    node_name: Some(exit.node_name.clone()),
                    endpoint: Some(exit.endpoint.clone()),
                    // The exit's session carries the machine's traffic; its
                    // handshake and bytes are the ones that matter.
                    last_handshake_secs: exit.tunnel.last_handshake.map(|d| d.as_secs()),
                    tx_bytes: exit.tunnel.tx_bytes,
                    rx_bytes: exit.tunnel.rx_bytes,
                    killswitch,
                    hops: a.circuit.hops(),
                    mode: s.mode.as_str().to_string(),
                    entry_name: s.entry().map(|h| h.node_name.clone()),
                    hops_detail: s
                        .hops
                        .iter()
                        .map(|h| HopReport {
                            role: match h.role {
                                Role::Entry => "entry",
                                Role::Exit => "exit",
                            }
                            .to_string(),
                            node_name: h.node_name.clone(),
                            endpoint: h.endpoint.clone(),
                            last_handshake_secs: h.tunnel.last_handshake.map(|d| d.as_secs()),
                            connected: h.tunnel.connected,
                        })
                        .collect(),
                    same_operator,
                })
            }
        }
    }

    /// Called when the service is stopping: leave nothing behind.
    pub async fn shutdown(&self) {
        let _ = self.down().await;
    }
}

/// An index other than `current`, at random, among the ones marked `ok`
/// when there are any, else among all the others; `current` itself when it
/// is the only one (and 0 for an empty list, which has no entry to rotate).
fn pick_other(ok: &[bool], current: usize) -> Result<usize> {
    let others: Vec<usize> = (0..ok.len()).filter(|&i| i != current).collect();
    if others.is_empty() {
        return Ok(current);
    }
    let preferred: Vec<usize> = others.iter().copied().filter(|&i| ok[i]).collect();
    let from = if preferred.is_empty() {
        others
    } else {
        preferred
    };
    Ok(from[random::index(from.len())?])
}

/// What `connect` will build, decided before anything is touched.
#[derive(Debug)]
pub struct Plan {
    pub exit: Invite,
    pub entry: Option<Invite>,
    pub alternates: Vec<Invite>,
    pub alternate_entries: Vec<Invite>,
    pub same_operator: Option<bool>,
}

/// Picks from the pocket for a mode: "rapido" is one hop through an exit,
/// "privado" two hops through an entry and an exit that are different nodes.
/// Choices are uniform and never logged.
pub fn plan_connect(pocket: &Pocket, mode: &str) -> Result<Plan> {
    if pocket.is_empty() && !pocket.known.is_empty() {
        return Err(anyhow!(
            "this machine knows {} node(s) from the node list but is admitted on none yet: a node that admits openly is joined with `hidravpn nodes join --all` (the service tries that itself when it connects, so if you see this, those nodes refused or did not answer); for one that admits by hand, run `hidravpn pubkey --node <its key>`, send the result to its operator (`hidravpn nodes list` names them) and add the invite with `hidravpn nodes add`",
            pocket.known.len()
        ));
    }
    if pocket.is_empty() {
        return Err(anyhow!(
            "the pocket has no nodes; add some with `hidravpn nodes add --entry e.json` and `--exit x.json`, or import a signed node list with `hidravpn nodes import nodes.json`"
        ));
    }
    let pick = match mode.trim().to_ascii_lowercase().as_str() {
        "rapido" => pocket.pick_rapido()?,
        "privado" => pocket.pick_privado()?,
        other => {
            return Err(anyhow!(
                "unknown mode \"{other}\": use \"rapido\" (one hop) or \"privado\" (two hops)"
            ))
        }
    };
    Ok(Plan {
        exit: pick.exit,
        entry: pick.entry,
        alternates: pick.other_exits,
        alternate_entries: pick.other_entries,
        same_operator: pick.same_operator,
    })
}

/// The pocket at a path. A file that is not there is an empty pocket.
pub fn load_pocket(path: &Path) -> Result<Pocket> {
    match std::fs::read_to_string(path) {
        Ok(s) => Pocket::from_json(&s).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Pocket::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Writes the pocket where `connect` reads it, readable by root only, and
/// atomically: the new file is written beside the old one and renamed over
/// it, so a reader never sees a half-written pocket and a crash mid-write
/// leaves the old one in place.
pub fn save_pocket(path: &Path, pocket: &Pocket) -> Result<()> {
    write_private_atomic(path, pocket.to_json().as_bytes())
}

/// Writes a file only root reads, atomically: beside the old one, then
/// renamed over it, so a reader never sees half a file and a crash leaves
/// the old one in place.
pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = {
        let mut s = path.as_os_str().to_owned();
        s.push(".tmp");
        std::path::PathBuf::from(s)
    };
    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Explicitly, in case the file was already there with wider rights.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("moving {} into place", path.display()))?;
    Ok(())
}

/// Slots, names and endpoints; never a key. Admitted nodes first, then the
/// ones this machine only knows of.
pub fn node_reports(pocket: &Pocket) -> Vec<NodeReport> {
    node_reports_with_passes(pocket, &hidravpn_core::pass::Wallet::default())
}

/// `node_reports`, with how many passes the wallet holds for each node that
/// admits with one. Counts only: never a pass, never a key.
pub fn node_reports_with_passes(
    pocket: &Pocket,
    wallet: &hidravpn_core::pass::Wallet,
) -> Vec<NodeReport> {
    pocket
        .iter()
        .map(|(slot, inv)| NodeReport {
            slot: hidravpn_core::pocket::slot_name(slot).to_string(),
            node_name: inv.node_name.clone(),
            endpoint: inv.endpoint.clone(),
            admitted: true,
            operator: inv.operator.clone(),
            role: inv.role.clone(),
            admission: inv.pass.as_ref().map(|_| "pass".to_string()),
            passes: inv
                .pass
                .as_ref()
                .map(|_| wallet.count_for(&inv.node_public_key)),
        })
        .chain(pocket.known.iter().map(|k| {
            NodeReport {
                slot: "known".to_string(),
                node_name: k.node_name.clone(),
                endpoint: k.endpoint.clone(),
                admitted: false,
                operator: k.operator.clone(),
                role: k.role.clone(),
                admission: k.admission.clone(),
                passes: k
                    .takes_passes()
                    .then(|| wallet.count_for(&k.node_public_key)),
            }
        }))
        .collect()
}

/// Brings a circuit up with the service's key. A kill switch a crashed run
/// left behind is undone first — unless one is `held` on purpose across a
/// change, in which case it stays until the new circuit's own rules replace
/// it in one step.
async fn connect(
    exit: &Invite,
    entry: Option<&Invite>,
    opts: &CircuitOptions,
    held: bool,
) -> Result<Circuit> {
    let key = load_key()?;
    if !held {
        let _ = killswitch::remove();
    }
    Circuit::up(
        CircuitSpec {
            exit: exit.clone(),
            entry: entry.cloned(),
        },
        key,
        opts.clone(),
    )
    .await
}

fn load_key() -> Result<ClientKey> {
    let path = paths::client_key();
    let s = std::fs::read_to_string(&path).map_err(|_| {
        anyhow!(
            "no client key at {} — run `hidravpn keygen` first",
            path.display()
        )
    })?;
    ClientKey::from_base64(&s)
}

/// A short wait helper the installer uses when stopping.
#[allow(dead_code)]
pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use hidravpn_core::Slot;

    fn invite(name: &str, endpoint: &str) -> Invite {
        Invite {
            node_name: name.into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: endpoint.into(),
            client_address: "10.77.0.2/16".into(),
            dns: std::net::Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1420,
            keepalive: 25,
            operator: None,
            role: None,
            pass: None,
        }
    }

    fn pocket(entries: &[&str], exits: &[&str]) -> Pocket {
        let mut p = Pocket::default();
        for (i, e) in entries.iter().enumerate() {
            p.add(
                Slot::Entry,
                invite(e, &format!("203.0.113.{}:51820", 20 + i)),
            )
            .unwrap();
        }
        for (i, x) in exits.iter().enumerate() {
            p.add(
                Slot::Exit,
                invite(x, &format!("203.0.113.{}:51820", 10 + i)),
            )
            .unwrap();
        }
        p
    }

    #[test]
    fn rapido_plans_one_exit_and_keeps_the_others_for_rotation() {
        let p = pocket(&["e1"], &["x1", "x2", "x3"]);
        let plan = plan_connect(&p, "rapido").unwrap();
        assert!(plan.entry.is_none(), "one hop has no entry");
        assert_eq!(plan.alternates.len(), 2);
        assert!(plan.alternate_entries.is_empty());
        assert!(!plan
            .alternates
            .iter()
            .any(|a| a.node_name == plan.exit.node_name));
        // Case and spacing do not matter to the mode.
        assert!(plan_connect(&p, " Rapido ").is_ok());
    }

    #[test]
    fn privado_plans_an_entry_and_an_exit_that_are_different_nodes() {
        let p = pocket(&["e1", "e2"], &["x1", "x2"]);
        for _ in 0..50 {
            let plan = plan_connect(&p, "privado").unwrap();
            let entry = plan.entry.expect("two hops have an entry");
            assert_ne!(entry.node_public_key, plan.exit.node_public_key);
            assert_eq!(plan.alternates.len(), 1);
            assert_eq!(plan.alternate_entries.len(), 1);
        }
    }

    #[test]
    fn an_empty_pocket_and_an_unknown_mode_are_refused_with_a_way_forward() {
        let e = plan_connect(&Pocket::default(), "rapido")
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("no nodes") && e.contains("hidravpn nodes add"),
            "{e}"
        );
        let e = plan_connect(&pocket(&[], &["x1"]), "fast")
            .unwrap_err()
            .to_string();
        assert!(e.contains("rapido") && e.contains("privado"), "{e}");
        let e = plan_connect(&pocket(&[], &["x1"]), "privado")
            .unwrap_err()
            .to_string();
        assert!(e.contains("no entry node"), "{e}");
    }

    #[test]
    fn a_pocket_that_only_knows_nodes_says_who_to_ask() {
        let mut p = Pocket::default();
        p.learn(hidravpn_core::NodeRecord {
            node_name: "node-1".into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: "203.0.113.10:51820".into(),
            operator: None,
            contact: None,
            role: None,
            admission: None,
            admission_port: None,
        })
        .unwrap();
        let e = plan_connect(&p, "rapido").unwrap_err().to_string();
        assert!(
            e.contains("knows 1 node(s)") && e.contains("hidravpn pubkey --node"),
            "{e}"
        );
        let r = node_reports(&p);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].slot, "known");
        assert!(!r[0].admitted);
    }

    #[test]
    fn node_reports_name_every_node_with_its_slot_and_carry_no_key() {
        let p = pocket(&["e1"], &["x1", "x2"]);
        let reports = node_reports(&p);
        assert_eq!(reports.len(), 3);
        assert!(reports.iter().all(|r| r.admitted));
        assert_eq!(reports[0].slot, "entry");
        assert_eq!(reports[0].node_name, "e1");
        assert_eq!(reports[2].slot, "exit");
        assert_eq!(reports[2].endpoint, "203.0.113.11:51820");
        let line = serde_json::to_string(&reports).unwrap();
        for inv in p.iter().map(|(_, i)| i) {
            assert!(!line.contains(&inv.node_public_key));
        }
    }

    #[test]
    fn a_pocket_file_that_is_not_there_is_an_empty_pocket_and_a_broken_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("hidravpn-daemon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = load_pocket(&dir.join("nothing-here.json")).unwrap();
        assert!(p.is_empty());
        let broken = dir.join("broken.json");
        std::fs::write(&broken, "{ not json").unwrap();
        let e = load_pocket(&broken).unwrap_err().to_string();
        assert!(e.contains("broken.json"), "{e}");
    }

    #[tokio::test]
    async fn only_root_may_hand_the_service_an_invite() {
        let d = Daemon::with_pocket(
            "tok".to_string(),
            std::env::temp_dir().join("never-read.json"),
        );
        let up = || Request {
            token: "tok".into(),
            cmd: Command::Up {
                invite: invite("x", "203.0.113.10:51820"),
                allow_lan: false,
                keep_ipv6: false,
                via: None,
                alternates: vec![],
                alternate_entries: vec![],
            },
        };
        let r = d.handle(up(), Some(1000)).await;
        assert!(!r.ok);
        assert!(
            r.error.as_deref().unwrap().contains("needs root"),
            "{:?}",
            r.error
        );
        // The unprivileged refusal comes before any pocket or network is touched,
        // and the token is still checked first.
        let wrong = Request {
            token: "nope".into(),
            cmd: Command::Status,
        };
        assert!(d
            .handle(wrong, Some(1000))
            .await
            .error
            .unwrap()
            .contains("unauthorised"));
        let ok = d
            .handle(
                Request {
                    token: "tok".into(),
                    cmd: Command::Ping,
                },
                Some(1000),
            )
            .await;
        assert!(ok.ok, "a group member may still ping");
    }

    #[test]
    fn a_rotation_prefers_the_nodes_a_circuit_can_be_built_with() {
        for _ in 0..50 {
            assert_eq!(pick_other(&[true, false, true], 0).unwrap(), 2);
            let i = pick_other(&[false, false, false], 1).unwrap();
            assert!(i == 0 || i == 2, "nothing usable: any other one");
        }
        assert_eq!(pick_other(&[true], 0).unwrap(), 0, "only one: itself");
        assert_eq!(pick_other(&[], 0).unwrap(), 0);
    }

    #[test]
    fn the_token_comparison_treats_every_difference_the_same() {
        assert!(same_token(b"abc", b"abc"));
        assert!(!same_token(b"abc", b"abd"));
        assert!(!same_token(b"abc", b"xbc"));
        assert!(!same_token(b"abc", b"abcd"));
        assert!(!same_token(b"", b"a"));
        assert!(same_token(b"", b""));
    }
}

#[cfg(test)]
mod key_choice_tests {
    use super::*;

    #[test]
    fn the_service_checks_node_lists_against_the_list_key_not_the_release_key() {
        let d = Daemon::with_pocket(
            "t".into(),
            std::env::temp_dir().join("hidravpn-list-key-choice.json"),
        );
        let want = ReleaseKey::embedded_list_key().map(|k| k.to_base64());
        assert_eq!(
            d.list_key_base64(),
            want,
            "the daemon must use LIST_PUBLIC_KEY_B64"
        );
        if let (Some(list), Some(release)) =
            (ReleaseKey::embedded_list_key(), ReleaseKey::embedded())
        {
            assert_ne!(
                list.to_base64(),
                release.to_base64(),
                "the list key and the release key are two keys"
            );
        }
    }
}
