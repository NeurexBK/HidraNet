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

use anyhow::{anyhow, Context, Result};
use hidravpn_core::killswitch;
use hidravpn_core::netcfg;
use hidravpn_core::{
    circuit, random, Circuit, CircuitOptions, CircuitSpec, ClientKey, Invite, Merge, Pocket,
    ReleaseKey, Role,
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
    /// The person said yes to two hops under one operator (or unnamed ones).
    allow_same_operator: bool,
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
    /// Set by `shutdown`: a connect still waiting for the state lock then
    /// gives up, instead of building a circuit nobody will take down.
    stopping: std::sync::atomic::AtomicBool,
    /// After a top-up that failed, none is tried again before this: an
    /// issuer that counted passes the service then could not keep, or one
    /// that is down, is not asked every ten minutes.
    refill_pause: std::sync::Mutex<Option<std::time::Instant>>,
    /// The circuits asked for and not built yet: waiting for the pocket's
    /// locks, or being built under the state lock. `down` stops them through
    /// this instead of waiting on the nodes (or acknowledging a disconnect
    /// that a connect still queued would undo), and `status` answers from
    /// it.
    connecting: std::sync::Mutex<Vec<(u64, Connecting)>>,
    next_connect: std::sync::atomic::AtomicU64,
}

/// A circuit being built: whose it is, what it will be, and the switch that
/// stops it.
struct Connecting {
    owner: Option<u32>,
    hops: u8,
    mode: &'static str,
    stop: tokio::sync::watch::Sender<bool>,
}

/// Takes its entry out of `Daemon::connecting` when the connect it stands
/// for ends, however.
struct Built<'a>(&'a std::sync::Mutex<Vec<(u64, Connecting)>>, u64);

impl Drop for Built<'_> {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(id, _)| *id != self.1);
    }
}

/// How long automatic passes rest after a top-up that failed.
const REFILL_PAUSE: std::time::Duration = std::time::Duration::from_secs(3600);

/// The answer to a request without the right control token.
pub const UNAUTHORISED: &str = "unauthorised: wrong or missing control token";

/// What another account is told when it tries to change the circuit.
const OWNED: &str = "the VPN was switched on by another account on this computer; only that account or root may switch it off";

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
            stopping: std::sync::atomic::AtomicBool::new(false),
            refill_pause: std::sync::Mutex::new(None),
            connecting: std::sync::Mutex::new(Vec::new()),
            next_connect: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Whether `token` is the control token, compared in full, in constant
    /// time.
    pub fn token_ok(&self, token: &str) -> bool {
        same_token(token.as_bytes(), self.token.as_bytes())
    }

    /// `caller` is the account asking: `Some(0)` for root (an elevated
    /// process on Windows), another uid for a member of the group, `None`
    /// when the channel cannot tell. The channel is shared with the group,
    /// whose members may connect through the pocket, disconnect what they
    /// switched on, rotate, join, and import a signed list — but never hand
    /// the service an invite of their own, which would route the whole
    /// machine through a node nobody vetted, and never switch off what
    /// another account switched on. Members may also look after the passes
    /// (fetching passes, automatic top-ups): the browser runs as the person,
    /// and the VPN page does that for them. What is at stake there is the
    /// pass account's quota, never the machine's network or its key. The
    /// account token itself is root's to replace: it may hold passes paid
    /// for, and the next purchase goes on whatever token is kept, so another
    /// account that replaced it could wipe the one and take the other. It is
    /// never repeated in an answer.
    pub async fn handle(&self, req: Request, caller: Option<u32>) -> Response {
        let privileged = caller == Some(0);
        // The token is compared in full, in constant time, before anything else.
        if !self.token_ok(&req.token) {
            return Response::err(UNAUTHORISED);
        }
        match req.cmd {
            Command::Ping => Response::ok(),
            Command::Status => self.status().await,
            Command::Up { .. } if !privileged => Response::err(
                "`up` with an invite needs root (an administrator prompt on Windows): only root may hand the service a node to route the machine through. Members of the hidravpn group use `hidravpn up --rapido` or `--privado` (or the browser's VPN page), which pick from the pocket root filled.",
            ),
            Command::Up {
                invite,
                allow_lan,
                keep_ipv6,
                via,
                alternates,
                alternate_entries,
                allow_same_operator,
            } => {
                let opts = CircuitOptions {
                    route_ipv6: !keep_ipv6,
                    allow_lan,
                    ..CircuitOptions::default()
                };
                match self
                    .up(
                        invite,
                        via,
                        alternates,
                        alternate_entries,
                        opts,
                        caller,
                        allow_same_operator,
                    )
                    .await
                {
                    Ok(notes) => noting_all(self.status().await, notes),
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::Connect {
                mode,
                allow_lan,
                keep_ipv6,
                allow_same_operator,
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
                match self
                    .connect_from_pocket(&mode, opts, caller, allow_same_operator)
                    .await
                {
                    Ok(notes) => noting_all(self.status().await, notes),
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
            Command::SetPassToken { .. } if !privileged => Response::err(
                "keeping the pass account token needs root (an administrator on Windows), as `up` with an invite does: the token holds the account's passes, bought ones too, and the next purchase goes on it. `sudo hidravpn passes token <file>` keeps one (on Windows, `hidravpn passes token <file>` in a terminal run as administrator).",
            ),
            Command::SetPassToken { pass_token } => match self.set_pass_token(&pass_token.0) {
                Ok(kept) => Response::ok().noting(match kept {
                    Some(p) => format!(
                        "the account token is kept on this machine, readable by root only; the one it replaced is kept at {}, readable by root only too",
                        p.display()
                    ),
                    None => "the account token is kept on this machine, readable by root only".to_string(),
                }),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::Refill {
                enabled,
                low,
                count,
            } => match self.set_refill(enabled, low, count).await {
                Ok(r) => {
                    let note = r.describe();
                    let mut resp = Response::ok().noting(note);
                    resp.refill = Some(r);
                    resp
                }
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
                // A circuit still being built is stopped first: otherwise
                // `down` would wait for every node it is waiting on.
                self.stop_connecting(caller);
                match self.down_for(caller).await {
                    Ok(_) => Response::ok(),
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::NewIdentity => {
                match self.new_identity(caller).await {
                    Ok(note) => self.status().await.noting(note),
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
        }
    }

    /// Marks a circuit as asked for, for `owner`, until the guard goes —
    /// before any lock is waited for; returns what stops it.
    fn begin_connecting(&self, owner: Option<u32>, hops: u8) -> (circuit::Cancel, Built<'_>) {
        let (stop, cancel) = circuit::Cancel::new();
        let id = self
            .next_connect
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.connecting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((
                id,
                Connecting {
                    owner,
                    hops,
                    mode: if hops == 2 { "privado" } else { "rapido" },
                    stop,
                },
            ));
        (cancel, Built(&self.connecting, id))
    }

    /// Stops every circuit asked for and not built yet that `caller` may
    /// stop: root any, an account its own.
    fn stop_connecting(&self, caller: Option<u32>) {
        for (_, c) in self
            .connecting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            if caller == Some(0) || c.owner == caller {
                let _ = c.stop.send(true);
            }
        }
    }

    /// Root, or the account that switched the circuit on, or nobody has it
    /// on: otherwise this caller may not switch it off or rotate it.
    async fn owned_by(&self, caller: Option<u32>) -> Result<()> {
        if caller == Some(0) {
            return Ok(());
        }
        match self.state.lock().await.as_ref() {
            Some(a) => not_someone_elses(a, caller),
            None => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn up(
        &self,
        exit: Invite,
        entry: Option<Invite>,
        alternates: Vec<Invite>,
        alternate_entries: Vec<Invite>,
        opts: CircuitOptions,
        caller: Option<u32>,
        allow_same_operator: bool,
    ) -> Result<Vec<String>> {
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
                CircuitSpec::new(exit.clone(), None).validate_plan()?;
            }
            for entry in &entries {
                if hidravpn_core::pocket::same_node(entry, exit) {
                    continue;
                }
                CircuitSpec::new(exit.clone(), Some(entry.clone())).validate_plan()?;
            }
        }
        if let Some(entry) = entries.first() {
            CircuitSpec::new(pool[0].clone(), Some(entry.clone())).validate_plan()?;
            if !hidravpn_core::pocket::pair_allowed(entry, &pool[0], allow_same_operator) {
                return Err(anyhow!("{}", hidravpn_core::pocket::SAME_OPERATOR_REFUSAL));
            }
        }

        // Asked for from here on: a `down` while this waits for the locks
        // below stops it, rather than tear down what is up and see this
        // build a new circuit right after.
        let hops = if entries.is_empty() { 1 } else { 2 };
        let (cancel, _building) = self.begin_connecting(caller, hops);

        // The pocket and the wallet are held first, then the circuit: the
        // order every other path takes (a top-up holds them, then looks at
        // the circuit), so nothing waits in a circle and no pass is taken
        // twice.
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path).await?;
        let mut guard = self.state.lock().await;
        if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(anyhow!("the service is stopping"));
        }
        if cancel.is_set() {
            return Err(anyhow!(circuit::CANCELLED));
        }
        // The owner is checked again under the lock: two accounts asking at
        // once both passed `owned_by` on an empty state, and the second must
        // not take down the circuit the first just built.
        if let Some(a) = guard.as_ref() {
            not_someone_elses(a, caller)?;
        }
        let old = guard.take();
        let had_old = old.is_some();
        let built = self
            .build(old, &pool[0], entries.first(), &opts, &cancel)
            .await;
        let (circuit, notes) = match built {
            Ok(c) => c,
            Err(Failed::Untouched(e, old)) => {
                *guard = old.map(|b| *b);
                return Err(e);
            }
            // Stopped by `down`, which takes it from here.
            Err(Failed::Held(_)) if cancel.is_set() => return Err(anyhow!(circuit::CANCELLED)),
            Err(Failed::Held(e)) if had_old || killswitch::is_active() => {
                return Err(e.context(HELD));
            }
            Err(Failed::Held(e)) => return Err(e),
        };
        *guard = Some(Active {
            owner: caller,
            circuit,
            entries,
            current_entry: 0,
            pool,
            current: 0,
            opts,
            allow_same_operator,
        });
        tracing::info!("connected");
        Ok(notes)
    }

    /// Writes down, for the invites won with a pass that this circuit uses,
    /// that they were used now: what tells later picks their lease stands.
    async fn note_used(&self, used: &[Invite]) {
        if !used.is_empty() {
            if let Err(e) = crate::passes::mark_used(&self.pocket_path, used).await {
                tracing::warn!("could not note a pass key's use: {e:#}");
            }
        }
    }

    /// Connects through nodes picked from the pocket: one exit for Rápido, an
    /// entry and an exit for Privado, each at random, the rest kept for
    /// `new_identity` to rotate to. The caller never sees an invite. A node
    /// that admits openly or with a pass needs no joining first: it is asked
    /// for a key for this connection as the circuit is built
    /// (`circuit::prepare`), which is how a machine that only imported the
    /// list connects at all. A node a circuit cannot be built with now (one
    /// that takes passes, with none left for it) is not picked while
    /// another will do. Returns notes for the person.
    async fn connect_from_pocket(
        &self,
        mode: &str,
        opts: CircuitOptions,
        caller: Option<u32>,
        allow_same_operator: bool,
    ) -> Result<Vec<String>> {
        let pocket = load_pocket(&self.pocket_path)?;
        let wallet = crate::passes::load_wallet(&self.wallet_path()).unwrap_or_default();
        let live = crate::passes::without_dead(&pocket, &wallet, mode, allow_same_operator);
        let plan = plan_connect(&live, mode, allow_same_operator)?;
        self.up(
            plan.exit,
            plan.entry,
            plan.alternates,
            plan.alternate_entries,
            opts,
            caller,
            allow_same_operator,
        )
        .await
    }

    /// Asks admission from the known nodes that admit openly (one by name,
    /// or all), with the key derived for each; a node that admits goes into
    /// the pocket under the role it declares. One node's refusal does not
    /// stop the others. Returns the pocket and a line per node.
    async fn join(&self, name: Option<&str>) -> Result<(Pocket, String)> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path).await?;
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
            match hidravpn_core::admission::request_admission(&rec, &shown, &host, false).await {
                Ok(invite) => {
                    for slot in hidravpn_core::pocket::slots_for_role(rec.role.as_deref()) {
                        let _ = pocket.add(slot, invite.clone());
                    }
                    joined += 1;
                    lines.push(format!(
                        "{}: admitted as {}",
                        rec.node_name,
                        rec.role.as_deref().unwrap_or("both")
                    ));
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

    /// Keeps the account token passes are asked for with, root only; the
    /// caller is root (`handle`). The token is checked for shape and never
    /// repeated in an answer. The one it replaces is kept beside it
    /// (`passes::keep_token`): it may hold a paid balance, and be its only
    /// copy. Returns where that one was kept, if one was.
    fn set_pass_token(&self, token: &str) -> Result<Option<PathBuf>> {
        let t = crate::passes::parse_token(token)?;
        let kept = crate::passes::keep_token(&self.token_path(), &t)?;
        tracing::info!("pass account token replaced");
        Ok(kept)
    }

    /// Reads the automatic-passes setting, and changes what is given. Any
    /// account that may drive the service may switch it: as with
    /// `get_passes`, only the account's quota is at stake. In the same
    /// order as every other change beside the pocket: the service's own
    /// lock, then the file lock. Inside the service the file lock is only
    /// taken under its own lock, so waiting for it here (a blocking wait)
    /// is only ever waiting for the command line, which may hold it across
    /// a fetch.
    async fn set_refill(
        &self,
        enabled: Option<bool>,
        low: Option<u32>,
        count: Option<u32>,
    ) -> Result<crate::passes::Refill> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path).await?;
        let mut r = crate::passes::load_refill(&self.pocket_path);
        let changed = r.apply(enabled, low.map(|n| n as usize), count.map(|n| n as usize))?;
        if changed {
            crate::passes::save_refill(&self.pocket_path, &r)?;
            tracing::info!(on = r.enabled, "automatic passes set");
            if r.enabled {
                // Switched on again: try at the next look, not an hour on.
                *self.refill_pause.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }
        }
        Ok(r)
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
    /// stake, and the token never leaves the service. Not while two hops are
    /// up: the request would leave through their exit
    /// (`passes::NOT_THROUGH_TWO_HOPS`).
    async fn get_passes(&self, name: Option<&str>, count: usize) -> Result<(Pocket, String)> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path).await?;
        // Under the pocket's locks no circuit is being built: what is up is
        // what the request would leave through. In the same order as every
        // other path: the pocket's locks, then the circuit's.
        let two_hops = self
            .state
            .lock()
            .await
            .as_ref()
            .is_some_and(|a| a.circuit.spec().hops() == 2);
        if two_hops {
            return Err(anyhow!("{}", crate::passes::NOT_THROUGH_TWO_HOPS));
        }
        let pocket = load_pocket(&self.pocket_path)?;
        let token = crate::passes::read_token(&self.token_path())?;
        let mut wallet = crate::passes::load_wallet(&self.wallet_path())?;
        let line = crate::passes::get_passes(&pocket, &mut wallet, &token, name, count).await?;
        crate::passes::save_wallet(&self.wallet_path(), &wallet)?;
        tracing::info!("passes fetched from the issuer");
        Ok((pocket, line))
    }

    /// Every so often (`HIDRAVPN_REFILL_SECS`, ten minutes by default, and
    /// up to half as long again at random, so the issuer cannot set a clock
    /// by it), tops the wallet up when it runs low.
    pub async fn refill_loop(&self) {
        let every: u64 = std::env::var("HIDRAVPN_REFILL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&n| n > 0)
            .unwrap_or(600);
        loop {
            let jitter = hidravpn_core::random::index((every / 2 + 1) as usize).unwrap_or(0) as u64;
            tokio::time::sleep(std::time::Duration::from_secs(every + jitter)).await;
            self.refill_once().await;
        }
    }

    /// One top-up, when it is on, a token is kept and a one-hop circuit is
    /// up: the issuer is then asked through the tunnel and sees the node's
    /// address. Never through two hops (`passes::refills_through`).
    /// Returns what was fetched, if anything.
    pub async fn refill_once(&self) -> Option<String> {
        let paused = self
            .refill_pause
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some_and(|until| std::time::Instant::now() < until);
        if paused {
            return None;
        }
        let r = crate::passes::load_refill(&self.pocket_path);
        if !r.enabled {
            return None;
        }
        // No token kept: nothing to ask with, and nothing to say.
        let token = crate::passes::read_token(&self.token_path()).ok()?;
        if !self.refill_may_go() {
            return None;
        }
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = match crate::passes::lock_beside(&self.pocket_path).await {
            Ok(f) => f,
            Err(_) => return self.refill_failed("the pocket's lock cannot be taken"),
        };
        let pocket = match load_pocket(&self.pocket_path) {
            Ok(p) => p,
            Err(_) => return self.refill_failed("the pocket cannot be read"),
        };
        let mut wallet = match crate::passes::load_wallet(&self.wallet_path()) {
            Ok(w) => w,
            Err(_) => return self.refill_failed("the wallet cannot be read"),
        };
        // Asked again now that the locks are held: whoever held them may
        // have been slow, and a `down` meanwhile would send the request,
        // with the account token, out of this machine's own address (a
        // connect in privado, through its exit).
        if !self.refill_may_go() {
            return None;
        }
        let before = wallet.passes.len();
        // Asked again before each request: a `down` while the issuer is
        // asked must stop the next one before it looks the issuer up.
        let got =
            crate::passes::refill(&pocket, &mut wallet, &token, &r, &|| self.refill_may_go()).await;
        if wallet.passes.len() != before
            && crate::passes::save_wallet(&self.wallet_path(), &wallet).is_err()
        {
            return self
                .refill_failed("the passes fetched could not be written down, and are lost");
        }
        match got {
            Ok(None) => None,
            Ok(Some(line)) => {
                tracing::info!("passes topped up by themselves");
                Some(line)
            }
            // Said without the reason: it can name the issuer's address.
            Err(_) => self.refill_failed("the issuer could not be asked"),
        }
    }

    /// Whether a top-up may go out now: a circuit is up, and one the
    /// issuer may be asked through (`passes::refills_through`: one hop, not
    /// two). One being built, or being changed, is not: the answer does not
    /// wait for it.
    fn refill_may_go(&self) -> bool {
        self.state.try_lock().is_ok_and(|g| {
            g.as_ref().is_some_and(|a| {
                a.circuit.status().connected
                    && crate::passes::refills_through(a.circuit.spec().mode())
            })
        })
    }

    /// Says why a top-up failed, without an address or a name, and rests
    /// automatic passes for `REFILL_PAUSE`.
    fn refill_failed(&self, why: &str) -> Option<String> {
        tracing::warn!("automatic passes: {why}; resting for an hour");
        *self.refill_pause.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(std::time::Instant::now() + REFILL_PAUSE);
        None
    }

    fn reports(&self, pocket: &Pocket) -> Vec<NodeReport> {
        let wallet = crate::passes::load_wallet(&self.wallet_path()).unwrap_or_default();
        node_reports_with_passes(pocket, &wallet)
    }

    /// Checks a signed node list against the embedded list key, and only
    /// then puts its nodes into the pocket and writes the pocket back. The
    /// pocket on disk is untouched by a list that is refused.
    async fn import_nodes(&self, list: &str, signature: &str) -> Result<(Pocket, Merge)> {
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path).await?;
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
    /// more than one — never into a pair one operator runs, unless the
    /// person said yes to that when connecting. An exit that admits openly
    /// is shown a fresh key, admitted through the entry, even when it is the
    /// same exit again. Returns the note for the person: which nodes it got,
    /// or that there was no other to choose, and why.
    async fn new_identity(&self, caller: Option<u32>) -> Result<String> {
        // Nothing up, nothing to rotate: said before the pocket's files are
        // touched (and checked again below, under the locks).
        let (owner, hops) = match self.state.lock().await.as_ref() {
            None => return Err(anyhow!("not connected; nothing to rotate")),
            Some(a) => (a.owner, if a.entries.is_empty() { 1 } else { 2 }),
        };
        // Asked for from here on, as in `up`: a `down` meanwhile stops it.
        let (cancel, _building) = self.begin_connecting(owner, hops);
        // The same order as `up`: the pocket and the wallet, then the circuit.
        let _one_at_a_time = self.pocket_lock.lock().await;
        let _file = crate::passes::lock_beside(&self.pocket_path).await?;
        let wallet = crate::passes::load_wallet(&self.wallet_path()).unwrap_or_default();
        let t = hidravpn_core::timefmt::now_unix().max(0) as u64;
        let mut guard = self.state.lock().await;
        if self.stopping.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(anyhow!("the service is stopping"));
        }
        if cancel.is_set() {
            return Err(anyhow!(circuit::CANCELLED));
        }
        // Whose circuit it is, under the same lock that rotates it.
        if let Some(a) = guard.as_ref() {
            not_someone_elses(a, caller)?;
        }
        let active = guard
            .take()
            .ok_or_else(|| anyhow!("not connected; nothing to rotate"))?;
        // Among the others, the nodes a circuit can be built with now are
        // preferred: not one that takes passes with none left for it.
        let usable = |i: &Invite, behind: bool| {
            if behind {
                crate::passes::usable_behind(i, &wallet)
            } else {
                crate::passes::usable(i, &wallet, t)
            }
        };
        let (next, next_entry, skipped) = match choose_rotation(&active, usable) {
            Ok(c) => c,
            Err(e) => {
                *guard = Some(active);
                return Err(e);
            }
        };
        let exit = active.pool[next].clone();
        let entry = active.entries.get(next_entry).cloned();
        let (pool, entries) = (active.pool.clone(), active.entries.clone());
        let (current, current_entry) = (active.current, active.current_entry);
        let (owner, opts, allow) = (
            active.owner,
            active.opts.clone(),
            active.allow_same_operator,
        );
        let built = self
            .build(Some(active), &exit, entry.as_ref(), &opts, &cancel)
            .await;
        match built {
            Ok((circuit, pass_notes)) => {
                let fresh = (exit.admits_openly() || exit.takes_passes()) && entry.is_some();
                let exit_note = if next == current {
                    let why = if skipped.is_empty() {
                        "only one exit node is configured".to_string()
                    } else {
                        format!(
                            "no other exit can go with the entry ({} not used)",
                            skipped.join(", ")
                        )
                    };
                    format!(
                        "{why}; reconnected to the same one, so the address the internet sees has not changed{}",
                        if fresh { " (it was shown a new key)" } else { "" }
                    )
                } else {
                    let mut n = format!(
                        "new identity: the exit is now {} (was {})",
                        pool[next].node_name, pool[current].node_name
                    );
                    if !skipped.is_empty() {
                        n.push_str(&format!("; not {}", skipped.join(", ")));
                    }
                    n
                };
                let entry_note = match entries.len() {
                    0 => String::new(),
                    1 => format!(
                        "; the entry stays {} (only one entry node is configured)",
                        entries[0].node_name
                    ),
                    _ if next_entry == current_entry => {
                        format!("; the entry stays {}", entries[next_entry].node_name)
                    }
                    _ => format!(
                        "; the entry is now {} (was {})",
                        entries[next_entry].node_name, entries[current_entry].node_name
                    ),
                };
                *guard = Some(Active {
                    owner,
                    circuit,
                    entries,
                    current_entry: next_entry,
                    pool,
                    current: next,
                    opts,
                    allow_same_operator: allow,
                });
                tracing::info!("new identity");
                let passes_note = if pass_notes.is_empty() {
                    String::new()
                } else {
                    format!("; {}", pass_notes.join("; "))
                };
                Ok(format!("{exit_note}{entry_note}{passes_note}"))
            }
            Err(Failed::Untouched(e, old)) => {
                *guard = old.map(|b| *b);
                Err(e)
            }
            Err(Failed::Held(_)) if cancel.is_set() => Err(anyhow!(circuit::CANCELLED)),
            // Nothing is up, and the hold still blocks the machine: say so
            // rather than pretend a circuit is up, or that it is open.
            Err(Failed::Held(e)) => Err(e.context(format!(
                "the new circuit could not be built; disconnected, and {HELD}"
            ))),
        }
    }

    /// Builds a circuit through `exit` (and `entry`), replacing `old`, with
    /// the service's key. The kill switch is held from the moment `old`
    /// starts to come down until the new circuit's own rules replace the
    /// hold, so there is no moment on the open network. Every node that
    /// admits openly or with a pass is shown a key made for this connection
    /// (`circuit::prepare`); the exit of two hops is asked through the entry.
    ///
    /// The caller holds the pocket's locks: the passes this takes come out
    /// of the wallet, and the invites they win go into the pocket, here.
    /// Returns the circuit and notes for the person.
    async fn build(
        &self,
        old: Option<Active>,
        exit: &Invite,
        entry: Option<&Invite>,
        opts: &CircuitOptions,
        cancel: &circuit::Cancel,
    ) -> std::result::Result<(Circuit, Vec<String>), Failed> {
        let ready = (|| -> Result<_> {
            let key = load_key()?;
            let first_hop = entry.unwrap_or(exit).endpoint_addr()?;
            let pocket = load_pocket(&self.pocket_path)?;
            let wallet = crate::passes::load_wallet(&self.wallet_path())?;
            Ok((key, first_hop, pocket, wallet))
        })();
        let (key, first_hop, mut pocket, mut wallet) = match ready {
            Ok(r) => r,
            Err(e) => return Err(Failed::Untouched(e, old.map(Box::new))),
        };
        // An invite won with a pass is taken as the pocket has it now: it
        // says when its key was last used, or holds a newer one.
        let exit = crate::passes::as_kept(&pocket, exit);
        let entry = entry.map(|e| crate::passes::as_kept(&pocket, e));
        let old_first_hop: Vec<std::net::SocketAddr> = old
            .as_ref()
            .and_then(|o| o.circuit.spec().first_hop_endpoint().ok())
            .into_iter()
            .collect();
        let had_old = old.is_some();
        // A circuit being replaced is held: from here on, only the old and
        // the new first hop may be reached. A machine already blocked (a
        // rotation that failed, a crashed run's rules) stays blocked the
        // same way while this circuit is built: lifting it would let every
        // program out in the clear for the proof of work and the requests.
        // Only a machine that was open is left open.
        let mut held = Vec::new();
        let mut was_held = false;
        if let Some(o) = old {
            held.push(first_hop);
            held.extend(old_first_hop.iter().copied().filter(|a| *a != first_hop));
            if let Err(e) = killswitch::hold(&held) {
                return Err(Failed::Untouched(
                    e.context("could not hold the kill switch across the change; staying on the current circuit"),
                    Some(Box::new(o)),
                ));
            }
            crate::passes::mark_used_in(&mut pocket, &spec_passes(o.circuit.spec()));
            let _ = o.circuit.down_with(false).await;
        } else if killswitch::is_active() {
            held.push(first_hop);
            if let Err(e) = killswitch::hold(&held) {
                return Err(Failed::Untouched(
                    e.context("could not hold the kill switch for the new circuit"),
                    None,
                ));
            }
            was_held = true;
        }
        let wallet_before = wallet.to_json();
        let mut won = Vec::new();
        let prepared = circuit::prepare(
            &exit,
            entry.as_ref(),
            &key,
            opts,
            &held,
            &mut wallet,
            &mut won,
            cancel,
        )
        .await;
        // Kept whatever happened next: a lease a pass won stands, and the
        // next connection uses it instead of another pass.
        for inv in won {
            let _ = pocket.replace(inv);
        }
        let mut notes = Vec::new();
        // Written whatever happened: a pass taken was spent, or went back.
        if wallet.to_json() != wallet_before {
            if let Err(e) = crate::passes::save_wallet(&self.wallet_path(), &wallet) {
                notes.push(format!("could not write the pass wallet: {e:#}"));
            }
        }
        let built = match prepared {
            Ok(_) if cancel.is_set() => Err(anyhow!(circuit::CANCELLED)),
            Ok(p) => {
                notes.extend(p.notes);
                Circuit::up(p.spec, key.clone(), opts.clone()).await
            }
            Err(e) => Err(e),
        };
        if let Ok(c) = &built {
            crate::passes::mark_used_in(&mut pocket, &spec_passes(c.spec()));
        }
        if let Err(e) = save_pocket(&self.pocket_path, &pocket) {
            tracing::warn!("could not write the pocket: {e:#}");
        }
        built.map(|c| (c, notes)).map_err(|e| {
            // A first connection that failed leaves the machine as it found
            // it, open or blocked; a replacement leaves it held, and the
            // caller says so.
            if !had_old && !was_held {
                let _ = killswitch::remove();
            }
            Failed::Held(e)
        })
    }

    pub async fn down(&self) -> Result<&'static str> {
        self.down_for(Some(0)).await
    }

    /// `down`, for `caller`: whose circuit it is is checked under the same
    /// lock that takes it down, so another account's connect that got in
    /// between is never taken down by this one.
    async fn down_for(&self, caller: Option<u32>) -> Result<&'static str> {
        let mut guard = self.state.lock().await;
        if let Some(a) = guard.as_ref() {
            not_someone_elses(a, caller)?;
        }
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
        // "disconnected". Their use is written down after, with the state
        // free: the pocket's lock may be held a while by a fetch.
        let used = spec_passes(active.circuit.spec());
        let r = active.circuit.down().await;
        drop(guard);
        tracing::info!("disconnected");
        self.note_used(&used).await;
        r.map(|_| "disconnected")
    }

    /// The status with no circuit up: `hops` and `mode` say what is being
    /// built, if anything (0 and "" when nothing is).
    fn not_connected(hops: u8, mode: &str) -> Response {
        Response::with_status(StatusReport {
            connected: false,
            node_name: None,
            endpoint: None,
            last_handshake_secs: None,
            tx_bytes: 0,
            rx_bytes: 0,
            killswitch: killswitch::is_active(),
            hops,
            mode: mode.to_string(),
            entry_name: None,
            hops_detail: Vec::new(),
            same_operator: None,
            version: env!("CARGO_PKG_VERSION").to_string(),
            ipv6: false,
        })
    }

    async fn status(&self) -> Response {
        // While a circuit is being built the state lock is held for all of
        // it: the answer is that it is being built (the hops it will have,
        // not connected), at once, rather than after the nodes answer.
        let guard = match self.state.try_lock() {
            Ok(g) => g,
            Err(_) => {
                let building = self
                    .connecting
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .first()
                    .map(|(_, c)| (c.hops, c.mode));
                match building {
                    Some((hops, mode)) => return Self::not_connected(hops, mode),
                    None => self.state.lock().await,
                }
            }
        };
        match guard.as_ref() {
            None => Self::not_connected(0, ""),
            Some(a) => {
                let killswitch = killswitch::is_active();
                let s = a.circuit.status();
                let exit = s.exit();
                let same_operator = a.entries.get(a.current_entry).and_then(|entry| {
                    hidravpn_core::pocket::same_operator(entry, &a.pool[a.current])
                });
                let entry_country = a
                    .entries
                    .get(a.current_entry)
                    .and_then(|i| i.country.clone());
                let exit_country = a.pool.get(a.current).and_then(|i| i.country.clone());
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
                            country: match h.role {
                                Role::Entry => entry_country.clone(),
                                Role::Exit => exit_country.clone(),
                            },
                        })
                        .collect(),
                    same_operator,
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    ipv6: s.ipv6,
                })
            }
        }
    }

    /// Called when the service is stopping: leave nothing behind.
    /// Takes the circuit down for good: anything still waiting to connect
    /// is refused, so the machine is not left routed (and its kill switch
    /// armed) by a circuit built after the last `down`.
    pub async fn shutdown(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.stop_connecting(Some(0));
        let _ = self.down().await;
    }
}

/// Root, or the account that switched the circuit on: anyone else may not
/// switch it off, rotate it, or connect over it.
fn not_someone_elses(a: &Active, caller: Option<u32>) -> Result<()> {
    match a.owner {
        Some(owner) if caller != Some(0) && Some(owner) != caller => Err(anyhow!("{}", OWNED)),
        _ => Ok(()),
    }
}

/// The ones `ok` marks among `from`, when there are any, else all of them:
/// a node a circuit can be built with now is preferred, without ruling the
/// others out when none can.
fn preferring(from: Vec<usize>, ok: impl Fn(usize) -> bool) -> Vec<usize> {
    let preferred: Vec<usize> = from.iter().copied().filter(|&i| ok(i)).collect();
    if preferred.is_empty() {
        from
    } else {
        preferred
    }
}

/// A circuit's invites won with a pass.
fn spec_passes(spec: &CircuitSpec) -> Vec<Invite> {
    std::iter::once(&spec.exit)
        .chain(spec.entry.as_ref())
        .filter(|i| i.pass.is_some())
        .cloned()
        .collect()
}

/// A response with the notes, if there are any, joined into one.
fn noting_all(r: Response, notes: Vec<String>) -> Response {
    if notes.is_empty() {
        r
    } else {
        r.noting(notes.join("; "))
    }
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
pub fn plan_connect(pocket: &Pocket, mode: &str, allow_same_operator: bool) -> Result<Plan> {
    if pocket.is_empty() && pocket.known.is_empty() {
        return Err(anyhow!(
            "the pocket has no nodes; add some with `hidravpn nodes add --entry e.json` and `--exit x.json`, or import a signed node list with `hidravpn nodes import nodes.json`"
        ));
    }
    if pocket.is_empty() && pocket.joinable().is_empty() {
        return Err(anyhow!(
            "this machine knows {} node(s) from the node list but none admits openly, and no operator has admitted it by hand: for such a node, run `hidravpn pubkey --node <its key>`, send the result to its operator (`hidravpn nodes list` names them) and add the invite with `hidravpn nodes add`",
            pocket.known.len()
        ));
    }
    let pick = match mode.trim().to_ascii_lowercase().as_str() {
        "rapido" => pocket.pick_rapido()?,
        "privado" => pocket.pick_privado(allow_same_operator)?,
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
            country: inv.country.clone(),
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
                country: k.country.clone(),
            }
        }))
        .collect()
}

/// Why a circuit could not be built, and in what state that left the
/// machine.
enum Failed {
    /// Nothing was touched: the old circuit (if any) is still up, as it was.
    Untouched(anyhow::Error, Option<Box<Active>>),
    /// The old circuit (if any) is gone. If there was one, the kill switch
    /// holds the machine blocked; if there was none, the machine is back as
    /// it was before the attempt.
    Held(anyhow::Error),
}

/// The next pair for a new identity: another exit when one may be paired
/// with an entry (two operators, or the person's yes), else the same exit;
/// another entry when there is one that may go with that exit. Also the
/// exits passed over, each with why: one operator runs it and the entry, or
/// no entry can ask it for admission.
/// Among them, the nodes `usable` says a circuit can be built with now
/// (the flag: as the exit of two hops) are preferred.
fn choose_rotation(
    a: &Active,
    usable: impl Fn(&Invite, bool) -> bool,
) -> Result<(usize, usize, Vec<String>)> {
    if a.entries.is_empty() {
        let others = (0..a.pool.len()).filter(|&x| x != a.current).collect();
        let others = preferring(others, |x| usable(&a.pool[x], false));
        let next = match others.len() {
            0 => a.current,
            n => others[random::index(n)?],
        };
        return Ok((next, 0, Vec::new()));
    }
    let ok = |e: usize, x: usize| {
        !hidravpn_core::pocket::same_node(&a.entries[e], &a.pool[x])
            && hidravpn_core::pocket::entry_can_reach(&a.entries[e], &a.pool[x])
            && hidravpn_core::pocket::pair_allowed(&a.entries[e], &a.pool[x], a.allow_same_operator)
    };
    let mut skipped: Vec<String> = Vec::new();
    let mut other_exits = Vec::new();
    for x in (0..a.pool.len()).filter(|&x| x != a.current) {
        if (0..a.entries.len()).any(|e| ok(e, x)) {
            other_exits.push(x);
        } else if (0..a.entries.len())
            .any(|e| !hidravpn_core::pocket::same_node(&a.entries[e], &a.pool[x]))
        {
            // Said with the reason: no entry it could be paired with can
            // ask it for admission, or one operator runs it and the entry.
            let relayable = (0..a.entries.len()).any(|e| {
                !hidravpn_core::pocket::same_node(&a.entries[e], &a.pool[x])
                    && hidravpn_core::pocket::entry_can_reach(&a.entries[e], &a.pool[x])
            });
            let why = if relayable {
                "run by the entry's operator"
            } else {
                "the entry cannot ask it for admission"
            };
            skipped.push(format!("{} ({why})", a.pool[x].node_name));
        }
    }
    let other_exits = preferring(other_exits, |x| usable(&a.pool[x], true));
    let next = if other_exits.is_empty() {
        a.current
    } else {
        other_exits[random::index(other_exits.len())?]
    };
    let entries_ok: Vec<usize> = (0..a.entries.len()).filter(|&e| ok(e, next)).collect();
    let others: Vec<usize> = entries_ok
        .iter()
        .copied()
        .filter(|&e| e != a.current_entry)
        .collect();
    let others = preferring(others, |e| usable(&a.entries[e], false));
    let next_entry = if !others.is_empty() {
        others[random::index(others.len())?]
    } else if entries_ok.contains(&a.current_entry) {
        a.current_entry
    } else {
        return Err(anyhow!("{}", hidravpn_core::pocket::SAME_OPERATOR_REFUSAL));
    };
    Ok((next, next_entry, skipped))
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
            client_address6: None,
            dns: std::net::Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1420,
            keepalive: 25,
            operator: None,
            role: None,
            pass: None,
            country: None,
            admission: Some("open".into()),
            admission_port: None,
            behind: false,
            features: vec![
                hidravpn_core::directory::features::SESSIONS.into(),
                hidravpn_core::directory::features::ADMISSION_RELAY.into(),
            ],
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
        let plan = plan_connect(&p, "rapido", true).unwrap();
        assert!(plan.entry.is_none(), "one hop has no entry");
        assert_eq!(plan.alternates.len(), 2);
        assert!(plan.alternate_entries.is_empty());
        assert!(!plan
            .alternates
            .iter()
            .any(|a| a.node_name == plan.exit.node_name));
        // Case and spacing do not matter to the mode.
        assert!(plan_connect(&p, " Rapido ", true).is_ok());
    }

    #[test]
    fn privado_plans_an_entry_and_an_exit_that_are_different_nodes() {
        let p = pocket(&["e1", "e2"], &["x1", "x2"]);
        for _ in 0..50 {
            let plan = plan_connect(&p, "privado", true).unwrap();
            let entry = plan.entry.expect("two hops have an entry");
            assert_ne!(entry.node_public_key, plan.exit.node_public_key);
            assert_eq!(plan.alternates.len(), 1);
            assert_eq!(plan.alternate_entries.len(), 1);
        }
    }

    #[test]
    fn an_empty_pocket_and_an_unknown_mode_are_refused_with_a_way_forward() {
        let e = plan_connect(&Pocket::default(), "rapido", true)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("no nodes") && e.contains("hidravpn nodes add"),
            "{e}"
        );
        let e = plan_connect(&pocket(&[], &["x1"]), "fast", true)
            .unwrap_err()
            .to_string();
        assert!(e.contains("rapido") && e.contains("privado"), "{e}");
        let e = plan_connect(&pocket(&[], &["x1"]), "privado", true)
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
            country: None,
            features: Vec::new(),
        })
        .unwrap();
        let e = plan_connect(&p, "rapido", true).unwrap_err().to_string();
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
                allow_same_operator: false,
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

    #[tokio::test]
    async fn only_root_may_replace_the_pass_account_token_and_the_old_one_is_kept() {
        let dir = std::env::temp_dir().join(format!(
            "hidravpn-daemon-tok-{}-{}",
            std::process::id(),
            random::index(1 << 30).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let d = Daemon::with_pocket("tok".to_string(), dir.join("circuit.json"));
        let set = |t: &str| Request {
            token: "tok".into(),
            cmd: Command::SetPassToken {
                pass_token: crate::ipc::Secret(t.into()),
            },
        };
        let kept = dir.join("pass.token");
        std::fs::write(&kept, "the-paid-one").unwrap();
        for caller in [Some(1000), None] {
            let r = d.handle(set("someone-elses"), caller).await;
            assert!(!r.ok);
            assert!(
                r.error.as_deref().unwrap().contains("needs root"),
                "{:?}",
                r.error
            );
        }
        assert_eq!(std::fs::read_to_string(&kept).unwrap(), "the-paid-one");
        assert!(!dir.join("pass.token.previous").exists());
        // Root replaces it, and the one replaced is kept beside it.
        let r = d.handle(set("a-new-one"), Some(0)).await;
        assert!(r.ok, "{:?}", r.error);
        assert!(r.note.as_deref().unwrap().contains("pass.token.previous"));
        assert!(!serde_json::to_string(&r).unwrap().contains("a-new-one"));
        assert_eq!(std::fs::read_to_string(&kept).unwrap(), "a-new-one");
        assert_eq!(
            std::fs::read_to_string(dir.join("pass.token.previous")).unwrap(),
            "the-paid-one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_rotation_prefers_the_nodes_a_circuit_can_be_built_with() {
        assert_eq!(preferring(vec![1, 2], |i| i == 2), vec![2]);
        assert_eq!(
            preferring(vec![0, 2], |_| false),
            vec![0, 2],
            "nothing usable: any other one"
        );
        assert!(preferring(Vec::new(), |_| true).is_empty());
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
