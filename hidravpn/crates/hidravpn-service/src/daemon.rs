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
    circuit, random, Circuit, CircuitOptions, CircuitSpec, ClientKey, Invite, Merge, Pocket,
    ReleaseKey, Role,
};
use tokio::sync::Mutex;

use crate::ipc::{Command, HopReport, NodeReport, Request, Response, StatusReport};
use crate::paths;

struct Active {
    /// The account that switched the circuit on (a uid; None on Windows or
    /// for root), so another account cannot switch it off.
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
                    Ok(()) => self.status().await,
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
                    Ok(()) => self.status().await,
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::Join { name } => match self.join(name.as_deref()).await {
                Ok((pocket, outcome)) => Response::with_nodes(node_reports(&pocket)).noting(outcome),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::Nodes => match load_pocket(&self.pocket_path) {
                Ok(p) => Response::with_nodes(node_reports(&p)),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::ImportNodes { list, signature } => {
                match self.import_nodes(&list, &signature).await {
                    Ok((pocket, merge)) => {
                        Response::with_nodes(node_reports(&pocket)).noting(merge.summary())
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
                CircuitSpec::new(exit.clone(), None).validate()?;
            }
            for entry in &entries {
                if hidravpn_core::pocket::same_node(entry, exit) {
                    continue;
                }
                CircuitSpec::new(exit.clone(), Some(entry.clone())).validate()?;
            }
        }
        if let Some(entry) = entries.first() {
            CircuitSpec::new(pool[0].clone(), Some(entry.clone())).validate()?;
            if !hidravpn_core::pocket::pair_allowed(entry, &pool[0], allow_same_operator) {
                return Err(anyhow!("{}", hidravpn_core::pocket::SAME_OPERATOR_REFUSAL));
            }
        }

        let mut guard = self.state.lock().await;
        let old = guard.take();
        let had_old = old.is_some();
        let circuit = match build(old, &pool[0], entries.first(), &opts).await {
            Ok(c) => c,
            Err(Failed::Untouched(e, old)) => {
                *guard = old.map(|b| *b);
                return Err(e);
            }
            Err(Failed::Held(e)) if had_old => return Err(e.context(HELD)),
            Err(Failed::Held(e)) => return Err(e),
        };
        *guard = Some(Active {
            owner: caller.filter(|&u| u != 0),
            circuit,
            entries,
            current_entry: 0,
            pool,
            current: 0,
            opts,
            allow_same_operator,
        });
        tracing::info!("connected");
        Ok(())
    }

    /// Connects through nodes picked from the pocket: one exit for Rápido, an
    /// entry and an exit for Privado, each at random, the rest kept for
    /// `new_identity` to rotate to. The caller never sees an invite. A node
    /// that admits openly needs no joining first: it is asked for a key for
    /// this connection as the circuit is built (`circuit::prepare`), which is
    /// how a machine that only imported the list connects at all.
    async fn connect_from_pocket(
        &self,
        mode: &str,
        opts: CircuitOptions,
        caller: Option<u32>,
        allow_same_operator: bool,
    ) -> Result<()> {
        let pocket = load_pocket(&self.pocket_path)?;
        let plan = plan_connect(&pocket, mode, allow_same_operator)?;
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
                Some(n) => format!("no known node named \"{n}\" admits openly; `nodes list` says whom to ask"),
                None => "no known node admits openly; import a node list, or ask an operator for an invite".to_string(),
            }));
        }
        let key = load_key()?;
        // The name a node files the lease under is a label for its operator,
        // not this machine's name: nothing identifying leaves here.
        let host = "client".to_string();
        let mut lines = Vec::new();
        let mut joined = 0;
        for rec in targets {
            let shown = key.for_node_base64(&rec.node_public_key)?.public_base64();
            match hidravpn_core::admission::request_admission(&rec, &shown, &host, false).await {
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
            tracing::info!(joined, "joined node(s) through open admission");
        }
        Ok((pocket, lines.join("; ")))
    }

    /// Checks a signed node list against the embedded release key, and only
    /// then puts its nodes into the pocket and writes the pocket back. The
    /// pocket on disk is untouched by a list that is refused.
    async fn import_nodes(&self, list: &str, signature: &str) -> Result<(Pocket, Merge)> {
        let _one_at_a_time = self.pocket_lock.lock().await;
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
    async fn new_identity(&self) -> Result<String> {
        let mut guard = self.state.lock().await;
        let active = guard
            .take()
            .ok_or_else(|| anyhow!("not connected; nothing to rotate"))?;
        let (next, next_entry, skipped) = match choose_rotation(&active) {
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
        match build(Some(active), &exit, entry.as_ref(), &opts).await {
            Ok(circuit) => {
                let fresh = exit.admits_openly() && entry.is_some();
                let exit_note = if next == current {
                    let why = if skipped.is_empty() {
                        "only one exit node is configured".to_string()
                    } else {
                        format!(
                            "no other exit is run by a different operator than the entry ({} not used)",
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
                        n.push_str(&format!(
                            "; not {}: run by the entry's operator",
                            skipped.join(", ")
                        ));
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
                Ok(format!("{exit_note}{entry_note}"))
            }
            Err(Failed::Untouched(e, old)) => {
                *guard = old.map(|b| *b);
                Err(e)
            }
            // Nothing is up, and the hold still blocks the machine: say so
            // rather than pretend a circuit is up, or that it is open.
            Err(Failed::Held(e)) => Err(e.context(format!(
                "the new circuit could not be built; disconnected, and {HELD}"
            ))),
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
                version: env!("CARGO_PKG_VERSION").to_string(),
            }),
            Some(a) => {
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
                })
            }
        }
    }

    /// Called when the service is stopping: leave nothing behind.
    pub async fn shutdown(&self) {
        let _ = self.down().await;
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
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let bytes = pocket.to_json();
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
        f.write_all(bytes.as_bytes())?;
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
    pocket
        .iter()
        .map(|(slot, inv)| NodeReport {
            slot: hidravpn_core::pocket::slot_name(slot).to_string(),
            node_name: inv.node_name.clone(),
            endpoint: inv.endpoint.clone(),
            admitted: true,
            operator: inv.operator.clone(),
            role: inv.role.clone(),
            admission: None,
            country: inv.country.clone(),
        })
        .chain(pocket.known.iter().map(|k| NodeReport {
            slot: "known".to_string(),
            node_name: k.node_name.clone(),
            endpoint: k.endpoint.clone(),
            admitted: false,
            operator: k.operator.clone(),
            role: k.role.clone(),
            admission: k.admission.clone(),
            country: k.country.clone(),
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

/// Builds a circuit through `exit` (and `entry`), replacing `old`, with the
/// service's key. The kill switch is held from the moment `old` starts to
/// come down until the new circuit's own rules replace the hold, so there is
/// no moment on the open network. An exit of two hops that admits openly is
/// first asked, through the entry, to admit a fresh key (`admit_behind`).
async fn build(
    old: Option<Active>,
    exit: &Invite,
    entry: Option<&Invite>,
    opts: &CircuitOptions,
) -> std::result::Result<Circuit, Failed> {
    let key = match load_key() {
        Ok(k) => k,
        Err(e) => return Err(Failed::Untouched(e, old.map(Box::new))),
    };
    let first_hop = match entry.unwrap_or(exit).endpoint_addr() {
        Ok(a) => a,
        Err(e) => return Err(Failed::Untouched(e, old.map(Box::new))),
    };
    let old_first_hop: Vec<std::net::SocketAddr> = old
        .as_ref()
        .and_then(|o| o.circuit.spec().first_hop_endpoint().ok())
        .into_iter()
        .collect();
    let had_old = old.is_some();
    // A kill switch a crashed run left behind is undone first — unless a
    // circuit is being replaced, when it is held instead: from here on, only
    // the old and the new first hop may be reached.
    let mut held = Vec::new();
    if let Some(o) = old {
        held.push(first_hop);
        held.extend(old_first_hop.iter().copied().filter(|a| *a != first_hop));
        if let Err(e) = killswitch::hold(&held) {
            return Err(Failed::Untouched(
                e.context("could not hold the kill switch across the change; staying on the current circuit"),
                Some(Box::new(o)),
            ));
        }
        let _ = o.circuit.down_with(false).await;
    } else {
        let _ = killswitch::remove();
    }
    let built = async {
        let spec = circuit::prepare(exit, entry, &key, opts, &held).await?;
        Circuit::up(spec, key.clone(), opts.clone()).await
    }
    .await;
    built.map_err(|e| {
        // A first connection that failed leaves the machine as it found it;
        // a replacement leaves it held, and the caller says so.
        if !had_old {
            let _ = killswitch::remove();
        }
        Failed::Held(e)
    })
}

/// The next pair for a new identity: another exit when one may be paired
/// with an entry (two operators, or the person's yes), else the same exit;
/// another entry when there is one that may go with that exit. Also the
/// names of exits passed over because one operator runs them and the entry.
fn choose_rotation(a: &Active) -> Result<(usize, usize, Vec<String>)> {
    if a.entries.is_empty() {
        let next = random::index_other_than(a.pool.len(), a.current)?.unwrap_or(a.current);
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
            skipped.push(a.pool[x].node_name.clone());
        }
    }
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
