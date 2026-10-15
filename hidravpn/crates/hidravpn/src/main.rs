//! HidraVPN client, command line: the whole machine, one hop or two.
//!
//!   hidravpn keygen                 make this machine's master key (once)
//!   hidravpn pubkey --node KEY      the key this machine presents to that node —
//!                                   the one its administrator admits
//!   hidravpn nodes add --entry e.json | --exit x.json
//!   hidravpn nodes list | remove NAME
//!                                   the pocket: nodes to pick from
//!   hidravpn up --privado           two hops from the pocket (an entry and an exit)
//!   hidravpn up --rapido            one hop from the pocket
//!   hidravpn up <exit.json>         connect, one hop (Rápido), this exit
//!   hidravpn up <exit.json> --via <entry.json>
//!                                   connect, two hops (Privado): the entry sees who,
//!                                   the exit sees where, neither sees both
//!   hidravpn up ... --alternate <other-exit.json> --alternate-entry <other-entry.json>
//!                                   more nodes for `new-identity` to rotate to
//!   hidravpn new-identity           rebuild the circuit through another exit (and
//!                                   another entry when there is one)
//!   hidravpn status                 mode, what it hides, hops, handshakes, kill switch
//!   hidravpn down                   disconnect, or restore the network after a crash
//!
//! Every node is shown a different key, derived from the one master key for
//! that node; the master key's public half reaches no node. `up`, `down` and
//! `nodes` need administrator rights. Nothing here records where the traffic
//! went.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use hidravpn_core::killswitch;
use hidravpn_core::netcfg;
use hidravpn_core::{
    Circuit, CircuitOptions, CircuitSpec, ClientKey, Invite, Pocket, ReleaseKey, Slot,
};
use hidravpn_service::ipc::{self, Command, StatusReport};
use hidravpn_service::paths;

#[derive(Parser)]
#[command(
    name = "hidravpn",
    version,
    about = "HidraVPN client: one hop (Rápido) or two (Privado)"
)]
struct Cli {
    /// Where this machine's master key is kept.
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    /// Where the pocket of nodes is kept.
    #[arg(long, global = true)]
    pocket: Option<PathBuf>,
    /// Make the change in this process instead of asking the background
    /// service, even if the service is running (phase-1 behaviour).
    #[arg(long, global = true)]
    direct: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create this machine's master key, if there is none. No node is ever
    /// shown it: the key to give a node comes from `pubkey --node`.
    Keygen,
    /// Print the key this machine presents to one node, derived from the
    /// master key and that node's public key. That is the key the node's
    /// administrator admits. Without --node, the master key's public half
    /// (which no node admits).
    Pubkey {
        /// The node's public key, as `hidravpn-node pubkey` prints it.
        #[arg(long, conflicts_with = "node_from_invite")]
        node: Option<String>,
        /// Read the node's public key from one of its invites.
        #[arg(long)]
        node_from_invite: Option<PathBuf>,
        /// The key this node is shown as the exit of two hops, reached
        /// through an entry: what to give an operator who admits by hand,
        /// for two hops. Never the one-hop key, so the exit cannot tie the
        /// traffic it carries to this machine's address.
        #[arg(long)]
        behind: bool,
    },
    /// The pocket: the entry and exit nodes `up --privado`, `up --rapido`
    /// and `new-identity` pick from.
    Nodes {
        #[command(subcommand)]
        what: Nodes,
    },
    /// Connect and route the whole machine through the circuit.
    Up {
        /// The exit node's invite: the node that reaches the internet.
        #[arg(required_unless_present_any = ["privado", "rapido"])]
        invite: Option<PathBuf>,
        /// An entry node's invite: two hops (Privado). The entry sees this
        /// machine's address but not where the traffic goes; the exit sees
        /// the traffic but gets it from the entry.
        #[arg(long)]
        via: Option<PathBuf>,
        /// Another exit's invite that `new-identity` may rotate to. May be
        /// given more than once. Used by the service only.
        #[arg(long = "alternate")]
        alternates: Vec<PathBuf>,
        /// Another entry's invite that `new-identity` may rotate to. May be
        /// given more than once; needs --via. Used by the service only.
        #[arg(long = "alternate-entry", requires = "via")]
        alternate_entries: Vec<PathBuf>,
        /// Two hops through nodes picked at random from the pocket: an
        /// entry and an exit, two different nodes.
        #[arg(long, conflicts_with_all = ["invite", "via", "alternates", "alternate_entries", "rapido"])]
        privado: bool,
        /// With --rapido: this exit from the pocket, by name, instead of one
        /// at random (what the uptime prober uses to try each node in turn).
        #[arg(long, requires = "rapido")]
        node: Option<String>,
        /// One hop through an exit picked at random from the pocket.
        #[arg(long, conflicts_with_all = ["invite", "via", "alternates", "alternate_entries"])]
        rapido: bool,
        /// Two hops whose entry and exit one operator runs (or whose
        /// operators are not named) are refused without this: one operator
        /// running both could see who you are and where you go.
        #[arg(long)]
        allow_same_operator: bool,
        /// Leave IPv6 alone instead of routing it into the tunnel (where it is
        /// dropped in this phase). Only for diagnosis: with this, IPv6 traffic
        /// bypasses the VPN.
        #[arg(long)]
        keep_ipv6: bool,
        /// Name of the outer (or only) tunnel interface; the inner one of a
        /// two-hop circuit takes the next number (hvpn0 → hvpn1).
        #[arg(long, default_value = "hvpn0")]
        interface: String,
        /// Do not arm the kill switch (diagnosis only: without it, traffic can
        /// leak to the open internet if the tunnel drops).
        #[arg(long)]
        no_kill_switch: bool,
    },
    /// Rebuild the circuit through another exit (and another entry, when
    /// the service holds more than one), so the address the internet sees
    /// changes. Needs the service.
    NewIdentity,
    /// Undo the routes and DNS of a connection that did not end cleanly.
    Down,
    /// Show the mode and what it hides, the hops and their handshakes, the
    /// nodes and whether the kill switch is on.
    Status,
}

#[derive(Subcommand)]
enum Nodes {
    /// Add a node's invite to the pocket, as an entry or as an exit.
    Add {
        /// An invite to use as an entry node (the first hop of Privado).
        #[arg(long, required_unless_present = "exit", conflicts_with = "exit")]
        entry: Option<PathBuf>,
        /// An invite to use as an exit node (the node that reaches the internet).
        #[arg(long)]
        exit: Option<PathBuf>,
        /// With --exit: the invite is for the key behind an entry (`pubkey
        /// --node K --behind`), so the node serves as the exit of two hops
        /// only.
        #[arg(long, requires = "exit")]
        behind: bool,
    },
    /// The nodes in the pocket: names and endpoints, never keys.
    List,
    /// Remove a node from the pocket by its name.
    Remove { name: String },
    /// Ask admission from known nodes whose operators admit openly: by name,
    /// or every one with --all. Each node is shown the key derived for it
    /// and its invite is checked against the list's record of it.
    Join {
        /// The node to ask; absent with --all.
        #[arg(required_unless_present = "all")]
        name: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Ask a node to describe itself (its record) by address, and with
    /// --trust write it down as known: for a node you know by other means
    /// than a signed list, such as your own. Nothing is trusted that this
    /// command did not print first.
    Discover {
        /// ip or ip:admission-port (the default admission port is 51821).
        address: String,
        /// Write the record down as a known node.
        #[arg(long)]
        trust: bool,
    },
    /// Put a signed node list into the pocket: the maintainers publish one so
    /// a new client has nodes to start with. Its signature is checked against
    /// the list key this build carries before anything is read from it.
    Import {
        /// The list as published (nodes.json).
        list: PathBuf,
        /// Its signature; LIST.sig beside it when not given.
        #[arg(long)]
        sig: Option<PathBuf>,
        /// A release public key given explicitly, base64. Only for a key that
        /// reached you by another channel than the list did; normally the one
        /// built into this client is used.
        #[arg(long)]
        pubkey: Option<String>,
    },
}

fn default_key_path() -> PathBuf {
    paths::client_key()
}

fn load_or_create_key(path: &Path, create: bool) -> Result<ClientKey> {
    match std::fs::read_to_string(path) {
        Ok(s) => ClientKey::from_base64(&s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
            let key = ClientKey::generate()?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            write_private(path, key.secret_base64().as_bytes())?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow!(
            "no key at {} — run `hidravpn keygen` first",
            path.display()
        )),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Readable by this account only.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?;
        std::io::Write::write_all(&mut f, bytes)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

/// Asks admission from the known nodes that admit openly — one by name, or
/// every one with `all` — and puts each invite into the pocket under the
/// slots its role allows. Prints a line per node; returns how many admitted.
/// The lease name sent is "client": nothing identifying leaves this machine.
async fn join_known(
    pocket: &mut hidravpn_core::Pocket,
    key_path: &Path,
    name: Option<&str>,
    all: bool,
) -> Result<usize> {
    let targets: Vec<hidravpn_core::NodeRecord> = pocket
        .joinable()
        .into_iter()
        .filter(|r| {
            all || name
                .map(|n| n.trim().eq_ignore_ascii_case(r.node_name.trim()))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    if targets.is_empty() {
        return Err(anyhow!(
            "no known node {} admits openly; `hidravpn nodes list` says whom to ask",
            name.map(|n| format!("named \"{n}\"")).unwrap_or_default()
        ));
    }
    let key = load_or_create_key(key_path, false)?;
    let mut joined = 0;
    for rec in targets {
        let shown = key.for_node_base64(&rec.node_public_key)?.public_base64();
        match hidravpn_core::admission::request_admission(&rec, &shown, "client", false).await {
            Ok(invite) => {
                for slot in hidravpn_core::pocket::slots_for_role(rec.role.as_deref()) {
                    let _ = pocket.add(slot, invite.clone());
                }
                joined += 1;
                println!(
                    "  + {}: admitted ({})",
                    rec.node_name,
                    rec.role.as_deref().unwrap_or("both")
                );
            }
            Err(e) => println!("  - {}: {e:#}", rec.node_name),
        }
    }
    Ok(joined)
}

fn load_pocket(path: &Path) -> Result<Pocket> {
    match std::fs::read_to_string(path) {
        Ok(s) => Pocket::from_json(&s).with_context(|| format!("reading {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Pocket::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

fn save_pocket(path: &Path, pocket: &Pocket) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    write_private(path, pocket.to_json().as_bytes())
}

fn require_admin() -> Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return Err(anyhow!("this needs root: run it with sudo"));
        }
    }
    Ok(())
}

fn fmt_bytes(n: u64) -> String {
    const K: f64 = 1024.0;
    let f = n as f64;
    if f < K {
        format!("{n} B")
    } else if f < K * K {
        format!("{:.1} KiB", f / K)
    } else if f < K * K * K {
        format!("{:.1} MiB", f / (K * K))
    } else {
        format!("{:.2} GiB", f / (K * K * K))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        // HidraVPN's own crates only, whatever RUST_LOG says.
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            hidravpn_core::logging::directives(
                std::env::var("RUST_LOG").ok().as_deref(),
                "hidravpn=info",
            ),
        ))
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let key_path = cli.key.clone().unwrap_or_else(default_key_path);
    let pocket_path = cli.pocket.clone().unwrap_or_else(paths::circuit_pocket);

    match cli.cmd {
        Cmd::Keygen => {
            let existed = key_path.exists();
            load_or_create_key(&key_path, true)?;
            if existed {
                eprintln!(
                    "a master key already exists at {}; keeping it",
                    key_path.display()
                );
            } else {
                eprintln!("master key written to {}", key_path.display());
            }
            eprintln!(
                "no node is shown this key. Each node gets its own, derived from it: for a node whose public key is KEY (its administrator gets it with `hidravpn-node pubkey`), run\n  hidravpn pubkey --node KEY\nand give the administrator the key it prints (hidravpn-node admit --pubkey ...)."
            );
        }
        Cmd::Pubkey {
            node,
            node_from_invite,
            behind,
        } => {
            let key = load_or_create_key(&key_path, false)?;
            let node = match (node, node_from_invite) {
                (Some(k), _) => Some(k),
                (None, Some(p)) => Some(read_invite(&p)?.node_public_key),
                (None, None) => None,
            };
            match node {
                Some(node) => {
                    let shown = if behind {
                        key.for_node_behind_base64(&node)
                    } else {
                        key.for_node_base64(&node)
                    };
                    println!(
                        "{}",
                        shown
                            .context("--node is not a valid node public key")?
                            .public_base64()
                    )
                }
                None => {
                    eprintln!("this is the master key's public half; no node admits it. For the key a node admits: hidravpn pubkey --node <that node's public key>");
                    println!("{}", key.public_base64());
                }
            }
        }
        Cmd::Nodes { what } => {
            require_admin()?;
            let mut pocket = load_pocket(&pocket_path)?;
            match what {
                Nodes::Add {
                    entry,
                    exit,
                    behind,
                } => {
                    let (slot, path) = match (entry, exit) {
                        (Some(p), _) => (Slot::Entry, p),
                        (None, Some(p)) => (Slot::Exit, p),
                        (None, None) => unreachable!("clap requires one of --entry and --exit"),
                    };
                    let mut invite = read_invite(&path)?;
                    invite.behind = behind;
                    let name = invite.node_name.clone();
                    pocket.add(slot, invite)?;
                    save_pocket(&pocket_path, &pocket)?;
                    println!(
                        "added {} as an {} ({} entries, {} exits in the pocket)",
                        name,
                        hidravpn_core::pocket::slot_name(slot),
                        pocket.entries.len(),
                        pocket.exits.len()
                    );
                }
                Nodes::List => {
                    if pocket.is_empty() && pocket.known.is_empty() {
                        println!("the pocket is empty: add nodes with `hidravpn nodes add --entry e.json` and `--exit x.json`, or import a signed node list with `hidravpn nodes import nodes.json`");
                    }
                    for (slot, inv) in pocket.iter() {
                        println!(
                            "{:<6} {:<24} {}{}{}",
                            hidravpn_core::pocket::slot_name(slot),
                            inv.node_name,
                            inv.endpoint,
                            inv.role
                                .as_deref()
                                .map(|r| format!("  {r}"))
                                .unwrap_or_default(),
                            inv.operator
                                .as_deref()
                                .map(|o| format!("  run by {o}"))
                                .unwrap_or_default()
                        );
                    }
                    for k in &pocket.known {
                        println!(
                            "known  {:<24} {}  {}{}{}{}",
                            k.node_name,
                            k.endpoint,
                            k.role.as_deref().unwrap_or("both"),
                            if k.is_open() {
                                "  admits openly"
                            } else {
                                "  admits by hand"
                            },
                            k.operator
                                .as_deref()
                                .map(|o| format!("  run by {o}"))
                                .unwrap_or_default(),
                            k.contact
                                .as_deref()
                                .map(|c| format!("  ask: {c}"))
                                .unwrap_or_default()
                        );
                    }
                    if pocket.known.iter().any(|k| k.is_open()) {
                        println!("known nodes that admit openly need no joining: each is asked for a key of its own on every connection.");
                    }
                    if pocket.known.iter().any(|k| !k.is_open()) {
                        println!("known nodes that admit by hand: run `hidravpn pubkey --node <its key>` (the key is in the list) and send the result to the operator; add the invite they return with `hidravpn nodes add --exit` (or --entry).");
                    }
                }
                Nodes::Remove { name } => {
                    let n = pocket.remove(&name);
                    if n == 0 {
                        return Err(anyhow!("no node named \"{name}\" in the pocket"));
                    }
                    save_pocket(&pocket_path, &pocket)?;
                    println!(
                        "removed {name} ({} entries, {} exits left)",
                        pocket.entries.len(),
                        pocket.exits.len()
                    );
                }
                Nodes::Join { name, all } => {
                    let joined = join_known(&mut pocket, &key_path, name.as_deref(), all).await?;
                    if joined > 0 {
                        save_pocket(&pocket_path, &pocket)?;
                    }
                    println!(
                        "joined {joined} node(s) ({} entries, {} exits, {} known in the pocket)",
                        pocket.entries.len(),
                        pocket.exits.len(),
                        pocket.known.len()
                    );
                }
                Nodes::Discover { address, trust } => {
                    let (ip, port) = match address.rsplit_once(':') {
                        Some((ip, port)) if !ip.contains(':') || ip.starts_with('[') => (
                            ip.trim_matches(|c| c == '[' || c == ']').to_string(),
                            port.parse::<u16>().context("the port is not a number")?,
                        ),
                        _ => (
                            address.clone(),
                            hidravpn_core::admission::DEFAULT_ADMISSION_PORT,
                        ),
                    };
                    let ip: std::net::IpAddr = ip.parse().context("not an ip address")?;
                    let rec = hidravpn_core::admission::fetch_record(ip, port).await?;
                    println!("{}", serde_json::to_string_pretty(&rec)?);
                    if trust {
                        match pocket.learn(rec.clone()) {
                            Ok(()) => {
                                save_pocket(&pocket_path, &pocket)?;
                                println!(
                                    "written down as known{}",
                                    if rec.is_open() {
                                        "; `hidravpn nodes join` admits this machine on it"
                                    } else {
                                        "; it admits by hand"
                                    }
                                );
                            }
                            Err(e) => println!("not written down: {e}"),
                        }
                    } else {
                        println!("(not written down; add --trust to know this node)");
                    }
                }
                Nodes::Import { list, sig, pubkey } => {
                    let bytes = std::fs::read(&list)
                        .with_context(|| format!("reading {}", list.display()))?;
                    let sig_path = sig.unwrap_or_else(|| {
                        let mut s = list.as_os_str().to_owned();
                        s.push(".sig");
                        PathBuf::from(s)
                    });
                    let signature = std::fs::read_to_string(&sig_path)
                        .with_context(|| format!("reading the signature {}", sig_path.display()))?;
                    let given = pubkey.as_deref().map(ReleaseKey::from_base64).transpose()?;
                    let key = given.or_else(ReleaseKey::embedded_list_key);
                    let merge = hidravpn_core::directory::import_signed(
                        &mut pocket,
                        &bytes,
                        &signature,
                        key.as_ref(),
                    )?;
                    save_pocket(&pocket_path, &pocket)?;
                    println!(
                        "{} ({} known, {} entries, {} exits in the pocket)",
                        merge.summary(),
                        pocket.known.len(),
                        pocket.entries.len(),
                        pocket.exits.len()
                    );
                    if !merge.added.is_empty() {
                        println!(
                            "known nodes are not admitted: `hidravpn nodes list` says how to ask."
                        );
                    }
                    for n in &merge.added {
                        println!("  + {n}");
                    }
                    for (n, what) in &merge.updated {
                        println!("  ~ {n}: {what}");
                    }
                    for (n, why) in &merge.skipped {
                        println!("  - {n}: {why}");
                    }
                }
            }
        }
        Cmd::Up {
            invite,
            via,
            alternates,
            alternate_entries,
            privado,
            rapido,
            node,
            keep_ipv6,
            interface,
            no_kill_switch,
            allow_same_operator,
        } => {
            let (spec, alternates, alternate_entries) = if privado || rapido {
                // A node that admits openly needs no joining first: it is
                // asked for a key for this connection as the circuit is
                // built, as the service does.
                let pocket = load_pocket(&pocket_path)?;
                if pocket.is_empty() && pocket.joinable().is_empty() {
                    return Err(anyhow!(if pocket.known.is_empty() {
                        format!(
                            "the pocket at {} is empty; add nodes with `hidravpn nodes add --entry e.json` and `--exit x.json`, or import a signed node list with `hidravpn nodes import nodes.json`",
                            pocket_path.display()
                        )
                    } else {
                        format!(
                            "this machine knows {} node(s) from the node list but none admits openly and none has admitted it by hand: `hidravpn nodes list` says whom to ask and how; add the invite they return with `hidravpn nodes add`",
                            pocket.known.len()
                        )
                    }));
                }
                let pick = if privado {
                    pocket.pick_privado(allow_same_operator)?
                } else if let Some(wanted) = node.as_deref() {
                    let (mut exits, _) = pocket.rapido_exits();
                    let i = exits
                        .iter()
                        .position(|x| x.node_name.trim().eq_ignore_ascii_case(wanted.trim()))
                        .ok_or_else(|| anyhow!("no exit named \"{wanted}\" in the pocket"))?;
                    let exit = exits.remove(i);
                    hidravpn_core::Pick {
                        exit,
                        entry: None,
                        other_exits: exits,
                        other_entries: Vec::new(),
                        same_operator: None,
                    }
                } else {
                    pocket.pick_rapido()?
                };
                (
                    CircuitSpec::new(pick.exit, pick.entry),
                    pick.other_exits,
                    pick.other_entries,
                )
            } else {
                let exit = read_invite(invite.as_deref().expect("clap requires the invite"))?;
                let entry = via.as_deref().map(read_invite).transpose()?;
                let alternates = alternates
                    .iter()
                    .map(|p| read_invite(p))
                    .collect::<Result<Vec<_>>>()?;
                let alternate_entries = alternate_entries
                    .iter()
                    .map(|p| read_invite(p))
                    .collect::<Result<Vec<_>>>()?;
                (CircuitSpec::new(exit, entry), alternates, alternate_entries)
            };
            spec.validate()?;
            if let Some(entry) = &spec.entry {
                if !hidravpn_core::pocket::pair_allowed(entry, &spec.exit, allow_same_operator) {
                    return Err(anyhow!("{}", hidravpn_core::pocket::SAME_OPERATOR_REFUSAL));
                }
            }
            // Prefer the installed service: it keeps the circuit after this
            // command returns. Only if it is not there do we hold it here.
            match service_call(
                cli.direct,
                Command::Up {
                    invite: spec.exit.clone(),
                    allow_lan: false,
                    keep_ipv6,
                    via: spec.entry.clone(),
                    alternates: alternates.clone(),
                    alternate_entries: alternate_entries.clone(),
                    allow_same_operator,
                },
            )
            .await
            {
                Some(res) => {
                    let r = res?;
                    if r.ok {
                        println!(
                            "connected through the HidraVPN service: {}",
                            r.status.as_ref().map(describe).unwrap_or_default()
                        );
                        if let Some(line) = r.status.as_ref().and_then(|s| s.explanation()) {
                            println!("  {line}");
                        }
                    } else {
                        return Err(anyhow!(r
                            .error
                            .unwrap_or_else(|| "the service could not connect".into())));
                    }
                }
                None => {
                    require_admin()?;
                    if !alternates.is_empty() || !alternate_entries.is_empty() {
                        eprintln!("note: other nodes to rotate to are used by the service's new-identity; in this process they do nothing");
                    }
                    let key = load_or_create_key(&key_path, false)?;
                    up(
                        spec,
                        key,
                        CircuitOptions {
                            route_ipv6: !keep_ipv6,
                            allow_lan: false,
                            kill_switch: !no_kill_switch,
                            interface_base: interface
                                .strip_suffix('0')
                                .unwrap_or(&interface)
                                .to_string(),
                        },
                    )
                    .await?;
                }
            }
        }
        Cmd::NewIdentity => match service_call(cli.direct, Command::NewIdentity).await {
            Some(res) => {
                let r = res?;
                if r.ok {
                    println!("{}", r.note.unwrap_or_else(|| "reconnected".into()));
                    if let Some(s) = r.status {
                        println!("{}", describe(&s));
                    }
                } else {
                    return Err(anyhow!(r
                        .error
                        .unwrap_or_else(|| "the service could not rotate".into())));
                }
            }
            None => {
                return Err(anyhow!(
                    "a new identity needs the HidraVPN service; without it, stop `hidravpn up` and run it again with another exit's invite"
                ));
            }
        },
        Cmd::Down => match service_call(cli.direct, Command::Down).await {
            Some(res) => {
                let r = res?;
                if r.ok {
                    println!("disconnected");
                } else {
                    return Err(anyhow!(r
                        .error
                        .unwrap_or_else(|| "the service could not disconnect".into())));
                }
            }
            None => {
                require_admin()?;
                let _ = killswitch::remove();
                match netcfg::load_plan()? {
                    None => println!("nothing to undo"),
                    Some(plan) => {
                        netcfg::revert(&plan)?;
                        println!("network restored");
                    }
                }
            }
        },
        Cmd::Status => match service_call(cli.direct, Command::Status).await {
            Some(res) => {
                let s = res?
                    .status
                    .ok_or_else(|| anyhow!("the service did not report a status"))?;
                if s.connected {
                    println!(
                        "connected: {}; kill switch {}; up {}, down {}; last handshake {}",
                        describe(&s),
                        if s.killswitch { "on" } else { "OFF" },
                        fmt_bytes(s.tx_bytes),
                        fmt_bytes(s.rx_bytes),
                        s.last_handshake_secs
                            .map(|n| format!("{n}s ago"))
                            .unwrap_or_else(|| "none".into()),
                    );
                    print_detail(&s);
                } else if s.hops > 0 {
                    println!(
                        "connecting: {}; no session with every node yet; kill switch {}",
                        describe(&s),
                        if s.killswitch { "on" } else { "OFF" }
                    );
                    print_detail(&s);
                } else {
                    println!(
                        "the service is running but not connected; kill switch {}",
                        if s.killswitch { "on" } else { "off" }
                    );
                }
            }
            None => {
                let ks = killswitch::is_active();
                let has_plan = netcfg::load_plan()?.is_some();
                if has_plan {
                    println!("a direct connection's network changes are in place (kill switch {}); run `hidravpn down` to undo", if ks { "on" } else { "off" });
                } else {
                    println!(
                        "not connected (no service, no tunnel); kill switch {}",
                        if ks { "on" } else { "off" }
                    );
                }
            }
        },
    }
    Ok(())
}

fn read_invite(path: &Path) -> Result<Invite> {
    Invite::from_json(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
}

/// One line about a circuit: its mode, its hops and its nodes.
fn describe(s: &StatusReport) -> String {
    let exit = s.node_name.as_deref().unwrap_or("?");
    let endpoint = s.endpoint.as_deref().unwrap_or("?");
    match (s.hops, s.entry_name.as_deref()) {
        (2, Some(entry)) => format!("privado, 2 hops: entry {entry} then exit {exit} ({endpoint})"),
        (1, _) => format!("rapido, 1 hop: {exit} ({endpoint})"),
        _ => format!("{} ({endpoint})", exit),
    }
}

/// After the status line: what the mode hides and what it does not, and
/// each hop's handshake age.
fn print_detail(s: &StatusReport) {
    if let Some(line) = s.explanation() {
        println!("  {line}");
    }
    for line in s.hop_lines() {
        println!("  {line}");
    }
}

/// Tries the background service. Returns None when it is not reachable (or when
/// `--direct` asked us to skip it), so the caller can act in this process
/// instead; Some(..) carries the service's answer to the command.
async fn service_call(direct: bool, cmd: Command) -> Option<Result<ipc::Response>> {
    if direct {
        return None;
    }
    // A cheap reachability probe first, so "service down" is told apart from
    // "command failed".
    match ipc::call(Command::Ping).await {
        Ok(r) if r.ok => Some(ipc::call(cmd).await),
        _ => None,
    }
}

/// Holds the circuit in this process until Ctrl+C, then puts the network back.
async fn up(spec: CircuitSpec, key: ClientKey, opts: CircuitOptions) -> Result<()> {
    if netcfg::load_plan()?.is_some() {
        eprintln!("undoing the network changes of a previous connection first");
    }
    let mode = spec.mode();
    let hops = spec.hops();
    let exit_port = spec.exit.endpoint_addr().map(|a| a.port()).unwrap_or(0);
    if !opts.kill_switch {
        eprintln!("kill switch OFF (--no-kill-switch): traffic can leak if the tunnel drops");
    }
    // Every node that admits openly is asked for a key for this connection:
    // the first hop directly, the exit of two hops through the entry.
    if let Some(first) = spec
        .entry
        .as_ref()
        .or(Some(&spec.exit))
        .filter(|n| n.admits_openly())
    {
        eprintln!("asking {} for a key for this connection", first.node_name);
    }
    if let (Some(entry), true) = (&spec.entry, spec.exit.admits_openly()) {
        eprintln!(
            "asking {} for a key for this connection, through {}",
            spec.exit.node_name, entry.node_name
        );
    }
    let _ = killswitch::remove();
    let built = async {
        let spec =
            hidravpn_core::circuit::prepare(&spec.exit, spec.entry.as_ref(), &key, &opts, &[])
                .await?;
        Circuit::up(spec, key, opts).await
    }
    .await;
    let circuit = match built {
        Ok(c) => c,
        Err(e) => {
            let _ = killswitch::remove();
            return Err(e);
        }
    };
    let st = circuit.status();
    for h in &st.hops {
        eprintln!(
            "tunnel interface {} up, {} to {} ({})",
            h.interface,
            match h.role {
                hidravpn_core::Role::Entry => "outer tunnel",
                hidravpn_core::Role::Exit => "tunnel",
            },
            h.node_name,
            h.endpoint
        );
    }
    eprintln!(
        "routes and DNS set: everything now goes through the {} ({} hop{})",
        mode.label(),
        hops,
        if hops == 1 { "" } else { "s" }
    );
    eprintln!(
        "  {}",
        match mode {
            hidravpn_core::Mode::Privado =>
                "privado: no node sees both who you are and where you go; the entry sees your address, the exit sees your traffic",
            hidravpn_core::Mode::Rapido =>
                "rapido: the node sees your address and your traffic; it hides them from your network, not from the node",
        }
    );
    if circuit.kill_switch_armed() {
        eprintln!("kill switch on: nothing leaves outside the tunnel");
    }

    // Report until Ctrl+C (or SIGTERM: a `kill`, a stopping service manager),
    // then put everything back. A tunnel process that died without restoring
    // the network would leave the kill switch armed and the machine offline.
    let mut was_connected = false;
    let mut waited = 0u32;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    #[cfg(unix)]
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("listening for SIGTERM")?;
    let outcome: Result<()> = loop {
        #[cfg(unix)]
        let terminated = term.recv();
        #[cfg(not(unix))]
        let terminated = std::future::pending::<Option<()>>();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = terminated => break Ok(()),
            _ = tick.tick() => {
                let s = circuit.status();
                if s.connected && !was_connected {
                    was_connected = true;
                    eprintln!("connected");
                } else if !s.connected {
                    waited += 1;
                    if waited == 15 {
                        let pending: Vec<&str> = s.hops.iter().filter(|h| !h.tunnel.connected).map(|h| h.node_name.as_str()).collect();
                        eprintln!("no answer from {} after 15 s — is UDP {} open, and was this machine's key for that node admitted there? (hidravpn pubkey --node ...; for the exit of two hops admitted by hand, ... --behind)", pending.join(" and "), exit_port);
                    }
                }
                if was_connected && waited.is_multiple_of(5) {
                    let exit = s.exit();
                    let hs = exit.tunnel.last_handshake.map(|d| format!("{}s ago", d.as_secs())).unwrap_or_else(|| "none".into());
                    eprint!("\r  {}  handshake {}  up {}  down {}      ", if s.connected { "connected   " } else { "reconnecting" }, hs, fmt_bytes(exit.tunnel.tx_bytes), fmt_bytes(exit.tunnel.rx_bytes));
                }
                if circuit.is_finished() { break Err(anyhow!("the tunnel stopped")); }
            }
        }
    };

    eprintln!("\ndisconnecting");
    circuit.down().await.context("restoring the network")?;
    eprintln!("network restored");
    outcome
}
