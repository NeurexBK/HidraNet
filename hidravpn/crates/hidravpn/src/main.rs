//! HidraVPN client, command line: the whole machine, one hop or two.
//!
//!   hidravpn keygen                 make this machine's master key (once)
//!   hidravpn pubkey --node KEY      the key this machine presents to that node —
//!                                   the one its administrator admits
//!   hidravpn nodes add --entry e.json | --exit x.json
//!   hidravpn nodes list | remove NAME
//!                                   the pocket: nodes to pick from
//!   hidravpn nodes import LIST      the signed node list: nodes to start with
//!   hidravpn nodes join NAME | --all
//!                                   admission on nodes that admit openly
//!   hidravpn nodes discover ADDR    a node's own record, by address
//!   hidravpn passes token | get | list | auto
//!                                   passes for nodes that admit with one
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
//! that node; the master key's public half reaches no node. `up` with an
//! invite, `down` without the service, `nodes` and `passes` need
//! administrator rights; a member of the hidravpn group may `up --rapido` or
//! `--privado` and `down` through the service. Nothing here records where the traffic
//! went.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use hidravpn_core::killswitch;
use hidravpn_core::netcfg;
use hidravpn_core::{Circuit, CircuitOptions, CircuitSpec, ClientKey, Invite, ReleaseKey, Slot};
use hidravpn_service::ipc::{self, Command, StatusReport};
use hidravpn_service::paths;
// The pocket is read and written as the service does: root only, and
// atomically, so neither ever reads half a file the other wrote.
use hidravpn_service::daemon::{load_pocket, save_pocket};

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
    /// Passes (phase 5): one connection's worth of admission on a node
    /// that admits with one, signed blind by the issuer the node list names.
    Passes {
        #[command(subcommand)]
        what: Passes,
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
        /// Leave IPv6 out of the tunnel's routes (it goes through the exit when
        /// the exit carries IPv6, and is blocked otherwise). Only for
        /// diagnosis: the kill switch then blocks it; without the kill switch
        /// IPv6 traffic bypasses the VPN.
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

#[derive(Subcommand)]
enum Passes {
    /// Keep the account token passes are asked for with, root only. From a
    /// file, or `-` for standard input.
    Token { file: PathBuf },
    /// Ask the issuer for passes: COUNT for each node that admits with a
    /// pass, or for the one named. The issuer never learns which node a pass
    /// is for.
    Get {
        #[arg(long, default_value_t = 10)]
        count: usize,
        #[arg(long)]
        node: Option<String>,
        /// The token, from this file instead of the one kept.
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// How many passes the wallet holds, per node.
    List,
    /// Let the service top the wallet up by itself, only while connected
    /// (through the tunnel): `on`, `off`, or nothing to see how it is set.
    Auto {
        #[arg(value_parser = ["on", "off"])]
        state: Option<String>,
        /// Top up a node with fewer passes than this (default 3).
        #[arg(long)]
        low: Option<usize>,
        /// ...back to this many (default 10, at most 100).
        #[arg(long)]
        count: Option<usize>,
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
            hidravpn_service::daemon::write_private_atomic(path, key.secret_base64().as_bytes())?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow!(
            "no key at {} — run `hidravpn keygen` first",
            path.display()
        )),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Asks admission from the known nodes that admit openly — one by name, or
/// every one with `all` — and puts each invite into the pocket under the
/// slots its role allows. Prints a line per node; returns how many admitted.
/// The lease name sent is "client": nothing identifying leaves this machine.
async fn join_known(
    pocket: &mut hidravpn_core::Pocket,
    pocket_path: &Path,
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
            "no known node {} admits openly or with a pass; `hidravpn nodes list` says whom to ask",
            name.map(|n| format!("named \"{n}\"")).unwrap_or_default()
        ));
    }
    let key = load_or_create_key(key_path, false)?;
    let mut joined = 0;
    let wallet_path = wallet_beside(pocket_path);
    let mut wallet = hidravpn_service::passes::load_wallet(&wallet_path)?;
    let wallet_before = wallet.passes.len();
    for rec in targets {
        if rec.takes_passes() {
            match hidravpn_service::passes::redeem_into(pocket, &mut wallet, &rec).await {
                Ok(_) => {
                    joined += 1;
                    println!(
                        "  + {}: admitted with a pass ({})",
                        rec.node_name,
                        rec.role.as_deref().unwrap_or("both")
                    );
                }
                Err(e) => println!("  - {}: {e:#}", rec.node_name),
            }
            continue;
        }
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
    if wallet.passes.len() != wallet_before {
        // The invites a pass won first: were the pocket lost after the
        // wallet was written, the pass would be gone and its invite too.
        save_pocket(pocket_path, pocket)?;
        hidravpn_service::passes::save_wallet(&wallet_path, &wallet)?;
    }
    Ok(joined)
}

/// The wallet and the token sit beside the pocket.
fn wallet_beside(pocket_path: &Path) -> PathBuf {
    pocket_path.with_file_name("passes.json")
}

fn token_beside(pocket_path: &Path) -> PathBuf {
    pocket_path.with_file_name("pass.token")
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
        Cmd::Passes { what } => {
            require_admin()?;
            // The service keeps passes in the same wallet: one writer at a time.
            let _file = hidravpn_service::passes::lock_beside(&pocket_path).await?;
            let wallet_path = wallet_beside(&pocket_path);
            match what {
                Passes::Token { file } => {
                    let text = if file.as_os_str() == "-" {
                        let mut t = String::new();
                        std::io::Read::read_to_string(&mut std::io::stdin(), &mut t)?;
                        t
                    } else {
                        std::fs::read_to_string(&file)
                            .with_context(|| format!("reading {}", file.display()))?
                    };
                    let token = hidravpn_service::passes::parse_token(&text)?;
                    let dest = token_beside(&pocket_path);
                    hidravpn_service::daemon::write_private_atomic(&dest, token.as_bytes())?;
                    println!("account token kept at {} (root only)", dest.display());
                }
                Passes::Get {
                    count,
                    node,
                    token_file,
                } => {
                    let pocket = load_pocket(&pocket_path)?;
                    let token = hidravpn_service::passes::read_token(
                        &token_file.unwrap_or_else(|| token_beside(&pocket_path)),
                    )?;
                    let mut wallet = hidravpn_service::passes::load_wallet(&wallet_path)?;
                    let line = hidravpn_service::passes::get_passes(
                        &pocket,
                        &mut wallet,
                        &token,
                        node.as_deref(),
                        count,
                    )
                    .await?;
                    hidravpn_service::passes::save_wallet(&wallet_path, &wallet)?;
                    println!("{line}");
                }
                Passes::List => {
                    let pocket = load_pocket(&pocket_path)?;
                    let wallet = hidravpn_service::passes::load_wallet(&wallet_path)?;
                    let nodes = hidravpn_service::passes::pass_nodes(&pocket);
                    for (name, key) in &nodes {
                        println!("{:<24} {} pass(es)", name, wallet.count_for(key));
                    }
                    if nodes.is_empty() {
                        println!("no node in the pocket admits with a pass");
                    }
                    match &pocket.pass_issuer {
                        Some(i) => println!("issuer: {} ({} key(s))", i.url, i.keys.len()),
                        None => println!("the node list names no pass issuer"),
                    }
                    println!(
                        "{}",
                        hidravpn_service::passes::load_refill(&pocket_path).describe()
                    );
                }
                Passes::Auto { state, low, count } => {
                    let mut r = hidravpn_service::passes::load_refill(&pocket_path);
                    if r.apply(state.as_deref().map(|s| s == "on"), low, count)? {
                        hidravpn_service::passes::save_refill(&pocket_path, &r)?;
                    }
                    println!("{}", r.describe());
                }
            }
        }
        Cmd::Nodes { what } => {
            require_admin()?;
            let _file = hidravpn_service::passes::lock_beside(&pocket_path).await?;
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
                            } else if k.takes_passes() {
                                "  admits with a pass"
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
                    if pocket.known.iter().any(|k| k.takes_passes()) {
                        println!("known nodes that admit with a pass: `sudo hidravpn passes get` asks the list's issuer for passes, then `sudo hidravpn nodes join --all`.");
                    }
                    if pocket
                        .known
                        .iter()
                        .any(|k| !k.is_open() && !k.takes_passes())
                    {
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
                    let joined =
                        join_known(&mut pocket, &pocket_path, &key_path, name.as_deref(), all)
                            .await?;
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
            // From the pocket the service reads, with no node named: the
            // service picks, as it does for the browser — which also lets a
            // member of the hidravpn group connect, and keeps the passes it
            // spends and the invites they win in the service's own hands.
            if (privado || rapido) && node.is_none() && pocket_path == paths::circuit_pocket() {
                let mode = if privado { "privado" } else { "rapido" };
                if let Some(res) = service_call(
                    cli.direct,
                    Command::Connect {
                        mode: mode.into(),
                        allow_lan: false,
                        keep_ipv6,
                        allow_same_operator,
                    },
                )
                .await
                {
                    let r = res?;
                    if !r.ok {
                        return Err(anyhow!(r
                            .error
                            .unwrap_or_else(|| "the service could not connect".into())));
                    }
                    if let Some(note) = &r.note {
                        println!("{note}");
                    }
                    println!(
                        "connected through the HidraVPN service: {}",
                        r.status.as_ref().map(describe).unwrap_or_default()
                    );
                    if let Some(line) = r.status.as_ref().and_then(|s| s.explanation()) {
                        println!("  {line}");
                    }
                    return Ok(());
                }
            }
            let (spec, alternates, alternate_entries) = if privado || rapido {
                // A node that admits openly or with a pass needs no joining
                // first: it is asked for a key for this connection as the
                // circuit is built, as the service does.
                let pocket = load_pocket(&pocket_path)?;
                if pocket.is_empty() && pocket.joinable().is_empty() {
                    return Err(anyhow!(if pocket.known.is_empty() {
                        format!(
                            "the pocket at {} is empty; add nodes with `hidravpn nodes add --entry e.json` and `--exit x.json`, or import a signed node list with `hidravpn nodes import nodes.json`",
                            pocket_path.display()
                        )
                    } else {
                        format!(
                            "this machine knows {} node(s) from the node list but none admits openly or with a pass, and none has admitted it by hand: `hidravpn nodes list` says whom to ask and how; add the invite they return with `hidravpn nodes add`",
                            pocket.known.len()
                        )
                    }));
                }
                // A node that takes passes, with none left for it, is not
                // picked while another will do.
                let wallet_now =
                    hidravpn_service::passes::load_wallet(&wallet_beside(&pocket_path))?;
                let live = hidravpn_service::passes::without_dead(
                    &pocket,
                    &wallet_now,
                    if privado { "privado" } else { "rapido" },
                    allow_same_operator,
                );
                let pick = if privado {
                    live.pick_privado(allow_same_operator)?
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
                    live.pick_rapido()?
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
            spec.validate_plan()?;
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
                        &pocket_path,
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
                    None => {
                        netcfg::recover_dns();
                        println!("nothing to undo")
                    }
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
                        "connected: {}; kill switch {}; up {}, down {}; last handshake {}; IPv6 {}",
                        describe(&s),
                        if s.killswitch { "on" } else { "OFF" },
                        fmt_bytes(s.tx_bytes),
                        fmt_bytes(s.rx_bytes),
                        s.last_handshake_secs
                            .map(|n| format!("{n}s ago"))
                            .unwrap_or_else(|| "none".into()),
                        if s.ipv6 {
                            "through the tunnel"
                        } else {
                            "blocked"
                        },
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
        // Only with no service at all does this process act on the network
        // itself. A service that is there but does not answer, answers
        // badly, or is not the service (an impostor) may hold the network:
        // say so, and never go around it, which would undo its kill switch.
        Err(e) if e.is::<ipc::NotRunning>() => None,
        Err(e) => Some(Err(e)),
        Ok(r) => Some(Err(anyhow!(
            "the HidraVPN service refused: {}",
            r.error.unwrap_or_else(|| "no reason given".into())
        ))),
    }
}

/// Holds the circuit in this process until Ctrl+C, then puts the network back.
async fn up(
    spec: CircuitSpec,
    key: ClientKey,
    opts: CircuitOptions,
    pocket_path: &Path,
) -> Result<()> {
    if netcfg::load_plan()?.is_some() {
        eprintln!("undoing the network changes of a previous connection first");
    }
    let mode = spec.mode();
    let hops = spec.hops();
    let exit_port = spec.exit.endpoint_addr().map(|a| a.port()).unwrap_or(0);
    if !opts.kill_switch {
        eprintln!("kill switch OFF (--no-kill-switch): traffic can leak if the tunnel drops");
    }
    // Every node that admits openly or with a pass is asked for a key for
    // this connection: the first hop directly, the exit of two hops through
    // the entry.
    let asks = |n: &Invite| n.admits_openly() || n.takes_passes();
    if let Some(first) = spec.entry.as_ref().or(Some(&spec.exit)).filter(|n| asks(n)) {
        eprintln!("asking {} for a key for this connection", first.node_name);
    }
    if let (Some(entry), true) = (&spec.entry, asks(&spec.exit)) {
        eprintln!(
            "asking {} for a key for this connection, through {}",
            spec.exit.node_name, entry.node_name
        );
    }
    let _ = killswitch::remove();
    let built = async {
        // The pocket and the wallet are held while passes are taken from
        // the one and the invites they win go into the other.
        let _file = hidravpn_service::passes::lock_beside(pocket_path).await?;
        let wallet_path = wallet_beside(pocket_path);
        let mut wallet = hidravpn_service::passes::load_wallet(&wallet_path)?;
        let before = wallet.to_json();
        let mut won = Vec::new();
        let prepared = hidravpn_core::circuit::prepare(
            &spec.exit,
            spec.entry.as_ref(),
            &key,
            &opts,
            &[],
            &mut wallet,
            &mut won,
            &hidravpn_core::circuit::Cancel::never(),
        )
        .await;
        if wallet.to_json() != before {
            hidravpn_service::passes::save_wallet(&wallet_path, &wallet)?;
        }
        // Kept whatever happened next: a lease a pass won stands, and the
        // next connection uses it instead of another pass.
        if !won.is_empty() {
            let mut pocket = load_pocket(pocket_path)?;
            for inv in won {
                let _ = pocket.replace(inv);
            }
            save_pocket(pocket_path, &pocket)?;
        }
        let prepared = prepared?;
        for note in &prepared.notes {
            eprintln!("note: {note}");
        }
        drop(_file);
        Circuit::up(prepared.spec, key, opts).await
    }
    .await;
    let circuit = match built {
        Ok(c) => c,
        Err(e) => {
            let _ = killswitch::remove();
            return Err(e);
        }
    };
    // Invites won with a pass that this circuit uses: their use is written
    // down when it goes up and when it comes down, which is what tells later
    // picks the node still holds the lease.
    let pass_keys: Vec<String> = {
        let spec = circuit.spec();
        std::iter::once(&spec.exit)
            .chain(spec.entry.as_ref())
            .filter(|i| i.pass.is_some())
            .map(|i| i.node_public_key.clone())
            .collect()
    };
    if !pass_keys.is_empty() {
        let _ = hidravpn_service::passes::mark_used(pocket_path, &pass_keys).await;
    }
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
    if !pass_keys.is_empty() {
        let _ = hidravpn_service::passes::mark_used(pocket_path, &pass_keys).await;
    }
    circuit.down().await.context("restoring the network")?;
    eprintln!("network restored");
    outcome
}
