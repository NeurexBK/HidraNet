//! HidraVPN client, command line: the whole machine, one hop or two.
//!
//!   hidravpn keygen                 make this machine's key, print the public half
//!   hidravpn up <exit.json>         connect, one hop (Rápido)
//!   hidravpn up <exit.json> --via <entry.json>
//!                                   connect, two hops (Privado): the entry sees who,
//!                                   the exit sees where, neither sees both
//!   hidravpn up ... --alternate <other-exit.json>
//!                                   more exits for `new-identity` to rotate to
//!   hidravpn new-identity           rebuild the circuit through the next exit
//!   hidravpn status                 mode, hops, nodes, kill switch
//!   hidravpn down                   disconnect, or restore the network after a crash
//!
//! `up` and `down` need administrator rights (a TUN interface, routes, DNS).
//! Nothing here records where the traffic went.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use hidravpn_core::killswitch;
use hidravpn_core::netcfg;
use hidravpn_core::{Circuit, CircuitOptions, CircuitSpec, ClientKey, Invite};
use hidravpn_service::ipc::{self, Command, StatusReport};

#[derive(Parser)]
#[command(
    name = "hidravpn",
    version,
    about = "HidraVPN client: one hop (Rápido) or two (Privado)"
)]
struct Cli {
    /// Where this machine's key is kept.
    #[arg(long, global = true)]
    key: Option<PathBuf>,
    /// Make the change in this process instead of asking the background
    /// service, even if the service is running (phase-1 behaviour).
    #[arg(long, global = true)]
    direct: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create this machine's key (if there is none) and print its public half.
    Keygen,
    /// Print this machine's public key.
    Pubkey,
    /// Connect and route the whole machine through the circuit.
    Up {
        /// The exit node's invite: the node that reaches the internet.
        invite: PathBuf,
        /// An entry node's invite: two hops (Privado). The entry sees this
        /// machine's address but not where the traffic goes; the exit sees
        /// the traffic but gets it from the entry.
        #[arg(long)]
        via: Option<PathBuf>,
        /// Another exit's invite that `new-identity` may rotate to. May be
        /// given more than once. Used by the service only.
        #[arg(long = "alternate")]
        alternates: Vec<PathBuf>,
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
    /// Rebuild the circuit through the next exit given with --alternate, so
    /// the address the internet sees changes. Needs the service.
    NewIdentity,
    /// Undo the routes and DNS of a connection that did not end cleanly.
    Down,
    /// Show the mode, the hops, the nodes and whether the kill switch is on.
    Status,
}

fn default_key_path() -> PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        PathBuf::from(base).join("HidraVPN").join("client.key")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/etc/hidravpn/client.key")
    }
}

fn load_or_create_key(path: &PathBuf, create: bool) -> Result<ClientKey> {
    match std::fs::read_to_string(path) {
        Ok(s) => ClientKey::from_base64(&s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
            let key = ClientKey::generate()?;
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("creating {}", dir.display()))?;
            }
            write_secret(path, key.secret_base64().as_bytes())?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow!(
            "no key at {} — run `hidravpn keygen` first",
            path.display()
        )),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// The secret is readable by this account only.
fn write_secret(path: &PathBuf, bytes: &[u8]) -> Result<()> {
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
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("hidravpn=info".parse()?),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let key_path = cli.key.clone().unwrap_or_else(default_key_path);

    match cli.cmd {
        Cmd::Keygen => {
            let existed = key_path.exists();
            let key = load_or_create_key(&key_path, true)?;
            if existed {
                eprintln!("a key already exists at {}; keeping it", key_path.display());
            } else {
                eprintln!("key written to {}", key_path.display());
            }
            println!("{}", key.public_base64());
            eprintln!("give this public key to the node's administrator (hidravpn-node admit)");
        }
        Cmd::Pubkey => {
            println!("{}", load_or_create_key(&key_path, false)?.public_base64());
        }
        Cmd::Up {
            invite,
            via,
            alternates,
            keep_ipv6,
            interface,
            no_kill_switch,
        } => {
            let exit = read_invite(&invite)?;
            let entry = via.as_deref().map(read_invite).transpose()?;
            let alternates = alternates
                .iter()
                .map(|p| read_invite(p))
                .collect::<Result<Vec<_>>>()?;
            let spec = CircuitSpec { exit, entry };
            spec.validate()?;
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
                },
            )
            .await
            {
                Some(res) => {
                    let r = res?;
                    if r.ok {
                        println!(
                            "connected through the HidraVPN service: {}",
                            r.status.map(describe).unwrap_or_default()
                        );
                    } else {
                        return Err(anyhow!(r
                            .error
                            .unwrap_or_else(|| "the service could not connect".into())));
                    }
                }
                None => {
                    require_admin()?;
                    if !alternates.is_empty() {
                        eprintln!("note: --alternate is used by the service's new-identity; in this process it does nothing");
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
                        println!("{}", describe(s));
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
                        describe(s.clone()),
                        if s.killswitch { "on" } else { "OFF" },
                        fmt_bytes(s.tx_bytes),
                        fmt_bytes(s.rx_bytes),
                        s.last_handshake_secs
                            .map(|n| format!("{n}s ago"))
                            .unwrap_or_else(|| "none".into()),
                    );
                } else if s.hops > 0 {
                    println!(
                        "connecting: {}; no session with every node yet; kill switch {}",
                        describe(s.clone()),
                        if s.killswitch { "on" } else { "OFF" }
                    );
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

fn read_invite(path: &std::path::Path) -> Result<Invite> {
    Invite::from_json(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
}

/// One line about a circuit: its mode, its hops and its nodes.
fn describe(s: StatusReport) -> String {
    let exit = s.node_name.as_deref().unwrap_or("?");
    let endpoint = s.endpoint.as_deref().unwrap_or("?");
    match (s.hops, s.entry_name.as_deref()) {
        (2, Some(entry)) => format!("privado, 2 hops: entry {entry} then exit {exit} ({endpoint})"),
        (1, _) => format!("rapido, 1 hop: {exit} ({endpoint})"),
        _ => format!("{} ({endpoint})", exit),
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
    let circuit = Circuit::up(spec, key, opts).await?;
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
    if circuit.kill_switch_armed() {
        eprintln!("kill switch on: nothing leaves outside the tunnel");
    }

    // Report until Ctrl+C, then put everything back.
    let mut was_connected = false;
    let mut waited = 0u32;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let outcome: Result<()> = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = tick.tick() => {
                let s = circuit.status();
                if s.connected && !was_connected {
                    was_connected = true;
                    eprintln!("connected");
                } else if !s.connected {
                    waited += 1;
                    if waited == 15 {
                        let pending: Vec<&str> = s.hops.iter().filter(|h| !h.tunnel.connected).map(|h| h.node_name.as_str()).collect();
                        eprintln!("no answer from {} after 15 s — is UDP {} open, and was this key admitted there?", pending.join(" and "), exit_port);
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
