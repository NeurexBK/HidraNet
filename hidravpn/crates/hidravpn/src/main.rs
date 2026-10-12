//! HidraVPN client, command line. Phase 1: one hop, the whole machine.
//!
//!   hidravpn keygen                 make this machine's key, print the public half
//!   hidravpn up <invite.json>       connect; Ctrl+C disconnects and restores the network
//!   hidravpn down                   restore the network after a crash or a kill
//!
//! `up` and `down` need administrator rights (a TUN interface, routes, DNS).
//! Nothing here records where the traffic went.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use hidravpn_core::killswitch::{self, KillConfig};
use hidravpn_core::netcfg::{self, Wanted};
use hidravpn_core::{ClientConfig, ClientKey, Invite, Tunnel};
use hidravpn_service::ipc::{self, Command};
use hidravpn_tun::TunConfig;

#[derive(Parser)]
#[command(
    name = "hidravpn",
    version,
    about = "HidraVPN client (phase 1: single hop)"
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
    /// Connect to the node in the invite and route the whole machine through it.
    Up {
        /// The invite the node printed when it admitted this machine's key.
        invite: PathBuf,
        /// Leave IPv6 alone instead of routing it into the tunnel (where it is
        /// dropped in this phase). Only for diagnosis: with this, IPv6 traffic
        /// bypasses the VPN.
        #[arg(long)]
        keep_ipv6: bool,
        /// Interface name.
        #[arg(long, default_value = "hvpn0")]
        interface: String,
        /// Do not arm the kill switch (diagnosis only: without it, traffic can
        /// leak to the open internet if the tunnel drops).
        #[arg(long)]
        no_kill_switch: bool,
    },
    /// Undo the routes and DNS of a connection that did not end cleanly.
    Down,
    /// Show whether a tunnel is up and whether the kill switch is on.
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
            keep_ipv6,
            interface,
            no_kill_switch,
        } => {
            let inv = Invite::from_json(
                &std::fs::read_to_string(&invite)
                    .with_context(|| format!("reading {}", invite.display()))?,
            )?;
            // Prefer the installed service: it keeps the tunnel after this
            // command returns. Only if it is not there do we hold it here.
            match service_call(
                cli.direct,
                Command::Up {
                    invite: inv.clone(),
                    allow_lan: false,
                    keep_ipv6,
                },
            )
            .await
            {
                Some(res) => {
                    let r = res?;
                    if r.ok {
                        println!("connected through the HidraVPN service");
                    } else {
                        return Err(anyhow!(r
                            .error
                            .unwrap_or_else(|| "the service could not connect".into())));
                    }
                }
                None => {
                    require_admin()?;
                    let key = load_or_create_key(&key_path, false)?;
                    up(inv, key, interface, !keep_ipv6, !no_kill_switch).await?;
                }
            }
        }
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
                            "connected through {} ({}); kill switch {}; up {}, down {}; last handshake {}",
                            s.node_name.as_deref().unwrap_or("?"),
                            s.endpoint.as_deref().unwrap_or("?"),
                            if s.killswitch { "on" } else { "OFF" },
                            fmt_bytes(s.tx_bytes),
                            fmt_bytes(s.rx_bytes),
                            s.last_handshake_secs.map(|n| format!("{n}s ago")).unwrap_or_else(|| "none".into()),
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

async fn up(
    inv: Invite,
    key: ClientKey,
    interface: String,
    route_ipv6: bool,
    kill_switch: bool,
) -> Result<()> {
    // A plan from a connection that died is undone first; otherwise the new
    // routes would stack on the old ones.
    if let Some(old) = netcfg::load_plan()? {
        eprintln!("undoing the network changes of a previous connection first");
        let _ = netcfg::revert(&old);
    }

    let (ip, prefix) = inv.client_ip()?;
    let tun = hidravpn_tun::open(&TunConfig {
        name: interface.clone(),
        ipv4: (ip, prefix),
        ipv6: None,
        mtu: inv.mtu,
    })?;
    let ifname = hidravpn_tun::name(&tun).unwrap_or(interface);
    eprintln!("tunnel interface {ifname} up with {ip}/{prefix}");

    let cfg = ClientConfig {
        invite: inv.clone(),
        key,
    };
    let tunnel = Arc::new(Tunnel::new(&cfg, tun).await?);

    let plan = match netcfg::apply(&Wanted {
        interface: ifname.clone(),
        node_ip: inv.endpoint_ip()?,
        dns: inv.dns,
        route_ipv6,
    }) {
        Ok(p) => p,
        Err(e) => {
            if let Ok(Some(p)) = netcfg::load_plan() {
                let _ = netcfg::revert(&p);
            }
            return Err(e.context("could not route the machine through the tunnel"));
        }
    };
    eprintln!(
        "routes and DNS set: everything now goes through {} ({})",
        inv.node_name, inv.endpoint
    );

    // Arm the kill switch. If it will not arm, undo the routing and refuse:
    // an unprotected tunnel is worse than no tunnel.
    let ks_armed = if kill_switch {
        match killswitch::apply(&KillConfig {
            interface: ifname.clone(),
            node_endpoint: inv.endpoint_addr()?,
            dns: inv.dns,
            allow_lan: false,
        }) {
            Ok(()) => {
                eprintln!("kill switch on: nothing leaves outside the tunnel");
                true
            }
            Err(e) => {
                let _ = netcfg::revert(&plan);
                return Err(e.context("could not arm the kill switch; connection refused"));
            }
        }
    } else {
        eprintln!("kill switch OFF (--no-kill-switch): traffic can leak if the tunnel drops");
        false
    };

    let runner = {
        let t = tunnel.clone();
        tokio::spawn(async move { t.run().await })
    };

    // Report until Ctrl+C, then put everything back.
    let mut was_connected = false;
    let mut waited = 0u32;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let outcome: Result<()> = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = tick.tick() => {
                let s = tunnel.status();
                if s.connected && !was_connected {
                    was_connected = true;
                    eprintln!("connected");
                } else if !s.connected {
                    waited += 1;
                    if waited == 15 {
                        eprintln!("no answer from the node after 15 s — is UDP {} open, and was this key admitted?", inv.endpoint_addr().map(|a| a.port()).unwrap_or(0));
                    }
                }
                if was_connected && waited.is_multiple_of(5) {
                    let hs = s.last_handshake.map(|d| format!("{}s ago", d.as_secs())).unwrap_or_else(|| "none".into());
                    eprint!("\r  {}  handshake {}  up {}  down {}      ", if s.connected { "connected   " } else { "reconnecting" }, hs, fmt_bytes(s.tx_bytes), fmt_bytes(s.rx_bytes));
                }
                if runner.is_finished() { break Err(anyhow!("the tunnel stopped")); }
            }
        }
    };

    eprintln!("\ndisconnecting");
    tunnel.stop();
    runner.abort();
    if ks_armed {
        let _ = killswitch::remove();
    }
    netcfg::revert(&plan).context("restoring the network")?;
    eprintln!("network restored");
    outcome
}
