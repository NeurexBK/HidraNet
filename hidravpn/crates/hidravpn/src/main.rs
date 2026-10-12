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
use hidravpn_core::netcfg::{self, Wanted};
use hidravpn_core::{ClientConfig, ClientKey, Invite, Tunnel};
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
    },
    /// Undo the routes and DNS of a connection that did not end cleanly.
    Down,
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
        Cmd::Down => {
            require_admin()?;
            match netcfg::load_plan()? {
                None => println!("nothing to undo"),
                Some(plan) => {
                    netcfg::revert(&plan)?;
                    println!("network restored");
                }
            }
        }
        Cmd::Up {
            invite,
            keep_ipv6,
            interface,
        } => {
            require_admin()?;
            let inv = Invite::from_json(
                &std::fs::read_to_string(&invite)
                    .with_context(|| format!("reading {}", invite.display()))?,
            )?;
            let key = load_or_create_key(&key_path, false)?;
            up(inv, key, interface, !keep_ipv6).await?;
        }
    }
    Ok(())
}

async fn up(inv: Invite, key: ClientKey, interface: String, route_ipv6: bool) -> Result<()> {
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
                if was_connected && waited % 5 == 0 {
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
    netcfg::revert(&plan).context("restoring the network")?;
    eprintln!("network restored");
    outcome
}
