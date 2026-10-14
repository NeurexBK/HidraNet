//! The HidraVPN service binary.
//!
//!   hidravpn-service run                 run the daemon (what the OS service starts)
//!   hidravpn-service install|uninstall   register / remove the OS service
//!   hidravpn-service start|stop          start / stop the OS service
//!   hidravpn-service status              ask the running service how things stand
//!   hidravpn-service up <exit.json> [--via entry.json] [--alternate other.json]...
//!                                        [--alternate-entry other-entry.json]...
//!                                        connect through the running service
//!   hidravpn-service new-identity        rebuild the circuit through another exit
//!   hidravpn-service down                disconnect
//!   hidravpn-service firewall on|off     the kill switch on its own (diagnostics)
//!
//! `run` must be the system (root / SYSTEM); the client commands talk to it
//! over the local control channel and need only the control token.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use hidravpn_core::killswitch::{self, KillConfig};
use hidravpn_core::Invite;
use hidravpn_service::daemon::Daemon;
use hidravpn_service::{install, ipc};

#[derive(Parser)]
#[command(
    name = "hidravpn-service",
    version,
    about = "The HidraVPN background service"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon in the foreground (the OS service runs this).
    Run,
    /// Install and start the OS service (also an update: a running service
    /// is stopped, replaced and started again). Makes this machine's key if
    /// it has none.
    Install {
        /// The command-line client to install beside the service.
        #[arg(long)]
        client: Option<PathBuf>,
        /// Linux: the account to add to the hidravpn group, so the browser
        /// it runs can drive the service.
        #[arg(long)]
        user: Option<String>,
    },
    /// Stop and remove the OS service.
    Uninstall {
        /// Also remove the installed programs, the pocket of nodes and this
        /// machine's key. Nodes know this machine by that key: after a purge
        /// it is a new machine to every node.
        #[arg(long)]
        purge: bool,
    },
    /// Start the OS service.
    Start,
    /// Stop the OS service.
    Stop,
    /// Print the current status.
    Status,
    /// Connect through the running service.
    Up {
        /// The exit node's invite: the node that reaches the internet.
        invite: PathBuf,
        /// An entry node's invite: two hops (Privado), the client talks to
        /// this node and, through it, to the exit.
        #[arg(long)]
        via: Option<PathBuf>,
        /// Another exit node's invite that `new-identity` may rotate to.
        /// May be given more than once.
        #[arg(long = "alternate")]
        alternates: Vec<PathBuf>,
        /// Another entry node's invite that `new-identity` may rotate to.
        /// May be given more than once; needs --via.
        #[arg(long = "alternate-entry", requires = "via")]
        alternate_entries: Vec<PathBuf>,
        #[arg(long)]
        allow_lan: bool,
        #[arg(long)]
        keep_ipv6: bool,
    },
    /// Rebuild the circuit through another exit node given with --alternate
    /// (and another entry given with --alternate-entry), so the address the
    /// internet sees changes.
    NewIdentity,
    /// Disconnect.
    Down,
    /// The kill switch on its own, without a tunnel (diagnostics and tests).
    Firewall {
        #[command(subcommand)]
        what: Firewall,
    },
}

#[derive(Subcommand)]
enum Firewall {
    /// Arm the kill switch.
    On {
        #[arg(long, default_value = "hvpn0")]
        interface: String,
        /// The node's WireGuard endpoint, ip:port.
        #[arg(long)]
        node: SocketAddr,
        /// The node's resolver.
        #[arg(long)]
        dns: std::net::Ipv4Addr,
        #[arg(long)]
        allow_lan: bool,
        /// A second tunnel interface to allow (the inner tunnel of a two-hop circuit).
        #[arg(long)]
        extra_interface: Option<String>,
    },
    /// Lift the kill switch.
    Off,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => run_daemon(),
        Cmd::Install { client, user } => {
            require_admin()?;
            install::install(&install::InstallOptions { client, user })?;
            println!("HidraVPN service installed and started");
            Ok(())
        }
        Cmd::Uninstall { purge } => {
            require_admin()?;
            install::uninstall(purge)?;
            println!(
                "{}",
                if purge {
                    "HidraVPN removed: the service, the programs, the nodes and this machine's key"
                } else {
                    "HidraVPN service stopped and removed (the key and the nodes are kept)"
                }
            );
            Ok(())
        }
        Cmd::Start => {
            require_admin()?;
            install::start()?;
            println!("started");
            Ok(())
        }
        Cmd::Stop => {
            require_admin()?;
            install::stop()?;
            println!("stopped");
            Ok(())
        }
        Cmd::Status => client(async {
            match ipc::call(ipc::Command::Status).await?.status {
                Some(s) => {
                    if s.connected {
                        println!(
                            "connected through {}{} ({}), {}, {} hop{}; kill switch {}; up {} B, down {} B; last handshake {}",
                            s.entry_name.as_deref().map(|e| format!("{e} then ")).unwrap_or_default(),
                            s.node_name.as_deref().unwrap_or("?"),
                            s.endpoint.as_deref().unwrap_or("?"),
                            if s.mode.is_empty() { "?" } else { s.mode.as_str() },
                            s.hops,
                            if s.hops == 1 { "" } else { "s" },
                            if s.killswitch { "on" } else { "OFF" },
                            s.tx_bytes,
                            s.rx_bytes,
                            s.last_handshake_secs.map(|n| format!("{n}s ago")).unwrap_or_else(|| "none".into()),
                        );
                        print_detail(&s);
                    } else if s.hops > 0 {
                        println!(
                            "connecting: {}, {} hop{}, no session with every node yet; kill switch {}",
                            s.mode,
                            s.hops,
                            if s.hops == 1 { "" } else { "s" },
                            if s.killswitch { "on" } else { "OFF" }
                        );
                        print_detail(&s);
                    } else {
                        println!(
                            "not connected; kill switch {}",
                            if s.killswitch { "on" } else { "off" }
                        );
                    }
                    Ok(())
                }
                None => anyhow::bail!("the service did not report a status"),
            }
        }),
        Cmd::Up {
            invite,
            via,
            alternates,
            alternate_entries,
            allow_lan,
            keep_ipv6,
        } => client(async move {
            let inv = read_invite(&invite)?;
            let via = via.as_deref().map(read_invite).transpose()?;
            let alternates = alternates
                .iter()
                .map(|p| read_invite(p))
                .collect::<Result<Vec<_>>>()?;
            let alternate_entries = alternate_entries
                .iter()
                .map(|p| read_invite(p))
                .collect::<Result<Vec<_>>>()?;
            let resp = ipc::call(ipc::Command::Up {
                invite: inv,
                allow_lan,
                keep_ipv6,
                via,
                alternates,
                alternate_entries,
            })
            .await?;
            if resp.ok {
                match resp.status {
                    Some(s) if s.hops == 2 => println!(
                        "connected: privado, 2 hops, entry {} then exit {}",
                        s.entry_name.as_deref().unwrap_or("?"),
                        s.node_name.as_deref().unwrap_or("?")
                    ),
                    Some(s) => println!(
                        "connected: rapido, 1 hop, through {}",
                        s.node_name.as_deref().unwrap_or("?")
                    ),
                    None => println!("connected"),
                }
                Ok(())
            } else {
                anyhow::bail!(resp.error.unwrap_or_else(|| "connect failed".into()))
            }
        }),
        Cmd::NewIdentity => client(async {
            let resp = ipc::call(ipc::Command::NewIdentity).await?;
            if resp.ok {
                println!("{}", resp.note.unwrap_or_else(|| "reconnected".into()));
                Ok(())
            } else {
                anyhow::bail!(resp.error.unwrap_or_else(|| "new identity failed".into()))
            }
        }),
        Cmd::Down => client(async {
            let resp = ipc::call(ipc::Command::Down).await?;
            if resp.ok {
                println!("disconnected");
                Ok(())
            } else {
                anyhow::bail!(resp.error.unwrap_or_else(|| "disconnect failed".into()))
            }
        }),
        Cmd::Firewall { what } => {
            require_admin()?;
            match what {
                Firewall::On {
                    interface,
                    node,
                    dns,
                    allow_lan,
                    extra_interface,
                } => {
                    killswitch::apply(&KillConfig {
                        interface,
                        node_endpoint: node,
                        dns,
                        allow_lan,
                        extra_interface,
                    })?;
                    println!("kill switch on");
                }
                Firewall::Off => {
                    killswitch::remove()?;
                    println!("kill switch off");
                }
            }
            Ok(())
        }
    }
}

/// After the status line: what the mode hides and what it does not, and
/// each hop's handshake age.
fn print_detail(s: &ipc::StatusReport) {
    if let Some(line) = s.explanation() {
        println!("  {line}");
    }
    for line in s.hop_lines() {
        println!("  {line}");
    }
}

fn read_invite(path: &std::path::Path) -> Result<Invite> {
    Invite::from_json(
        &std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
}

/// Runs an async client command on a small runtime.
fn client<F>(fut: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(fut)
}

fn run_daemon() -> Result<()> {
    require_admin()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("hidravpn_service=info")),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let token = ipc::write_token().context("writing the control token")?;
        let daemon = Daemon::new(token);
        tracing::info!("HidraVPN service starting");

        let serve = {
            let d = daemon.clone();
            tokio::spawn(async move { ipc::serve(d).await })
        };

        wait_for_stop().await;
        tracing::info!("stopping; putting the network back");
        daemon.shutdown().await;
        serve.abort();
        Ok::<(), anyhow::Error>(())
    })
}

#[cfg(unix)]
async fn wait_for_stop() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn wait_for_stop() {
    let _ = tokio::signal::ctrl_c().await;
}

fn require_admin() -> Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            anyhow::bail!("this needs root: run it with sudo");
        }
    }
    Ok(())
}
