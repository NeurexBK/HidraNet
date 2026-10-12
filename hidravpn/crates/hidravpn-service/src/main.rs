//! The HidraVPN service binary.
//!
//!   hidravpn-service run                 run the daemon (what the OS service starts)
//!   hidravpn-service install|uninstall   register / remove the OS service
//!   hidravpn-service start|stop          start / stop the OS service
//!   hidravpn-service status              ask the running service how things stand
//!   hidravpn-service up <invite.json>    connect through the running service
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
    /// Install and start the OS service.
    Install,
    /// Stop and remove the OS service.
    Uninstall,
    /// Start the OS service.
    Start,
    /// Stop the OS service.
    Stop,
    /// Print the current status.
    Status,
    /// Connect through the running service.
    Up {
        invite: PathBuf,
        #[arg(long)]
        allow_lan: bool,
        #[arg(long)]
        keep_ipv6: bool,
    },
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
    },
    /// Lift the kill switch.
    Off,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => run_daemon(),
        Cmd::Install => {
            require_admin()?;
            install::install()?;
            println!("HidraVPN service installed and started");
            Ok(())
        }
        Cmd::Uninstall => {
            require_admin()?;
            install::uninstall()?;
            println!("HidraVPN service stopped and removed");
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
                            "connected through {} ({}); kill switch {}; up {} B, down {} B; last handshake {}",
                            s.node_name.as_deref().unwrap_or("?"),
                            s.endpoint.as_deref().unwrap_or("?"),
                            if s.killswitch { "on" } else { "OFF" },
                            s.tx_bytes,
                            s.rx_bytes,
                            s.last_handshake_secs.map(|n| format!("{n}s ago")).unwrap_or_else(|| "none".into()),
                        );
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
            allow_lan,
            keep_ipv6,
        } => client(async move {
            let inv = Invite::from_json(
                &std::fs::read_to_string(&invite)
                    .with_context(|| format!("reading {}", invite.display()))?,
            )?;
            let resp = ipc::call(ipc::Command::Up {
                invite: inv,
                allow_lan,
                keep_ipv6,
            })
            .await?;
            if resp.ok {
                println!("connected");
                Ok(())
            } else {
                anyhow::bail!(resp.error.unwrap_or_else(|| "connect failed".into()))
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
                } => {
                    killswitch::apply(&KillConfig {
                        interface,
                        node_endpoint: node,
                        dns,
                        allow_lan,
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
