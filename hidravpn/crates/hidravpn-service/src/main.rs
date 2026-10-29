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
//!   hidravpn-service firewall on|hold|off
//!                                        the kill switch on its own (diagnostics)
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

/// Running as a real Windows service (the SCM's control handler and status).
#[cfg(windows)]
mod service;

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
        /// Replace an installed service even when it is newer than this one.
        /// Without it, an older build refuses and changes nothing.
        #[arg(long)]
        allow_downgrade: bool,
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
        /// Two hops whose entry and exit one operator runs (or whose
        /// operators the invites do not name) are refused without this: one
        /// operator running both could see who you are and where you go.
        #[arg(long)]
        allow_same_operator: bool,
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
    /// Hold the line as a rotation does: the nodes' WireGuard endpoints
    /// and the admission ports given, off-tunnel, and nothing else, no
    /// tunnel interface.
    Hold {
        /// A node's WireGuard endpoint, ip:port. May be given more than once.
        #[arg(long = "node", required = true)]
        nodes: Vec<SocketAddr>,
        /// A first hop's admission port, ip:port, as while a connection asks
        /// for admission. May be given more than once.
        #[arg(long = "admission")]
        admission: Vec<SocketAddr>,
    },
    /// Lift the kill switch.
    Off,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run => run_daemon(),
        Cmd::Install {
            client,
            user,
            allow_downgrade,
        } => {
            require_admin()?;
            install::install(&install::InstallOptions {
                client,
                user,
                allow_downgrade,
            })?;
            if answers_within(STARTUP_WAIT) {
                println!("HidraVPN service installed and started");
                Ok(())
            } else {
                // Installed, but not known to work: an exit code of its own,
                // so the browser's installer does not report it as running.
                println!(
                    "HidraVPN service installed, but it has not answered in {} seconds: `hidravpn-service status` says when it is ready",
                    STARTUP_WAIT.as_secs()
                );
                std::process::exit(NOT_ANSWERING);
            }
        }
        Cmd::Uninstall { purge } => {
            require_admin()?;
            install::uninstall(purge)?;
            println!(
                "{}",
                if purge {
                    "HidraVPN removed: the service, the programs, the nodes, the passes and this machine's key"
                } else {
                    "HidraVPN service stopped and removed (the key and the nodes are kept)"
                }
            );
            Ok(())
        }
        Cmd::Start => {
            require_admin()?;
            install::start()?;
            if answers_within(STARTUP_WAIT) {
                println!("started");
            } else {
                println!(
                    "starting, but the service has not answered yet: `hidravpn-service status` says when it is ready"
                );
            }
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
            allow_same_operator,
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
                allow_same_operator,
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
                        outer_peer: None,
                        tunnel_ipv6: None,
                    })?;
                    println!("kill switch on");
                }
                Firewall::Hold { nodes, admission } => {
                    if admission.is_empty() {
                        killswitch::hold(&nodes)?;
                    } else {
                        killswitch::hold_admitting(&nodes, &admission, None)?;
                    }
                    println!("kill switch holding");
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
/// How long `install` and `start` wait for the new service to answer.
const STARTUP_WAIT: std::time::Duration = std::time::Duration::from_secs(15);

/// The exit code of an install whose service did not answer within
/// STARTUP_WAIT (EX_UNAVAILABLE). The browser's installer tells it apart
/// from success: hidra-browser/src/main/vpn-installer.js.
const NOT_ANSWERING: i32 = 69;

/// Waits until the service answers on its control channel. The OS starts
/// it in the background, so without this a client run right after
/// `install` finds no service yet and connects on its own, in the
/// foreground, instead of through it.
fn answers_within(limit: std::time::Duration) -> bool {
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    rt.block_on(async {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            if matches!(ipc::call(ipc::Command::Ping).await, Ok(r) if r.ok) {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    })
}

fn client<F>(fut: F) -> Result<()>
where
    F: std::future::Future<Output = Result<()>>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(fut)
}

/// The service's log file on Windows, appended to, and started afresh when
/// it has grown past a megabyte. None if it cannot be opened.
#[cfg(windows)]
fn windows_log_file() -> Option<std::sync::Arc<std::fs::File>> {
    let path = hidravpn_service::paths::service_log();
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1024 * 1024) {
        let _ = std::fs::remove_file(&path);
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .ok()
        .map(std::sync::Arc::new)
}

fn run_daemon() -> Result<()> {
    require_admin()?;
    #[cfg(windows)]
    {
        // Prefer running as the registered service. Only when no SCM started
        // us (someone ran `run` from a console, to watch it) do we fall
        // through to the foreground. `dispatch` blocks for the service's
        // whole life and sets up its own logging through `service_main`.
        match service::dispatch()? {
            service::Dispatch::Ran => return Ok(()),
            service::Dispatch::NotStartedByScm => {}
        }
    }
    init_logging();
    run_daemon_until(foreground_stop())
}

/// Sets up the daemon's logging. On Windows the service has no console, so
/// warnings and errors also go to a file. Call once per process.
fn init_logging() {
    let logs = tracing_subscriber::fmt()
        // HidraVPN's own crates only, whatever RUST_LOG says.
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            hidravpn_core::logging::directives(
                std::env::var("RUST_LOG").ok().as_deref(),
                "hidravpn_service=info",
            ),
        ))
        .with_target(false);
    #[cfg(windows)]
    match windows_log_file() {
        // Warnings and errors also go to a file: the service has no console.
        // They name no address, key or name, like every log here.
        Some(file) => {
            use tracing_subscriber::fmt::writer::MakeWriterExt;
            logs.with_ansi(false)
                .with_writer(std::io::stderr.and(file.with_max_level(tracing::Level::WARN)))
                .init();
        }
        None => logs.with_writer(std::io::stderr).init(),
    }
    #[cfg(not(windows))]
    logs.with_writer(std::io::stderr).init();
}

/// Builds the runtime and serves until `stop` completes. The synchronous
/// entry both the foreground path and the Windows service call. `pub(crate)`
/// so the service's `mod service` can drive it with the SCM's stop signal.
pub(crate) fn run_daemon_until<S>(stop: S) -> Result<()>
where
    S: std::future::Future<Output = ()>,
{
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(serve_until(stop))
}

/// Serves the control channel and the refill loop until `stop` completes,
/// then puts the network back. Shared by the foreground and the service.
async fn serve_until<S>(stop: S) -> Result<()>
where
    S: std::future::Future<Output = ()>,
{
    let token = ipc::write_token().context("writing the control token")?;
    let daemon = Daemon::new(token);
    tracing::info!("HidraVPN service starting");
    hidravpn_core::netcfg::recover_dns();

    let serve = {
        let d = daemon.clone();
        tokio::spawn(async move { ipc::serve(d).await })
    };
    let refill = {
        let d = daemon.clone();
        tokio::spawn(async move { d.refill_loop().await })
    };

    stop.await;
    tracing::info!("stopping; putting the network back");
    refill.abort();
    daemon.shutdown().await;
    serve.abort();
    Ok(())
}

#[cfg(unix)]
async fn foreground_stop() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

#[cfg(not(unix))]
async fn foreground_stop() {
    // Run in a console with no Ctrl+C to take: then it runs until it is ended
    // from outside, never stopping at once. (As a service, the SCM's stop
    // control drives the shutdown instead — see `mod service`.)
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

fn require_admin() -> Result<()> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            anyhow::bail!("this needs root: run it with sudo");
        }
    }
    #[cfg(windows)]
    {
        if !this_process_is_elevated() {
            anyhow::bail!(
                "this needs an administrator: run it from a PowerShell opened with \"Run as administrator\""
            );
        }
    }
    Ok(())
}

/// Whether this process runs elevated (an administrator's prompt, or
/// SYSTEM). Anything that cannot be established counts as not.
#[cfg(windows)]
fn this_process_is_elevated() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut token = HANDLE::default();
    // SAFETY: the current process's pseudo-handle needs no closing; the
    // token opened here is closed here; every out-pointer is to a local.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let got = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        got && elevation.TokenIsElevated != 0
    }
}
