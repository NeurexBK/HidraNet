//! HidraVPN node. Phase 1: a single hop that any admitted client can reach.
//!
//!   hidravpn-node init --endpoint IP:PORT --name NAME   write /etc/hidravpn/node.toml with a new key
//!   hidravpn-node run                                   bring the tunnel up and serve until stopped
//!   hidravpn-node pubkey                                print this node's public key, for a
//!                                                       client to derive the key it will present
//!   hidravpn-node admit --name NAME --pubkey KEY        let a client in; prints its invite
//!   hidravpn-node revoke --pubkey KEY                   throw a client out
//!   hidravpn-node status                                peers, handshakes, bytes — never addresses
//!
//! What it keeps: its own key and settings in /etc/hidravpn, and the current
//! leases in /var/lib/hidravpn, which survive a reboot. It logs counts, never who did what.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hidravpn-node runs on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
mod admission;
#[cfg(target_os = "linux")]
mod config;
#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod leases;
#[cfg(target_os = "linux")]
mod nat;
#[cfg(target_os = "linux")]
mod userspace;
#[cfg(target_os = "linux")]
mod wg;

#[cfg(target_os = "linux")]
mod node {
    use std::net::{IpAddr, SocketAddr};
    use std::path::PathBuf;

    use anyhow::{anyhow, Context, Result};
    use clap::{Parser, Subcommand};
    use std::time::Duration;

    use hidravpn_core::Invite;
    use tracing::{info, warn};

    use crate::config::NodeConfig;
    use crate::leases::Leases;

    #[derive(Parser)]
    #[command(
        name = "hidravpn-node",
        version,
        about = "HidraVPN node (phase 1: single hop)"
    )]
    struct Cli {
        /// Settings file.
        #[arg(long, global = true, default_value = "/etc/hidravpn/node.toml")]
        config: PathBuf,
        #[command(subcommand)]
        cmd: Cmd,
    }

    #[derive(Subcommand)]
    enum Cmd {
        /// Create the settings file with a fresh key.
        Init {
            /// The address clients connect to, ip:port (this machine's public address).
            #[arg(long)]
            endpoint: SocketAddr,
            /// A name for this node, shown to clients.
            #[arg(long, default_value = "hidravpn-node")]
            name: String,
            /// UDP port to listen on.
            #[arg(long, default_value_t = 51820)]
            port: u16,
            /// The subnet clients get addresses from; the node is its first address.
            #[arg(long, default_value = "10.77.0.0/16")]
            tunnel: String,
            /// DNS upstreams, inside the tunnel: https://host/path@ip[,ip] or udp://ip.
            #[arg(long, num_args = 1.., default_values_t = NodeConfig::default_dns())]
            dns: Vec<String>,
            /// The interface traffic leaves through; detected from the default route if absent.
            #[arg(long)]
            out_interface: Option<String>,
            /// What this node is for: entry (forwards only WireGuard to other
            /// nodes), exit (forwards the internet), or both.
            #[arg(long, default_value = "both")]
            role: String,
            /// Who runs this node, as clients and lists will show it.
            #[arg(long)]
            operator: Option<String>,
            /// How to reach the operator: an address or a page.
            #[arg(long)]
            contact: Option<String>,
            /// Admit any client that asks on the admission port, rate-limited
            /// and capped, instead of by hand.
            #[arg(long)]
            open_admission: bool,
            /// TCP port of the admission service.
            #[arg(long, default_value_t = hidravpn_core::admission::DEFAULT_ADMISSION_PORT)]
            admission_port: u16,
            /// How many clients may hold a lease at once.
            #[arg(long, default_value_t = 4000)]
            max_clients: u32,
            /// Days without a handshake after which an openly admitted client
            /// loses its lease (0: never).
            #[arg(long, default_value_t = 30)]
            idle_days: u32,
        },
        /// Bring the tunnel up and serve until SIGTERM or Ctrl+C.
        Run,
        /// Print this node's record: what a signed node list carries about it.
        Record,
        /// Print this node's public key. A client derives, from this, the
        /// key it presents here (`hidravpn pubkey --node KEY`); that is the
        /// key to admit.
        Pubkey,
        /// Admit a client's public key; prints the invite to give it.
        Admit {
            #[arg(long)]
            name: String,
            #[arg(long)]
            pubkey: String,
        },
        /// Remove a client.
        Revoke {
            #[arg(long)]
            pubkey: String,
        },
        /// Print the invite of an admitted client again.
        Invite {
            #[arg(long)]
            pubkey: String,
        },
        /// Peers, handshakes and bytes.
        Status,
        /// Resolve a name through the DNS upstreams, to prove they work from here.
        DnsCheck {
            #[arg(default_value = "example.com")]
            name: String,
            /// Upstreams to try instead of the configured ones.
            #[arg(long, num_args = 1..)]
            dns: Vec<String>,
        },
    }

    fn require_root() -> Result<()> {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err(anyhow!("this needs root"));
        }
        Ok(())
    }

    pub async fn main() -> Result<()> {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("hidravpn_node=info".parse()?),
            )
            .with_target(false)
            // Logs go to stderr so that what `admit` and `invite` print on
            // stdout is the invite and nothing else.
            .with_writer(std::io::stderr)
            .init();
        let cli = Cli::parse();

        match cli.cmd {
            Cmd::Init {
                endpoint,
                name,
                port,
                tunnel,
                dns,
                out_interface,
                role,
                operator,
                contact,
                open_admission,
                admission_port,
                max_clients,
                idle_days,
            } => {
                require_root()?;
                if cli.config.exists() {
                    return Err(anyhow!(
                        "{} exists; not overwriting the node's key",
                        cli.config.display()
                    ));
                }
                let mut cfg = NodeConfig::fresh(name, endpoint, port, &tunnel, dns, out_interface)?;
                cfg.set_role(&role)?;
                cfg.operator = operator.filter(|s| !s.trim().is_empty());
                cfg.contact = contact.filter(|s| !s.trim().is_empty());
                cfg.admission = if open_admission { "open" } else { "manual" }.into();
                cfg.admission_port = admission_port;
                cfg.max_clients = max_clients;
                cfg.idle_days = idle_days;
                cfg.save(&cli.config)?;
                println!("node public key: {}", cfg.public_key()?);
                println!("settings written to {}", cli.config.display());
                println!(
                    "role {}; admission {}; admission port TCP {}",
                    cfg.role, cfg.admission, cfg.admission_port
                );
            }
            Cmd::Record => {
                let cfg = NodeConfig::load(&cli.config)?;
                println!("{}", serde_json::to_string_pretty(&cfg.record()?)?);
            }
            Cmd::Run => {
                require_root()?;
                let cfg = NodeConfig::load(&cli.config)?;
                run(cfg).await?;
            }
            Cmd::Pubkey => {
                let cfg = NodeConfig::load(&cli.config)?;
                println!("{}", cfg.public_key()?);
            }
            Cmd::Admit { name, pubkey } => {
                require_root()?;
                let cfg = NodeConfig::load(&cli.config)?;
                let mut leases = Leases::load()?;
                let lease = leases.admit(&name, &pubkey, &cfg.tunnel_network()?)?;
                leases.save()?;
                // Into the running device too, if there is one.
                match crate::wg::open_existing(&cfg.interface) {
                    Ok(dev) => dev.add_peer(&lease.public_key, lease.ip, lease.preshared_key.as_deref())?,
                    Err(e) => warn!("the node is not running ({e}); the client is admitted the next time it starts"),
                }
                println!("{}", invite_for(&cfg, &lease)?.to_json());
            }
            Cmd::Revoke { pubkey } => {
                require_root()?;
                let cfg = NodeConfig::load(&cli.config)?;
                let mut leases = Leases::load()?;
                if !leases.revoke(&pubkey) {
                    return Err(anyhow!("that key is not admitted"));
                }
                leases.save()?;
                if let Ok(dev) = crate::wg::open_existing(&cfg.interface) {
                    dev.remove_peer(&pubkey)?;
                }
                println!("revoked");
            }
            Cmd::Invite { pubkey } => {
                let cfg = NodeConfig::load(&cli.config)?;
                let leases = Leases::load()?;
                let lease = leases
                    .find(&pubkey)
                    .ok_or_else(|| anyhow!("that key is not admitted"))?;
                println!("{}", invite_for(&cfg, lease)?.to_json());
            }
            Cmd::DnsCheck { name, dns } => {
                let upstreams = if dns.is_empty() {
                    NodeConfig::load(&cli.config)
                        .map(|c| c.dns)
                        .unwrap_or_else(|_| NodeConfig::default_dns())
                } else {
                    dns
                };
                crate::dns::check(&upstreams, &name).await?;
            }
            Cmd::Status => {
                require_root()?;
                let cfg = NodeConfig::load(&cli.config)?;
                let leases = Leases::load()?;
                let dev =
                    crate::wg::open_existing(&cfg.interface).context("the node is not running")?;
                let stats = dev.peer_stats()?;
                println!(
                    "{:<16} {:>14} {:>12} {:>12}",
                    "client", "handshake", "received", "sent"
                );
                for l in leases.iter() {
                    let s = stats.get(&l.public_key);
                    let hs = s
                        .and_then(|s| s.last_handshake)
                        .map(|d| format!("{}s ago", d.as_secs()))
                        .unwrap_or_else(|| "never".into());
                    println!(
                        "{:<16} {:>14} {:>12} {:>12}",
                        l.name,
                        hs,
                        s.map(|s| s.rx_bytes).unwrap_or(0),
                        s.map(|s| s.tx_bytes).unwrap_or(0)
                    );
                }
                if leases.is_empty() {
                    println!("(no clients admitted)");
                }
            }
        }
        Ok(())
    }

    fn invite_for(cfg: &NodeConfig, lease: &crate::leases::Lease) -> Result<Invite> {
        let net = cfg.tunnel_network()?;
        Ok(Invite {
            node_name: cfg.name.clone(),
            node_public_key: cfg.public_key()?,
            endpoint: cfg.public_endpoint.to_string(),
            client_address: format!("{}/{}", lease.ip, net.prefix),
            dns: net.node_ip,
            allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
            mtu: 1420,
            keepalive: 25,
            operator: cfg.operator.clone(),
            role: Some(cfg.role.clone()),
            preshared_key: lease.preshared_key.clone(),
            kem_ciphertext: None,
        })
    }

    async fn run(cfg: NodeConfig) -> Result<()> {
        let net = cfg.tunnel_network()?;
        let out_if = match &cfg.out_interface {
            Some(i) => i.clone(),
            None => crate::nat::default_interface()?,
        };

        crate::nat::enable_forwarding()?;
        let dev = crate::wg::bring_up(&cfg, &net).await?;
        info!(
            "tunnel interface {} up ({} WireGuard), listening on UDP {}",
            cfg.interface,
            dev.backend_name(),
            cfg.listen_port
        );

        crate::nat::apply(&cfg.interface, &out_if, &net.cidr, &cfg.role)?;
        info!(
            "forwarding and NAT set through {out_if} (role: {})",
            cfg.role
        );

        let node_public_key = cfg.public_key()?;
        let mut leases = Leases::load()?;
        let mut n = 0;
        for l in leases.iter() {
            dev.add_peer(&l.public_key, l.ip, l.preshared_key.as_deref())?;
            n += 1;
        }
        info!("{n} admitted client(s) loaded");

        let dns_addr = SocketAddr::new(IpAddr::V4(net.node_ip), 53);
        let mut dns = tokio::spawn(crate::dns::serve(dns_addr, cfg.dns.clone()));
        info!("DNS forwarder on {dns_addr} → {}", cfg.dns.join(", "));

        // The admission service: describes the node always, admits when open.
        let (admit_tx, mut admit_rx) = tokio::sync::mpsc::channel::<crate::admission::Admit>(64);
        let shared = std::sync::Arc::new(cfg.clone());
        let admission_addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            cfg.admission_port,
        );
        let mut admission = tokio::spawn(crate::admission::serve(admission_addr, shared, admit_tx));

        // The reaper: openly admitted clients that never came, or stopped
        // coming, lose their lease. HIDRAVPN_IDLE_SECS shortens the window
        // for tests.
        let idle_secs: u64 = std::env::var("HIDRAVPN_IDLE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(u64::from(cfg.idle_days) * 86_400);
        // At most a quarter of an hour between checks, so a lease that never
        // came (leases::NEVER_CAME_SECS) is gone soon after it lapses.
        let period = Duration::from_secs((idle_secs / 4).clamp(2, 900));
        let mut reaper = tokio::time::interval(period);
        reaper.tick().await; // the first tick is immediate; skip it

        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = term.recv() => break,
                r = &mut dns => { if let Err(e) = r { warn!("DNS forwarder stopped: {e}"); } break; },
                r = &mut admission => {
                    // The tunnel outlives the admission service: without it
                    // the node admits nobody new, which is better than
                    // serving nobody at all.
                    match r { Ok(Err(e)) => warn!("admission service stopped: {e:#}; the node keeps serving admitted clients"), Err(e) => warn!("admission service task: {e}"), Ok(Ok(())) => {} }
                    admission = tokio::spawn(std::future::pending());
                },
                Some(req) = admit_rx.recv() => {
                    let answer = if leases.len() as u32 >= cfg.max_clients && leases.find(&req.public_key).is_none() {
                        Err((503, "this node is full; try another".to_string()))
                    } else {
                        // The post-quantum pre-shared key, agreed with the
                        // client's KEM key when it sent one. The ciphertext
                        // goes back in the invite; the key itself never does.
                        let agreed = match req.kem_public_key.as_deref() {
                            Some(ek) => match hidravpn_core::psk::answer(ek, &node_public_key, &req.public_key) {
                                Ok((ct, psk)) => Ok(Some((ct, psk))),
                                Err(e) => Err((400, format!("kem_public_key: {e:#}"))),
                            },
                            None => Ok(None),
                        };
                        match agreed {
                            Err(e) => Err(e),
                            Ok(agreed) => match leases.admit_open(&req.name, &req.public_key, &net, agreed.as_ref().map(|(_, psk)| psk.clone())) {
                                Ok(lease) => match leases.save().and_then(|_| dev.add_peer(&lease.public_key, lease.ip, lease.preshared_key.as_deref())) {
                                    Ok(()) => {
                                        info!("admitted a client through the admission service ({} leases{})", leases.len(), if agreed.is_some() { ", post-quantum key agreed" } else { ", older client, no post-quantum key" });
                                        invite_for(&cfg, &lease).map(|mut inv| { inv.preshared_key = None; inv.kem_ciphertext = agreed.map(|(ct, _)| ct); inv }).map_err(|e| (500, format!("{e:#}")))
                                    }
                                    Err(e) => Err((500, format!("could not admit: {e:#}"))),
                                },
                                Err(e) => Err((400, e.to_string())),
                            },
                        }
                    };
                    let _ = req.reply.send(answer);
                }
                _ = reaper.tick() => {
                    if idle_secs > 0 {
                        match dev.peer_stats() {
                            Ok(stats) => {
                                let ages = stats.iter().map(|(k, s)| (k.clone(), s.last_handshake)).collect();
                                let now = crate::leases::now_unix();
                                let touched = leases.note_handshakes(now, &ages);
                                let gone = leases.expire_idle(now, idle_secs);
                                for l in &gone { let _ = dev.remove_peer(&l.public_key); }
                                if touched || !gone.is_empty() {
                                    if let Err(e) = leases.save() { warn!("saving leases: {e}"); }
                                }
                                if !gone.is_empty() {
                                    info!("{} idle openly-admitted client(s) expired ({} leases left)", gone.len(), leases.len());
                                }
                            }
                            Err(e) => warn!("reading peer stats for expiry: {e}"),
                        }
                    }
                }
            }
        }
        admission.abort();

        info!("stopping");
        // Write down the last handshakes, so a restart is not idleness.
        if let Ok(stats) = dev.peer_stats() {
            let ages = stats
                .iter()
                .map(|(k, s)| (k.clone(), s.last_handshake))
                .collect();
            if leases.note_handshakes(crate::leases::now_unix(), &ages) {
                if let Err(e) = leases.save() {
                    warn!("saving leases at shutdown: {e}");
                }
            }
        }
        if let Err(e) = crate::nat::remove() {
            warn!("removing NAT rules: {e}");
        }
        dev.tear_down();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    node::main().await
}
