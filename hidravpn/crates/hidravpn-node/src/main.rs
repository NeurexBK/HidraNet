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
//! leases in /run/hidravpn, which is RAM. It logs counts, never who did what.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("hidravpn-node runs on Linux");
    std::process::exit(1);
}

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
        },
        /// Bring the tunnel up and serve until SIGTERM or Ctrl+C.
        Run,
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
            } => {
                require_root()?;
                if cli.config.exists() {
                    return Err(anyhow!(
                        "{} exists; not overwriting the node's key",
                        cli.config.display()
                    ));
                }
                let cfg = NodeConfig::fresh(name, endpoint, port, &tunnel, dns, out_interface)?;
                cfg.save(&cli.config)?;
                println!("node public key: {}", cfg.public_key()?);
                println!("settings written to {}", cli.config.display());
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
                    Ok(dev) => dev.add_peer(&lease.public_key, lease.ip)?,
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
                if leases.iter().count() == 0 {
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

        crate::nat::apply(&cfg.interface, &out_if, &net.cidr)?;
        info!("forwarding and NAT set through {out_if}");

        let leases = Leases::load()?;
        let mut n = 0;
        for l in leases.iter() {
            dev.add_peer(&l.public_key, l.ip)?;
            n += 1;
        }
        info!("{n} admitted client(s) loaded");

        let dns_addr = SocketAddr::new(IpAddr::V4(net.node_ip), 53);
        let dns = tokio::spawn(crate::dns::serve(dns_addr, cfg.dns.clone()));
        info!("DNS forwarder on {dns_addr} → {}", cfg.dns.join(", "));

        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
            r = dns => { if let Err(e) = r { warn!("DNS forwarder stopped: {e}"); } },
        }

        info!("stopping");
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
