//! HidraVPN node: a WireGuard endpoint that admits clients by hand, openly
//! or with a pass, and serves as an entry, an exit or both.
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
    #[command(name = "hidravpn-node", version, about = "HidraVPN node")]
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
            /// Where this node is, two letters (ISO 3166-1 alpha-2, e.g. FI),
            /// as lists and clients will show it.
            #[arg(long)]
            country: Option<String>,
            /// Admit any client that asks on the admission port, rate-limited
            /// and capped, instead of by hand.
            #[arg(long, conflicts_with = "pass_admission")]
            open_admission: bool,
            /// Admit a client that redeems a pass signed by an issuer this
            /// node trusts (`pass-key add`), instead of by hand.
            #[arg(long)]
            pass_admission: bool,
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
        /// The issuer keys whose passes this node takes (with --pass-admission).
        PassKey {
            #[command(subcommand)]
            what: PassKeyCmd,
        },
        /// Resolve a name through the DNS upstreams, to prove they work from here.
        DnsCheck {
            #[arg(default_value = "example.com")]
            name: String,
            /// Upstreams to try instead of the configured ones.
            #[arg(long, num_args = 1..)]
            dns: Vec<String>,
        },
    }

    #[derive(Subcommand)]
    enum PassKeyCmd {
        /// Trust an issuer key: the record as the signed list carries it
        /// (`hidravpn-issuer record` prints it), from a file or `-`.
        Add { record: PathBuf },
        /// The keys this node trusts.
        List,
        /// Stop trusting a key, by id.
        Remove { id: String },
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
            // HidraVPN's own crates only, whatever RUST_LOG says: a library
            // at DEBUG would write the names clients look up.
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                hidravpn_core::logging::directives(
                    std::env::var("RUST_LOG").ok().as_deref(),
                    "hidravpn_node=info",
                ),
            ))
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
                country,
                open_admission,
                pass_admission,
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
                cfg.country = match country.filter(|s| !s.trim().is_empty()) {
                    Some(c) => Some(hidravpn_core::directory::normalise_country(&c)?),
                    None => None,
                };
                cfg.admission = if open_admission {
                    "open"
                } else if pass_admission {
                    "pass"
                } else {
                    "manual"
                }
                .into();
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
            Cmd::PassKey { what } => {
                let mut cfg = NodeConfig::load(&cli.config)?;
                match what {
                    PassKeyCmd::Add { record } => {
                        require_root()?;
                        let text = if record.as_os_str() == "-" {
                            let mut t = String::new();
                            std::io::Read::read_to_string(&mut std::io::stdin(), &mut t)?;
                            t
                        } else {
                            std::fs::read_to_string(&record)
                                .with_context(|| format!("reading {}", record.display()))?
                        };
                        let mut rec: hidravpn_core::pass::PassKeyRecord =
                            serde_json::from_str(&text).context("that is not a pass key record")?;
                        rec.validate()?;
                        // Stored as the passes name it, so every lookup matches.
                        rec.id = rec.id.trim().to_ascii_lowercase();
                        if cfg.pass_keys.iter().any(|k| k.id == rec.id) {
                            println!("already trusted: {}", rec.id);
                        } else {
                            cfg.pass_keys.push(rec.clone());
                            cfg.save_over(&cli.config)?;
                            println!(
                                "trusting passes under {} until {}; restart the node for it to take them",
                                rec.id, rec.not_after
                            );
                        }
                        if !cfg.admits_with_passes() {
                            println!("note: this node's admission is \"{}\", not \"pass\"; set admission = \"pass\" in {} to take passes", cfg.admission, cli.config.display());
                        }
                    }
                    PassKeyCmd::List => {
                        let now = hidravpn_core::timefmt::now_unix();
                        for k in &cfg.pass_keys {
                            println!(
                                "{}  until {}{}",
                                k.id,
                                k.not_after,
                                if k.is_current(now) { "" } else { "  (expired)" }
                            );
                        }
                        if cfg.pass_keys.is_empty() {
                            println!("(no pass keys)");
                        }
                    }
                    PassKeyCmd::Remove { id } => {
                        require_root()?;
                        let before = cfg.pass_keys.len();
                        cfg.pass_keys
                            .retain(|k| !k.id.eq_ignore_ascii_case(id.trim()));
                        if cfg.pass_keys.len() == before {
                            return Err(anyhow!("no pass key {id}"));
                        }
                        cfg.save_over(&cli.config)?;
                        println!(
                            "removed {id}; restart the node for it to stop taking those passes"
                        );
                    }
                }
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
                let net = cfg.tunnel_network()?;
                let lease = Leases::update(|l| {
                    let r = l.admit(&name, &pubkey, &net);
                    let ok = r.is_ok();
                    (r, ok)
                })??;
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
                if !Leases::update(|l| {
                    let gone = l.revoke(&pubkey);
                    (gone, gone)
                })? {
                    return Err(anyhow!("that key is not admitted"));
                }
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

    /// The keys that received bytes since the last look, and the counts to
    /// compare with next time. Kept here, not in the leases file, which is
    /// read afresh every time.
    fn active_keys(
        stats: &std::collections::HashMap<String, crate::wg::PeerStats>,
        rx_seen: &mut std::collections::HashMap<String, u64>,
    ) -> std::collections::HashSet<String> {
        let mut active = std::collections::HashSet::new();
        for (k, s) in stats {
            if s.rx_bytes > rx_seen.get(k).copied().unwrap_or(0) {
                active.insert(k.clone());
            }
            rx_seen.insert(k.clone(), s.rx_bytes);
        }
        rx_seen.retain(|k, _| stats.contains_key(k));
        active
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
            pass: None,
            country: cfg.country.clone(),
            admission: Some(
                if cfg.admission_is_open() {
                    "open"
                } else {
                    "manual"
                }
                .into(),
            ),
            admission_port: Some(cfg.admission_port),
            behind: false,
            features: cfg.features(),
        })
    }

    async fn run(cfg: NodeConfig) -> Result<()> {
        let net = cfg.tunnel_network()?;
        let out_if = match &cfg.out_interface {
            Some(i) => i.clone(),
            None => crate::nat::default_interface()?,
        };

        let forwarding_was_on = crate::nat::enable_forwarding()?;
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

        let leases = Leases::load()?;
        let mut n = 0;
        for l in leases.iter() {
            dev.add_peer(&l.public_key, l.ip)?;
            n += 1;
        }
        info!("{n} admitted client(s) loaded");

        let dns_addr = SocketAddr::new(IpAddr::V4(net.node_ip), 53);
        let mut dns = tokio::spawn(crate::dns::serve(dns_addr, cfg.dns.clone()));
        info!("DNS forwarder on {dns_addr} → {}", cfg.dns.join(", "));

        // The admission service: describes the node always, admits when
        // open or for a pass.
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
        // A session lease (a key made for one connection) is forgotten soon
        // after the connection ends. HIDRAVPN_SESSION_IDLE_SECS shortens the
        // window for tests.
        let session_secs: u64 = std::env::var("HIDRAVPN_SESSION_IDLE_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(crate::leases::SESSION_IDLE_SECS);
        // Leases won with a pass lapse after `pass_idle_hours` without a
        // sign of life; HIDRAVPN_PASS_IDLE_SECS shortens that for tests.
        let pass_idle_secs: u64 = if cfg.admits_with_passes() {
            std::env::var("HIDRAVPN_PASS_IDLE_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::from(cfg.pass_idle_hours) * 3_600)
        } else {
            0
        };
        let windows = crate::leases::IdleWindows {
            open: idle_secs,
            session: session_secs,
            pass: pass_idle_secs,
        };
        // Only a node that takes passes needs the list; one that admits
        // openly or by hand never reads it, so a damaged file cannot stop it.
        // A pass node with a list it cannot read refuses to start: going on
        // without it would let every pass already spent be spent again.
        let mut spent = if cfg.admits_with_passes() {
            crate::leases::SpentPasses::load().context(
                "the list of spent passes cannot be read; refusing to take passes without it",
            )?
        } else {
            crate::leases::SpentPasses::default()
        };
        if cfg.admits_with_passes() {
            info!(
                "admission with passes: {} issuer key(s) trusted, {} spent pass(es) remembered",
                cfg.pass_keys.len(),
                spent.len()
            );
        }
        // At most a quarter of an hour between checks, so a lease that never
        // came (leases::NEVER_CAME_SECS) is gone soon after it lapses, and a
        // quarter of the shortest window, so a key made for one connection
        // does not linger.
        let shortest = [idle_secs, session_secs, pass_idle_secs]
            .into_iter()
            .filter(|w| *w > 0)
            .min()
            .unwrap_or(900);
        let period = Duration::from_secs((shortest / 4).clamp(2, 900));
        // The bytes each key had sent when last looked at: more since is a
        // sign of life, even between handshakes (every two minutes).
        let mut rx_seen: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
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
                    // The admission side stopped waiting (its client was
                    // told the node did not answer in time, and keeps its
                    // pass): admitting now would spend that pass for nothing.
                    if req.reply.is_closed() {
                        continue;
                    }
                    let answer = if req.pass.as_ref().is_some_and(|p| spent.contains(&p.tag)) {
                        Err((409, "this pass was already spent here; use another".to_string()))
                    } else {
                        // The leases are read afresh, under their lock, so
                        // an operator's `admit` or `revoke` is never undone.
                        // A 5xx answer tells the client to keep its pass; it
                        // is never given once the pass is spent and its key
                        // could still be admitted.
                        let admitted = Leases::update(|leases| {
                            if leases.find(&req.public_key).is_none()
                                && (leases.len() as u32 >= cfg.max_clients || !leases.has_room(&net))
                            {
                                return (Err((503, "this node is full; try another".to_string())), false);
                            }
                            // Written down as spent before its key is
                            // admitted, so a crash in between cannot let it
                            // be spent again.
                            if let Some(p) = &req.pass {
                                if let Err(e) = spent.record(p.tag.clone(), p.valid_until) {
                                    return (Err((503, format!("could not write the pass down: {e:#}"))), false);
                                }
                            }
                            let r = if req.pass.is_some() {
                                leases.admit_pass(&req.name, &req.public_key, &net)
                            } else {
                                leases.admit_open(&req.name, &req.public_key, &net, req.session)
                            };
                            match r {
                                Ok(lease) => (Ok((lease, leases.len())), true),
                                Err(e) => (Err((400, e.to_string())), false),
                            }
                        });
                        match admitted {
                            Ok(Ok((lease, count))) => match dev.add_peer(&lease.public_key, lease.ip) {
                                Ok(()) => {
                                    info!("admitted a client {} ({} leases)", if req.pass.is_some() { "with a pass" } else { "through the admission service" }, count);
                                    invite_for(&cfg, &lease).map_err(|e| (500, format!("{e:#}")))
                                }
                                Err(e) => Err((500, format!("could not admit: {e:#}"))),
                            },
                            Ok(Err(refused)) => Err(refused),
                            Err(e) => Err((503, format!("could not write the leases: {e:#}"))),
                        }
                    };
                    let _ = req.reply.send(answer);
                }
                _ = reaper.tick() => {
                    let pruned = spent.prune(hidravpn_core::timefmt::now_unix());
                    if pruned > 0 || spent.needs_compacting() {
                        if let Err(e) = spent.save() { warn!("saving spent passes: {e}"); }
                    }
                    {
                        match dev.peer_stats() {
                            Ok(stats) => {
                                let ages = stats.iter().map(|(k, s)| (k.clone(), s.last_handshake)).collect();
                                let now = crate::leases::now_unix();
                                let active = active_keys(&stats, &mut rx_seen);
                                match Leases::update(|leases| {
                                    let touched = leases.note_handshakes(now, &ages) | leases.note_traffic(now, &active);
                                    let gone = leases.expire_idle(now, &windows);
                                    let save = touched || !gone.is_empty();
                                    ((gone, leases.len()), save)
                                }) {
                                    Ok((gone, left)) => {
                                        for l in &gone { let _ = dev.remove_peer(&l.public_key); }
                                        if !gone.is_empty() {
                                            info!("{} idle client(s) expired ({} leases left)", gone.len(), left);
                                        }
                                    }
                                    Err(e) => warn!("saving leases: {e}"),
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
            let active = active_keys(&stats, &mut rx_seen);
            if let Err(e) = Leases::update(|leases| {
                let now = crate::leases::now_unix();
                let touched =
                    leases.note_handshakes(now, &ages) | leases.note_traffic(now, &active);
                ((), touched)
            }) {
                warn!("saving leases at shutdown: {e}");
            }
        }
        if let Err(e) = crate::nat::remove() {
            warn!("removing NAT rules: {e}");
        }
        if let Err(e) = crate::nat::restore_forwarding(forwarding_was_on) {
            warn!("restoring IPv4 forwarding: {e}");
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
