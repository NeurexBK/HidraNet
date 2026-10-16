#![deny(warnings)]

// =============================================================================
// HidraNet — Single-file consolidated binary
// Secure overlay network with Noise XX, onion routing, DHT, SOCKS5 proxy
// =============================================================================

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use clap::Parser;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use tracing::{debug, info, warn};
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;
use crate::safelog::sensitive;

// ─────────────────────────────────────────────────────────────────────────────
// mod error
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library. These two were byte-identical.
#[path = "error.rs"]
mod error;

// ─────────────────────────────────────────────────────────────────────────────
// mod logging
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library. These two were byte-identical.
#[path = "logging.rs"]
mod logging;

// ─────────────────────────────────────────────────────────────────────────────
// mod config
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library rather than inlined. It was inlined under a
// different name, `app_config`, which is why the two never looked like the
// duplicates they were.
#[path = "config.rs"]
mod config;

// ─────────────────────────────────────────────────────────────────────────────
// mod crypto
// ─────────────────────────────────────────────────────────────────────────────
#[path = "crypto/mod.rs"]
mod crypto;

// ─────────────────────────────────────────────────────────────────────────────
// mod network
// ─────────────────────────────────────────────────────────────────────────────
#[path = "network/mod.rs"]
mod network;

// ─────────────────────────────────────────────────────────────────────────────
// mod onion
// ─────────────────────────────────────────────────────────────────────────────
#[path = "onion/mod.rs"]
mod onion;

// ─────────────────────────────────────────────────────────────────────────────
// mod p2p
// ─────────────────────────────────────────────────────────────────────────────
#[path = "p2p/mod.rs"]
mod p2p;

// ─────────────────────────────────────────────────────────────────────────────
// mod relay
// ─────────────────────────────────────────────────────────────────────────────
#[path = "relay/mod.rs"]
mod relay;

// ─────────────────────────────────────────────────────────────────────────────
// mod proxy
// ─────────────────────────────────────────────────────────────────────────────
#[path = "proxy/mod.rs"]
mod proxy;

// ─────────────────────────────────────────────────────────────────────────────
// mod client
// ─────────────────────────────────────────────────────────────────────────────
#[path = "client/mod.rs"]
mod client;

// ─────────────────────────────────────────────────────────────────────────────
// mod local_guard
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library target rather than inlined a second time: this is
// the screening every loopback server runs on an incoming request, and a copy
// that drifts is a copy that stops screening.
#[path = "local_guard.rs"]
mod local_guard;

#[path = "safelog.rs"]
mod safelog;

// ─────────────────────────────────────────────────────────────────────────────
// mod api
// ─────────────────────────────────────────────────────────────────────────────
// Shared with the library rather than inlined a second time. This endpoint
// decides what the outside world learns about a live circuit, and a copy
// that drifts is a copy that goes on answering the old way.
#[path = "api.rs"]
mod api;

// =============================================================================
// mod apps — HidraNet decentralized applications
// =============================================================================
// The three apps the node can serve. hidramail lived inline here, beside two
// siblings that were already files — which is why it was the only one the
// library could not reach, and the only one with no tests.
#[path = "apps/mod.rs"]
mod apps;

// =============================================================================
// mod search — HidraSearch: encrypted, uncensored search engine
// =============================================================================
// Lives in its own file rather than inline, so the library can reach it and
// its tests run against the code that ships. It was binary-only, which is
// how it ended up with no tests at all.
#[path = "search/mod.rs"]
mod search;

// =============================================================================
// mod analytics — Local network analytics dashboard
// =============================================================================
// Lives in its own file rather than inline, so the library can reach it and
// its tests run against the code that ships. It was binary-only, which is
// how it ended up with no tests at all.
#[path = "analytics/mod.rs"]
mod analytics;

// =============================================================================
// mod security — Defense-in-depth: rate limiting, PoW, traffic obfuscation,
//                post-quantum crypto, encrypted storage, system hardening
// =============================================================================
#[allow(dead_code)]
// Lives in its own file rather than inline, so the library can reach it and
// its tests run against the code that ships. It was binary-only, which is
// how it ended up with no tests at all.
#[path = "security/mod.rs"]
mod security;

// =============================================================================
// CLI & main
// =============================================================================

#[derive(Parser)]
#[command(
    name = "hidra-node",
    about = "HidraNet secure relay node",
    version
)]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(short = 'C', long)]
    connect: Option<String>,

    #[arg(short, long)]
    send: Option<String>,

    #[arg(long)]
    dht_discover: bool,

    #[arg(long)]
    proxy: bool,

    #[arg(long)]
    server: bool,

    #[arg(long, help = "Run HidraChat server standalone on local port (for testing)")]
    chat: bool,

    #[arg(long, help = "Run HidraMail server standalone on local port (for testing)")]
    mail: bool,

    #[arg(long, help = "Run both HidraMail (port 8080) and HidraChat (port 8081) standalone")]
    apps: bool,

    #[arg(long, help = "Run analytics dashboard on port 8082")]
    dashboard: bool,

    #[arg(long, help = "Run SevenNine.hidra website builder on port 8084")]
    sevennine: bool,
}

const LOCAL_RELAY_PORTS: [u16; 3] = [7001, 7002, 7003];
const API_PORT: u16 = 9051;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    security::hardening::zeroize_on_panic();
    let _ = security::hardening::disable_core_dumps();

    let app_cfg = config::load_config(&cli.config)?;

    // Logging comes up before the keys are touched. It used to be the other
    // way round, which silently threw away everything loading the keys has to
    // say — including the warning that a secret on disk is readable by other
    // accounts, which is the one message on this path nobody can afford to
    // miss.
    safelog::set_unsafe_logging(app_cfg.logging.unsafe_addresses);
    logging::init_logging(&app_cfg.logging.level, &app_cfg.logging.format);
    if app_cfg.logging.unsafe_addresses {
        tracing::warn!(
            "unsafe_addresses is on: this log will record who connected to this \
             node and, at an exit, the hostnames they asked for. Turn it off \
             on anything carrying other people's traffic."
        );
    }

    let keys =
        crypto::keys::NodeKeys::load_or_generate(Path::new(&app_cfg.paths.keys_dir))?;
    let node_id = keys.node_id.clone();

    let _root = tracing::info_span!("hidra_node", node_id = %node_id).entered();

    info!(
        name = %app_cfg.node.name,
        noise_pubkey = %base64::engine::general_purpose::STANDARD
            .encode(keys.noise_static_public.as_bytes()),
        "node initialized"
    );

    let mut secret_bytes = keys.noise_static_secret.to_bytes();
    let network_secret = StaticSecret::from(secret_bytes);
    secret_bytes.zeroize();

    let signing_key = SigningKey::from_bytes(&keys.identity_signing.to_bytes());

    if cli.sevennine {
        run_sevennine_mode(&app_cfg).await?;
    } else if cli.dashboard {
        run_dashboard_mode(&app_cfg).await?;
    } else if cli.apps {
        run_apps_standalone(&app_cfg, signing_key).await?;
    } else if cli.mail {
        run_mail_standalone(&app_cfg, signing_key).await?;
    } else if cli.chat {
        run_chat_standalone(&app_cfg).await?;
    } else if cli.server {
        run_server_mode(&app_cfg, network_secret, signing_key).await?;
    } else if cli.proxy {
        run_proxy_mode(&app_cfg, network_secret, signing_key).await?;
    } else if let Some(ref payload) = cli.send {
        run_send_mode(&app_cfg, network_secret, signing_key, payload, cli.dht_discover)
            .await?;
    } else if let Some(ref peer_addr) = cli.connect {
        let addr: SocketAddr = peer_addr.parse()?;
        network::listener::connect_to_peer(addr, network_secret).await?;
    } else {
        run_relay_mode(&app_cfg, network_secret, signing_key).await?;
    }

    info!("node stopped");
    Ok(())
}

async fn spawn_local_relays(
) -> std::result::Result<Vec<relay::registry::RelayEntry>, Box<dyn std::error::Error>> {
    let mut entries = Vec::with_capacity(LOCAL_RELAY_PORTS.len());

    for (i, &port) in LOCAL_RELAY_PORTS.iter().enumerate() {
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

        let mut rng_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rng_bytes);
        let relay_secret = StaticSecret::from(rng_bytes);
        rng_bytes.zeroize();

        let listener = network::listener::NodeListener::bind(addr, relay_secret).await?;
        let relay_num = i + 1;

        info!(relay = relay_num, addr = %addr, "local relay node started");

        tokio::spawn(async move {
            if let Err(e) = listener.accept_loop().await {
                tracing::error!(relay = relay_num, error = %e, "local relay error");
            }
        });

        entries.push(relay::registry::RelayEntry {
            name: format!("local-relay-{relay_num}"),
            addr,
            noise_pubkey_b64: String::new(),
        });
    }

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    info!(
        count = entries.len(),
        ports = ?LOCAL_RELAY_PORTS,
        "all local relay nodes ready"
    );

    Ok(entries)
}

/// Room passphrase for a standalone chat server.
///
/// It used to be the literal `"hidrachat-standalone-test"`, compiled into
/// every copy of the binary, and in hidden-service mode it was
/// `format!("hidrachat-{hidra_address}")` — derived entirely from the address
/// the service publishes, so knowing where the room was meant knowing how to
/// get in. Both are now replaced by a value read from `HIDRA_CHAT_PASSPHRASE`
/// or, failing that, generated fresh and printed once for the operator to
/// hand out.
fn chat_room_passphrase() -> String {
    if let Ok(p) = std::env::var("HIDRA_CHAT_PASSPHRASE")
        && !p.is_empty()
    {
        return p;
    }
    let mut bytes = [0u8; 18];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    let generated = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    warn!(
        "no HIDRA_CHAT_PASSPHRASE set — generated one for this run: {generated}"
    );
    warn!("share it with the people you want in the room; it changes on restart");
    generated
}

async fn run_apps_standalone(
    app_cfg: &config::AppConfig,
    signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mail_port: u16 = 8080;
    let chat_port: u16 = 8081;

    let mail_addr: SocketAddr = format!("127.0.0.1:{mail_port}").parse()?;
    // Loopback only. Bound to 0.0.0.0 the room was reachable from every
    // machine on the network, and the WebSocket asks for no credential: a
    // stranger on the same Wi-Fi could join, read the backlog and list users.
    let chat_addr: SocketAddr = format!("127.0.0.1:{chat_port}").parse()?;

    let keys_dir = std::path::Path::new(&app_cfg.paths.keys_dir);
    let mail_keys = apps::hidramail::crypto::MailKeys::load_or_generate(keys_dir)?;
    let mail_name = app_cfg
        .hidden_service
        .mail_name
        .as_deref()
        .unwrap_or("local");
    let mail_addr_str = format!("{mail_name}@standalone.hidra");
    let mail_dir = keys_dir.join("mail_store");
    let store = apps::hidramail::storage::MailStore::new(&mail_dir)?;
    let state = apps::hidramail::server::ServerState {
        mail_addr: mail_addr_str.clone(),
        mail_keys,
        signing_key,
        store,
    };
    let mail_server = apps::hidramail::server::MailServer::new(mail_addr, state);

    let room_name = "hidrachat-local".to_string();
    let passphrase = chat_room_passphrase();
    let chat_server = apps::hidrachat::server::ChatServer::new(
        chat_addr,
        room_name,
        &passphrase,
    );

    let search_port: u16 = 8083;
    let search_addr: SocketAddr = format!("127.0.0.1:{search_port}").parse()?;
    let search_server = search::engine::SearchServer::new(search_addr, None);
    tokio::spawn(async move {
        if let Err(e) = search_server.run().await {
            tracing::error!(error = %e, "HidraSearch error");
        }
    });

    let sevennine_port: u16 = 8084;
    let sevennine_data = std::path::PathBuf::from(&app_cfg.paths.keys_dir)
        .parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
    let sn_data = sevennine_data.clone();
    tokio::spawn(async move {
        // Loopback only: binding 0.0.0.0 published the site builder to every
        // machine on the local network.
        if let Err(e) = apps::sevennine::run_sevennine("127.0.0.1", sevennine_port, &sn_data).await {
            tracing::error!(error = %e, "SevenNine error");
        }
    });

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraNet Apps — local mode                                ║");
    info!("║  HidraMail:     http://127.0.0.1:{mail_port}                      ║");
    info!("║  HidraChat:     http://127.0.0.1:{chat_port}                      ║");
    info!("║  HidraSearch:   http://127.0.0.1:{search_port}                      ║");
    info!("║  SevenNine:     http://127.0.0.1:{sevennine_port}                    ║");
    info!("║  Address:       {}", mail_addr_str);
    info!("╚══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        result = mail_server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraMail error");
            }
        }
        result = chat_server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraChat error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_dashboard_mode(
    app_cfg: &config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dashboard_port: u16 = 8082;
    let dashboard_addr: SocketAddr = format!("127.0.0.1:{dashboard_port}").parse()?;

    let db_path = std::path::Path::new(&app_cfg.paths.keys_dir).join("analytics.db");
    let db = std::sync::Arc::new(analytics::storage::AnalyticsDb::open(&db_path)?);

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraNet Analytics Dashboard                              ║");
    info!("║  Dashboard:  http://127.0.0.1:{dashboard_port}                        ║");
    info!("║  API:        http://127.0.0.1:{dashboard_port}/api/stats              ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    let collector_db = std::sync::Arc::clone(&db);
    tokio::spawn(async move {
        analytics::collector::run_collector(collector_db, 30).await;
    });

    tokio::select! {
        result = analytics::dashboard::run_dashboard(dashboard_addr, db) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "dashboard error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_chat_standalone(
    app_cfg: &config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let local_port = app_cfg.hidden_service.local_port;
    let chat_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse()?;
    let room_name = "hidrachat-local".to_string();
    let passphrase = chat_room_passphrase();
    let chat_server = apps::hidrachat::server::ChatServer::new(
        chat_addr,
        room_name,
        &passphrase,
    );

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraChat standalone: http://127.0.0.1:{}", local_port);
    info!("║  Local mode (no onion routing) — for testing");
    info!("╚══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        result = chat_server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraChat error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_mail_standalone(
    app_cfg: &config::AppConfig,
    signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let local_port = app_cfg.hidden_service.local_port;
    let mail_addr_str = format!("127.0.0.1:{local_port}");
    let mail_sock: SocketAddr = mail_addr_str.parse()?;

    let keys_dir = std::path::Path::new(&app_cfg.paths.keys_dir);
    let mail_keys = apps::hidramail::crypto::MailKeys::load_or_generate(keys_dir)?;

    let mail_name = app_cfg
        .hidden_service
        .mail_name
        .as_deref()
        .unwrap_or("local");
    let mail_addr = format!("{mail_name}@standalone.hidra");

    let mail_dir = keys_dir.join("mail_store");
    let store = apps::hidramail::storage::MailStore::new(&mail_dir)?;

    let state = apps::hidramail::server::ServerState {
        mail_addr: mail_addr.clone(),
        mail_keys,
        signing_key,
        store,
    };
    let server = apps::hidramail::server::MailServer::new(mail_sock, state);

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  HidraMail standalone: http://127.0.0.1:{}", local_port);
    info!("║  Address: {}", mail_addr);
    info!("║  Local mode (no onion routing) — for testing");
    info!("╚══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HidraMail error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }
    Ok(())
}

async fn run_server_mode(
    app_cfg: &config::AppConfig,
    _network_secret: StaticSecret,
    _signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::crypto::keys::ServiceKeys;

    info!("=== HidraNet Hidden Service Mode ===");

    let service_keys = ServiceKeys::load_or_generate(
        Path::new(&app_cfg.paths.keys_dir),
    )?;
    let hidra_address = &service_keys.address;
    let service_hash = service_keys.address_hash;

    info!(
        address = %sensitive(&hidra_address),
        "hidden service identity loaded"
    );

    info!("spawning local relay nodes...");
    let local_relays = spawn_local_relays().await?;

    let dht_addr: SocketAddr = format!("0.0.0.0:{}", app_cfg.dht.port).parse()?;
    let dht_signing_key = ed25519_dalek::SigningKey::generate(
        &mut rand_core::OsRng,
    );
    let mut dht = p2p::dht::DhtNode::new(dht_addr, dht_signing_key, None).await?;
    dht.start().await;

    let bootstrap_addrs: Vec<SocketAddr> = app_cfg
        .dht
        .bootstrap_nodes
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    if !bootstrap_addrs.is_empty() {
        if let Err(e) = p2p::bootstrap::bootstrap(&dht, &bootstrap_addrs).await {
            warn!(error = %e, "DHT bootstrap failed");
        }
    }

    let mut config_relays = relay::registry::load_relay_list(&app_cfg.relays).unwrap_or_default();
    for lr in &local_relays {
        if !config_relays.iter().any(|r| r.addr == lr.addr) {
            config_relays.push(lr.clone());
        }
    }
    let relays = if config_relays.len() >= 3 {
        config_relays
    } else {
        local_relays.clone()
    };

    if relays.len() < 3 {
        return Err("need at least 3 relays for hidden service".into());
    }

    let local_port = app_cfg.hidden_service.local_port;

    let intro_addr = relays[0].addr;
    // Signed by the service's own key: a node on the lookup path can
    // withhold this descriptor but not swap its introduction points.
    if let Err(e) = dht.announce_signed_service(
        &service_keys.signing_key,
        vec![intro_addr],
    )
    .await {
        warn!(error = %e, "failed to announce service in DHT, continuing with local registration");
    }

    info!(
        intro_point = %intro_addr,
        "announced service in DHT"
    );

    let mut server_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut server_secret_bytes);
    let server_secret = StaticSecret::from(server_secret_bytes);
    server_secret_bytes.zeroize();

    info!("building circuit to introduction point...");
    let mut intro_circuit = client::streaming::StreamingCircuit::build(
        &relays,
        server_secret,
    )
    .await?;

    intro_circuit.register_service(service_hash.to_vec()).await?;
    info!("registered at introduction point");

    let app_name = app_cfg.hidden_service.app.as_deref();

    if app_name == Some("hidrachat") {
        // Tor reaches the service over loopback. Bound to 0.0.0.0 the same
        // service also answered on the public interface, so anyone scanning
        // the host's IP found the thing the hidden service exists to hide.
        let chat_addr: SocketAddr = format!("127.0.0.1:{local_port}").parse()?;
        let room_name = hidra_address.replace(".hidra", "");
        // Was format!("hidrachat-{hidra_address}"): the address is published,
        // so the passphrase was public too and gated nothing.
        let passphrase = chat_room_passphrase();
        let chat_server = apps::hidrachat::server::ChatServer::new(
            chat_addr,
            room_name,
            &passphrase,
        );
        tokio::spawn(async move {
            if let Err(e) = chat_server.run().await {
                tracing::error!(error = %e, "HidraChat server error");
            }
        });
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  HidraChat is available at: http://{}", hidra_address);
        info!("║  Encrypted chat room — local port: {}", local_port);
        info!("╚══════════════════════════════════════════════════════════════╝");
    } else if app_name == Some("hidramail") {
        let mail_sock: SocketAddr = format!("127.0.0.1:{local_port}").parse()?;
        let keys_dir = std::path::Path::new(&app_cfg.paths.keys_dir);
        let mail_keys = apps::hidramail::crypto::MailKeys::load_or_generate(keys_dir)?;
        let mail_name = app_cfg
            .hidden_service
            .mail_name
            .as_deref()
            .unwrap_or("anon");
        let mail_addr = format!("{mail_name}@{hidra_address}");
        let mail_dir = keys_dir.join("mail_store");
        let store = apps::hidramail::storage::MailStore::new(&mail_dir)?;
        let mail_signing = SigningKey::from_bytes(&_signing_key.to_bytes());
        let state = apps::hidramail::server::ServerState {
            mail_addr: mail_addr.clone(),
            mail_keys,
            signing_key: mail_signing,
            store,
        };
        let mail_server = apps::hidramail::server::MailServer::new(mail_sock, state);
        tokio::spawn(async move {
            if let Err(e) = mail_server.run().await {
                tracing::error!(error = %e, "HidraMail server error");
            }
        });
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  HidraMail is available at: http://{}", hidra_address);
        info!("║  Address: {}", mail_addr);
        info!("║  Porta local: {}", local_port);
        info!("╚══════════════════════════════════════════════════════════════╝");
    } else if app_name == Some("sevennine") {
        let sevennine_port = local_port;
        let data_dir = std::path::PathBuf::from(&app_cfg.paths.keys_dir)
            .parent().unwrap_or(std::path::Path::new(".")).to_path_buf();
        let sn_data = data_dir.clone();
        let (dht_tx, mut dht_rx) = tokio::sync::mpsc::channel::<apps::sevennine::DhtAnnouncement>(64);
        tokio::spawn(async move {
            let manager = std::sync::Arc::new(
                apps::sevennine::SiteManager::new_with_dht(&sn_data, dht_tx, sevennine_port)
            );
            // Re-announce existing sites to DHT on startup
            manager.announce_all_sites().await;
            // Loopback only, as in run_apps_standalone: on 0.0.0.0 the site
            // builder was published to every machine on the local network.
            let listener = match tokio::net::TcpListener::bind(
                format!("127.0.0.1:{sevennine_port}")
            ).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, "SevenNine bind failed");
                    return;
                }
            };
            tracing::info!("SevenNine.hidra listening on port {}", sevennine_port);
            loop {
                if let Ok((stream, _)) = listener.accept().await {
                    let mgr = manager.clone();
                    tokio::spawn(apps::sevennine::handle_connection_pub(stream, mgr));
                }
            }
        });
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  SevenNine.hidra — Decentralised site builder              ║");
        info!("║  Address:    http://{}", hidra_address);
        info!("║  Local:      http://127.0.0.1:{}", local_port);
        info!("║  Every site created is published to the DHT automatically  ║");
        info!("╚══════════════════════════════════════════════════════════════╝");

        // Process DHT announcements from SevenNine in the service loop
        let sn_intro_addr = intro_addr;
        tokio::spawn(async move {
            while let Some(announcement) = dht_rx.recv().await {
                match announcement {
                    apps::sevennine::DhtAnnouncement::Publish { service_hash, service_key } => {
                        if let Err(e) = dht.announce_signed_service(
                            &service_key,
                            vec![sn_intro_addr],
                        ).await {
                            tracing::warn!(error = %e, "failed to publish site to DHT");
                        } else {
                            let hex: String = service_hash.iter().map(|b| format!("{b:02x}")).collect();
                            tracing::info!(address = %sensitive(&hex), "site announced in DHT");
                        }
                    }
                    apps::sevennine::DhtAnnouncement::Withdraw { service_hash } => {
                        dht.withdraw_service(&service_hash).await;
                        tracing::info!("site withdrawn from DHT republishing");
                    }
                }
            }
        });
    } else {
        info!("╔══════════════════════════════════════════════════════════════╗");
        info!("║  Your site is available at: http://{}", hidra_address);
        info!("║  Porta local: {}", local_port);
        info!("╚══════════════════════════════════════════════════════════════╝");
    }

    // Service loop: receive client data from intro point, forward to local server
    loop {
        tokio::select! {
            data_result = intro_circuit.recv_data() => {
                match data_result {
                    Ok(Some(data)) => {
                        let local_addr = format!("127.0.0.1:{local_port}");
                        match tokio::net::TcpStream::connect(&local_addr).await {
                            Ok(mut local_stream) => {
                                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                                if local_stream.write_all(&data).await.is_ok() {
                                    let mut response_buf = vec![0u8; 16384];
                                    match local_stream.read(&mut response_buf).await {
                                        Ok(0) => {}
                                        Ok(n) => {
                                            let _ = intro_circuit.send_data(&response_buf[..n]).await;
                                        }
                                        Err(e) => {
                                            debug!(error = %e, "local server read error");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, local_port, "failed to connect to local server");
                            }
                        }
                    }
                    Ok(None) => {
                        info!("intro circuit closed, reconnecting...");
                        break;
                    }
                    Err(e) => {
                        warn!(error = %e, "intro circuit error");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received shutdown signal");
                break;
            }
        }
    }

    Ok(())
}

async fn run_proxy_mode(
    app_cfg: &config::AppConfig,
    _network_secret: StaticSecret,
    _signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    info!("=== HidraNet Proxy Mode ===");
    info!("spawning local relay nodes for onion routing...");

    let local_relays = spawn_local_relays().await?;
    let relay_addrs: Vec<SocketAddr> = local_relays.iter().map(|r| r.addr).collect();

    let proxy_addr: SocketAddr =
        format!("{}:{}", app_cfg.proxy.listen_addr, app_cfg.proxy.port).parse()?;

    // Port 0, not the configured one. A client has no reason to run a
    // predictable, scannable service: on a fixed port, anyone who sweeps the
    // internet for it gets a list of this network's users by IP, and "is a
    // HidraNet user" is in many situations the whole thing a user needs
    // hidden. An ephemeral port still sends queries and still receives the
    // replies; it just is not something you can go looking for.
    //
    // It does not hide the address from a DHT peer that is contacted
    // directly. Routing lookups through a circuit is the fix for that, and it
    // is not done yet — see SECURITY.md.
    let dht_addr: SocketAddr = "0.0.0.0:0".parse()?;

    let bootstrap_addrs: Vec<SocketAddr> = app_cfg
        .dht
        .bootstrap_nodes
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    let mut config_relays = relay::registry::load_relay_list(&app_cfg.relays).unwrap_or_default();

    for lr in &local_relays {
        if !config_relays.iter().any(|r| r.addr == lr.addr) {
            config_relays.push(lr.clone());
        }
    }

    let static_relays = if config_relays.len() >= 3 {
        config_relays
    } else {
        local_relays.clone()
    };

    let mut proxy_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut proxy_secret_bytes);

    let proxy_config = client::proxy_runner::ProxyConfig {
        listen_addr: proxy_addr,
        dht_addr,
        bootstrap_addrs,
        secret_bytes: proxy_secret_bytes,
        static_relays,
    };

    proxy_secret_bytes.zeroize();

    let api_addr: SocketAddr = format!("127.0.0.1:{API_PORT}").parse()?;
    // The circuit view needs a token the engine leaves in the keys
    // directory. A page in a browser cannot read a local file, so even a
    // failure in the Host/Origin screening does not get it the relays.
    let api_token = api::issue_token(std::path::Path::new(&app_cfg.paths.keys_dir));
    let api_state = Arc::new(api::ApiState::new(
        Instant::now(),
        relay_addrs.len(),
        relay_addrs,
        3,
        api_token,
    ));

    tokio::spawn({
        let state = Arc::clone(&api_state);
        async move {
            api::run_api_server(api_addr, state).await;
        }
    });

    info!(
        proxy_addr = %proxy_addr,
        api_addr = %api_addr,
        "SOCKS5 proxy starting — configure your browser to use socks5://127.0.0.1:{}",
        app_cfg.proxy.port
    );

    info!(
        "test with: curl --socks5-hostname 127.0.0.1:{} https://check.torproject.org/",
        app_cfg.proxy.port
    );

    tokio::select! {
        result = client::proxy_runner::run_proxy(proxy_config) => {
            if let Err(e) = result {
                tracing::error!(error = %e, "proxy error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal — shutting down gracefully");
        }
    }

    Ok(())
}

async fn run_send_mode(
    app_cfg: &config::AppConfig,
    network_secret: StaticSecret,
    signing_key: SigningKey,
    payload: &str,
    dht_discover: bool,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    if dht_discover && app_cfg.dht.enabled {
        // Ephemeral, as in proxy mode: a one-shot send is a client.
        let dht_addr: SocketAddr = "0.0.0.0:0".parse()?;
        let mut dht = p2p::dht::DhtNode::new(dht_addr, signing_key, None).await?;
        dht.start().await;

        let bootstrap_addrs: Vec<SocketAddr> = app_cfg
            .dht
            .bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        p2p::bootstrap::bootstrap(&dht, &bootstrap_addrs).await?;

        let relays = dht.find_relays(3).await?;
        if relays.len() < 3 {
            eprintln!("ERROR: DHT found only {} relays, need 3", relays.len());
            std::process::exit(1);
        }

        let relay_entries: Vec<relay::registry::RelayEntry> = relays
            .into_iter()
            .map(|r| relay::registry::RelayEntry {
                name: format!("{}", r.id),
                addr: r.relay_addr.unwrap_or(r.dht_addr),
                noise_pubkey_b64: String::new(),
            })
            .collect();

        info!(relays = relay_entries.len(), "discovered relays via DHT");

        let response =
            client::session::run_client_session(&relay_entries, network_secret, payload)
                .await?;

        info!(bytes = response.len(), "onion circuit complete (DHT discovery)");
    } else {
        let relay_list = relay::registry::load_relay_list(&app_cfg.relays)?;

        if relay_list.len() < 3 {
            eprintln!(
                "ERROR: need at least 3 relays in config, found {}",
                relay_list.len()
            );
            std::process::exit(1);
        }

        info!(
            relays = relay_list.len(),
            bytes = payload.len(),
            "starting client onion session"
        );

        let response =
            client::session::run_client_session(&relay_list, network_secret, payload)
                .await?;

        info!(bytes = response.len(), "onion circuit complete");
    }

    Ok(())
}

async fn run_relay_mode(
    app_cfg: &config::AppConfig,
    network_secret: StaticSecret,
    signing_key: SigningKey,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let listen_addr = format!(
        "{}:{}",
        app_cfg.network.listen_addr, app_cfg.network.listen_port
    );
    let addr: SocketAddr = listen_addr.parse()?;

    let relay_addr = Some(addr);

    let dht_node = if app_cfg.dht.enabled {
        let dht_addr: SocketAddr =
            format!("{}:{}", app_cfg.network.listen_addr, app_cfg.dht.port).parse()?;
        let mut dht = p2p::dht::DhtNode::new(dht_addr, signing_key, relay_addr).await?;
        dht.start().await;

        let bootstrap_addrs: Vec<SocketAddr> = app_cfg
            .dht
            .bootstrap_nodes
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        if let Err(e) = p2p::bootstrap::bootstrap(&dht, &bootstrap_addrs).await {
            tracing::warn!(error = %e, "DHT bootstrap failed");
        }

        if let Err(e) = dht.announce_relay().await {
            tracing::debug!(
                error = %e,
                "initial relay announcement skipped (no peers yet)"
            );
        }

        Some(dht)
    } else {
        None
    };

    let listener = network::listener::NodeListener::bind(addr, network_secret).await?;
    info!(addr = %addr, "listening for inbound connections");

    tokio::select! {
        result = listener.accept_loop() => {
            if let Err(e) = result {
                tracing::error!(error = %e, "listener error");
            }
        }
        _ = async {
            if let Some(ref dht) = dht_node {
                p2p::discovery::run_maintenance_loop(dht).await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {}
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal — shutting down gracefully");
        }
    }

    Ok(())
}

async fn run_sevennine_mode(
    cfg: &config::AppConfig,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let data_dir = std::path::PathBuf::from(&cfg.paths.keys_dir).parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    info!("╔═══════════════════════════════════════════════════════════════╗");
    info!("║  SevenNine.hidra — Decentralised site builder               ║");
    info!("║  Open: http://127.0.0.1:8084                               ║");
    info!("╚═══════════════════════════════════════════════════════════════╝");

    tokio::select! {
        // Loopback only — the banner above already promises 127.0.0.1.
        result = apps::sevennine::run_sevennine("127.0.0.1", 8084, &data_dir) => {
            if let Err(e) = result {
                tracing::error!("SevenNine error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SevenNine shutting down");
        }
    }

    Ok(())
}

// =============================================================================
// Tests — Security modules
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pow_solve_and_verify() {
        let challenge = security::pow::generate_challenge(8);
        let solution = security::pow::solve_challenge(&challenge)
            .expect("should solve PoW with difficulty 8");
        security::pow::verify_solution(&challenge, &solution, 300)
            .expect("valid solution should verify");
    }

    #[test]
    fn test_pow_rejects_bad_solution() {
        let challenge = security::pow::generate_challenge(16);
        let bad = security::pow::PowSolution {
            nonce: 0,
            hash: [0xFF; 32],
        };
        assert!(security::pow::verify_solution(&challenge, &bad, 300).is_err());
    }

    #[test]
    fn test_traffic_pad_unpad_roundtrip() {
        let original = b"Hidra secret message";
        let padded = security::traffic::pad_message(original)
            .expect("pad should succeed");
        assert_eq!(padded.len(), security::traffic::PADDED_CELL_SIZE);
        let recovered = security::traffic::unpad_message(&padded)
            .expect("unpad should succeed");
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_traffic_chaff_detection() {
        let chaff = security::traffic::generate_chaff();
        assert!(security::traffic::is_chaff(&chaff));
        assert_eq!(chaff.len(), security::traffic::PADDED_CELL_SIZE);
        assert!(security::traffic::unpad_message(&chaff).is_err());
    }

    #[test]
    fn test_vault_encrypt_decrypt_roundtrip() {
        let passphrase = b"super-secret-passphrase-42";
        let data = b"private key material here";
        let config = security::vault::VaultConfig::default();

        let sealed = security::vault::vault_encrypt(passphrase, data, &config)
            .expect("encrypt should succeed");
        let recovered = security::vault::vault_decrypt(passphrase, &sealed, &config)
            .expect("decrypt should succeed");
        assert_eq!(recovered, data);
    }

    #[test]
    fn test_vault_wrong_passphrase_fails() {
        let data = b"private key material";
        let config = security::vault::VaultConfig::default();

        let sealed = security::vault::vault_encrypt(b"correct", data, &config)
            .expect("encrypt should succeed");
        let result = security::vault::vault_decrypt(b"wrong", &sealed, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_tampered_data_fails() {
        let passphrase = b"my-passphrase";
        let data = b"secret";
        let config = security::vault::VaultConfig::default();

        let mut sealed = security::vault::vault_encrypt(passphrase, data, &config)
            .expect("encrypt should succeed");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert!(security::vault::vault_decrypt(passphrase, &sealed, &config).is_err());
    }

    #[test]
    fn test_post_quantum_hybrid_roundtrip() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");
        let peer_x25519_public = keys.x25519_public;

        let (shared_enc, encapsulation) = security::post_quantum::hybrid_encapsulate(
            &peer_x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate should succeed");

        let shared_dec = security::post_quantum::hybrid_decapsulate(&keys, &encapsulation)
            .expect("decapsulate should succeed");

        assert_eq!(shared_enc.as_bytes(), shared_dec.as_bytes());
    }

    /// ML-KEM answers a tampered ciphertext with an unrelated key instead of
    /// an error (Fujisaki-Okamoto implicit rejection). That is the property
    /// pqc_kyber's AVX2 backend dropped, and losing it is what let a
    /// chosen-ciphertext attacker walk the decapsulation key out one query at
    /// a time. Assert the derived key diverges rather than matching.
    #[test]
    fn test_post_quantum_tampered_ciphertext_does_not_recover_key() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");

        let (shared_enc, mut encapsulation) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate should succeed");

        encapsulation.kyber_ciphertext[0] ^= 0x01;

        let shared_dec = security::post_quantum::hybrid_decapsulate(&keys, &encapsulation)
            .expect("implicit rejection returns a key, it does not fail");

        assert_ne!(shared_enc.as_bytes(), shared_dec.as_bytes());
    }

    /// The combiner hashes the transcript, not just the two secrets, so the
    /// same ML-KEM ciphertext replayed under a different X25519 ephemeral
    /// cannot land on the session key it was captured from.
    #[test]
    fn test_post_quantum_transcript_is_bound_to_session_key() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");

        let (shared_enc, mut encapsulation) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate should succeed");

        encapsulation.x25519_ephemeral_public[0] ^= 0x01;

        let shared_dec = security::post_quantum::hybrid_decapsulate(&keys, &encapsulation)
            .expect("decapsulate should succeed");

        assert_ne!(shared_enc.as_bytes(), shared_dec.as_bytes());
    }

    /// A malformed encapsulation key is refused outright rather than being
    /// encapsulated to.
    #[test]
    fn test_post_quantum_rejects_malformed_encapsulation_key() {
        let keys = security::post_quantum::HybridKeyPair::generate()
            .expect("keygen should succeed");

        let truncated = &keys.kyber_public[..keys.kyber_public.len() - 1];
        assert!(
            security::post_quantum::hybrid_encapsulate(&keys.x25519_public, truncated).is_err()
        );
        assert!(
            security::post_quantum::hybrid_encapsulate(&keys.x25519_public, &[]).is_err()
        );
    }

    /// Two independent handshakes must never agree on a key.
    #[test]
    fn test_post_quantum_distinct_sessions_differ() {
        let keys = security::post_quantum::HybridKeyPair::generate().expect("keygen");

        let (a, _) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate");
        let (b, _) = security::post_quantum::hybrid_encapsulate(
            &keys.x25519_public,
            &keys.kyber_public,
        )
        .expect("encapsulate");

        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = [0x42u8; 32];
        let b = [0x42u8; 32];
        let c = [0x43u8; 32];
        assert!(security::hardening::constant_time_compare(&a, &b));
        assert!(!security::hardening::constant_time_compare(&a, &c));
    }

    #[test]
    fn test_rate_limiter_allows_burst() {
        let limiter = security::rate_limiter::RateLimiter::new(
            security::rate_limiter::RateLimitConfig {
                max_requests_per_sec: 10.0,
                burst_size: 5.0,
                max_connections_per_ip: 8,
                max_violations_before_ban: 100,
                ban_duration: std::time::Duration::from_secs(60),
                cleanup_interval: std::time::Duration::from_secs(60),
            },
        );
        let ip: std::net::IpAddr = "192.168.1.1".parse().expect("valid IP");
        for _ in 0..5 {
            limiter.check_rate_limit(ip).expect("should allow within burst");
        }
        assert!(limiter.check_rate_limit(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_connection_limit() {
        let limiter = security::rate_limiter::RateLimiter::new(
            security::rate_limiter::RateLimitConfig {
                max_connections_per_ip: 2,
                ..security::rate_limiter::RateLimitConfig::default()
            },
        );
        let ip: std::net::IpAddr = "10.0.0.1".parse().expect("valid IP");
        limiter.track_connection(ip).expect("conn 1");
        limiter.track_connection(ip).expect("conn 2");
        assert!(limiter.track_connection(ip).is_err());
        limiter.release_connection(ip);
        limiter.track_connection(ip).expect("conn after release");
    }

    #[test]
    fn test_secure_random_bytes_nonzero() {
        let mut buf = [0u8; 32];
        security::hardening::secure_random_bytes(&mut buf);
        assert_ne!(buf, [0u8; 32]);
    }
}
