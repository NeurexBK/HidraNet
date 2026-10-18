//! `hidra-relay`: the project's own relay for the chat and the forum.
//!
//! A separate binary on purpose: it shares the library with `hidra-node`
//! but none of its start-up (keys, circuits, DHT), so it can run on a small
//! machine of its own, behind a reverse proxy that provides TLS. Everything
//! it does is in `hidra_node::apps::hidrarelay`.
//!
//!   hidra-relay --listen 127.0.0.1:1884 --data /var/lib/hidra-relay

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use hidra_node::apps::hidrarelay;

#[derive(Parser, Debug)]
#[command(
    name = "hidra-relay",
    about = "HidraNet's own MQTT-over-WebSocket relay for the chat and the forum"
)]
struct Cli {
    /// Address to listen on for plain WebSocket. Keep it on loopback and put
    /// a TLS reverse proxy in front.
    #[arg(long, default_value = "127.0.0.1:1884")]
    listen: SocketAddr,

    /// Directory for retained messages (SQLite). Omit to keep them in memory
    /// only, which loses the forum on restart.
    #[arg(long)]
    data: Option<PathBuf>,

    /// Log level: error, warn, info, debug.
    #[arg(long, default_value = "info", value_parser = ["error", "warn", "info", "debug"])]
    log_level: String,

    /// The forum registrar's public key (the base64 the pages carry as
    /// REGISTRY_PUBKEY). Turns the forum rules on: the relay then keeps a
    /// registry list only from this key.
    #[arg(long)]
    registrar_key: Option<String>,

    /// Run with no forum rules at all: a plain relay for the two topic
    /// trees, which keeps whatever is published. For tests of the pages'
    /// own checks, not for a relay people use.
    #[arg(long)]
    no_forum_rules: bool,
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    hidra_node::logging::init_logging(&cli.log_level, "pretty");
    if let Some(key) = &cli.registrar_key {
        if hidrarelay::forum::canonical_pub(key).is_none() {
            return Err("the key must be the 88-character base64 the forum page shows".into());
        }
    }
    // The moderator is not a flag: the relay takes it from the registrar's
    // list (its set-admin), which is also where the pages learn it.
    let policy: Arc<dyn hidrarelay::Policy> = if cli.no_forum_rules {
        if cli.registrar_key.is_some() {
            return Err("--no-forum-rules takes no key".into());
        }
        Arc::new(hidrarelay::OpenPolicy)
    } else if cli.registrar_key.is_some() {
        Arc::new(hidrarelay::forum::ForumPolicy::new(cli.registrar_key, None))
    } else {
        return Err(
            "pass --registrar-key <the REGISTRY_PUBKEY of forum.html>, or --no-forum-rules for a relay with no forum rules"
                .into(),
        );
    };
    hidrarelay::run(hidrarelay::RelayConfig {
        listen: cli.listen,
        data_dir: cli.data,
        policy,
    })
    .await?;
    Ok(())
}
