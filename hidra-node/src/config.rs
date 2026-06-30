use serde::Deserialize;

use crate::error::Result;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub node: NodeConfig,
    pub network: NetworkConfig,
    pub logging: LoggingConfig,
    pub paths: PathsConfig,
    #[serde(default)]
    pub relays: Vec<RelayInfo>,
    #[serde(default)]
    pub dht: DhtConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DhtConfig {
    #[serde(default = "default_dht_port")]
    pub port: u16,
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for DhtConfig {
    fn default() -> Self {
        Self {
            port: default_dht_port(),
            bootstrap_nodes: Vec::new(),
            enabled: true,
        }
    }
}

fn default_dht_port() -> u16 {
    7000
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProxyConfig {
    #[serde(default = "default_proxy_addr")]
    pub listen_addr: String,
    #[serde(default = "default_proxy_port")]
    pub port: u16,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_proxy_addr(),
            port: default_proxy_port(),
        }
    }
}

fn default_proxy_addr() -> String {
    "127.0.0.1".into()
}

fn default_proxy_port() -> u16 {
    9050
}

#[derive(Debug, Deserialize, Clone)]
pub struct RelayInfo {
    pub name: String,
    pub addr: String,
    pub noise_pubkey: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NodeConfig {
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathsConfig {
    pub keys_dir: String,
}

pub fn load_config(path: &str) -> Result<AppConfig> {
    let config = config::Config::builder()
        .add_source(config::File::new(path, config::FileFormat::Toml))
        .build()?;
    let app_config: AppConfig = config.try_deserialize()?;
    Ok(app_config)
}
