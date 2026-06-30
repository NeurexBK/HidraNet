use thiserror::Error;

#[derive(Debug, Error)]
pub enum HidraError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("handshake error: {0}")]
    Handshake(String),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("key management error: {0}")]
    KeyManagement(String),

    #[error("invalid address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("relay error: {0}")]
    Relay(String),

    #[error("circuit error: {0}")]
    Circuit(String),
}

pub type Result<T> = std::result::Result<T, HidraError>;
