use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use crate::error::{HidraError, Result};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REPLY_SUCCESS: u8 = 0x00;
const REPLY_GENERAL_FAILURE: u8 = 0x01;
const REPLY_CONN_REFUSED: u8 = 0x05;
const REPLY_CMD_NOT_SUPPORTED: u8 = 0x07;

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    pub fn host_string(&self) -> String {
        match self {
            Self::Ip(addr) => addr.ip().to_string(),
            Self::Domain(host, _) => host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(addr) => addr.port(),
            Self::Domain(_, port) => *port,
        }
    }
}

impl std::fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(addr) => write!(f, "{addr}"),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

pub async fn handshake(stream: &mut TcpStream) -> Result<()> {
    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        return Err(HidraError::Protocol(format!(
            "unsupported SOCKS version: 0x{version:02x}"
        )));
    }

    let n_methods = stream.read_u8().await?;
    let mut methods = vec![0u8; n_methods as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&AUTH_NONE) {
        stream.write_all(&[SOCKS5_VERSION, 0xFF]).await?;
        return Err(HidraError::Protocol(
            "client does not support no-auth method".into(),
        ));
    }

    stream.write_all(&[SOCKS5_VERSION, AUTH_NONE]).await?;
    stream.flush().await?;
    debug!("SOCKS5 auth negotiated (no auth)");
    Ok(())
}

pub async fn read_request(stream: &mut TcpStream) -> Result<TargetAddr> {
    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        return Err(HidraError::Protocol(format!(
            "bad SOCKS5 request version: 0x{version:02x}"
        )));
    }

    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?;

    if cmd != CMD_CONNECT {
        send_reply(stream, REPLY_CMD_NOT_SUPPORTED, None).await?;
        return Err(HidraError::Protocol(format!(
            "unsupported SOCKS5 command: 0x{cmd:02x}"
        )));
    }

    let atyp = stream.read_u8().await?;

    let target = match atyp {
        ATYP_IPV4 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(Ipv4Addr::from(ip).into(), port))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain_buf = vec![0u8; len];
            stream.read_exact(&mut domain_buf).await?;
            let port = stream.read_u16().await?;
            let domain = String::from_utf8(domain_buf).map_err(|_| {
                HidraError::Protocol("invalid UTF-8 in domain name".into())
            })?;
            TargetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Ip(SocketAddr::new(Ipv6Addr::from(ip).into(), port))
        }
        _ => {
            send_reply(stream, REPLY_GENERAL_FAILURE, None).await?;
            return Err(HidraError::Protocol(format!(
                "unsupported address type: 0x{atyp:02x}"
            )));
        }
    };

    debug!(target = %target, "SOCKS5 CONNECT request");
    Ok(target)
}

pub async fn send_reply(
    stream: &mut TcpStream,
    reply_code: u8,
    bind_addr: Option<SocketAddr>,
) -> Result<()> {
    let mut buf = Vec::with_capacity(10);
    buf.push(SOCKS5_VERSION);
    buf.push(reply_code);
    buf.push(0x00); // RSV

    match bind_addr {
        Some(SocketAddr::V4(v4)) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
        }
        Some(SocketAddr::V6(v6)) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.ip().octets());
            buf.extend_from_slice(&v6.port().to_be_bytes());
        }
        None => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&[0, 0, 0, 0]);
            buf.extend_from_slice(&[0, 0]);
        }
    }

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn send_success(stream: &mut TcpStream) -> Result<()> {
    send_reply(stream, REPLY_SUCCESS, None).await
}

pub async fn send_failure(stream: &mut TcpStream) -> Result<()> {
    send_reply(stream, REPLY_GENERAL_FAILURE, None).await
}

pub async fn send_conn_refused(stream: &mut TcpStream) -> Result<()> {
    send_reply(stream, REPLY_CONN_REFUSED, None).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks5_handshake_no_auth() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake(&mut stream).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();

        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [0x05, 0x00]);

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_request_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake(&mut stream).await.unwrap();
            let target = read_request(&mut stream).await.unwrap();
            match target {
                TargetAddr::Domain(host, port) => {
                    assert_eq!(host, "example.com");
                    assert_eq!(port, 80);
                }
                _ => panic!("expected domain target"),
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // Handshake
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // CONNECT to example.com:80
        let domain = b"example.com";
        let mut req = Vec::new();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
        req.push(domain.len() as u8);
        req.extend_from_slice(domain);
        req.extend_from_slice(&80u16.to_be_bytes());
        client.write_all(&req).await.unwrap();

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_connect_request_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake(&mut stream).await.unwrap();
            let target = read_request(&mut stream).await.unwrap();
            match target {
                TargetAddr::Ip(sa) => {
                    assert_eq!(sa, "93.184.216.34:443".parse::<SocketAddr>().unwrap());
                }
                _ => panic!("expected IP target"),
            }
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();

        // CONNECT to 93.184.216.34:443
        let mut req = Vec::new();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]);
        req.extend_from_slice(&[93, 184, 216, 34]);
        req.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&req).await.unwrap();

        server.await.unwrap();
    }
}
