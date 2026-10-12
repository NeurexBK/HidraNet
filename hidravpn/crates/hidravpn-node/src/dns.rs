//! The DNS forwarder clients use inside the tunnel.
//!
//! Queries arrive at the node's tunnel address and leave it over DNS-over-
//! HTTPS, so no one between the node and the resolver sees the names, and
//! the client's own ISP never sees them at all. The names are not logged.
//!
//! Upstreams are written as `https://host/path@ip[,ip]` or `udp://ip`; the
//! second form exists for the local test network, which has no internet.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{info, warn};

/// What fits in a UDP answer without fragmentation trouble.
const UDP_MAX: usize = 1232;

pub fn parse_upstream(s: &str) -> Result<Vec<NameServerConfig>> {
    if let Some(rest) = s.strip_prefix("udp://") {
        let ip: IpAddr = rest.parse().with_context(|| format!("not an IP in {s}"))?;
        return Ok(vec![NameServerConfig::udp_and_tcp(ip)]);
    }
    if let Some(rest) = s.strip_prefix("https://") {
        let (url, ips) = rest
            .split_once('@')
            .ok_or_else(|| anyhow!("{s}: write https://host/path@ip"))?;
        let (host, path) = url
            .split_once('/')
            .map(|(h, p)| (h, format!("/{p}")))
            .unwrap_or((url, "/dns-query".into()));
        let host: Arc<str> = Arc::from(host);
        let path: Arc<str> = Arc::from(path.as_str());
        let mut v = Vec::new();
        for ip in ips.split(',') {
            let ip: IpAddr = ip
                .trim()
                .parse()
                .with_context(|| format!("not an IP in {s}"))?;
            v.push(NameServerConfig::https(
                ip,
                host.clone(),
                Some(path.clone()),
            ));
        }
        if v.is_empty() {
            return Err(anyhow!("{s}: no IP given"));
        }
        return Ok(v);
    }
    Err(anyhow!(
        "{s}: upstreams are https://host/path@ip or udp://ip"
    ))
}

fn build_resolver(upstreams: &[String]) -> Result<Resolver<TokioRuntimeProvider>> {
    let mut servers = Vec::new();
    for u in upstreams {
        servers.extend(parse_upstream(u)?);
    }
    let config = ResolverConfig::from_name_servers(servers);
    let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
    let opts = builder.options_mut();
    opts.timeout = Duration::from_secs(4);
    opts.attempts = 2;
    opts.cache_size = 8192;
    opts.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
    Ok(builder.build().context("building the resolver")?)
}

pub async fn serve(bind: SocketAddr, upstreams: Vec<String>) -> Result<()> {
    let resolver = Arc::new(build_resolver(&upstreams)?);
    let udp = Arc::new(
        UdpSocket::bind(bind)
            .await
            .with_context(|| format!("binding DNS on {bind}"))?,
    );
    let tcp = TcpListener::bind(bind)
        .await
        .with_context(|| format!("binding DNS/TCP on {bind}"))?;

    let udp_task = {
        let udp = udp.clone();
        let resolver = resolver.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let q = buf[..n].to_vec();
                let udp = udp.clone();
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    if let Some(mut resp) = answer(&resolver, &q).await {
                        if resp.len() > UDP_MAX {
                            resp = truncated(&q);
                        }
                        let _ = udp.send_to(&resp, from).await;
                    }
                });
            }
        })
    };

    let tcp_task = {
        let resolver = resolver.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    continue;
                };
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    let mut len = [0u8; 2];
                    if stream.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let n = u16::from_be_bytes(len) as usize;
                    let mut q = vec![0u8; n];
                    if stream.read_exact(&mut q).await.is_err() {
                        return;
                    }
                    if let Some(resp) = answer(&resolver, &q).await {
                        let _ = stream.write_all(&(resp.len() as u16).to_be_bytes()).await;
                        let _ = stream.write_all(&resp).await;
                    }
                });
            }
        })
    };

    info!("DNS forwarder ready");
    tokio::select! {
        r = udp_task => { warn!("DNS/UDP loop ended: {r:?}"); }
        r = tcp_task => { warn!("DNS/TCP loop ended: {r:?}"); }
    }
    Ok(())
}

/// A response for one query, or nothing if the bytes were not a query.
async fn answer(resolver: &Resolver<TokioRuntimeProvider>, raw: &[u8]) -> Option<Vec<u8>> {
    let req = Message::from_vec(raw).ok()?;
    if req.metadata.message_type != MessageType::Query || req.metadata.op_code != OpCode::Query {
        return None;
    }
    let query = req.queries.first()?.clone();

    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.recursion_desired = req.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_query(query.clone());

    let rtype: RecordType = query.query_type();
    match resolver.lookup(query.name().clone(), rtype).await {
        Ok(lookup) => {
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_answers(lookup.answers().iter().cloned());
        }
        Err(e) if e.is_nx_domain() => resp.metadata.response_code = ResponseCode::NXDomain,
        Err(e) if e.is_no_records_found() => resp.metadata.response_code = ResponseCode::NoError,
        Err(_) => resp.metadata.response_code = ResponseCode::ServFail,
    }
    resp.to_vec().ok()
}

/// The same query echoed back with TC set: "ask again over TCP".
fn truncated(raw: &[u8]) -> Vec<u8> {
    let Ok(req) = Message::from_vec(raw) else {
        return Vec::new();
    };
    let mut resp = Message::response(req.metadata.id, OpCode::Query);
    resp.metadata.recursion_available = true;
    resp.metadata.truncation = true;
    if let Some(q) = req.queries.first() {
        resp.add_query(q.clone());
    }
    resp.to_vec().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstreams_parse() {
        let v = parse_upstream("https://dns.quad9.net/dns-query@9.9.9.9,149.112.112.112").unwrap();
        assert_eq!(v.len(), 2);
        let v = parse_upstream("udp://10.201.0.2").unwrap();
        assert_eq!(v.len(), 1);
        assert!(parse_upstream("dns.quad9.net").is_err());
        assert!(parse_upstream("https://dns.quad9.net/dns-query").is_err());
    }
}
