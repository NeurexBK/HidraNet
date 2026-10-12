//! WireGuard in userspace, for a Linux without the kernel module (containers,
//! old kernels, this test machine). Many peers on one UDP socket, the usual
//! way: a handshake initiation names the sender's static key, every other
//! packet carries the receiver's index, and the top bits of that index are
//! the peer's number here.
//!
//! It is driven through the standard WireGuard control protocol on
//! /var/run/wireguard/<name>.sock — the same text that `wg(8)` speaks — so
//! `admit`, `revoke` and `status` configure it exactly as they configure the
//! kernel: through wireguard-control, and from another process.
//!
//! What it does not do, on purpose: log a peer's endpoint, or a packet.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use hidravpn_tun::{AsyncDevice, TunConfig};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UdpSocket, UnixListener};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::config::TunnelNet;

const BUF: usize = 65536;
/// Handshakes per second before cookies are demanded, as boringtun's own
/// device uses.
const HANDSHAKE_RATE_LIMIT: u64 = 100;

struct Peer {
    index: u32,
    public: PublicKey,
    tunn: Mutex<Tunn>,
    endpoint: Mutex<Option<SocketAddr>>,
    allowed: Vec<(Ipv4Addr, u8)>,
    keepalive: Option<u16>,
    rx: AtomicU64,
    tx: AtomicU64,
}

impl Peer {
    fn allows(&self, ip: Ipv4Addr) -> bool {
        self.allowed.iter().any(|(net, prefix)| {
            let mask = if *prefix == 0 {
                0
            } else {
                u32::MAX << (32 - *prefix)
            };
            (u32::from(ip) & mask) == (u32::from(*net) & mask)
        })
    }
}

#[derive(Default)]
struct Peers {
    by_index: HashMap<u32, Arc<Peer>>,
    by_key: HashMap<[u8; 32], u32>,
    next_index: u32,
}

struct Inner {
    name: String,
    secret: StaticSecret,
    public: PublicKey,
    listen_port: u16,
    tun: Arc<AsyncDevice>,
    udp: Arc<UdpSocket>,
    peers: RwLock<Peers>,
    limiter: Arc<RateLimiter>,
}

pub struct UserspaceDevice {
    inner: Arc<Inner>,
    tasks: Vec<JoinHandle<()>>,
}

pub fn socket_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("/var/run/wireguard/{name}.sock"))
}

impl UserspaceDevice {
    /// Opens the interface and the UDP port and starts serving. Peers are
    /// added afterwards through the control socket.
    pub async fn start(
        name: &str,
        private_key_b64: &str,
        listen_port: u16,
        net: &TunnelNet,
    ) -> Result<Self> {
        let secret = hidravpn_core::ClientKey::from_base64(private_key_b64)
            .map_err(|_| anyhow!("invalid node key"))?
            .into_secret();
        let public = PublicKey::from(&secret);

        let tun = hidravpn_tun::open(&TunConfig {
            name: name.into(),
            ipv4: (net.node_ip, net.prefix),
            ipv6: None,
            mtu: 1420,
        })?;
        let udp = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            listen_port,
        ))
        .await
        .with_context(|| format!("binding UDP {listen_port}"))?;

        let inner = Arc::new(Inner {
            name: name.into(),
            secret,
            public,
            listen_port,
            tun,
            udp: Arc::new(udp),
            peers: RwLock::new(Peers {
                next_index: 1,
                ..Default::default()
            }),
            limiter: Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT)),
        });

        let path = socket_path(name);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let _ = std::fs::remove_file(&path);
        let listener =
            UnixListener::bind(&path).with_context(|| format!("binding {}", path.display()))?;
        std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;

        let tasks = vec![
            tokio::spawn(udp_loop(inner.clone())),
            tokio::spawn(tun_loop(inner.clone())),
            tokio::spawn(timer_loop(inner.clone())),
            tokio::spawn(control_loop(inner.clone(), listener)),
        ];
        info!(
            "userspace WireGuard serving {} peers' control socket at {}",
            0,
            path.display()
        );
        Ok(Self { inner, tasks })
    }

    pub fn stop(self) {
        for t in &self.tasks {
            t.abort();
        }
        let _ = std::fs::remove_file(socket_path(&self.inner.name));
    }
}

// ── Data plane ────────────────────────────────────────────────────────────

fn find_peer(inner: &Inner, packet: &Packet, datagram: &[u8]) -> Option<Arc<Peer>> {
    let peers = inner.peers.read().ok()?;
    match packet {
        Packet::HandshakeInit(p) => {
            let _ = datagram;
            let half = parse_handshake_anon(&inner.secret, &inner.public, p).ok()?;
            let idx = peers.by_key.get(&half.peer_static_public)?;
            peers.by_index.get(idx).cloned()
        }
        Packet::HandshakeResponse(p) => peers.by_index.get(&(p.receiver_idx >> 8)).cloned(),
        Packet::PacketCookieReply(p) => peers.by_index.get(&(p.receiver_idx >> 8)).cloned(),
        Packet::PacketData(p) => peers.by_index.get(&(p.receiver_idx >> 8)).cloned(),
    }
}

async fn udp_loop(inner: Arc<Inner>) {
    let mut buf = vec![0u8; BUF];
    let mut out = vec![0u8; BUF];
    loop {
        let Ok((n, src)) = inner.udp.recv_from(&mut buf).await else {
            continue;
        };
        let datagram = &buf[..n];

        // MAC check and, under load, cookies — before any peer is touched.
        let packet = match inner
            .limiter
            .verify_packet(Some(src.ip()), datagram, &mut out)
        {
            Ok(p) => p,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                let _ = inner.udp.send_to(cookie, src).await;
                continue;
            }
            Err(_) => continue,
        };
        let Some(peer) = find_peer(&inner, &packet, datagram) else {
            continue;
        };

        let mut to_send: Vec<Vec<u8>> = Vec::new();
        let mut to_tun: Option<Vec<u8>> = None;
        let mut authenticated = false;
        {
            let Ok(mut t) = peer.tunn.lock() else {
                continue;
            };
            let mut res = t.decapsulate(Some(src.ip()), datagram, &mut out);
            loop {
                match res {
                    TunnResult::WriteToNetwork(p) => {
                        authenticated = true;
                        to_send.push(p.to_vec());
                        res = t.decapsulate(None, &[], &mut out);
                    }
                    TunnResult::WriteToTunnelV4(p, from) => {
                        authenticated = true;
                        // Cryptokey routing: a peer may only send from its own addresses.
                        if peer.allows(from) {
                            to_tun = Some(p.to_vec());
                        }
                        break;
                    }
                    TunnResult::WriteToTunnelV6(..) => break,
                    TunnResult::Done => {
                        authenticated = true;
                        break;
                    }
                    TunnResult::Err(_) => break,
                }
            }
        }
        if authenticated {
            // Peers roam; the last place an authentic packet came from is where
            // replies go.
            if let Ok(mut e) = peer.endpoint.lock() {
                *e = Some(src);
            }
        }
        for p in to_send {
            let _ = inner.udp.send_to(&p, src).await;
        }
        if let Some(p) = to_tun {
            if inner.tun.send(&p).await.is_ok() {
                peer.rx.fetch_add(p.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

async fn tun_loop(inner: Arc<Inner>) {
    let mut pkt = vec![0u8; BUF];
    let mut out = vec![0u8; BUF];
    loop {
        let Ok(n) = inner.tun.recv(&mut pkt).await else {
            continue;
        };
        if n == 0 {
            continue;
        }
        let Some(IpAddr::V4(dst)) = Tunn::dst_address(&pkt[..n]) else {
            continue;
        };
        let peer = {
            let Ok(peers) = inner.peers.read() else {
                continue;
            };
            peers.by_index.values().find(|p| p.allows(dst)).cloned()
        };
        let Some(peer) = peer else { continue };
        let endpoint = peer.endpoint.lock().ok().and_then(|e| *e);
        let Some(endpoint) = endpoint else { continue };
        let send = {
            let Ok(mut t) = peer.tunn.lock() else {
                continue;
            };
            match t.encapsulate(&pkt[..n], &mut out) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                _ => None,
            }
        };
        if let Some(p) = send {
            if inner.udp.send_to(&p, endpoint).await.is_ok() {
                peer.tx.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
}

async fn timer_loop(inner: Arc<Inner>) {
    let mut out = vec![0u8; BUF];
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tick.tick().await;
        let peers: Vec<Arc<Peer>> = match inner.peers.read() {
            Ok(p) => p.by_index.values().cloned().collect(),
            Err(_) => continue,
        };
        for peer in peers {
            let endpoint = peer.endpoint.lock().ok().and_then(|e| *e);
            let Some(endpoint) = endpoint else { continue };
            let send = {
                let Ok(mut t) = peer.tunn.lock() else {
                    continue;
                };
                match t.update_timers(&mut out) {
                    TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                    _ => None,
                }
            };
            if let Some(p) = send {
                let _ = inner.udp.send_to(&p, endpoint).await;
            }
        }
    }
}

// ── Control socket: the WireGuard UAPI ────────────────────────────────────

async fn control_loop(inner: Arc<Inner>, listener: UnixListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let inner = inner.clone();
        tokio::spawn(async move {
            let (r, mut w) = stream.into_split();
            let mut lines = BufReader::new(r).lines();
            let Ok(Some(first)) = lines.next_line().await else {
                return;
            };
            let reply = match first.as_str() {
                "get=1" => {
                    // Drain the request's terminating blank line.
                    while let Ok(Some(l)) = lines.next_line().await {
                        if l.is_empty() {
                            break;
                        }
                    }
                    get_response(&inner)
                }
                "set=1" => {
                    let mut body = Vec::new();
                    while let Ok(Some(l)) = lines.next_line().await {
                        if l.is_empty() {
                            break;
                        }
                        body.push(l);
                    }
                    match apply_set(&inner, &body) {
                        Ok(()) => "errno=0\n\n".to_string(),
                        Err(e) => {
                            warn!("control: rejected a set request: {e}");
                            "errno=22\n\n".to_string()
                        }
                    }
                }
                _ => "errno=22\n\n".to_string(),
            };
            let _ = w.write_all(reply.as_bytes()).await;
            let _ = w.shutdown().await;
        });
    }
}

fn get_response(inner: &Inner) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "private_key={}\n",
        hex::encode(inner.secret.to_bytes())
    ));
    s.push_str(&format!("listen_port={}\n", inner.listen_port));
    if let Ok(peers) = inner.peers.read() {
        let mut list: Vec<&Arc<Peer>> = peers.by_index.values().collect();
        list.sort_by_key(|p| p.index);
        for p in list {
            s.push_str(&format!(
                "public_key={}\n",
                hex::encode(p.public.as_bytes())
            ));
            if let Some(e) = p.endpoint.lock().ok().and_then(|e| *e) {
                s.push_str(&format!("endpoint={e}\n"));
            }
            for (ip, prefix) in &p.allowed {
                s.push_str(&format!("allowed_ip={ip}/{prefix}\n"));
            }
            s.push_str(&format!(
                "persistent_keepalive_interval={}\n",
                p.keepalive.unwrap_or(0)
            ));
            let since = p
                .tunn
                .lock()
                .ok()
                .and_then(|t| t.time_since_last_handshake());
            let (sec, nsec) = match since
                .and_then(|d| SystemTime::now().checked_sub(d))
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            {
                Some(d) => (d.as_secs(), d.subsec_nanos()),
                None => (0, 0),
            };
            s.push_str(&format!(
                "last_handshake_time_sec={sec}\nlast_handshake_time_nsec={nsec}\n"
            ));
            s.push_str(&format!(
                "rx_bytes={}\ntx_bytes={}\n",
                p.rx.load(Ordering::Relaxed),
                p.tx.load(Ordering::Relaxed)
            ));
            s.push_str("protocol_version=1\n");
        }
    }
    s.push_str("errno=0\n\n");
    s
}

/// One peer section of a `set=1` request, collected until the next one.
#[derive(Default)]
struct PeerSet {
    public: Option<[u8; 32]>,
    remove: bool,
    replace_allowed: bool,
    allowed: Vec<(Ipv4Addr, u8)>,
    endpoint: Option<SocketAddr>,
    keepalive: Option<u16>,
    preshared: Option<[u8; 32]>,
}

fn hex32(v: &str) -> Result<[u8; 32]> {
    let b = hex::decode(v).context("not hex")?;
    b.try_into().map_err(|_| anyhow!("a key is 32 bytes"))
}

fn apply_set(inner: &Inner, body: &[String]) -> Result<()> {
    let mut replace_peers = false;
    let mut sections: Vec<PeerSet> = Vec::new();
    for line in body {
        let (k, v) = line.split_once('=').ok_or_else(|| anyhow!("bad line"))?;
        match k {
            "private_key" => {
                if hex32(v)? != inner.secret.to_bytes() {
                    return Err(anyhow!("the key cannot be changed while running"));
                }
            }
            "listen_port" => {
                if v.parse::<u16>().ok() != Some(inner.listen_port) {
                    return Err(anyhow!("the port cannot be changed while running"));
                }
            }
            "fwmark" => {}
            "replace_peers" => replace_peers = v == "true",
            "public_key" => sections.push(PeerSet {
                public: Some(hex32(v)?),
                ..Default::default()
            }),
            _ => {
                let cur = sections
                    .last_mut()
                    .ok_or_else(|| anyhow!("{k} before any public_key"))?;
                match k {
                    "remove" => cur.remove = v == "true",
                    "replace_allowed_ips" => cur.replace_allowed = v == "true",
                    "allowed_ip" => {
                        let (ip, prefix) = v
                            .split_once('/')
                            .ok_or_else(|| anyhow!("allowed_ip needs a prefix"))?;
                        if let Ok(ip) = ip.parse::<Ipv4Addr>() {
                            let prefix: u8 = prefix.parse().context("bad prefix")?;
                            if prefix > 32 {
                                return Err(anyhow!("bad prefix"));
                            }
                            cur.allowed.push((ip, prefix));
                        }
                        // IPv6 allowed IPs are accepted and ignored: this
                        // device carries IPv4 in this phase.
                    }
                    "endpoint" => cur.endpoint = Some(v.parse().context("bad endpoint")?),
                    "persistent_keepalive_interval" => {
                        cur.keepalive = Some(v.parse().context("bad keepalive")?)
                    }
                    "preshared_key" => cur.preshared = Some(hex32(v)?),
                    other => return Err(anyhow!("unknown field {other}")),
                }
            }
        }
    }

    let mut peers = inner
        .peers
        .write()
        .map_err(|_| anyhow!("peer table poisoned"))?;
    if replace_peers {
        peers.by_index.clear();
        peers.by_key.clear();
    }
    for s in sections {
        let key = s.public.unwrap();
        if s.remove {
            if let Some(idx) = peers.by_key.remove(&key) {
                peers.by_index.remove(&idx);
            }
            continue;
        }
        let existing = peers
            .by_key
            .get(&key)
            .and_then(|i| peers.by_index.get(i).cloned());
        let (index, mut allowed, endpoint) = match &existing {
            Some(p) => (
                p.index,
                if s.replace_allowed {
                    Vec::new()
                } else {
                    p.allowed.clone()
                },
                p.endpoint.lock().ok().and_then(|e| *e),
            ),
            None => {
                let i = peers.next_index;
                peers.next_index += 1;
                (i, Vec::new(), None)
            }
        };
        allowed.extend(s.allowed);
        let public = PublicKey::from(key);
        let tunn = Tunn::new(
            inner.secret.clone(),
            public,
            s.preshared,
            s.keepalive,
            index,
            None,
        );
        let peer = Arc::new(Peer {
            index,
            public,
            tunn: Mutex::new(tunn),
            endpoint: Mutex::new(s.endpoint.or(endpoint)),
            allowed,
            keepalive: s.keepalive,
            rx: AtomicU64::new(0),
            tx: AtomicU64::new(0),
        });
        peers.by_key.insert(key, index);
        peers.by_index.insert(index, peer);
    }
    Ok(())
}
