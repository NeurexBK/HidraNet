//! The data plane: packets from the TUN interface are encrypted and sent to
//! the node over UDP; datagrams from the node are decrypted and written to
//! the TUN interface. WireGuard itself is boringtun's `Tunn`, which is pure
//! protocol with no I/O of its own — that is what lets the same loop run on
//! Linux, macOS and Windows.
//!
//! Three tasks share one `Tunn` behind a mutex: TUN→network, network→TUN, and
//! a timer that drives handshakes, keepalives and rekeys. The critical
//! sections are a single encrypt or decrypt each, so the mutex is not a
//! bottleneck at the speeds a VPN client sees.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use hidravpn_tun::AsyncDevice;
use tokio::net::UdpSocket;
use tokio::sync::watch;

use crate::config::ClientConfig;
use crate::keys::public_key_from_base64;

/// Large enough for a full MTU packet plus WireGuard's overhead.
const BUF: usize = 65536;

/// WireGuard considers a session dead after this long without a handshake.
const REJECT_AFTER: Duration = Duration::from_secs(180);

#[derive(Debug, Clone, Default)]
pub struct TunnelStatus {
    /// A handshake completed recently enough for the session to be live.
    pub connected: bool,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

pub struct Tunnel {
    tunn: Arc<Mutex<Tunn>>,
    sock: Arc<UdpSocket>,
    tun: Arc<AsyncDevice>,
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
    stop: watch::Sender<bool>,
}

impl Tunnel {
    /// Binds the UDP socket and prepares the session. Nothing is sent until
    /// `run` is called.
    pub async fn new(cfg: &ClientConfig, tun: Arc<AsyncDevice>) -> Result<Self> {
        let endpoint = cfg.invite.endpoint_addr()?;
        let node_key = public_key_from_base64(&cfg.invite.node_public_key)?;
        let bind: SocketAddr = if endpoint.is_ipv4() {
            "0.0.0.0:0".parse()?
        } else {
            "[::]:0".parse()?
        };
        let sock = UdpSocket::bind(bind)
            .await
            .context("could not open the UDP socket")?;
        sock.connect(endpoint)
            .await
            .with_context(|| format!("could not address the node at {endpoint}"))?;

        // The key shown to this node is the one derived for it; the master
        // key's public half never leaves the client. The pre-shared key,
        // when the invite has one, is what keeps a recording of this
        // tunnel closed to a quantum computer.
        let preshared = cfg.invite.preshared()?;
        let tunn = Tunn::new(
            cfg.node_key()?.secret(),
            node_key,
            preshared,
            Some(cfg.invite.keepalive),
            0,
            None,
        );
        let (stop, _) = watch::channel(false);
        Ok(Self {
            tunn: Arc::new(Mutex::new(tunn)),
            sock: Arc::new(sock),
            tun,
            tx: Arc::new(AtomicU64::new(0)),
            rx: Arc::new(AtomicU64::new(0)),
            stop,
        })
    }

    pub fn status(&self) -> TunnelStatus {
        let last = self
            .tunn
            .lock()
            .map(|t| t.time_since_last_handshake())
            .unwrap_or(None);
        TunnelStatus {
            connected: last.map(|d| d < REJECT_AFTER).unwrap_or(false),
            last_handshake: last,
            tx_bytes: self.tx.load(Ordering::Relaxed),
            rx_bytes: self.rx.load(Ordering::Relaxed),
        }
    }

    /// Asks the running tunnel to stop; `run` then returns.
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }

    /// Runs until `stop` is called or the socket fails. Starts with a
    /// handshake so the session is up before the first packet needs it.
    pub async fn run(&self) -> Result<()> {
        self.initiate_handshake().await?;

        let mut stop_rx = self.stop.subscribe();
        let mut to_net = tokio::spawn(tun_to_network(
            self.tunn.clone(),
            self.sock.clone(),
            self.tun.clone(),
            self.tx.clone(),
        ));
        let mut to_tun = tokio::spawn(network_to_tun(
            self.tunn.clone(),
            self.sock.clone(),
            self.tun.clone(),
            self.rx.clone(),
        ));
        let mut timers = tokio::spawn(drive_timers(self.tunn.clone(), self.sock.clone()));

        let outcome = tokio::select! {
            r = &mut to_net => r.map_err(|e| anyhow!("TUN reader stopped: {e}"))?,
            r = &mut to_tun => r.map_err(|e| anyhow!("network reader stopped: {e}"))?,
            r = &mut timers => r.map_err(|e| anyhow!("timer stopped: {e}"))?,
            _ = stop_rx.changed() => Ok(()),
        };

        // Stop the other two tasks and wait for them to let go. Each holds a
        // clone of the TUN device; only once all are dropped does the kernel
        // interface go away — which matters to the service, where the process
        // keeps running after a disconnect instead of exiting.
        to_net.abort();
        to_tun.abort();
        timers.abort();
        let _ = to_net.await;
        let _ = to_tun.await;
        let _ = timers.await;
        outcome
    }

    async fn initiate_handshake(&self) -> Result<()> {
        let mut buf = vec![0u8; BUF];
        let out = {
            let mut t = self
                .tunn
                .lock()
                .map_err(|_| anyhow!("tunnel state poisoned"))?;
            match t.format_handshake_initiation(&mut buf, false) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                TunnResult::Done => None,
                TunnResult::Err(e) => return Err(anyhow!("handshake could not be formed: {e:?}")),
                _ => None,
            }
        };
        if let Some(p) = out {
            self.sock
                .send(&p)
                .await
                .context("could not send the handshake")?;
        }
        Ok(())
    }
}

async fn tun_to_network(
    tunn: Arc<Mutex<Tunn>>,
    sock: Arc<UdpSocket>,
    tun: Arc<AsyncDevice>,
    tx: Arc<AtomicU64>,
) -> Result<()> {
    let mut pkt = vec![0u8; BUF];
    let mut out = vec![0u8; BUF];
    loop {
        let n = tun
            .recv(&mut pkt)
            .await
            .context("reading the tunnel interface")?;
        if n == 0 {
            continue;
        }
        let send = {
            let mut t = tunn.lock().map_err(|_| anyhow!("tunnel state poisoned"))?;
            match t.encapsulate(&pkt[..n], &mut out) {
                TunnResult::WriteToNetwork(p) => Some(p.len()),
                // No session yet: the packet is queued inside Tunn and a
                // handshake goes out; the timer task flushes the queue.
                TunnResult::Done => None,
                TunnResult::Err(_) => None,
                _ => None,
            }
        };
        if let Some(len) = send {
            if sock.send(&out[..len]).await.is_ok() {
                tx.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }
}

async fn network_to_tun(
    tunn: Arc<Mutex<Tunn>>,
    sock: Arc<UdpSocket>,
    tun: Arc<AsyncDevice>,
    rx: Arc<AtomicU64>,
) -> Result<()> {
    let mut dgram = vec![0u8; BUF];
    let mut out = vec![0u8; BUF];
    let peer_ip: Option<IpAddr> = sock.peer_addr().ok().map(|a| a.ip());
    loop {
        let n = sock
            .recv(&mut dgram)
            .await
            .context("reading the UDP socket")?;
        // One datagram can produce a packet for the interface, a reply for the
        // network (handshake response, keepalive), and then queued packets
        // that were waiting for the session; drain them all.
        let mut to_send: Vec<Vec<u8>> = Vec::new();
        let mut to_tun: Vec<Vec<u8>> = Vec::new();
        {
            let mut t = tunn.lock().map_err(|_| anyhow!("tunnel state poisoned"))?;
            let mut res = t.decapsulate(peer_ip, &dgram[..n], &mut out);
            loop {
                match res {
                    TunnResult::WriteToNetwork(p) => {
                        to_send.push(p.to_vec());
                        res = t.decapsulate(None, &[], &mut out);
                    }
                    TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                        to_tun.push(p.to_vec());
                        break;
                    }
                    TunnResult::Done | TunnResult::Err(_) => break,
                }
            }
        }
        for p in to_send {
            let _ = sock.send(&p).await;
        }
        for p in to_tun {
            if tun.send(&p).await.is_ok() {
                rx.fetch_add(p.len() as u64, Ordering::Relaxed);
            }
        }
    }
}

/// WireGuard's timers: handshake retries, keepalives, rekeying and the
/// flush of packets queued before a session existed.
async fn drive_timers(tunn: Arc<Mutex<Tunn>>, sock: Arc<UdpSocket>) -> Result<()> {
    let mut out = vec![0u8; BUF];
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    loop {
        tick.tick().await;
        let send = {
            let mut t = tunn.lock().map_err(|_| anyhow!("tunnel state poisoned"))?;
            match t.update_timers(&mut out) {
                TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                TunnResult::Err(boringtun::noise::errors::WireGuardError::ConnectionExpired) => {
                    // The node went quiet past the protocol's limit. A fresh
                    // handshake is the only way back; keep trying.
                    match t.format_handshake_initiation(&mut out, true) {
                        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                        _ => None,
                    }
                }
                _ => None,
            }
        };
        if let Some(p) = send {
            let _ = sock.send(&p).await;
        }
    }
}
