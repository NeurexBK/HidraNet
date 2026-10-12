//! The daemon: it holds the tunnel while it is up, arms the kill switch, and
//! puts everything back when it is told to disconnect or when it is stopped.
//!
//! Only one tunnel at a time. Bringing a second one up replaces the first. If
//! the kill switch cannot be armed, the connection is refused and undone — the
//! service never routes the machine through a tunnel it cannot protect.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use hidravpn_core::killswitch::{self, KillConfig};
use hidravpn_core::netcfg::{self, RevertPlan, Wanted};
use hidravpn_core::{ClientConfig, ClientKey, Invite, Tunnel};
use hidravpn_tun::TunConfig;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::ipc::{Command, Request, Response, StatusReport};
use crate::paths;

struct Active {
    tunnel: Arc<Tunnel>,
    runner: JoinHandle<()>,
    plan: RevertPlan,
    node_name: String,
    endpoint: String,
}

pub struct Daemon {
    token: String,
    state: Mutex<Option<Active>>,
}

impl Daemon {
    pub fn new(token: String) -> Arc<Self> {
        Arc::new(Self {
            token,
            state: Mutex::new(None),
        })
    }

    pub async fn handle(&self, req: Request) -> Response {
        // Constant-ish check: the token is compared in full before anything else.
        if req.token.as_bytes() != self.token.as_bytes() {
            return Response::err("unauthorised: wrong or missing control token");
        }
        match req.cmd {
            Command::Ping => Response::ok(),
            Command::Status => self.status().await,
            Command::Up {
                invite,
                allow_lan,
                keep_ipv6,
            } => match self.up(invite, allow_lan, !keep_ipv6).await {
                Ok(()) => self.status().await,
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::Down => match self.down().await {
                Ok(msg) => {
                    let mut r = Response::ok();
                    r.error = None;
                    let _ = msg;
                    r
                }
                Err(e) => Response::err(format!("{e:#}")),
            },
        }
    }

    async fn up(&self, inv: Invite, allow_lan: bool, route_ipv6: bool) -> Result<()> {
        inv.validate()?;
        let mut guard = self.state.lock().await;
        if guard.is_some() {
            // Replace an existing connection cleanly.
            drop(guard);
            let _ = self.down().await;
            guard = self.state.lock().await;
        }

        // Any plan a crashed run left behind is undone first.
        if let Ok(Some(old)) = netcfg::load_plan() {
            let _ = netcfg::revert(&old);
        }
        let _ = killswitch::remove();

        let key = load_key()?;
        let (ip, prefix) = inv.client_ip()?;
        let interface = "hvpn0".to_string();
        let tun = hidravpn_tun::open(&TunConfig {
            name: interface.clone(),
            ipv4: (ip, prefix),
            ipv6: None,
            mtu: inv.mtu,
        })?;
        let ifname = hidravpn_tun::name(&tun).unwrap_or(interface);

        let cfg = ClientConfig {
            invite: inv.clone(),
            key,
        };
        let tunnel = Arc::new(Tunnel::new(&cfg, tun).await?);

        // Route the machine through the tunnel.
        let plan = netcfg::apply(&Wanted {
            interface: ifname.clone(),
            node_ip: inv.endpoint_ip()?,
            dns: inv.dns,
            route_ipv6,
        })
        .context("could not route the machine through the tunnel")?;

        // Arm the kill switch. If it cannot be armed, undo the routing and the
        // tunnel: better no connection than an unprotected one.
        let ks = KillConfig {
            interface: ifname.clone(),
            node_endpoint: inv.endpoint_addr()?,
            dns: inv.dns,
            allow_lan,
        };
        if let Err(e) = killswitch::apply(&ks) {
            let _ = netcfg::revert(&plan);
            tunnel.stop();
            return Err(e.context("could not arm the kill switch; connection refused"));
        }

        let runner = {
            let t = tunnel.clone();
            tokio::spawn(async move {
                let _ = t.run().await;
            })
        };

        *guard = Some(Active {
            tunnel,
            runner,
            plan,
            node_name: inv.node_name.clone(),
            endpoint: inv.endpoint.clone(),
        });
        tracing::info!("connected");
        Ok(())
    }

    pub async fn down(&self) -> Result<&'static str> {
        let mut guard = self.state.lock().await;
        let active = match guard.take() {
            None => {
                // Even with nothing running, make sure nothing is left armed.
                let _ = killswitch::remove();
                if let Ok(Some(old)) = netcfg::load_plan() {
                    let _ = netcfg::revert(&old);
                }
                return Ok("already disconnected");
            }
            Some(a) => a,
        };
        // Order: drop the firewall and the routing first, then the tunnel.
        let ks = killswitch::remove();
        let nc = netcfg::revert(&active.plan);
        // Ask the tunnel to stop and let run() finish: it aborts its reader
        // tasks and releases their handle to the interface. Aborting the
        // runner instead would cancel that cleanup, so the interface would
        // stay. Then drop our own handle, which is the last one, so the
        // kernel interface goes away before we report "disconnected".
        active.tunnel.stop();
        let _ = active.runner.await;
        drop(active.tunnel);
        tracing::info!("disconnected");
        ks.and(nc).map(|_| "disconnected")
    }

    async fn status(&self) -> Response {
        let guard = self.state.lock().await;
        let killswitch = killswitch::is_active();
        match guard.as_ref() {
            None => Response::with_status(StatusReport {
                connected: false,
                node_name: None,
                endpoint: None,
                last_handshake_secs: None,
                tx_bytes: 0,
                rx_bytes: 0,
                killswitch,
            }),
            Some(a) => {
                let s = a.tunnel.status();
                Response::with_status(StatusReport {
                    connected: s.connected,
                    node_name: Some(a.node_name.clone()),
                    endpoint: Some(a.endpoint.clone()),
                    last_handshake_secs: s.last_handshake.map(|d| d.as_secs()),
                    tx_bytes: s.tx_bytes,
                    rx_bytes: s.rx_bytes,
                    killswitch,
                })
            }
        }
    }

    /// Called when the service is stopping: leave nothing behind.
    pub async fn shutdown(&self) {
        let _ = self.down().await;
    }
}

fn load_key() -> Result<ClientKey> {
    let path = paths::client_key();
    let s = std::fs::read_to_string(&path).map_err(|_| {
        anyhow!(
            "no client key at {} — run `hidravpn keygen` first",
            path.display()
        )
    })?;
    ClientKey::from_base64(&s)
}

/// A short wait helper the installer uses when stopping.
#[allow(dead_code)]
pub async fn settle() {
    tokio::time::sleep(Duration::from_millis(200)).await;
}
