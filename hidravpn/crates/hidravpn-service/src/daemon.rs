//! The daemon: it holds the circuit while it is up, arms the kill switch, and
//! puts everything back when it is told to disconnect or when it is stopped.
//!
//! Only one circuit at a time. Bringing a second one up replaces the first. If
//! the kill switch cannot be armed, the connection is refused and undone — the
//! service never routes the machine through a tunnel it cannot protect.
//!
//! It keeps what it needs to rebuild: the entry node, the pool of exit nodes
//! and which one is in use, so `new_identity` can rotate to the next exit.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use hidravpn_core::killswitch;
use hidravpn_core::netcfg;
use hidravpn_core::{Circuit, CircuitOptions, CircuitSpec, ClientKey, Invite};
use tokio::sync::Mutex;

use crate::ipc::{Command, Request, Response, StatusReport};
use crate::paths;

struct Active {
    circuit: Circuit,
    /// The entry node, when there are two hops.
    entry: Option<Invite>,
    /// The exit nodes, in the order given; `current` is the one in use.
    pool: Vec<Invite>,
    current: usize,
    opts: CircuitOptions,
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
                via,
                alternates,
            } => {
                let opts = CircuitOptions {
                    route_ipv6: !keep_ipv6,
                    allow_lan,
                    ..CircuitOptions::default()
                };
                match self.up(invite, via, alternates, opts).await {
                    Ok(()) => self.status().await,
                    Err(e) => Response::err(format!("{e:#}")),
                }
            }
            Command::Down => match self.down().await {
                Ok(_) => Response::ok(),
                Err(e) => Response::err(format!("{e:#}")),
            },
            Command::NewIdentity => match self.new_identity().await {
                Ok(note) => self.status().await.noting(note),
                Err(e) => Response::err(format!("{e:#}")),
            },
        }
    }

    async fn up(
        &self,
        exit: Invite,
        entry: Option<Invite>,
        alternates: Vec<Invite>,
        opts: CircuitOptions,
    ) -> Result<()> {
        // Everything is checked before anything is touched.
        let mut pool = Vec::with_capacity(1 + alternates.len());
        pool.push(exit);
        pool.extend(alternates);
        for exit in &pool {
            CircuitSpec {
                exit: exit.clone(),
                entry: entry.clone(),
            }
            .validate()?;
        }

        let mut guard = self.state.lock().await;
        if let Some(old) = guard.take() {
            // Replace an existing connection cleanly.
            let _ = old.circuit.down().await;
        }
        let circuit = connect(&pool[0], entry.as_ref(), &opts).await?;
        *guard = Some(Active {
            circuit,
            entry,
            pool,
            current: 0,
            opts,
        });
        tracing::info!("connected");
        Ok(())
    }

    /// Rebuilds the circuit through the next exit in the pool. Returns the
    /// note for the person: which exit it got, or that there was only one.
    async fn new_identity(&self) -> Result<String> {
        let mut guard = self.state.lock().await;
        let active = guard
            .take()
            .ok_or_else(|| anyhow!("not connected; nothing to rotate"))?;
        let Active {
            circuit,
            entry,
            pool,
            current,
            opts,
        } = active;
        let next = (current + 1) % pool.len();

        // The old circuit goes down completely before the new one comes up:
        // the exit's session, its routes and the kill switch all belong to
        // the old identity.
        let _ = circuit.down().await;
        match connect(&pool[next], entry.as_ref(), &opts).await {
            Ok(circuit) => {
                *guard = Some(Active {
                    circuit,
                    entry,
                    pool: pool.clone(),
                    current: next,
                    opts,
                });
                tracing::info!("new identity");
                Ok(if pool.len() == 1 {
                    "only one exit node is configured; reconnected to the same one, so the address the internet sees has not changed".to_string()
                } else {
                    format!(
                        "new identity: the exit is now {} (was {})",
                        pool[next].node_name, pool[current].node_name
                    )
                })
            }
            Err(e) => {
                // The machine is back on its own network, with nothing left
                // armed; say so rather than pretend a circuit is up.
                Err(e.context("the new circuit could not be built; disconnected"))
            }
        }
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
        // The circuit takes itself down in order: the firewall and the routing
        // first, then the tunnels, waiting for their tasks to let go of the
        // interfaces so the kernel interfaces are gone before we report
        // "disconnected".
        let r = active.circuit.down().await;
        tracing::info!("disconnected");
        r.map(|_| "disconnected")
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
                hops: 0,
                mode: String::new(),
                entry_name: None,
            }),
            Some(a) => {
                let s = a.circuit.status();
                let exit = s.exit();
                Response::with_status(StatusReport {
                    connected: s.connected,
                    node_name: Some(exit.node_name.clone()),
                    endpoint: Some(exit.endpoint.clone()),
                    // The exit's session carries the machine's traffic; its
                    // handshake and bytes are the ones that matter.
                    last_handshake_secs: exit.tunnel.last_handshake.map(|d| d.as_secs()),
                    tx_bytes: exit.tunnel.tx_bytes,
                    rx_bytes: exit.tunnel.rx_bytes,
                    killswitch,
                    hops: a.circuit.hops(),
                    mode: s.mode.as_str().to_string(),
                    entry_name: s.entry().map(|h| h.node_name.clone()),
                })
            }
        }
    }

    /// Called when the service is stopping: leave nothing behind.
    pub async fn shutdown(&self) {
        let _ = self.down().await;
    }
}

/// Brings a circuit up with the service's key. Any plan or kill switch a
/// crashed run left behind is undone first.
async fn connect(exit: &Invite, entry: Option<&Invite>, opts: &CircuitOptions) -> Result<Circuit> {
    let key = load_key()?;
    let _ = killswitch::remove();
    Circuit::up(
        CircuitSpec {
            exit: exit.clone(),
            entry: entry.cloned(),
        },
        key,
        opts.clone(),
    )
    .await
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
