//! The local control channel between a client (the command line now, the
//! browser in phase 4) and the service.
//!
//! One request, one response, one connection, each a single line of JSON. On
//! Unix it is a socket in /run that root and the `hidravpn` group may open
//! (mode 0660); on Windows a named pipe. Either way every request must carry
//! the control token, a secret the service writes where only those who may
//! drive it can read it (root and the group on Unix, mode 0640; on Windows
//! SYSTEM, administrators and signed-in users), so a web page that guesses
//! the address still cannot drive the tunnel.
//!
//! A client may also seal its request to the service's key (`seal.rs`), and
//! then believes only an answer the service sealed: that is how it knows
//! the service, and not something else holding the pipe's name, is what
//! answers. The command line and the browser always seal when the service
//! has a key; a plain request is still read, so older clients keep working.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hidravpn_core::Invite;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::daemon::Daemon;
use crate::paths;
use crate::seal::{self, AnswerSealer, ServiceKey};

/// A request from a client. The token is checked before the command is read.
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub token: String,
    #[serde(flatten)]
    pub cmd: Command,
}

/// Printed without the token, so no debug output can ever repeat it.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("token", &"<redacted>")
            .field("cmd", &self.cmd)
            .finish()
    }
}

/// A secret carried in a command (the pass account's token): the text as
/// it is on the wire, printed as "<redacted>".
#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

// `Up` carries up to a handful of invites and the others nothing; a request
// is one short-lived value, so the size difference costs nothing worth boxing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Command {
    /// Is the service alive?
    Ping,
    /// Connect: bring up the circuit, route the machine through it, arm the
    /// kill switch. `invite` is the exit node; `via` an entry node for two
    /// hops; `alternates` other exits and `alternate_entries` other entries
    /// that `new_identity` may rotate to. All but the first are absent in
    /// requests from before phase 3, which still work.
    Up {
        invite: Invite,
        #[serde(default)]
        allow_lan: bool,
        #[serde(default)]
        keep_ipv6: bool,
        #[serde(default)]
        via: Option<Invite>,
        #[serde(default)]
        alternates: Vec<Invite>,
        #[serde(default)]
        alternate_entries: Vec<Invite>,
        /// Two hops whose operator is the same, or not named, are refused
        /// unless this is true: the person's explicit yes.
        #[serde(default)]
        allow_same_operator: bool,
    },
    /// Disconnect and put the network back.
    Down,
    /// How things stand.
    Status,
    /// Rebuild the circuit through another exit node the service holds an
    /// invite for (and another entry, when it holds more than one), so the
    /// address the internet sees changes. With only one exit it reconnects
    /// to the same one and the reply's `note` says so.
    NewIdentity,
    /// Connect through nodes picked at random from the pocket this machine
    /// holds (`hidravpn nodes`), so the caller never handles an invite or a
    /// key: `mode` is "rapido" (one hop) or "privado" (two hops). This is
    /// how the browser connects.
    Connect {
        mode: String,
        #[serde(default)]
        allow_lan: bool,
        #[serde(default)]
        keep_ipv6: bool,
        /// Two hops whose operator is the same, or not named, are refused
        /// unless this is true: the person's explicit yes.
        #[serde(default)]
        allow_same_operator: bool,
    },
    /// The nodes in the pocket: slots, names and endpoints, never keys.
    Nodes,
    /// Put a signed node list into the pocket. `list` is the exact text of
    /// the published list and `signature` the text of its .sig; the service
    /// checks the signature against the list key it carries and only then
    /// reads the list. The answer carries the pocket as `nodes` and what
    /// happened as `note`. A list nobody signed goes nowhere.
    ImportNodes { list: String, signature: String },
    /// Ask admission from known nodes whose operators admit openly: one by
    /// name, or every one when `name` is absent. The service shows each node
    /// the key derived for it and checks the invite it gets against the
    /// list's record of that node. The answer carries the pocket as `nodes`
    /// and what happened as `note`.
    Join {
        #[serde(default)]
        name: Option<String>,
    },
    /// Ask the pass issuer the node list names for passes (phase 5), with
    /// the account token this machine keeps: `count` (10 by default) for
    /// each node that admits with a pass, or for the one named. The token
    /// never crosses the control channel. The answer carries the pocket as
    /// `nodes`, with each pass node's count, and what happened as `note`.
    GetPasses {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        count: Option<u32>,
    },
    /// Keep the account token `get_passes` asks with, root only on disk. The
    /// answer never repeats it.
    /// (`pass_token`, not `token`: that name is the control token's.)
    SetPassToken { pass_token: Secret },
    /// Automatic passes (phase 6): what is given is changed, the rest kept;
    /// with nothing given, only read. The answer carries the setting as
    /// `refill` and says it as `note`.
    Refill {
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default)]
        low: Option<u32>,
        #[serde(default)]
        count: Option<u32>,
    },
}

/// One node of the pocket, as `nodes` reports it. No key leaves the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeReport {
    /// "entry" or "exit" for a node this machine is admitted on; "known" for
    /// one it only knows of, from a signed list.
    pub slot: String,
    pub node_name: String,
    pub endpoint: String,
    /// False for a known node: it cannot be connected to until its operator
    /// admits this machine's key.
    #[serde(default)]
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// "entry", "exit" or "both", when the node said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// For a known node: "open" or "pass" means `join` can admit this
    /// machine on it. "pass" for an admitted node joined with a pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
    /// For a node that admits with a pass: how many the wallet holds for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passes: Option<usize>,
    /// Where the node is, two letters, when the list or the node said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// One hop of the circuit, as `status` reports it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopReport {
    /// "entry" or "exit".
    pub role: String,
    pub node_name: String,
    pub endpoint: String,
    /// Seconds since this hop's last WireGuard handshake; none yet if absent.
    pub last_handshake_secs: Option<u64>,
    /// This hop has a live session.
    pub connected: bool,
    /// Where the node is, two letters, when the list or the node said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub connected: bool,
    pub node_name: Option<String>,
    pub endpoint: Option<String>,
    pub last_handshake_secs: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub killswitch: bool,
    /// 1 (Rápido) or 2 (Privado); 0 when not connected.
    #[serde(default)]
    pub hops: u8,
    /// "rapido" or "privado"; empty when not connected.
    #[serde(default)]
    pub mode: String,
    /// The entry node of a two-hop circuit.
    #[serde(default)]
    pub entry_name: Option<String>,
    /// Every hop, entry first: its node, endpoint and handshake age.
    #[serde(default)]
    pub hops_detail: Vec<HopReport>,
    /// Two hops: both run by the same operator, as far as the invites say.
    /// Absent for one hop or when either node did not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_operator: Option<bool>,
    /// The version of the service answering, so a page can tell whether a
    /// newer signed release exists. Empty from a service older than this.
    #[serde(default)]
    pub version: String,
    /// IPv6 goes through the exit (it gave the tunnel an address); false
    /// when it is blocked while connected, or from an older service.
    #[serde(default)]
    pub ipv6: bool,
}

impl StatusReport {
    /// One honest line on what the current mode does and does not hide.
    /// Strong privacy, never anonymity: it says what each node sees.
    pub fn explanation(&self) -> Option<&'static str> {
        match self.mode.as_str() {
            "privado" => Some(
                "privado: no node sees both who you are and where you go; the entry sees your address, the exit sees your traffic",
            ),
            "rapido" => Some(
                "rapido: the node sees your address and your traffic; it hides them from your network, not from the node",
            ),
            _ => None,
        }
    }

    /// One line per hop: its role, node, endpoint and how old its last
    /// handshake is (a session is live for 180 s after a handshake).
    pub fn hop_lines(&self) -> Vec<String> {
        self.hops_detail
            .iter()
            .map(|h| {
                format!(
                    "{} {} ({}): last handshake {}{}",
                    h.role,
                    h.node_name,
                    h.endpoint,
                    h.last_handshake_secs
                        .map(|n| format!("{n}s ago"))
                        .unwrap_or_else(|| "none yet".into()),
                    if h.connected { "" } else { ", no session" }
                )
            })
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusReport>,
    /// Something the person should know that is not an error: for instance
    /// that a new identity could not change the exit because there is only
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The answer to `nodes`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<Vec<NodeReport>>,
    /// The answer to `refill`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refill: Option<crate::passes::Refill>,
}

impl Response {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            note: None,
            nodes: None,
            refill: None,
        }
    }
    pub fn with_status(s: StatusReport) -> Self {
        Self {
            ok: true,
            error: None,
            status: Some(s),
            note: None,
            nodes: None,
            refill: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            status: None,
            note: None,
            nodes: None,
            refill: None,
        }
    }
    pub fn noting(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
    pub fn with_nodes(nodes: Vec<NodeReport>) -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            note: None,
            nodes: Some(nodes),
            refill: None,
        }
    }
}

// ---- token ---------------------------------------------------------------

/// Makes a fresh control token and writes it where only the owner can read it.
pub fn write_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness: {e}"))?;
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(bytes);
    write_shared(&paths::control_token(), &token)?;
    Ok(token)
}

/// Makes the service's key for this run and writes its public half beside
/// the token, with the token's rights. The private half is never written.
pub fn write_service_key() -> Result<ServiceKey> {
    let key = ServiceKey::generate()?;
    write_shared(&paths::control_public_key(), &key.public_base64())?;
    Ok(key)
}

/// Writes a file the service owns and those who may drive it can read.
///
/// Written beside its place and then moved into it, so a client never finds
/// the file missing or half written while the service starts: a browser
/// that found the token but no key would take the service for one from
/// before sealed requests.
fn write_shared(path: &std::path::Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".new");
    let fresh = path.with_file_name(name);
    // A file of its own every time, never one left from an earlier run: that
    // keeps its mode and group (Unix), or the owner who made it first
    // (Windows), which may not be the ones wanted.
    let _ = std::fs::remove_file(&fresh);
    {
        use std::io::Write;
        let mut open = std::fs::OpenOptions::new();
        open.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.mode(0o600);
        }
        let mut f = open
            .open(&fresh)
            .with_context(|| format!("writing {}", fresh.display()))?;
        f.write_all(contents.as_bytes())
            .with_context(|| format!("writing {}", fresh.display()))?;
    }
    // Then its own rights: on Unix root's, the control group's to read; on
    // Windows inherited from nowhere, SYSTEM and administrators everything,
    // interactive users read.
    #[cfg(unix)]
    share_with_control_group(&fresh, 0o640)?;
    #[cfg(windows)]
    protect_shared(&fresh)?;
    if std::fs::rename(&fresh, path).is_err() {
        // Windows refuses to replace a file someone holds open without
        // letting it be deleted; it is removed first then, as before.
        let _ = std::fs::remove_file(path);
        std::fs::rename(&fresh, path).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

fn read_token() -> Result<String> {
    let path = paths::control_token();
    let t = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "could not read the control token at {} — is the HidraVPN service running, and are you running this as an administrator?",
            path.display()
        )
    })?;
    Ok(t.trim().to_string())
}

/// The service's public key, when it has one. None from a service older
/// than sealed requests, which wrote no key: it is asked in the clear, as
/// before. A key file that is there but unreadable is an error, never a
/// reason to fall back to the clear.
fn read_service_key() -> Result<Option<x25519_dalek::PublicKey>> {
    let path = paths::control_public_key();
    match std::fs::read_to_string(&path) {
        Ok(text) => seal::public_from_base64(&text)
            .map(Some)
            .with_context(|| format!("the service's key at {} is unreadable", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("could not read {}", path.display())),
    }
}

// ---- server --------------------------------------------------------------

/// The control channel, made but not yet served: the socket bound, or the
/// pipe's first instance created. Made before the service says it is
/// running, so a service that cannot have its channel never runs.
pub struct Listener {
    #[cfg(unix)]
    unix: tokio::net::UnixListener,
    #[cfg(windows)]
    first: tokio::net::windows::named_pipe::NamedPipeServer,
}

/// Makes the control channel. An error here is the end of the service: on
/// Windows it means another program already holds the pipe's name, and
/// would answer every client in the service's place.
pub fn listen() -> Result<Listener> {
    #[cfg(unix)]
    {
        Ok(Listener {
            unix: bind_unix(&paths::control_socket())?,
        })
    }
    #[cfg(windows)]
    {
        Ok(Listener {
            first: first_instance(paths::CONTROL_PIPE)?,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        anyhow::bail!("no control channel on this operating system")
    }
}

/// Serves the control channel until the process ends. Each connection is one
/// request and one response, sealed with `key` when the client sealed it.
pub async fn serve(listener: Listener, daemon: Arc<Daemon>, key: Arc<ServiceKey>) -> Result<()> {
    #[cfg(unix)]
    {
        serve_unix_listener(listener.unix, daemon, key).await
    }
    #[cfg(windows)]
    {
        serve_windows(listener.first, paths::CONTROL_PIPE, daemon, key).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (listener, daemon, key);
        anyhow::bail!("no control channel on this operating system")
    }
}

/// The Unix server, on a given path. Split out so a test can use a temporary
/// socket instead of the one in /run that only root may create.
#[cfg(unix)]
pub async fn serve_unix_at(
    path: &std::path::Path,
    daemon: Arc<Daemon>,
    key: Arc<ServiceKey>,
) -> Result<()> {
    serve_unix_listener(bind_unix(path)?, daemon, key).await
}

#[cfg(unix)]
fn bind_unix(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        // systemd makes /run/hidravpn 0750 root:root; a member of the group
        // has to be able to enter it to reach the socket.
        share_with_control_group(dir, 0o750)?;
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding the control socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    share_with_control_group(path, 0o660)?;
    Ok(listener)
}

#[cfg(unix)]
async fn serve_unix_listener(
    listener: tokio::net::UnixListener,
    daemon: Arc<Daemon>,
    key: Arc<ServiceKey>,
) -> Result<()> {
    tracing::info!("control channel ready");
    // So many at once and no more: a member of the group could otherwise
    // open connections until the service ran out of memory.
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let slot = slots.clone().acquire_owned().await?;
        // An accept error (out of descriptors) is waited out: ending here
        // would leave the circuit up with nobody able to send `down`.
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!("control channel: {e}; waiting");
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        // Who is asking: root may do everything; a member of the group may
        // not hand the service an invite, and may not switch off what
        // another account switched on.
        let caller = stream.peer_cred().ok().map(|c| c.uid());
        let d = daemon.clone();
        let key = key.clone();
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(e) = handle_conn(stream, d, &key, caller).await {
                tracing::debug!("control connection ended: {e}");
            }
        });
    }
}

/// The rights of the control token and the service's public key on
/// Windows, inherited from nowhere: SYSTEM and administrators everything,
/// interactive users read.
#[cfg(windows)]
pub fn protect_shared(path: &std::path::Path) -> Result<()> {
    let out = std::process::Command::new("icacls")
        .arg(path)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:F",
            "*S-1-5-32-544:F",
            "*S-1-5-4:R",
        ])
        .output()
        .with_context(|| format!("running icacls on {}", path.display()))?;
    if !out.status.success() {
        anyhow::bail!(
            "could not set the rights of {}: {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Hands the socket or the token to the control group when this machine has
/// one, so a member (the browser, running as the person) may open it. With no
/// such group everything stays root-only, as before.
#[cfg(unix)]
fn share_with_control_group(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(gid) = paths::control_gid() {
        std::os::unix::fs::chown(path, None, Some(gid)).with_context(|| {
            format!(
                "giving {} to the {} group",
                path.display(),
                paths::CONTROL_GROUP
            )
        })?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Sends one request to a given Unix socket path, in the clear (used by
/// tests, and as an older client would).
#[cfg(unix)]
pub async fn call_unix_at(path: &std::path::Path, token: &str, cmd: Command) -> Result<Response> {
    call_unix_sealed_at(path, token, None, cmd).await
}

/// The same, sealed to `key` when one is given (used by tests).
#[cfg(unix)]
pub async fn call_unix_sealed_at(
    path: &std::path::Path,
    token: &str,
    key: Option<&x25519_dalek::PublicKey>,
    cmd: Command,
) -> Result<Response> {
    let stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| anyhow!("could not reach the service ({e})"))?;
    exchange(stream, token, key, cmd).await
}

/// The pipe's first instance. It fails when the name already exists: then
/// some other program made the pipe first, and the service must not run
/// beside it (its clients could reach that program instead).
#[cfg(windows)]
fn first_instance(pipe: &str) -> Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    pipe_acl::instance(pipe, true).with_context(|| {
        format!("creating the control pipe {pipe}: another program may already hold that name")
    })
}

/// The pipe's instances, at most `PIPE_INSTANCES`. One instance always
/// listens: as soon as a client connects to it, it goes to that client and
/// a fresh one is made to listen, so there is never a moment with nothing
/// listening while a client is served. The limit does not keep other users
/// out: an idle service holds one instance of the eight, and a signed-in
/// user may add an instance of their own beside it (the pipe's descriptor
/// has to grant them write, and on a pipe write includes the right to make
/// an instance). A client cannot know which instance answers it; the
/// command line checks the server is in session 0, and both it and the
/// browser seal their requests (`seal.rs`), so whatever else answers can
/// neither read them nor answer them.
///
/// An instance serves one client and is closed: one disconnected and
/// listened on again no longer tells its next clients that the service, in
/// session 0, holds it (seen on Windows). It is closed only once the client
/// has closed its end, so the answer is never cut off and the slot is free
/// again at once for the next instance (closing first left the slot taken
/// until the client let go, and after eight clients in a row nothing
/// listened for seconds; seen on Windows).
#[cfg(windows)]
async fn serve_windows(
    first: tokio::net::windows::named_pipe::NamedPipeServer,
    pipe: &'static str,
    daemon: Arc<Daemon>,
    key: Arc<ServiceKey>,
) -> Result<()> {
    let mut listening = first;
    tracing::info!("control channel ready");
    loop {
        if let Err(e) = listening.connect().await {
            // An instance whose connect failed is not tried again.
            tracing::warn!("control pipe: {e}");
            listening = fresh_instance(pipe).await;
            continue;
        }
        let d = daemon.clone();
        tokio::spawn(serve_one(listening, d, key.clone()));
        listening = fresh_instance(pipe).await;
    }
}

/// A new listening instance, retried until the pool has a slot for it: a
/// slot frees when a client being served is done.
#[cfg(windows)]
async fn fresh_instance(pipe: &str) -> tokio::net::windows::named_pipe::NamedPipeServer {
    let mut wait = std::time::Duration::from_millis(5);
    let mut tries = 0u32;
    loop {
        match pipe_acl::instance(pipe, false) {
            Ok(s) => return s,
            Err(e) => {
                tries += 1;
                // Every slot busy is normal for a moment; for long, it is not.
                if tries == 40 {
                    tracing::warn!("control pipe: no new instance for a while: {e:#}");
                }
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(std::time::Duration::from_millis(100));
            }
        }
    }
}

/// One client on its own instance: its request, the answer, and then the
/// instance is closed once the client has closed its end (or after a
/// short wait).
#[cfg(windows)]
async fn serve_one(
    mut server: tokio::net::windows::named_pipe::NamedPipeServer,
    daemon: Arc<Daemon>,
    key: Arc<ServiceKey>,
) {
    // Windows has no uid on a pipe; an elevated caller counts as root, and
    // everyone else as one unnamed account.
    let caller = if pipe_acl::client_is_elevated(&server) {
        Some(0)
    } else {
        None
    };
    if let Err(e) = handle_conn(&mut server, daemon, &key, caller).await {
        tracing::debug!("control connection ended: {e}");
    }
    let mut rest = [0u8; 256];
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            match server.read(&mut rest).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;
}

/// Who may open the control pipe. Its default descriptor lets a signed-in
/// user read only, so a request from the browser (which runs as the person,
/// not elevated) would be refused before the token was ever looked at. This
/// one gives SYSTEM and administrators everything and any signed-in user
/// read and write. The token is still what every request must carry.
#[cfg(windows)]
mod pipe_acl {
    use anyhow::{anyhow, Result};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    // SYSTEM and administrators everything; interactive users (console and
    // Remote Desktop) read and write. Not "authenticated users": that would
    // include service accounts and network logons, which have no business
    // here. A client's GENERIC_READ|GENERIC_WRITE maps to exactly what GRGW
    // grants, so a plain user's open succeeds; nothing narrower would let it.
    // On a pipe that write includes FILE_APPEND_DATA, which is also
    // FILE_CREATE_PIPE_INSTANCE: a signed-in user may add an instance of
    // this pipe. It cannot be taken out without breaking the browser, whose
    // Node opens a pipe with GENERIC_WRITE or read only, so the clients do
    // not trust the name: they seal (`seal.rs`).
    const SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: the descriptor came from the converter below, which
            // allocates it with LocalAlloc.
            unsafe {
                let _ = LocalFree(HLOCAL(self.0 .0));
            }
        }
    }

    /// Is the server at the other end of this client handle in session 0,
    /// where services live? A pipe made by a signed-in user is not.
    pub fn server_is_a_service(client: &tokio::net::windows::named_pipe::NamedPipeClient) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Pipes::GetNamedPipeServerSessionId;
        let pipe = HANDLE(client.as_raw_handle());
        let mut session = u32::MAX;
        // SAFETY: a query on a handle this process owns, into a local.
        unsafe { GetNamedPipeServerSessionId(pipe, &mut session).is_ok() && session == 0 }
    }

    /// Is the client at the other end of this instance an elevated process
    /// (an administrator's prompt, or SYSTEM)? Anything that cannot be
    /// established counts as not.
    pub fn client_is_elevated(server: &NamedPipeServer) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
        use windows::Win32::System::Threading::{
            OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        let pipe = HANDLE(server.as_raw_handle());
        let mut pid = 0u32;
        // SAFETY: plain Win32 calls on handles this process owns; every
        // out-pointer is to a local; handles opened here are closed here.
        unsafe {
            if GetNamedPipeClientProcessId(pipe, &mut pid).is_err() {
                return false;
            }
            let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                return false;
            };
            let mut token = HANDLE::default();
            let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token).is_ok();
            let _ = CloseHandle(process);
            if !opened {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut len = 0u32;
            let got = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut TOKEN_ELEVATION as *mut std::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            )
            .is_ok();
            let _ = CloseHandle(token);
            got && elevation.TokenIsElevated != 0
        }
    }

    /// One pipe instance with that descriptor, and the pool's size as the
    /// pipe's limit. The descriptor is copied into the pipe when it is made,
    /// so it is freed as soon as this returns and nothing with a raw pointer
    /// is ever held across an await.
    pub fn instance(pipe: &str, first: bool) -> Result<NamedPipeServer> {
        let wide: Vec<u16> = SDDL.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the
        // call; `raw` is a valid out-pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut raw,
                None,
            )
        }
        .map_err(|e| anyhow!("building the control pipe's security descriptor: {e}"))?;
        let descriptor = Descriptor(raw);
        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0 .0,
            bInheritHandle: false.into(),
        };
        // SAFETY: `attrs` is a complete SECURITY_ATTRIBUTES that lives until
        // the call returns, and the descriptor it points to lives longer.
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first)
                .max_instances(super::PIPE_INSTANCES as usize)
                .create_with_security_attributes_raw(
                    pipe,
                    &mut attrs as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void,
                )
        }?;
        Ok(server)
    }
}

/// A request is one line: a command, or a node list of a few hundred nodes
/// at most (a few hundred kilobytes, a third more when sealed). Past this it
/// is not a client talking, and the line is cut, which makes it unreadable
/// JSON and so a refused request.
const MAX_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
/// A client that opens a connection says what it wants within this, and takes
/// the answer within this; otherwise the connection is dropped, so a client
/// that only opens connections holds nothing for long.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Connections served at once on the Unix socket.
#[cfg(unix)]
const MAX_CONNECTIONS: usize = 16;
/// Pipe instances on Windows: the whole pipe, held by the service.
#[cfg(windows)]
const PIPE_INSTANCES: u32 = 8;

async fn handle_conn<S>(
    stream: S,
    daemon: Arc<Daemon>,
    key: &ServiceKey,
    caller: Option<u32>,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r.take(MAX_REQUEST_BYTES));
    let mut line = String::new();
    let n = tokio::time::timeout(REQUEST_TIMEOUT, reader.read_line(&mut line))
        .await
        .map_err(|_| anyhow!("no request within {REQUEST_TIMEOUT:?}"))??;
    if n == 0 {
        return Ok(());
    }
    let mut sealer = None;
    let resp = if !line.ends_with('\n') && line.len() as u64 >= MAX_REQUEST_BYTES {
        Response::err("bad request: larger than anything the service accepts")
    } else {
        match open_line(line.trim(), key) {
            // Sealed, but not to this service's key, or not sealed right:
            // said in the clear, since there is no key to answer under.
            Err(e) => Response::err(format!("bad request: {e:#}")),
            Ok((value, s)) => {
                sealer = s;
                // The token first: whoever does not hold it learns nothing
                // of how the service reads a command, not even what is
                // wrong with theirs.
                let token = value
                    .as_ref()
                    .and_then(|v| v.get("token"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                if !daemon.token_ok(token) {
                    Response::err(crate::daemon::UNAUTHORISED)
                } else {
                    match serde_json::from_value::<Request>(value.unwrap_or_default()) {
                        Ok(req) => daemon.handle(req, caller).await,
                        Err(e) => Response::err(format!("bad request: {e}")),
                    }
                }
            }
        }
    };
    let mut out = serde_json::to_string(&resp)?;
    if let Some(sealer) = sealer {
        out = sealer.seal(out.as_bytes())?;
    }
    out.push('\n');
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        w.write_all(out.as_bytes()).await?;
        w.flush().await
    })
    .await
    .map_err(|_| anyhow!("the client did not take the answer within {REQUEST_TIMEOUT:?}"))??;
    Ok(())
}

/// The request a line carries: the line itself, or, for a sealed line, what
/// it opens to, with what seals its answer. A line that is not JSON is no
/// request at all, refused for its missing token.
fn open_line(
    line: &str,
    key: &ServiceKey,
) -> Result<(Option<serde_json::Value>, Option<AnswerSealer>)> {
    match serde_json::from_str::<serde_json::Value>(line).ok() {
        Some(value) if value.get("seal").is_some() => {
            let sealed: seal::SealedRequest = serde_json::from_value(value)
                .map_err(|_| anyhow!("a sealed request missing a part"))?;
            let (plain, sealer) = key.open(&sealed)?;
            Ok((serde_json::from_slice(&plain).ok(), Some(sealer)))
        }
        value => Ok((value, None)),
    }
}

// ---- client --------------------------------------------------------------

/// The service's channel is answered by something that is not the service:
/// a pipe served outside session 0, or an answer not sealed with the
/// service's key. A client says so and stops: it never goes around the
/// service by changing the network itself, which would undo the service's
/// kill switch.
#[derive(Debug)]
pub struct Impostor;

impl std::fmt::Display for Impostor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("something other than the HidraVPN service is answering on its control channel; refusing to believe it (restart the HidraVPN service, or this computer)")
    }
}

impl std::error::Error for Impostor {}

/// There is no service to ask: no control channel, or no token. Only then
/// may a client act on the network itself. A service that is there but
/// does not answer, or answers badly, is a different error: a client says
/// so and stops, since that service may hold the network.
#[derive(Debug)]
pub struct NotRunning(String);

impl std::fmt::Display for NotRunning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NotRunning {}

/// Sends one command to the running service and returns its answer. Sealed
/// to the service's key when it has one, and then only an answer the
/// service sealed is believed.
pub async fn call(cmd: Command) -> Result<Response> {
    let token = read_token().map_err(|e| NotRunning(format!("{e:#}")))?;
    let key = read_service_key()?;

    #[cfg(unix)]
    {
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(paths::control_socket())
            .await
            .map_err(|e| NotRunning(format!("the HidraVPN service is not running ({e})")))?;
        exchange(stream, &token, key.as_ref(), cmd).await
    }
    #[cfg(windows)]
    {
        let stream = open_pipe(paths::CONTROL_PIPE, true).await?;
        exchange(stream, &token, key.as_ref(), cmd).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (token, key, cmd);
        anyhow::bail!("no control channel on this operating system")
    }
}

/// One request and its answer on a connected stream: sealed to `key` when
/// there is one, and then the answer must open with it.
async fn exchange<S>(
    stream: S,
    token: &str,
    key: Option<&x25519_dalek::PublicKey>,
    cmd: Command,
) -> Result<Response>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let plain = serde_json::to_string(&Request {
        token: token.to_string(),
        cmd,
    })?;
    let (mut line, opener) = match key {
        Some(key) => {
            let (line, opener) = seal::seal_request(key, plain.as_bytes())?;
            (line, Some(opener))
        }
        None => (plain, None),
    };
    line.push('\n');
    let mut answer = round_trip(stream, line.as_bytes()).await?;
    if let Some(opener) = opener {
        let plain = opener.open(&answer).map_err(|_| Impostor)?;
        answer = String::from_utf8(plain).map_err(|_| Impostor)?;
    }
    serde_json::from_str(answer.trim()).context("the service sent an unreadable answer")
}

/// Opens the pipe `pipe`, and checks before anything is sent that its
/// server is in session 0. `only_the_service` is false only in tests, which
/// cannot run a server in session 0.
#[cfg(windows)]
async fn open_pipe(
    pipe: &str,
    only_the_service: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use std::time::Duration;
    use tokio::net::windows::named_pipe::ClientOptions;
    // ERROR_PIPE_BUSY: every instance of the fixed pool is serving another
    // client for the moment; each listens again once its client is done,
    // so the wait is short; retry briefly rather than report the service
    // down. A missing pipe (service really not running) fails at once.
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut tries = 0u32;
    let stream = loop {
        match ClientOptions::new().open(pipe) {
            Ok(s) => break s,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 40 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err(
                    NotRunning(format!("the HidraVPN service is not running ({e})")).into(),
                );
            }
            Err(e) => {
                return Err(anyhow!(
                    "the HidraVPN service is running but its control channel does not answer ({e}); restart it: Stop-ScheduledTask -TaskName HidraVPN, then Start-ScheduledTask -TaskName HidraVPN"
                ));
            }
        }
    };
    // Before the token goes anywhere: is the service at the other end?
    // The service runs in session 0; a pipe instance made by a signed-in
    // user sits in that user's session.
    if only_the_service && !pipe_acl::server_is_a_service(&stream) {
        return Err(Impostor.into());
    }
    Ok(stream)
}

/// Writes the request line and reads the answer line.
async fn round_trip<S>(stream: S, request: &[u8]) -> Result<String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    w.write_all(request).await?;
    w.flush().await?;
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    if line.trim().is_empty() {
        // Some pipe closes give EOF with no line; read the rest if any.
        let mut rest = String::new();
        let _ = reader.read_to_string(&mut rest).await;
        line.push_str(&rest);
    }
    Ok(line)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn no_debug_output_repeats_a_token() {
        let r = Request {
            token: "control-secret".into(),
            cmd: Command::SetPassToken {
                pass_token: Secret("account-secret".into()),
            },
        };
        let d = format!("{r:?}");
        assert!(
            !d.contains("control-secret") && !d.contains("account-secret"),
            "{d}"
        );
        // And the wire form is unchanged: a plain string.
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"pass_token\":\"account-secret\""), "{j}");
    }
    use crate::daemon::Daemon;

    async fn start(token: &str) -> std::path::PathBuf {
        start_with_pocket(token, None).await
    }

    /// A daemon whose pocket is a given file, so `connect` and `nodes` can be
    /// tried without touching /etc.
    async fn start_with_pocket(
        token: &str,
        pocket: Option<std::path::PathBuf>,
    ) -> std::path::PathBuf {
        let d = match pocket {
            Some(p) => Daemon::with_pocket(token.to_string(), p),
            None => Daemon::new(token.to_string()),
        };
        serve_daemon(d).await.0
    }

    /// Serves `d` on a temporary socket with a key of its own: the socket,
    /// and the public key a client seals to.
    async fn serve_daemon(d: Arc<Daemon>) -> (std::path::PathBuf, x25519_dalek::PublicKey) {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join(format!("ctl-{}.sock", rand_suffix()));
        let key = Arc::new(ServiceKey::generate().unwrap());
        let public = seal::public_from_base64(&key.public_base64()).unwrap();
        let s = sock.clone();
        tokio::spawn(async move {
            let _ = serve_unix_at(&s, d, key).await;
        });
        // Give the listener a moment to bind.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (sock, public)
    }

    fn rand_suffix() -> u64 {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        u64::from_le_bytes(b)
    }

    #[tokio::test]
    async fn ping_needs_the_right_token() {
        let sock = start("the-secret").await;
        let ok = call_unix_at(&sock, "the-secret", Command::Ping)
            .await
            .unwrap();
        assert!(ok.ok, "a correct token is accepted");
        let bad = call_unix_at(&sock, "wrong", Command::Ping).await.unwrap();
        assert!(!bad.ok, "a wrong token is refused");
        assert!(bad.error.unwrap().contains("unauthorised"));
    }

    #[tokio::test]
    async fn status_reports_disconnected_when_nothing_is_up() {
        let sock = start("tok").await;
        let resp = call_unix_at(&sock, "tok", Command::Status).await.unwrap();
        assert!(resp.ok);
        let s = resp.status.expect("a status report");
        assert!(!s.connected);
        assert_eq!(s.tx_bytes, 0);
        assert_eq!(s.hops, 0);
        assert_eq!(s.mode, "");
        assert!(s.entry_name.is_none());
    }

    #[tokio::test]
    async fn new_identity_with_nothing_up_is_an_error_not_a_crash() {
        let sock = start("tok").await;
        let resp = call_unix_at(&sock, "tok", Command::NewIdentity)
            .await
            .unwrap();
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("not connected"));
    }

    fn invite(name: &str, endpoint: &str) -> Invite {
        Invite {
            node_name: name.into(),
            node_public_key: hidravpn_core::ClientKey::generate()
                .unwrap()
                .public_base64(),
            endpoint: endpoint.into(),
            client_address: "10.77.0.2/16".into(),
            client_address6: None,
            dns: std::net::Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1420,
            keepalive: 25,
            operator: None,
            role: None,
            pass: None,
            country: None,
            admission: None,
            admission_port: None,
            behind: false,
            features: Vec::new(),
        }
    }

    #[test]
    fn a_phase_2_up_request_still_parses_with_no_via_and_no_alternates() {
        let inv = invite("exit", "203.0.113.10:51820");
        let old = format!(
            r#"{{"token":"t","cmd":"up","invite":{},"allow_lan":false}}"#,
            serde_json::to_string(&inv).unwrap()
        );
        let req: Request = serde_json::from_str(&old).unwrap();
        match req.cmd {
            Command::Up {
                via, alternates, ..
            } => {
                assert!(via.is_none());
                assert!(alternates.is_empty());
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn a_two_hop_up_request_round_trips_with_its_alternates() {
        let req = Request {
            token: "t".into(),
            cmd: Command::Up {
                invite: invite("exit", "203.0.113.10:51820"),
                allow_lan: false,
                keep_ipv6: false,
                via: Some(invite("entry", "203.0.113.20:51820")),
                alternates: vec![invite("exit2", "198.51.100.9:51820")],
                alternate_entries: vec![invite("entry2", "203.0.113.21:51820")],
                allow_same_operator: false,
            },
        };
        let line = serde_json::to_string(&req).unwrap();
        assert!(line.contains(r#""cmd":"up""#));
        let again: Request = serde_json::from_str(&line).unwrap();
        match again.cmd {
            Command::Up {
                via,
                alternates,
                alternate_entries,
                ..
            } => {
                assert_eq!(via.unwrap().node_name, "entry");
                assert_eq!(alternates.len(), 1);
                assert_eq!(alternates[0].node_name, "exit2");
                assert_eq!(alternate_entries.len(), 1);
                assert_eq!(alternate_entries[0].node_name, "entry2");
            }
            other => panic!("parsed as {other:?}"),
        }
        let ni: Request = serde_json::from_str(r#"{"token":"t","cmd":"new_identity"}"#).unwrap();
        assert!(matches!(ni.cmd, Command::NewIdentity));
    }

    #[test]
    fn the_status_report_carries_the_mode_and_the_hops_and_a_note_is_optional() {
        let s = StatusReport {
            connected: true,
            node_name: Some("exit".into()),
            endpoint: Some("203.0.113.10:51820".into()),
            last_handshake_secs: Some(3),
            tx_bytes: 1,
            rx_bytes: 2,
            killswitch: true,
            hops: 2,
            mode: "privado".into(),
            entry_name: Some("entry".into()),
            hops_detail: vec![HopReport {
                role: "entry".into(),
                node_name: "entry".into(),
                endpoint: "203.0.113.20:51820".into(),
                last_handshake_secs: Some(4),
                connected: true,
                country: None,
            }],
            same_operator: None,
            version: String::new(),
            ipv6: false,
        };
        let r = Response::with_status(s).noting("rotated");
        let line = serde_json::to_string(&r).unwrap();
        assert!(line.contains(r#""hops":2"#));
        assert!(line.contains(r#""mode":"privado""#));
        assert!(line.contains(r#""entry_name":"entry""#));
        assert!(line.contains(r#""note":"rotated""#));
        assert!(line.contains(r#""hops_detail":[{"role":"entry""#));
        let plain = serde_json::to_string(&Response::ok()).unwrap();
        assert!(!plain.contains("note"));
        // A report from a phase-2 service, without the new fields, still reads.
        let old: StatusReport = serde_json::from_str(
            r#"{"connected":false,"node_name":null,"endpoint":null,"last_handshake_secs":null,"tx_bytes":0,"rx_bytes":0,"killswitch":false}"#,
        )
        .unwrap();
        assert_eq!(old.hops, 0);
        assert!(old.hops_detail.is_empty());
        assert!(old.explanation().is_none());
        assert!(old.hop_lines().is_empty());
    }

    #[test]
    fn the_explanation_says_what_each_node_sees_and_never_promises_anonymity() {
        let mut s = StatusReport {
            connected: true,
            node_name: Some("exit".into()),
            endpoint: Some("203.0.113.10:51820".into()),
            last_handshake_secs: Some(3),
            tx_bytes: 0,
            rx_bytes: 0,
            killswitch: true,
            hops: 2,
            mode: "privado".into(),
            entry_name: Some("entry".into()),
            hops_detail: vec![
                HopReport {
                    role: "entry".into(),
                    node_name: "entry".into(),
                    endpoint: "203.0.113.20:51820".into(),
                    last_handshake_secs: Some(4),
                    connected: true,
                    country: None,
                },
                HopReport {
                    role: "exit".into(),
                    node_name: "exit".into(),
                    endpoint: "203.0.113.10:51820".into(),
                    last_handshake_secs: None,
                    connected: false,
                    country: None,
                },
            ],
            same_operator: None,
            version: String::new(),
            ipv6: false,
        };
        let p = s.explanation().unwrap();
        assert!(p.contains("no node sees both"));
        assert!(p.contains("the entry sees your address"));
        s.mode = "rapido".into();
        let r = s.explanation().unwrap();
        assert!(r.contains("the node sees your address and your traffic"));
        for text in [p, r] {
            assert!(!text.to_lowercase().contains("anonym"), "{text}");
        }
        let lines = s.hop_lines();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("entry entry (203.0.113.20:51820): last handshake 4s ago"));
        assert!(
            lines[1].ends_with("last handshake none yet, no session"),
            "{}",
            lines[1]
        );
    }

    #[test]
    fn a_phase_3_up_request_without_alternate_entries_still_parses() {
        let inv = invite("exit", "203.0.113.10:51820");
        let old = format!(
            r#"{{"token":"t","cmd":"up","invite":{},"via":{},"alternates":[]}}"#,
            serde_json::to_string(&inv).unwrap(),
            serde_json::to_string(&invite("entry", "203.0.113.20:51820")).unwrap()
        );
        let req: Request = serde_json::from_str(&old).unwrap();
        match req.cmd {
            Command::Up {
                via,
                alternate_entries,
                ..
            } => {
                assert!(via.is_some());
                assert!(alternate_entries.is_empty());
            }
            other => panic!("parsed as {other:?}"),
        }
    }

    #[test]
    fn a_connect_request_parses_with_its_defaults_and_nodes_has_no_fields() {
        let req: Request =
            serde_json::from_str(r#"{"token":"t","cmd":"connect","mode":"privado"}"#).unwrap();
        match req.cmd {
            Command::Connect {
                mode,
                allow_lan,
                keep_ipv6,
                allow_same_operator,
            } => {
                assert!(
                    !allow_same_operator,
                    "two hops under one operator only when asked"
                );
                assert_eq!(mode, "privado");
                assert!(!allow_lan);
                assert!(!keep_ipv6);
            }
            other => panic!("parsed as {other:?}"),
        }
        let req: Request = serde_json::from_str(r#"{"token":"t","cmd":"nodes"}"#).unwrap();
        assert!(matches!(req.cmd, Command::Nodes));
        let line = serde_json::to_string(&Request {
            token: "t".into(),
            cmd: Command::Connect {
                mode: "rapido".into(),
                allow_lan: false,
                keep_ipv6: true,
                allow_same_operator: false,
            },
        })
        .unwrap();
        assert!(line.contains(r#""cmd":"connect""#));
        assert!(line.contains(r#""mode":"rapido""#));
    }

    fn write_pocket(dir: &std::path::Path, pocket: &hidravpn_core::Pocket) -> std::path::PathBuf {
        let p = dir.join(format!("pocket-{}.json", rand_suffix()));
        std::fs::write(&p, pocket.to_json()).unwrap();
        p
    }

    #[tokio::test]
    async fn nodes_lists_the_pocket_by_name_and_slot_and_never_a_key() {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut pocket = hidravpn_core::Pocket::default();
        pocket
            .add(
                hidravpn_core::Slot::Entry,
                invite("entry-a", "203.0.113.20:51820"),
            )
            .unwrap();
        pocket
            .add(
                hidravpn_core::Slot::Exit,
                invite("exit-a", "203.0.113.10:51820"),
            )
            .unwrap();
        let path = write_pocket(&dir, &pocket);
        let sock = start_with_pocket("tok", Some(path)).await;
        let resp = call_unix_at(&sock, "tok", Command::Nodes).await.unwrap();
        assert!(resp.ok, "{:?}", resp.error);
        let nodes = resp.nodes.clone().expect("a node list");
        assert_eq!(nodes.len(), 2);
        assert_eq!(
            (nodes[0].slot.as_str(), nodes[0].node_name.as_str()),
            ("entry", "entry-a")
        );
        assert_eq!(
            (nodes[1].slot.as_str(), nodes[1].node_name.as_str()),
            ("exit", "exit-a")
        );
        let line = serde_json::to_string(&resp).unwrap();
        assert!(
            !line.contains("public_key"),
            "a key reached the wire: {line}"
        );
        assert!(!line.contains(&pocket.exits[0].node_public_key));
    }

    #[tokio::test]
    async fn connect_refuses_an_empty_pocket_and_an_unknown_mode_before_touching_anything() {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A pocket file that does not exist is an empty pocket.
        let missing = dir.join(format!("absent-{}.json", rand_suffix()));
        let sock = start_with_pocket("tok", Some(missing)).await;
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::Connect {
                mode: "rapido".into(),
                allow_lan: false,
                keep_ipv6: false,
                allow_same_operator: false,
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        assert!(
            resp.error.as_deref().unwrap().contains("no nodes"),
            "{:?}",
            resp.error
        );
        let status = call_unix_at(&sock, "tok", Command::Status).await.unwrap();
        assert!(!status.status.unwrap().connected);

        let mut pocket = hidravpn_core::Pocket::default();
        pocket
            .add(
                hidravpn_core::Slot::Exit,
                invite("exit-a", "203.0.113.10:51820"),
            )
            .unwrap();
        let sock = start_with_pocket("tok", Some(write_pocket(&dir, &pocket))).await;
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::Connect {
                mode: "turbo".into(),
                allow_lan: false,
                keep_ipv6: false,
                allow_same_operator: false,
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        let e = resp.error.unwrap();
        assert!(e.contains("rapido") && e.contains("privado"), "{e}");
        // Privado needs an entry too; with only an exit it says which is missing.
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::Connect {
                mode: "privado".into(),
                allow_lan: false,
                keep_ipv6: false,
                allow_same_operator: false,
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("no entry node"));
    }

    /// A signing key for this test only; the real one never comes near here.
    fn test_signer() -> (ed25519_dalek::SigningKey, hidravpn_core::ReleaseKey) {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        use base64::Engine;
        let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        (sk, hidravpn_core::ReleaseKey::from_base64(&pk).unwrap())
    }

    fn signed_list(sk: &ed25519_dalek::SigningKey) -> (String, String) {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let rec = |name: &str, ep: &str| hidravpn_core::NodeRecord {
            node_name: name.into(),
            node_public_key: hidravpn_core::ClientKey::generate()
                .unwrap()
                .public_base64(),
            endpoint: ep.into(),
            operator: Some("the maintainers".into()),
            contact: None,
            role: Some("both".into()),
            admission: Some("manual".into()),
            admission_port: None,
            country: None,
            features: Vec::new(),
        };
        let dir = hidravpn_core::Directory {
            version: 1,
            generated: "2026-10-13T00:00:00Z".into(),
            sequence: 1,
            expires: None,
            removed: vec![],
            note: None,
            nodes: vec![
                rec("node-1", "203.0.113.20:51820"),
                rec("node-2", "203.0.113.10:51820"),
            ],
            pass_issuer: None,
        };
        let json = dir.to_json();
        let sig =
            base64::engine::general_purpose::STANDARD.encode(sk.sign(json.as_bytes()).to_bytes());
        (json, sig)
    }

    #[tokio::test]
    async fn a_signed_node_list_fills_the_pocket_through_the_socket_and_a_changed_one_does_not() {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pocket_path = dir.join(format!("import-{}.json", rand_suffix()));
        let (sk, key) = test_signer();
        let (json, sig) = signed_list(&sk);

        let d = Daemon::with_pocket_and_key("tok".to_string(), pocket_path.clone(), Some(key));
        let (sock, _) = serve_daemon(d).await;

        // Changed after signing: refused, and no pocket file appears.
        let tampered = json.replace("203.0.113.10", "198.51.100.7");
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::ImportNodes {
                list: tampered,
                signature: sig.clone(),
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("not accepted"));
        assert!(!pocket_path.exists(), "a refused import wrote a pocket");

        // As signed: the pocket is written, and the answer lists it without keys.
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::ImportNodes {
                list: json.clone(),
                signature: sig.clone(),
            },
        )
        .await
        .unwrap();
        assert!(resp.ok, "{:?}", resp.error);
        assert_eq!(resp.note.as_deref(), Some("added 2 node(s)"));
        let nodes = resp.nodes.unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.slot == "known" && !n.admitted));
        assert_eq!(nodes[0].operator.as_deref(), Some("the maintainers"));
        assert!(!serde_json::to_string(&nodes)
            .unwrap()
            .contains("public_key"));
        let on_disk =
            hidravpn_core::Pocket::from_json(&std::fs::read_to_string(&pocket_path).unwrap())
                .unwrap();
        assert_eq!(on_disk.known.len(), 2);
        assert!(on_disk.is_empty(), "a list admits nobody");
        // And so connecting still says what is missing, naming the known nodes.
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::Connect {
                mode: "rapido".into(),
                allow_lan: false,
                keep_ipv6: false,
                allow_same_operator: false,
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        assert!(
            resp.error.as_deref().unwrap().contains("knows 2 node(s)"),
            "{:?}",
            resp.error
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&pocket_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        // Once more: nothing added, nothing broken.
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::ImportNodes {
                list: json,
                signature: sig,
            },
        )
        .await
        .unwrap();
        assert!(resp.ok);
        assert_eq!(resp.note.as_deref(), Some("added 0 node(s), skipped 2"));
    }

    #[tokio::test]
    async fn an_import_signed_with_another_key_than_the_built_in_one_is_refused() {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (sk, _) = test_signer();
        let (json, sig) = signed_list(&sk);
        // The default daemon carries whatever this build embeds: the
        // maintainers' list key, or nothing. Either way a list signed by this
        // test's key goes nowhere, and the reason says which.
        let sock = start_with_pocket(
            "tok",
            Some(dir.join(format!("nokey-{}.json", rand_suffix()))),
        )
        .await;
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::ImportNodes {
                list: json,
                signature: sig,
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        let err = resp.error.unwrap();
        if hidravpn_core::release::LIST_PUBLIC_KEY_B64.is_empty() {
            assert!(err.contains("no list key"), "{err}");
        } else {
            assert!(err.contains("not accepted"), "{err}");
        }
    }

    #[tokio::test]
    async fn automatic_passes_are_read_and_set_over_the_channel() {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-refill-{}", rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let pocket = dir.join("circuit.json");
        let sock = start_with_pocket("ref", Some(pocket)).await;
        let read = || Command::Refill {
            enabled: None,
            low: None,
            count: None,
        };
        let resp = call_unix_at(&sock, "ref", read()).await.unwrap();
        assert!(resp.ok && resp.refill == Some(crate::passes::Refill::default()));
        assert!(!dir.join("refill.json").exists(), "reading writes nothing");
        let resp = call_unix_at(
            &sock,
            "ref",
            Command::Refill {
                enabled: Some(false),
                low: None,
                count: Some(20),
            },
        )
        .await
        .unwrap();
        assert!(resp.ok, "{:?}", resp.error);
        let r = resp.refill.unwrap();
        assert!(!r.enabled && r.low == 3 && r.count == 20);
        assert!(resp.note.unwrap().contains("off"));
        let resp = call_unix_at(
            &sock,
            "ref",
            Command::Refill {
                enabled: None,
                low: Some(30),
                count: None,
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok, "a low not below the count is refused");
        let resp = call_unix_at(&sock, "ref", read()).await.unwrap();
        assert_eq!(resp.refill.unwrap().count, 20, "and changed nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_pass_token_is_kept_root_only_and_never_repeated() {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-tok-{}", rand_suffix()));
        std::fs::create_dir_all(&dir).unwrap();
        let pocket = dir.join("circuit.json");
        let sock = start_with_pocket("tok", Some(pocket)).await;
        let token = "Zm9vYmFyLXRva2VuLTEyMw";
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::SetPassToken {
                pass_token: Secret(format!("  {token}\n")),
            },
        )
        .await
        .unwrap();
        assert!(resp.ok, "{:?}", resp.error);
        assert!(!serde_json::to_string(&resp).unwrap().contains(token));
        let kept = dir.join("pass.token");
        assert_eq!(std::fs::read_to_string(&kept).unwrap(), token);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::SetPassToken {
                pass_token: Secret("two words".into()),
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        assert_eq!(
            std::fs::read_to_string(&kept).unwrap(),
            token,
            "a bad token changes nothing"
        );
        // With a token but no list naming an issuer, asking for passes says
        // what is missing.
        let resp = call_unix_at(
            &sock,
            "tok",
            Command::GetPasses {
                name: None,
                count: Some(1),
            },
        )
        .await
        .unwrap();
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("names no pass issuer"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_request_far_larger_than_any_node_list_is_refused_not_buffered() {
        let sock = start("tok").await;
        // Five megabytes of a single line: cut at the cap, so unreadable JSON.
        let huge = format!(
            r#"{{"token":"tok","cmd":"import_nodes","signature":"x","list":"{}"}}"#,
            "a".repeat(5 * 1024 * 1024)
        );
        let mut line = huge;
        line.push('\n');
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        // The server stops reading at the cap and answers; the rest of the
        // write may then fail with a closed pipe, which is the point: nothing
        // past the cap is read. So the write runs on its own, errors ignored,
        // while the answer is read.
        let (r, mut w) = tokio::io::split(stream);
        let bytes = line.into_bytes();
        tokio::spawn(async move {
            let _ = w.write_all(&bytes).await;
        });
        let mut reader = BufReader::new(r);
        let mut answer = String::new();
        reader.read_line(&mut answer).await.unwrap();
        let resp: Response = serde_json::from_str(answer.trim()).unwrap();
        assert!(!resp.ok);
        assert!(resp.error.unwrap().contains("larger than anything"));
    }

    #[tokio::test]
    async fn a_sealed_request_is_answered_sealed_and_a_plain_one_still_in_the_clear() {
        let (sock, public) = serve_daemon(Daemon::new("tok".into())).await;
        let resp = call_unix_sealed_at(&sock, "tok", Some(&public), Command::Status)
            .await
            .unwrap();
        assert!(resp.ok && !resp.status.unwrap().connected);
        // The token inside the seal is still checked.
        let resp = call_unix_sealed_at(&sock, "wrong", Some(&public), Command::Ping)
            .await
            .unwrap();
        assert!(!resp.ok && resp.error.unwrap().contains("unauthorised"));
        // An older client, or a script, that does not seal is still answered.
        let resp = call_unix_at(&sock, "tok", Command::Ping).await.unwrap();
        assert!(resp.ok);

        // On the wire: the token never travels readable, and the answer is
        // sealed too.
        let plain = serde_json::to_string(&Request {
            token: "tok".into(),
            cmd: Command::Status,
        })
        .unwrap();
        let (mut line, opener) = seal::seal_request(&public, plain.as_bytes()).unwrap();
        assert!(!line.contains("tok"), "{line}");
        line.push('\n');
        let stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let answer = round_trip(stream, line.as_bytes()).await.unwrap();
        assert!(
            answer.contains(seal::SCHEME) && !answer.contains("connected"),
            "{answer}"
        );
        let opened: Response = serde_json::from_slice(&opener.open(&answer).unwrap()).unwrap();
        assert!(opened.ok && opened.status.is_some());
    }

    #[tokio::test]
    async fn a_request_sealed_to_another_key_is_refused_and_the_client_believes_nothing() {
        let (sock, _) = serve_daemon(Daemon::new("tok".into())).await;
        // The key of the service before it restarted, say.
        let stale = ServiceKey::generate().unwrap();
        let stale = seal::public_from_base64(&stale.public_base64()).unwrap();
        let e = call_unix_sealed_at(&sock, "tok", Some(&stale), Command::Status)
            .await
            .unwrap_err();
        assert!(e.is::<Impostor>(), "{e:#}");
    }

    /// Something else answering on the channel, as a squatter on the
    /// Windows pipe would: it reads the request and answers whatever it
    /// likes. Returns the socket and the lines it read.
    async fn impostor(
        answer: &'static str,
    ) -> (std::path::PathBuf, Arc<std::sync::Mutex<Vec<String>>>) {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join(format!("impostor-{}.sock", rand_suffix()));
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let lines = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (r, mut w) = tokio::io::split(stream);
                let mut line = String::new();
                let _ = BufReader::new(r).read_line(&mut line).await;
                lines.lock().unwrap().push(line);
                let _ = w.write_all(answer.as_bytes()).await;
            }
        });
        (sock, seen)
    }

    #[tokio::test]
    async fn an_impostor_that_cannot_seal_is_not_believed_and_never_sees_the_token() {
        let service = ServiceKey::generate().unwrap();
        let public = seal::public_from_base64(&service.public_base64()).unwrap();
        for answer in [
            "{\"ok\":true,\"status\":{\"connected\":true,\"node_name\":\"exit\",\"endpoint\":\"203.0.113.10:51820\",\"last_handshake_secs\":3,\"tx_bytes\":0,\"rx_bytes\":0,\"killswitch\":true}}\n",
            "{\"seal\":\"x25519-aes256gcm\",\"nonce\":\"AAAAAAAAAAAAAAAA\",\"data\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}\n",
            "{\"ok\":false,\"error\":\"unauthorised: wrong or missing control token\"}\n",
        ] {
            let (sock, seen) = impostor(answer).await;
            let e = call_unix_sealed_at(
                &sock,
                "the-control-token",
                Some(&public),
                Command::SetPassToken {
                    pass_token: Secret("the-account-token".into()),
                },
            )
            .await
            .unwrap_err();
            assert!(e.is::<Impostor>(), "{answer}: {e:#}");
            let seen = seen.lock().unwrap().join("");
            assert!(
                !seen.contains("the-control-token") && !seen.contains("the-account-token"),
                "the impostor read a token: {seen}"
            );
        }
        // Asked in the clear, as a client of an older service does, the
        // same impostor is believed: which is why the browser on Windows
        // does not ask in the clear.
        let (sock, _) = impostor(
            "{\"ok\":true,\"status\":{\"connected\":true,\"node_name\":null,\"endpoint\":null,\"last_handshake_secs\":null,\"tx_bytes\":0,\"rx_bytes\":0,\"killswitch\":true}}\n",
        )
        .await;
        let r = call_unix_at(&sock, "t", Command::Status).await.unwrap();
        assert!(r.status.unwrap().connected);
    }

    #[test]
    fn a_shared_file_is_replaced_whole_and_never_found_missing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-shared-{}", rand_suffix()));
        let path = dir.join("control.pub");
        // A file left from an earlier run, readable by anyone, and a
        // half-written one from a start that was cut short.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::fs::write(dir.join("control.pub.new"), "half").unwrap();
        // Read over and over while it is written: never missing, never half.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let (path, stop) = (path.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let text = std::fs::read_to_string(&path).expect("the file went missing");
                    assert!(text == "old" || text == "new key", "read {text:?}");
                }
            })
        };
        for _ in 0..200 {
            write_shared(&path, "new key").unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        reader.join().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new key");
        // A file of its own, not the old one's mode.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o037, 0, "mode {mode:o}");
        assert!(!dir.join("control.pub.new").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_control_socket_that_cannot_be_made_is_an_error_not_a_silent_service() {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-bind-{}", rand_suffix()));
        // Something that is not a socket, and that removing a file does not
        // clear, where the socket should be.
        let sock = dir.join("control.sock");
        std::fs::create_dir_all(sock.join("in-the-way")).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let e = rt.block_on(async { bind_unix(&sock) }).unwrap_err();
        assert!(
            format!("{e:#}").contains("binding the control socket"),
            "{e:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use crate::daemon::Daemon;

    fn test_pipe(what: &str) -> &'static str {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).unwrap();
        Box::leak(
            format!(
                r"\\.\pipe\hidravpn-test-{what}-{}-{}",
                std::process::id(),
                u64::from_le_bytes(b)
            )
            .into_boxed_str(),
        )
    }

    async fn ask(
        pipe: &str,
        token: &str,
        key: Option<&x25519_dalek::PublicKey>,
        cmd: Command,
    ) -> Result<Response> {
        exchange(open_pipe(pipe, false).await?, token, key, cmd).await
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_control_pipe_answers_every_client_one_after_another_and_at_once() {
        let id = std::process::id();
        let pipe = test_pipe("pool");
        let dir = std::env::temp_dir().join(format!("hidravpn-pipe-test-{id}"));
        std::fs::create_dir_all(&dir).unwrap();
        let daemon = Daemon::with_pocket("pipe-test-token".into(), dir.join("circuit.json"));
        let key = Arc::new(ServiceKey::generate().unwrap());
        let public = seal::public_from_base64(&key.public_base64()).unwrap();
        tokio::spawn(serve_windows(
            first_instance(pipe).unwrap(),
            pipe,
            daemon,
            key,
        ));
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // One after another, as the command line asks: a probe, then the
        // command, many times over (the pool has eight instances). Sealed,
        // as the command line and the browser ask, and in the clear, as an
        // older client does.
        for i in 0..200 {
            let key = (i % 2 == 0).then_some(&public);
            let r = ask(pipe, "pipe-test-token", key, Command::Ping)
                .await
                .unwrap_or_else(|e| panic!("request {i}: {e:#}"));
            assert!(r.ok, "request {i}: {:?}", r.error);
        }

        // And at once: twice as many clients as the pool has instances.
        let mut set = tokio::task::JoinSet::new();
        for c in 0..16 {
            set.spawn(async move {
                for i in 0..20 {
                    let r = ask(pipe, "pipe-test-token", Some(&public), Command::Ping)
                        .await
                        .unwrap_or_else(|e| panic!("client {c}, request {i}: {e:#}"));
                    assert!(r.ok, "client {c}, request {i}: {:?}", r.error);
                }
            });
        }
        while let Some(r) = set.join_next().await {
            r.unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pipe_name_someone_else_holds_stops_the_service_from_starting() {
        let pipe = test_pipe("taken");
        // Another program made the pipe first.
        let _squat = pipe_acl::instance(pipe, true).unwrap();
        let e = first_instance(pipe).unwrap_err();
        assert!(
            format!("{e:#}").contains("another program may already hold"),
            "{e:#}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_impostor_on_the_pipe_that_cannot_seal_is_not_believed_and_never_sees_the_token() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let pipe = test_pipe("impostor");
        let mut squat = ServerOptions::new()
            .first_pipe_instance(true)
            .create(pipe)
            .unwrap();
        let seen = tokio::spawn(async move {
            squat.connect().await.unwrap();
            let mut line = String::new();
            {
                let mut reader = BufReader::new(&mut squat);
                let _ = reader.read_line(&mut line).await;
            }
            let _ = squat
                .write_all(b"{\"ok\":true,\"status\":{\"connected\":true,\"node_name\":null,\"endpoint\":null,\"last_handshake_secs\":3,\"tx_bytes\":0,\"rx_bytes\":0,\"killswitch\":true}}\n")
                .await;
            line
        });
        let service = ServiceKey::generate().unwrap();
        let public = seal::public_from_base64(&service.public_base64()).unwrap();
        let e = ask(
            pipe,
            "the-control-token",
            Some(&public),
            Command::SetPassToken {
                pass_token: Secret("the-account-token".into()),
            },
        )
        .await
        .unwrap_err();
        assert!(e.is::<Impostor>(), "{e:#}");
        let seen = seen.await.unwrap();
        assert!(
            !seen.contains("the-control-token") && !seen.contains("the-account-token"),
            "{seen}"
        );
    }
}
