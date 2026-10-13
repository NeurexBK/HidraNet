//! The local control channel between a client (the command line now, the
//! browser in phase 4) and the service.
//!
//! One request, one response, one connection, each a single line of JSON. On
//! Unix it is a socket in /run that only root may open (mode 0660); on Windows
//! a named pipe. Either way every request must carry the control token, a
//! secret the service writes where only the owner can read it, so a web page
//! that guesses the address still cannot drive the tunnel.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use hidravpn_core::Invite;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::daemon::Daemon;
use crate::paths;

/// A request from a client. The token is checked before the command is read.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub token: String,
    #[serde(flatten)]
    pub cmd: Command,
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
}

impl Response {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
            note: None,
        }
    }
    pub fn with_status(s: StatusReport) -> Self {
        Self {
            ok: true,
            error: None,
            status: Some(s),
            note: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            status: None,
            note: None,
        }
    }
    pub fn noting(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

// ---- token ---------------------------------------------------------------

/// Makes a fresh control token and writes it where only the owner can read it.
pub fn write_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("no randomness: {e}"))?;
    use base64::Engine;
    let token = base64::engine::general_purpose::STANDARD.encode(bytes);
    let path = paths::control_token();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        f.write_all(token.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, &token).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(token)
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

// ---- server --------------------------------------------------------------

/// Serves the control channel until the process ends. Each connection is one
/// request and one response.
pub async fn serve(daemon: Arc<Daemon>) -> Result<()> {
    #[cfg(unix)]
    {
        serve_unix(daemon).await
    }
    #[cfg(windows)]
    {
        serve_windows(daemon).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = daemon;
        anyhow::bail!("no control channel on this operating system")
    }
}

#[cfg(unix)]
async fn serve_unix(daemon: Arc<Daemon>) -> Result<()> {
    serve_unix_at(&paths::control_socket(), daemon).await
}

/// The Unix server, on a given path. Split out so a test can use a temporary
/// socket instead of the one in /run that only root may create.
#[cfg(unix)]
pub async fn serve_unix_at(path: &std::path::Path, daemon: Arc<Daemon>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding the control socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    tracing::info!("control channel ready");
    loop {
        let (stream, _) = listener.accept().await?;
        let d = daemon.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, d).await {
                tracing::debug!("control connection ended: {e}");
            }
        });
    }
}

/// Sends one request to a given Unix socket path (used by tests).
#[cfg(unix)]
pub async fn call_unix_at(path: &std::path::Path, token: &str, cmd: Command) -> Result<Response> {
    let req = Request {
        token: token.to_string(),
        cmd,
    };
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');
    let stream = tokio::net::UnixStream::connect(path)
        .await
        .map_err(|e| anyhow!("could not reach the service ({e})"))?;
    round_trip(stream, line.as_bytes()).await
}

#[cfg(windows)]
async fn serve_windows(daemon: Arc<Daemon>) -> Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(paths::CONTROL_PIPE)
        .context("creating the control pipe")?;
    tracing::info!("control channel ready");
    loop {
        server.connect().await?;
        let connected = server;
        server = ServerOptions::new().create(paths::CONTROL_PIPE)?;
        let d = daemon.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(connected, d).await {
                tracing::debug!("control connection ended: {e}");
            }
        });
    }
}

async fn handle_conn<S>(stream: S, daemon: Arc<Daemon>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let resp = match serde_json::from_str::<Request>(line.trim()) {
        Ok(req) => daemon.handle(req).await,
        Err(e) => Response::err(format!("bad request: {e}")),
    };
    let mut out = serde_json::to_string(&resp)?;
    out.push('\n');
    w.write_all(out.as_bytes()).await?;
    w.flush().await?;
    Ok(())
}

// ---- client --------------------------------------------------------------

/// Sends one command to the running service and returns its answer.
pub async fn call(cmd: Command) -> Result<Response> {
    let token = read_token()?;
    let req = Request { token, cmd };
    let mut line = serde_json::to_string(&req)?;
    line.push('\n');

    #[cfg(unix)]
    {
        use tokio::net::UnixStream;
        let stream = UnixStream::connect(paths::control_socket())
            .await
            .map_err(|e| anyhow!("the HidraVPN service is not running ({e})"))?;
        round_trip(stream, line.as_bytes()).await
    }
    #[cfg(windows)]
    {
        use std::time::Duration;
        use tokio::net::windows::named_pipe::ClientOptions;
        // ERROR_PIPE_BUSY: every instance is serving another client for the
        // moment. The server makes a new instance right after it accepts one,
        // so the wait is tiny; retry briefly rather than report the service
        // down. A missing pipe (service really not running) fails at once.
        const ERROR_PIPE_BUSY: i32 = 231;
        let mut tries = 0u32;
        let stream = loop {
            match ClientOptions::new().open(paths::CONTROL_PIPE) {
                Ok(s) => break s,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 40 => {
                    tries += 1;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => return Err(anyhow!("the HidraVPN service is not running ({e})")),
            }
        };
        round_trip(stream, line.as_bytes()).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = line;
        anyhow::bail!("no control channel on this operating system")
    }
}

#[allow(dead_code)]
async fn round_trip<S>(stream: S, request: &[u8]) -> Result<Response>
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
    serde_json::from_str(line.trim()).context("the service sent an unreadable answer")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::daemon::Daemon;

    async fn start(token: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hidravpn-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join(format!("ctl-{}.sock", rand_suffix()));
        let d = Daemon::new(token.to_string());
        let s = sock.clone();
        tokio::spawn(async move {
            let _ = serve_unix_at(&s, d).await;
        });
        // Give the listener a moment to bind.
        for _ in 0..50 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        sock
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
            dns: std::net::Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: vec!["0.0.0.0/0".into()],
            mtu: 1420,
            keepalive: 25,
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
                alternates: vec![invite("exit2", "9.9.9.9:51820")],
                alternate_entries: vec![invite("entry2", "203.0.113.21:51820")],
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
            }],
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
                },
                HopReport {
                    role: "exit".into(),
                    node_name: "exit".into(),
                    endpoint: "203.0.113.10:51820".into(),
                    last_handshake_secs: None,
                    connected: false,
                },
            ],
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
        assert!(lines[1].ends_with("last handshake none yet, no session"));
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
}
