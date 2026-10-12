//! Where the service keeps its control socket, its control token and the
//! client key. On Linux the socket and token live in /run (RAM), so a reboot
//! starts clean; the key lives in /etc, written once by `hidravpn keygen`,
//! and the pocket of nodes next to it.

use std::path::PathBuf;

#[cfg(windows)]
fn program_data() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
    PathBuf::from(base).join("HidraVPN")
}

/// The local control channel the client connects to.
#[cfg(unix)]
pub fn control_socket() -> PathBuf {
    PathBuf::from("/run/hidravpn/control.sock")
}

/// On Windows the control channel is a named pipe, not a path on disk.
#[cfg(windows)]
pub const CONTROL_PIPE: &str = r"\\.\pipe\hidravpn";

/// The shared secret a client must present. Readable only by the owner.
pub fn control_token() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/run/hidravpn/control.token")
    }
    #[cfg(windows)]
    {
        program_data().join("control.token")
    }
}

/// The pocket: the entry and exit nodes this machine holds invites for,
/// managed by `hidravpn nodes`. Next to the key; written by the administrator.
pub fn circuit_pocket() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/hidravpn/circuit.json")
    }
    #[cfg(windows)]
    {
        program_data().join("circuit.json")
    }
}

/// The client's private key, made once by `hidravpn keygen`.
pub fn client_key() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/hidravpn/client.key")
    }
    #[cfg(windows)]
    {
        program_data().join("client.key")
    }
}
