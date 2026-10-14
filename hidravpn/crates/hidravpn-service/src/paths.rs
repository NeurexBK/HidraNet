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

/// The group whose members may drive the service through the control
/// channel without being root. The browser runs as the person, not as root,
/// and it has to be able to say "connect". `hidravpn-service install` makes
/// the group; when a machine has none, the socket and the token stay
/// root-only, as before. A member can connect and disconnect; the client key
/// stays root-only and no request ever returns a key.
#[cfg(unix)]
pub const CONTROL_GROUP: &str = "hidravpn";

/// The gid of that group, when this machine has it.
#[cfg(unix)]
pub fn control_gid() -> Option<u32> {
    let name = std::ffi::CString::new(CONTROL_GROUP).ok()?;
    // The reentrant lookup: this runs on a multi-threaded runtime, and
    // getgrnam's static buffer is not for that.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 16 * 1024];
    let mut found: *mut libc::group = std::ptr::null_mut();
    // SAFETY: every pointer is to memory owned by this frame and sized as
    // passed; the result points into `grp` or is null, checked before use.
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() {
        None
    } else {
        Some(grp.gr_gid)
    }
}

/// The shared secret a client must present. Readable only by the owner, and
/// by the control group when there is one.
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

/// The passes this machine holds (phase 5): root only, beside the pocket.
pub fn pass_wallet() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/hidravpn/passes.json")
    }
    #[cfg(windows)]
    {
        program_data().join("passes.json")
    }
}

/// The account token passes are asked for with, when this machine keeps
/// one (`hidravpn passes token`): root only.
pub fn pass_token() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from("/etc/hidravpn/pass.token")
    }
    #[cfg(windows)]
    {
        program_data().join("pass.token")
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
