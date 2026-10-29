//! Installing and removing the background service, and starting and stopping
//! it. Each operating system does this its own way; everything that is shared
//! lives here.
//!
//! Install copies this executable to a fixed place and registers it to run as
//! the system (root / SYSTEM), because the tunnel needs to create an interface
//! and set routes and firewall rules. Uninstall first disconnects cleanly, so
//! the kill switch is never left armed with no service to lift it.

use std::path::PathBuf;

use anyhow::{Context, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// The name HidraVPN is registered under: the Windows service, and the
/// Scheduled Task older builds used by the same name. Public so the service
/// binary's own `mod service` registers under the same name.
#[cfg(windows)]
pub const SERVICE_NAME: &str = "HidraVPN";

/// Where the installed copy of the service lives.
pub fn installed_binary() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/usr/local/bin/hidravpn-service")
    }
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into());
        PathBuf::from(base)
            .join("HidraVPN")
            .join("hidravpn-service.exe")
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        PathBuf::from("/usr/local/bin/hidravpn-service")
    }
}

/// Copies this running executable to its installed location.
fn place_binary() -> Result<PathBuf> {
    let src = std::env::current_exe().context("finding this executable")?;
    let dst = installed_binary();
    if let Some(dir) = dst.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Copying a running binary over itself fails; skip when already in place.
    if src != dst {
        copy_when_free(&src, &dst)
            .with_context(|| format!("copying the service to {}", dst.display()))?;
    }
    Ok(dst)
}

/// Copies `src` over `dst`, waiting up to ten seconds for `dst` to be let go
/// of. A stop returns before the old process has exited (`schtasks /End`
/// does not wait), and until it has, Windows refuses the copy as a sharing
/// violation and Linux as ETXTBSY.
fn copy_when_free(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<u64> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match std::fs::copy(src, dst) {
            Err(e) if still_in_use(&e) && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            r => return r,
        }
    }
}

/// The file is open in a process that has not exited yet.
fn still_in_use(e: &std::io::Error) -> bool {
    // ERROR_SHARING_VIOLATION (32) and ERROR_LOCK_VIOLATION (33) on Windows;
    // ETXTBSY (26) on Linux.
    let busy: &[i32] = if cfg!(windows) { &[32, 33] } else { &[26] };
    e.raw_os_error().is_some_and(|c| busy.contains(&c))
}

/// What `install` does besides registering the service.
#[derive(Debug, Default, Clone)]
pub struct InstallOptions {
    /// The command-line client to install beside the service (`hidravpn`),
    /// when the release carries it.
    pub client: Option<PathBuf>,
    /// Linux: the account to put in the control group, so the browser it
    /// runs can drive the service. The installer runs as root and cannot
    /// tell who asked otherwise.
    pub user: Option<String>,
}

/// Where the installed command-line client lives.
pub fn installed_client() -> PathBuf {
    let name = if cfg!(windows) {
        "hidravpn.exe"
    } else {
        "hidravpn"
    };
    installed_binary()
        .parent()
        .map(|d| d.join(name))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// The machine's master key, made once at install so the first connect
/// needs nothing typed. An existing key is never touched: it is what every
/// node this machine was admitted on knows it by.
fn ensure_client_key() -> Result<bool> {
    let path = crate::paths::client_key();
    if path.exists() {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let key = hidravpn_core::keys::ClientKey::generate()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?;
        std::io::Write::write_all(&mut f, key.secret_base64().as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        // The folder was given SYSTEM-and-administrators-only rights by the
        // Windows installer before this runs; the file inherits them.
        std::fs::write(&path, key.secret_base64().as_bytes())
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(true)
}

/// A running service holds its binary open, and a copy over a running
/// binary fails (ETXTBSY on Linux, a sharing violation on Windows). An
/// update stops it first, disconnecting cleanly so the kill switch is not
/// left armed, and starts the new one when it is in place.
fn stop_for_update() {
    #[cfg(target_os = "linux")]
    let _ = linux::stop();
    #[cfg(windows)]
    let _ = windows::stop();
}

pub fn install(opts: &InstallOptions) -> Result<()> {
    #[cfg(any(target_os = "linux", windows))]
    {
        // Everything that can be refused is refused before anything changes.
        #[cfg(target_os = "linux")]
        if let Some(u) = opts.user.as_deref() {
            if !linux::valid_user(u) {
                anyhow::bail!("{u:?} is not a login name");
            }
        }
        if let Some(client) = &opts.client {
            if !client.is_file() {
                anyhow::bail!("{} is not a file", client.display());
            }
        }
        stop_for_update();
        // Stopped, the old service is started again if the new one cannot
        // be put in place: a failed update never leaves the machine with no
        // service at all.
        let placed = (|| -> Result<PathBuf> {
            let bin = place_binary()?;
            if let Some(client) = &opts.client {
                let dst = installed_client();
                if client != &dst {
                    copy_when_free(client, &dst)
                        .with_context(|| format!("copying the client to {}", dst.display()))?;
                }
            }
            Ok(bin)
        })();
        let bin = match placed {
            Ok(bin) => bin,
            Err(e) => {
                if installed_binary().is_file() && start().is_ok() {
                    return Err(e.context(
                        "nothing was updated; the service already installed is running again",
                    ));
                }
                return Err(e);
            }
        };
        #[cfg(target_os = "linux")]
        linux::install(&bin, opts.user.as_deref())?;
        #[cfg(windows)]
        windows::install(&bin)?;
        if ensure_client_key()? {
            println!("made this machine's key");
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = opts;
        anyhow::bail!("installing the service is not built for this operating system yet")
    }
}

/// Removes the service. With `purge`, also the installed programs and the
/// data: the pocket of nodes, the machine's key, which nodes know this
/// machine by, the passes, the account token and the tokens it replaced.
/// Without it, a later install finds both where they were.
pub fn uninstall(purge: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::uninstall()?;
        if purge {
            // DNS a connection cut short left behind is put back before the
            // copy that says how goes.
            hidravpn_core::netcfg::recover_dns();
            let _ = std::fs::remove_file(installed_client());
            // The client's files one by one, never the whole folder: a node
            // on the same machine keeps its own settings there.
            let _ = std::fs::remove_file(crate::paths::circuit_pocket());
            let _ = std::fs::remove_file(crate::paths::client_key());
            let _ = std::fs::remove_file(crate::paths::pass_wallet());
            for kept in crate::passes::kept_tokens(&crate::paths::pass_token()) {
                let _ = std::fs::remove_file(kept);
            }
            let _ = std::fs::remove_file(crate::paths::pass_token());
            let pocket = crate::paths::circuit_pocket();
            for name in ["hidravpn.lock", "resolv.conf.saved"] {
                let _ = std::fs::remove_file(pocket.with_file_name(name));
            }
            if let Some(dir) = crate::paths::client_key().parent() {
                let _ = std::fs::remove_dir(dir);
            }
            // Last: this may be the running executable, which Linux lets go.
            let _ = std::fs::remove_file(installed_binary());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows::uninstall()?;
        if purge {
            windows::purge()?;
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        anyhow::bail!("removing the service is not built for this operating system yet")
    }
}

pub fn start() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::start()
    }
    #[cfg(windows)]
    {
        windows::start()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        anyhow::bail!("not built for this operating system yet")
    }
}

pub fn stop() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::stop()
    }
    #[cfg(windows)]
    {
        windows::stop()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        anyhow::bail!("not built for this operating system yet")
    }
}

/// Runs a command and fails with its error output.
pub(crate) fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("running {cmd}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binary_still_held_by_a_stopping_process_is_waited_for_not_given_up_on() {
        let busy = if cfg!(windows) { 32 } else { 26 };
        assert!(still_in_use(&std::io::Error::from_raw_os_error(busy)));
        // Anything else is an answer at once: no ten seconds spent on a
        // missing file or a refusal.
        assert!(!still_in_use(&std::io::Error::from_raw_os_error(2)));
        assert!(!still_in_use(&std::io::Error::from_raw_os_error(5)));
        assert!(!still_in_use(&std::io::Error::other("not an OS error")));
    }

    #[test]
    fn a_free_destination_is_copied_at_once() {
        let dir = std::env::temp_dir().join(format!("hidravpn-copy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (src, dst) = (dir.join("new"), dir.join("installed"));
        std::fs::write(&src, b"new build").unwrap();
        std::fs::write(&dst, b"old build").unwrap();
        let t = std::time::Instant::now();
        copy_when_free(&src, &dst).unwrap();
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
        assert_eq!(std::fs::read(&dst).unwrap(), b"new build");
        // A missing source fails at once too.
        assert!(copy_when_free(&dir.join("missing"), &dst).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
