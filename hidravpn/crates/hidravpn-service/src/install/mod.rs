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
        std::fs::copy(&src, &dst)
            .with_context(|| format!("copying the service to {}", dst.display()))?;
    }
    Ok(dst)
}

pub fn install() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let bin = place_binary()?;
        linux::install(&bin)
    }
    #[cfg(windows)]
    {
        let bin = place_binary()?;
        windows::install(&bin)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        anyhow::bail!("installing the service is not built for this operating system yet")
    }
}

pub fn uninstall() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::uninstall()
    }
    #[cfg(windows)]
    {
        windows::uninstall()
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
#[allow(dead_code)]
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
