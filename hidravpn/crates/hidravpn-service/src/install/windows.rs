//! Windows: a Scheduled Task that runs the service as SYSTEM at boot. A task
//! runs an ordinary console program, unlike a true Windows service, so the
//! same `run` binary serves here without a service-control handshake; a native
//! service is a later refinement. Everything is reversible with schtasks.

use std::path::Path;

use anyhow::{Context, Result};

use super::run;

const TASK: &str = "HidraVPN";

pub fn install(bin: &Path) -> Result<()> {
    // wintun.dll must sit beside the installed service, or it cannot create the
    // tunnel: tun-rs loads it from the executable's own directory. Copy it from
    // beside the exe the user is running; if it is nowhere, stop with a clear
    // message rather than install a service that cannot connect.
    if let Some(dst_dir) = bin.parent() {
        let dst_dll = dst_dir.join("wintun.dll");
        if !dst_dll.exists() {
            let src_dll = std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(|d| d.join("wintun.dll")));
            match src_dll {
                Some(src) if src.exists() => {
                    std::fs::copy(&src, &dst_dll)
                        .with_context(|| format!("copying wintun.dll to {}", dst_dll.display()))?;
                }
                _ => anyhow::bail!(
                    "wintun.dll must sit beside hidravpn-service.exe before installing (get it from https://www.wintun.net, the amd64 build)"
                ),
            }
        }
    }

    let tr = format!("\"{}\" run", bin.display());
    // /rl HIGHEST + /ru SYSTEM: full rights, no interactive logon needed.
    run(
        "schtasks",
        &[
            "/Create", "/TN", TASK, "/TR", &tr, "/SC", "ONSTART", "/RU", "SYSTEM", "/RL",
            "HIGHEST", "/F",
        ],
    )?;
    // Start it now as well, so the user need not reboot.
    let _ = run("schtasks", &["/Run", "/TN", TASK]);
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let _ = crate::cli_down_blocking();
    let _ = run("schtasks", &["/End", "/TN", TASK]);
    let _ = run("schtasks", &["/Delete", "/TN", TASK, "/F"]);
    // Make sure nothing is left armed if the task was killed mid-connection.
    let _ = hidravpn_core::killswitch::remove();
    if let Ok(Some(plan)) = hidravpn_core::netcfg::load_plan() {
        let _ = hidravpn_core::netcfg::revert(&plan);
    }
    Ok(())
}

pub fn start() -> Result<()> {
    run("schtasks", &["/Run", "/TN", TASK]).map(|_| ())
}

pub fn stop() -> Result<()> {
    let _ = crate::cli_down_blocking();
    run("schtasks", &["/End", "/TN", TASK]).map(|_| ())
}
