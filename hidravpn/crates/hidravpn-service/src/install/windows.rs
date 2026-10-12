//! Windows: a Scheduled Task that runs the service as SYSTEM at boot. A task
//! runs an ordinary console program, unlike a true Windows service, so the
//! same `run` binary serves here without a service-control handshake; a native
//! service is a later refinement. Everything is reversible with schtasks.

use std::path::Path;

use anyhow::Result;

use super::run;

const TASK: &str = "HidraVPN";

pub fn install(bin: &Path) -> Result<()> {
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
