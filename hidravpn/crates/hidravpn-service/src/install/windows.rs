//! Windows: a real service, registered with the SCM to start as SYSTEM at
//! boot. The SCM hands it a stop and a shutdown control, so the daemon puts
//! the network back when the machine stops as surely as when a person
//! disconnects — which a Scheduled Task, hard-terminated, did not. Older
//! builds installed a Scheduled Task by the same name; install and uninstall
//! remove it so the two never both run. The service-side of this (the
//! control handler, the status the SCM reads) lives in `crate::service`.

use std::path::Path;

use anyhow::{Context, Result};

use super::{run, SERVICE_NAME};

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

    // The folder under ProgramData holds the client key and the pocket.
    // ProgramData lets any user create files in a new folder there, and a
    // file a user made first stays that user's: so the folder is taken
    // (in case someone made it before us) and given rights inherited from
    // nowhere, SYSTEM and administrators only. The service then grants
    // interactive users read on the token alone, when it writes it.
    let data = crate::paths::control_token()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\ProgramData\\HidraVPN"));
    std::fs::create_dir_all(&data)?;
    let dir = data.to_string_lossy().into_owned();
    let _ = run("takeown", &["/F", &dir, "/R", "/A", "/D", "Y"]);
    // The folder alone: its rights are made to be inherited (OI, CI). Given
    // to its files as well (/T), they would lose what they inherited and
    // gain nothing (an inheritable grant does not apply to a file), and be
    // left with no rights at all: not even the service could read the key
    // or the pocket of a machine that had them before this install, or of
    // any update.
    run(
        "icacls",
        &[
            &dir,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
        ],
    )
    .context("protecting the HidraVPN data folder")?;
    // What is already inside takes the folder's rights, and only them:
    // whatever a user gave a file before is replaced. With nothing inside
    // (a first install) there is nothing to reset, and icacls would fail on
    // the empty pattern; otherwise a failure stops the install.
    let has_entries = std::fs::read_dir(&data)
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    if has_entries {
        let inside = format!("{dir}\\*");
        run("icacls", &[&inside, "/reset", "/T", "/C", "/Q"])
            .context("giving the files in the HidraVPN data folder the folder's rights")?;
    }
    // The control token, if the service already wrote one, keeps the one
    // extra right it has: interactive users may read it.
    let token = crate::paths::control_token();
    if token.exists() {
        crate::ipc::protect_token(&token)?;
    }

    // An older build may have left a Scheduled Task by this name; remove it
    // so the task and the service never both run.
    remove_legacy_task();

    // Register the service: started by the SCM at boot as LocalSystem, its
    // ImagePath the installed exe with `run`. `sc` wants `key= value` with
    // the space part of the syntax, so the key and value are two arguments;
    // the exe path is quoted inside the value because of "Program Files".
    //
    // An install over an existing service re-points it (config, in case the
    // path changed) rather than failing on "already exists". A first install
    // has nothing to re-point, so a failed config there is the real error.
    let image = service_image_path(bin);
    let created = run(
        "sc.exe",
        &[
            "create",
            SERVICE_NAME,
            "binPath=",
            &image,
            "start=",
            "auto",
            "obj=",
            "LocalSystem",
            "DisplayName=",
            "HidraVPN",
        ],
    );
    if created.is_err() {
        run(
            "sc.exe",
            &[
                "config",
                SERVICE_NAME,
                "binPath=",
                &image,
                "start=",
                "auto",
                "obj=",
                "LocalSystem",
            ],
        )
        .context("creating the HidraVPN service")?;
    }
    let _ = run("sc.exe", &["description", SERVICE_NAME, "HidraVPN service"]);
    // Restarted if it ever exits with an error: three times, a minute apart,
    // the failure count forgotten after a day.
    let _ = run(
        "sc.exe",
        &[
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/60000/restart/60000/restart/60000",
        ],
    );
    // Start it now as well, so the user need not reboot.
    let _ = run("sc.exe", &["start", SERVICE_NAME]);
    Ok(())
}

/// The service's ImagePath: the installed exe, quoted (its folder has a
/// space), with the `run` argument the SCM launches it with.
fn service_image_path(bin: &Path) -> String {
    format!("\"{}\" run", bin.display())
}

/// Removes the Scheduled Task older builds installed, if present. Failures
/// (no such task) are ignored.
fn remove_legacy_task() {
    let _ = run("schtasks", &["/End", "/TN", SERVICE_NAME]);
    let _ = run("schtasks", &["/Delete", "/TN", SERVICE_NAME, "/F"]);
}

pub fn uninstall() -> Result<()> {
    let _ = crate::cli_down_blocking();
    let _ = run("sc.exe", &["stop", SERVICE_NAME]);
    let _ = run("sc.exe", &["delete", SERVICE_NAME]);
    remove_legacy_task();
    // Make sure nothing is left armed if the service was killed mid-connection.
    let _ = hidravpn_core::killswitch::remove();
    if let Ok(Some(plan)) = hidravpn_core::netcfg::load_plan() {
        let _ = hidravpn_core::netcfg::revert(&plan);
    }
    Ok(())
}

/// Removes the installed programs and the data folder (the pocket and the
/// machine's key). The running executable cannot delete itself on Windows,
/// so the folder is removed a few seconds after this process exits, by a
/// command started detached for that alone.
pub fn purge() -> Result<()> {
    let data = crate::paths::control_token()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("C:\\ProgramData\\HidraVPN"));
    let _ = std::fs::remove_dir_all(&data);
    if let Some(dir) = super::installed_binary().parent() {
        let dir = dir.to_string_lossy().into_owned();
        // Only ever the folder the installer made, never a path from outside.
        if dir.to_ascii_lowercase().ends_with("\\hidravpn") {
            let cmd = format!("ping -n 4 127.0.0.1 >nul & rmdir /s /q \"{dir}\"");
            std::process::Command::new("cmd")
                .args(["/C", &cmd])
                .spawn()
                .context("scheduling the removal of the program folder")?;
        }
    }
    Ok(())
}

pub fn start() -> Result<()> {
    run("sc.exe", &["start", SERVICE_NAME]).map(|_| ())
}

pub fn stop() -> Result<()> {
    let _ = crate::cli_down_blocking();
    // Best effort: the SCM answers at once and the service then unwinds
    // (STOP_PENDING while it puts the network back). An already-stopped
    // service is not an error to report; a stop for an update waits on the
    // binary being free, not on this.
    let _ = run("sc.exe", &["stop", SERVICE_NAME]);
    let _ = run("schtasks", &["/End", "/TN", SERVICE_NAME]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_image_path_quotes_the_exe_and_passes_run() {
        // The exe is quoted (its folder has a space) and `run` is the
        // argument the SCM starts it with.
        let p = service_image_path(Path::new(r"C:\Program Files\HidraVPN\hidravpn-service.exe"));
        assert_eq!(p, r#""C:\Program Files\HidraVPN\hidravpn-service.exe" run"#);
    }
}
