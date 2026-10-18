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

    // The task is described in full rather than with schtasks' switches,
    // whose defaults are wrong for a service: start only on mains power,
    // stop when the laptop goes on battery, stop after three days. Seen on
    // a laptop: on battery the service never started, or was ended, and the
    // command line found nothing to talk to.
    let xml = data.join("task.xml");
    std::fs::write(&xml, utf16_with_bom(&task_xml(bin)))
        .with_context(|| format!("writing {}", xml.display()))?;
    let path = xml.to_string_lossy().into_owned();
    let made = run("schtasks", &["/Create", "/TN", TASK, "/XML", &path, "/F"]);
    let _ = std::fs::remove_file(&xml);
    made.context("creating the HidraVPN task")?;
    // Start it now as well, so the user need not reboot.
    let _ = run("schtasks", &["/Run", "/TN", TASK]);
    Ok(())
}

/// The task: at boot, as SYSTEM with full rights, on battery as on mains,
/// for as long as the machine runs, one instance, restarted if it fails.
fn task_xml(bin: &Path) -> String {
    let command = bin
        .display()
        .to_string()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>HidraVPN service</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>4</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>run</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// schtasks reads a task file as UTF-16, as Windows writes them.
fn utf16_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
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
    run("schtasks", &["/Run", "/TN", TASK]).map(|_| ())
}

pub fn stop() -> Result<()> {
    let _ = crate::cli_down_blocking();
    run("schtasks", &["/End", "/TN", TASK]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_task_runs_on_battery_for_as_long_as_the_machine_runs() {
        let xml = task_xml(Path::new(r"C:\Program Files\A&B\hidravpn-service.exe"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"));
        assert!(xml.contains("<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>"));
        assert!(xml.contains("<UserId>S-1-5-18</UserId>"));
        assert!(xml.contains(r"<Command>C:\Program Files\A&amp;B\hidravpn-service.exe</Command>"));
        let bytes = utf16_with_bom("ab");
        assert_eq!(bytes, vec![0xFF, 0xFE, b'a', 0, b'b', 0]);
    }
}
