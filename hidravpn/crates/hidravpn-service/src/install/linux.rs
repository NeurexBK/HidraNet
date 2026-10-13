//! Linux: a systemd unit, enabled to start at boot. The service is hardened
//! the same way the node is — root only for the capabilities it truly needs,
//! everything else taken away.

use std::path::Path;

use anyhow::Result;

use super::run;

const UNIT_PATH: &str = "/etc/systemd/system/hidravpn.service";

fn unit(bin: &Path) -> String {
    format!(
        r#"[Unit]
Description=HidraVPN client service
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
ExecStart={bin} run
Restart=on-failure
RestartSec=3
# The control socket and token live here (RAM); kept across a service restart
# so a reconnect does not need the token re-read, cleared by a reboot.
RuntimeDirectory=hidravpn
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
Environment=RUST_LOG=hidravpn_service=info
# The tunnel interface, routes, nftables and DNS need these; nothing more.
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
# Reads the client key under /etc/hidravpn and writes resolv.conf on non-resolved systems.
ReadWritePaths=/etc /proc/sys/net
ProtectHome=true
PrivateTmp=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
MemoryDenyWriteExecute=true
DeviceAllow=/dev/net/tun rw
DevicePolicy=closed
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
"#,
        bin = bin.display()
    )
}

/// The group whose members may drive the service without being root (the
/// browser runs as the person). Made once; a machine that refuses to make it
/// still gets a working, root-only service.
fn ensure_control_group() {
    if crate::paths::control_gid().is_some() {
        return;
    }
    if run("groupadd", &["--system", crate::paths::CONTROL_GROUP]).is_err()
        || crate::paths::control_gid().is_none()
    {
        eprintln!(
            "note: the {} group could not be made; only root will be able to drive the service (the browser's VPN page needs a member of that group)",
            crate::paths::CONTROL_GROUP
        );
    }
}

pub fn install(bin: &Path) -> Result<()> {
    ensure_control_group();
    std::fs::write(UNIT_PATH, unit(bin))?;
    run("systemctl", &["daemon-reload"])?;
    run("systemctl", &["enable", "--now", "hidravpn"])?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    // Disconnect cleanly first, so the kill switch is never left armed.
    let _ = crate::cli_down_blocking();
    let _ = run("systemctl", &["disable", "--now", "hidravpn"]);
    let _ = std::fs::remove_file(UNIT_PATH);
    let _ = run("systemctl", &["daemon-reload"]);
    Ok(())
}

pub fn start() -> Result<()> {
    run("systemctl", &["start", "hidravpn"]).map(|_| ())
}

pub fn stop() -> Result<()> {
    // A clean disconnect before the process goes away.
    let _ = crate::cli_down_blocking();
    run("systemctl", &["stop", "hidravpn"]).map(|_| ())
}
