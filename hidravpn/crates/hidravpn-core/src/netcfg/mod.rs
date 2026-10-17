//! Sending the whole machine through the tunnel, and undoing it.
//!
//! Three things change: a route to the node through the original gateway (so
//! the tunnel's own packets do not try to go through the tunnel), the default
//! route (as 0.0.0.0/1 and 128.0.0.0/1, which win over the real default route
//! by being more specific and leave it in place for the way back), and the
//! DNS server. IPv6 is routed into the tunnel as well, where in this phase it
//! goes nowhere: better no IPv6 than IPv6 beside the tunnel.
//!
//! Every change is recorded in a plan file before it is made, so `down` can
//! undo it after a crash, a kill, or a reboot that left things half-done. The
//! changes are made with the system's own tools (`ip`, `resolvectl`, the
//! PowerShell network cmdlets); the kill switch (nftables, WFP) is apart, in
//! `killswitch`.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

/// What was changed, so it can be put back.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevertPlan {
    pub interface: String,
    pub node_ip: Option<IpAddr>,
    /// The original default gateway and its interface, which the node route
    /// was added through.
    pub gateway: Option<String>,
    pub gateway_if: Option<String>,
    pub routes_added: Vec<String>,
    pub dns_changed: bool,
    /// Linux without systemd-resolved: the resolv.conf that was replaced.
    pub resolv_conf_backup: Option<String>,
    /// Linux: where resolv.conf linked to, when it was a link (into /run,
    /// NetworkManager's or resolvconf's). Absent in plans from before.
    #[serde(default)]
    pub resolv_conf_link: Option<String>,
    /// Windows: the interface index of the tunnel adapter.
    pub if_index: Option<u32>,
    /// Host routes added through a tunnel interface: a two-hop circuit sends
    /// the exit node's endpoint through the entry tunnel. Absent in plans
    /// written before phase 3.
    #[serde(default)]
    pub via_routes: Vec<ViaRouteAdded>,
}

/// A host route that was added through a tunnel interface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ViaRouteAdded {
    pub prefix: String,
    pub interface: String,
    /// Windows: the tunnel adapter's interface index.
    pub if_index: Option<u32>,
}

/// Where the plan is kept. On Linux `/run` is RAM, which is right: a reboot
/// undoes every change by itself, so there is nothing left to revert.
pub fn plan_path() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        PathBuf::from("/run/hidravpn/netcfg.json")
    }
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into());
        PathBuf::from(base).join("HidraVPN").join("netcfg.json")
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        PathBuf::from("/var/run/hidravpn/netcfg.json")
    }
}

pub fn save_plan(plan: &RevertPlan) -> Result<()> {
    let path = plan_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    // Beside and renamed over: a crash mid-write must not leave a plan that
    // cannot be read, and with it routes nobody undoes.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(plan)?)
        .and_then(|()| std::fs::rename(&tmp, &path))
        .with_context(|| format!("writing {}", path.display()))
}

pub fn load_plan() -> Result<Option<RevertPlan>> {
    match std::fs::read(plan_path()) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("the saved network plan is unreadable")?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Puts the machine's DNS back when a connection was cut short by a reboot
/// and left its resolv.conf behind. Nothing to do elsewhere: systemd-resolved
/// and Windows forget a tunnel's DNS with its interface.
pub fn recover_dns() {
    #[cfg(target_os = "linux")]
    linux::recover_dns();
}

pub fn clear_plan() {
    let _ = std::fs::remove_file(plan_path());
}

/// What the tunnel wants from the system.
#[derive(Debug, Clone)]
pub struct Wanted {
    /// Where the default route goes: the inner tunnel of a two-hop circuit,
    /// the only tunnel of a single hop.
    pub interface: String,
    /// The node reached over the physical link: the entry node of a two-hop
    /// circuit, the only node of a single hop.
    pub node_ip: IpAddr,
    pub dns: Ipv4Addr,
    pub route_ipv6: bool,
    /// Hosts reached *through* a tunnel interface instead of the physical
    /// link: the exit node's endpoint through the entry tunnel, so the inner
    /// tunnel's packets ride inside the outer one. Empty for a single hop.
    pub via_tunnel: Vec<ViaRoute>,
}

/// A host to route through a tunnel interface.
#[derive(Debug, Clone)]
pub struct ViaRoute {
    pub host: IpAddr,
    pub interface: String,
}

/// Routes everything through the tunnel. Returns the plan that undoes it,
/// already saved to disk.
pub fn apply(w: &Wanted) -> Result<RevertPlan> {
    #[cfg(any(target_os = "linux", windows))]
    {
        #[cfg(target_os = "linux")]
        let r = linux::apply(w);
        #[cfg(windows)]
        let r = windows::apply(w);
        // Failed partway: what was done is in the plan saved step by step,
        // and is undone now, not left until the next connection.
        if r.is_err() {
            if let Ok(Some(done)) = load_plan() {
                let _ = revert(&done);
            }
        }
        r
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = w;
        anyhow::bail!("this operating system is not supported yet (macOS comes right after Linux and Windows)")
    }
}

/// Puts the system back the way it was. Each step is attempted even if an
/// earlier one failed, and the plan file is removed only when all went
/// through, so a second `down` can finish the job.
pub fn revert(plan: &RevertPlan) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::revert(plan)
    }
    #[cfg(windows)]
    {
        windows::revert(plan)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = plan;
        anyhow::bail!("this operating system is not supported yet")
    }
}

/// Routes one host into a tunnel interface, and nothing else: how the
/// client reaches an exit's admission port through the entry before any
/// circuit exists. The route goes away with the interface.
pub fn route_host_via(host: IpAddr, interface: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let prefix = match host {
            IpAddr::V4(a) => format!("{a}/32"),
            IpAddr::V6(a) => format!("{a}/128"),
        };
        run("ip", &["route", "replace", &prefix, "dev", interface]).map(|_| ())
    }
    #[cfg(windows)]
    {
        windows::route_host_via(host, interface)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (host, interface);
        anyhow::bail!("this operating system is not supported yet")
    }
}

/// Windows will not hold one address on two interfaces (it gives the second
/// a link-local one, silently); Linux does, and two hops with the same
/// address on both interfaces work there.
pub const ONE_ADDRESS_PER_INTERFACE: bool = cfg!(windows);

/// Whether a tunnel interface holds the address it was given. Windows will
/// not put one address on two interfaces, and gives the second a link-local
/// one instead (169.254.x.x), silently: a circuit through it carries
/// nothing. Linux has no such case to check.
pub fn check_address(interface: &str, ip: std::net::Ipv4Addr) -> Result<()> {
    #[cfg(windows)]
    {
        windows::check_address(interface, ip)
    }
    #[cfg(not(windows))]
    {
        let _ = (interface, ip);
        Ok(())
    }
}

/// Runs a system tool and gives its output or a readable error.
pub(crate) fn run(cmd: &str, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("could not run {cmd}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{cmd} {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
