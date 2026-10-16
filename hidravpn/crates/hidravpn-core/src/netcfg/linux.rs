//! Linux: `ip route` and either `resolvectl` (systemd-resolved) or a swapped
//! `/etc/resolv.conf`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use super::{clear_plan, load_plan, run, save_plan, RevertPlan, ViaRouteAdded, Wanted};

const RESOLV_CONF: &str = "/etc/resolv.conf";
/// Written beside it and renamed over it, which replaces a link without
/// touching what the link points at.
const RESOLV_CONF_TMP: &str = "/etc/.resolv.conf.hidravpn";
/// What resolv.conf was before it was swapped, kept on disk beside the
/// client's key: the plan lives in /run and a reboot clears it, but a machine
/// that lost power while connected comes back with the swapped file, and on a
/// machine without systemd-resolved nothing else would put it back.
const RESOLV_SAVED: &str = "/etc/hidravpn/resolv.conf.saved";
const RESOLV_MARK: &str = "# HidraVPN: restored by `hidravpn down`";

#[derive(Serialize, Deserialize)]
struct SavedResolvConf {
    /// Where resolv.conf linked to (NetworkManager's or resolvconf's file in
    /// /run), if it was a link.
    link: Option<String>,
    content: String,
}

/// The default route's gateway, if it has one, and its interface, from `ip
/// route`.
fn default_route() -> Result<(Option<String>, String)> {
    let out = run("ip", &["-4", "route", "show", "default"])?;
    let line = out
        .lines()
        .next()
        .ok_or_else(|| anyhow!("this machine has no default route; is it online?"))?;
    parse_default_route(line)
}

/// "default via 10.0.0.1 dev eth0 proto dhcp metric 100", or a link with no
/// gateway at all ("default dev ppp0 scope link": a modem, a point-to-point
/// link), where the node is reached on the interface itself.
fn parse_default_route(line: &str) -> Result<(Option<String>, String)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| {
        words
            .iter()
            .position(|w| *w == key)
            .and_then(|i| words.get(i + 1))
            .map(|v| v.to_string())
    };
    match after("dev") {
        Some(dev) => Ok((after("via"), dev)),
        // Said without the line: it names the gateway's address.
        None => Err(anyhow!(
            "could not read the default route: it names no interface"
        )),
    }
}

fn resolved_active() -> bool {
    // resolvectl must answer AND /etc/resolv.conf must be systemd-resolved's
    // stub (127.0.0.53). If resolved is running but resolv.conf points
    // somewhere else, a program that reads resolv.conf directly would ignore
    // the DNS we set through resolvectl, so we fall back to swapping the file.
    let resolvectl_ok = std::process::Command::new("resolvectl")
        .arg("status")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !resolvectl_ok {
        return false;
    }
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|c| {
            c.lines().any(|l| {
                let l = l.trim();
                l.starts_with("nameserver") && l.contains("127.0.0.53")
            })
        })
        .unwrap_or(false)
}

pub fn apply(w: &Wanted) -> Result<RevertPlan> {
    let mut plan = RevertPlan {
        interface: w.interface.clone(),
        node_ip: Some(w.node_ip),
        ..Default::default()
    };
    // Saved before anything changes: if we die mid-way, `down` still knows.
    save_plan(&plan)?;

    let (gw, dev) = default_route()?;
    plan.gateway = gw.clone();
    plan.gateway_if = Some(dev.clone());

    // The node stays reachable the ordinary way.
    if w.node_ip.is_ipv4() {
        let r = format!("{}/32", w.node_ip);
        match &gw {
            Some(gw) => run(
                "ip",
                &["-4", "route", "replace", &r, "via", gw, "dev", &dev],
            )?,
            None => run("ip", &["-4", "route", "replace", &r, "dev", &dev])?,
        };
        plan.routes_added.push(r);
        save_plan(&plan)?;
    }

    // Two-hop: the exit node's endpoint goes through the entry tunnel, so the
    // inner tunnel's packets ride inside the outer one. Set before the
    // default route, and before the inner tunnel opens its socket.
    for v in &w.via_tunnel {
        if v.host.is_ipv4() {
            let r = format!("{}/32", v.host);
            run("ip", &["-4", "route", "replace", &r, "dev", &v.interface])?;
            plan.via_routes.push(ViaRouteAdded {
                prefix: r,
                interface: v.interface.clone(),
                if_index: None,
            });
            save_plan(&plan)?;
        }
    }

    // Everything else goes into the tunnel.
    for r in ["0.0.0.0/1", "128.0.0.0/1"] {
        run("ip", &["-4", "route", "replace", r, "dev", &w.interface])?;
        plan.routes_added.push(r.into());
        save_plan(&plan)?;
    }
    if w.route_ipv6 {
        for r in ["::/1", "8000::/1"] {
            // Not every machine has IPv6 enabled; that is not a failure.
            if run("ip", &["-6", "route", "replace", r, "dev", &w.interface]).is_ok() {
                plan.routes_added.push(r.into());
                save_plan(&plan)?;
            }
        }
    }

    // DNS: the node, and only the node.
    let dns = w.dns.to_string();
    if resolved_active() {
        run("resolvectl", &["dns", &w.interface, &dns])?;
        run("resolvectl", &["domain", &w.interface, "~."])?;
        let _ = run("resolvectl", &["default-route", &w.interface, "true"]);
        plan.dns_changed = true;
    } else {
        let saved = original_resolv_conf();
        write_saved(&saved)?;
        plan.resolv_conf_backup = Some(saved.content);
        plan.resolv_conf_link = saved.link.clone();
        save_plan(&plan)?;
        let ours = format!("{RESOLV_MARK}\nnameserver {dns}\noptions edns0\n");
        if saved.link.is_some() {
            // A link into /run (NetworkManager, resolvconf): the service may
            // not write there (the unit makes all but /etc read-only), and
            // the program that owns that file would write over ours. The
            // link itself is replaced, and put back on the way down.
            let _ = std::fs::remove_file(RESOLV_CONF_TMP);
            std::fs::write(RESOLV_CONF_TMP, ours)
                .and_then(|()| std::fs::rename(RESOLV_CONF_TMP, RESOLV_CONF))
                .context("replacing /etc/resolv.conf")?;
        } else {
            std::fs::write(RESOLV_CONF, ours).context("writing /etc/resolv.conf")?;
        }
        plan.dns_changed = true;
    }
    save_plan(&plan)?;
    Ok(plan)
}

pub fn revert(plan: &RevertPlan) -> Result<()> {
    let mut problems = Vec::new();
    for v in plan.via_routes.iter().rev() {
        if let Err(e) = run(
            "ip",
            &["-4", "route", "del", &v.prefix, "dev", &v.interface],
        ) {
            // Gone with the interface is fine.
            let s = e.to_string();
            if !(s.contains("No such process") || s.contains("Cannot find device")) {
                problems.push(s);
            }
        }
    }
    for r in plan.routes_added.iter().rev() {
        let fam = if r.contains(':') { "-6" } else { "-4" };
        if let Err(e) = run("ip", &[fam, "route", "del", r]) {
            // Gone already (the interface closed and took its routes) is fine.
            if !e.to_string().contains("No such process") {
                problems.push(e.to_string());
            }
        }
    }
    if plan.dns_changed {
        if let Some(backup) = &plan.resolv_conf_backup {
            if let Err(e) = put_back_resolv_conf(plan.resolv_conf_link.as_deref(), backup) {
                problems.push(format!("restoring /etc/resolv.conf: {e}"));
            }
        } else {
            // resolvectl settings die with the interface; revert for the case
            // where the interface is still there.
            let _ = run("resolvectl", &["revert", &plan.interface]);
        }
    }
    if problems.is_empty() {
        clear_plan();
        Ok(())
    } else {
        Err(anyhow!(
            "not everything could be put back:\n  {}",
            problems.join("\n  ")
        ))
    }
}

/// resolv.conf as it is now, unless it is one we wrote and the copy of the
/// one before it survived: then that copy, so a connection made after a
/// crash does not save our own file as the machine's.
fn original_resolv_conf() -> SavedResolvConf {
    let current = SavedResolvConf {
        link: std::fs::read_link(RESOLV_CONF)
            .ok()
            .map(|p| p.to_string_lossy().into_owned()),
        content: std::fs::read_to_string(RESOLV_CONF).unwrap_or_default(),
    };
    if current.link.is_none() && current.content.starts_with(RESOLV_MARK) {
        if let Some(saved) = read_saved() {
            return saved;
        }
    }
    current
}

fn read_saved() -> Option<SavedResolvConf> {
    serde_json::from_slice(&std::fs::read(RESOLV_SAVED).ok()?).ok()
}

fn write_saved(saved: &SavedResolvConf) -> Result<()> {
    let path = std::path::Path::new(RESOLV_SAVED);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec(saved)?)
        .and_then(|()| std::fs::rename(&tmp, path))
        .with_context(|| format!("writing {RESOLV_SAVED}"))
}

fn put_back_resolv_conf(link: Option<&str>, content: &str) -> std::io::Result<()> {
    match link {
        Some(target) => {
            let _ = std::fs::remove_file(RESOLV_CONF_TMP);
            std::os::unix::fs::symlink(target, RESOLV_CONF_TMP)?;
            std::fs::rename(RESOLV_CONF_TMP, RESOLV_CONF)?;
        }
        None => std::fs::write(RESOLV_CONF, content)?,
    }
    let _ = std::fs::remove_file(RESOLV_SAVED);
    Ok(())
}

/// After a reboot that came while connected: no plan is left (it lived in
/// /run), but resolv.conf is still ours. Put the machine's back. A
/// resolv.conf someone changed since is left as it is.
pub fn recover_dns() {
    if !matches!(load_plan(), Ok(None)) {
        return;
    }
    let Some(saved) = read_saved() else {
        return;
    };
    let ours = std::fs::read_link(RESOLV_CONF).is_err()
        && std::fs::read_to_string(RESOLV_CONF)
            .map(|c| c.starts_with(RESOLV_MARK))
            .unwrap_or(false);
    if ours {
        if put_back_resolv_conf(saved.link.as_deref(), &saved.content).is_ok() {
            tracing::info!("put back the DNS settings a connection cut short had left");
        }
    } else {
        let _ = std::fs::remove_file(RESOLV_SAVED);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_route_with_or_without_a_gateway_is_read() {
        assert_eq!(
            parse_default_route("default via 10.0.0.1 dev eth0 proto dhcp metric 100").unwrap(),
            (Some("10.0.0.1".into()), "eth0".into())
        );
        assert_eq!(
            parse_default_route("default dev ppp0 scope link").unwrap(),
            (None, "ppp0".into())
        );
        let e = parse_default_route("default via 10.0.0.1")
            .unwrap_err()
            .to_string();
        assert!(!e.contains("10.0.0.1"), "an error names no address: {e}");
    }
}
