//! Linux: `ip route` and either `resolvectl` (systemd-resolved) or a swapped
//! `/etc/resolv.conf`.

use anyhow::{anyhow, Context, Result};

use super::{clear_plan, run, save_plan, RevertPlan, Wanted};

/// The default route's gateway and interface, from `ip route`.
fn default_route() -> Result<(String, String)> {
    let out = run("ip", &["-4", "route", "show", "default"])?;
    // "default via 10.0.0.1 dev eth0 proto dhcp metric 100"
    let line = out
        .lines()
        .next()
        .ok_or_else(|| anyhow!("this machine has no default route; is it online?"))?;
    let words: Vec<&str> = line.split_whitespace().collect();
    let via = words
        .iter()
        .position(|w| *w == "via")
        .and_then(|i| words.get(i + 1));
    let dev = words
        .iter()
        .position(|w| *w == "dev")
        .and_then(|i| words.get(i + 1));
    match (via, dev) {
        (Some(v), Some(d)) => Ok((v.to_string(), d.to_string())),
        _ => Err(anyhow!("could not read the default route: {line}")),
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
    plan.gateway = Some(gw.clone());
    plan.gateway_if = Some(dev.clone());

    // The node stays reachable the ordinary way.
    if w.node_ip.is_ipv4() {
        let r = format!("{}/32", w.node_ip);
        run(
            "ip",
            &["-4", "route", "replace", &r, "via", &gw, "dev", &dev],
        )?;
        plan.routes_added.push(r);
        save_plan(&plan)?;
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
        let current = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        plan.resolv_conf_backup = Some(current);
        save_plan(&plan)?;
        std::fs::write(
            "/etc/resolv.conf",
            format!("# HidraVPN: restored by `hidravpn down`\nnameserver {dns}\noptions edns0\n"),
        )
        .context("writing /etc/resolv.conf")?;
        plan.dns_changed = true;
    }
    save_plan(&plan)?;
    Ok(plan)
}

pub fn revert(plan: &RevertPlan) -> Result<()> {
    let mut problems = Vec::new();
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
            if let Err(e) = std::fs::write("/etc/resolv.conf", backup) {
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
