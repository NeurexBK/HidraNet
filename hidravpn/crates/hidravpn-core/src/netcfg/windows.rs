//! Windows: `route`, `netsh` and one PowerShell query for the default route.
//! Phase 2 replaces these with the IP Helper API and adds WFP for the kill
//! switch; the plan file and the shape of `apply`/`revert` stay the same.

use anyhow::{anyhow, Result};

use super::{clear_plan, run, save_plan, RevertPlan, Wanted};

/// The default route's next hop and interface index, lowest metric first.
fn default_route() -> Result<(String, u32)> {
    let out = run(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1; \"$($r.NextHop) $($r.InterfaceIndex)\"",
        ],
    )?;
    let mut it = out.split_whitespace();
    match (it.next(), it.next().and_then(|s| s.parse().ok())) {
        (Some(gw), Some(idx)) if gw != "0.0.0.0" => Ok((gw.to_string(), idx)),
        _ => Err(anyhow!("this machine has no default route; is it online?")),
    }
}

fn if_index(name: &str) -> Result<u32> {
    let out = run(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("(Get-NetAdapter -Name '{name}').ifIndex"),
        ],
    )?;
    out.trim()
        .parse()
        .map_err(|_| anyhow!("could not find the adapter \"{name}\""))
}

pub fn apply(w: &Wanted) -> Result<RevertPlan> {
    let mut plan = RevertPlan {
        interface: w.interface.clone(),
        node_ip: Some(w.node_ip),
        ..Default::default()
    };
    save_plan(&plan)?;

    let (gw, gw_idx) = default_route()?;
    plan.gateway = Some(gw.clone());
    plan.gateway_if = Some(gw_idx.to_string());
    let idx = if_index(&w.interface)?;
    plan.if_index = Some(idx);
    let idx_s = idx.to_string();
    let gw_idx_s = gw_idx.to_string();

    // The node stays reachable the ordinary way.
    if w.node_ip.is_ipv4() {
        let node = w.node_ip.to_string();
        run(
            "route",
            &[
                "add",
                &node,
                "mask",
                "255.255.255.255",
                &gw,
                "if",
                &gw_idx_s,
                "metric",
                "1",
            ],
        )?;
        plan.routes_added.push(format!("{node}/32"));
        save_plan(&plan)?;
    }

    // Everything else goes into the tunnel. Wintun is point-to-point, so the
    // gateway is the interface itself, written as 0.0.0.0 with `if`.
    for (net, mask) in [("0.0.0.0", "128.0.0.0"), ("128.0.0.0", "128.0.0.0")] {
        run(
            "route",
            &[
                "add", net, "mask", mask, "0.0.0.0", "if", &idx_s, "metric", "1",
            ],
        )?;
        plan.routes_added.push(format!("{net}/1"));
        save_plan(&plan)?;
    }
    if w.route_ipv6 {
        for r in ["::/1", "8000::/1"] {
            if run(
                "netsh",
                &[
                    "interface",
                    "ipv6",
                    "add",
                    "route",
                    r,
                    &idx_s,
                    "metric=1",
                    "store=active",
                ],
            )
            .is_ok()
            {
                plan.routes_added.push(r.into());
                save_plan(&plan)?;
            }
        }
    }

    // DNS on the tunnel adapter. The adapter has the lowest metric, so it is
    // asked first; phase 2 makes it the only one that can be asked.
    run(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={}", idx),
            "static",
            &w.dns.to_string(),
            "primary",
            "validate=no",
        ],
    )?;
    plan.dns_changed = true;
    save_plan(&plan)?;
    Ok(plan)
}

pub fn revert(plan: &RevertPlan) -> Result<()> {
    let mut problems = Vec::new();
    for r in plan.routes_added.iter().rev() {
        let res = if r.contains(':') {
            match plan.if_index {
                Some(idx) => run(
                    "netsh",
                    &["interface", "ipv6", "delete", "route", r, &idx.to_string()],
                ),
                None => Ok(String::new()),
            }
        } else if r.ends_with("/32") {
            run("route", &["delete", r.trim_end_matches("/32")])
        } else {
            run(
                "route",
                &["delete", r.trim_end_matches("/1"), "mask", "128.0.0.0"],
            )
        };
        if let Err(e) = res {
            let s = e.to_string();
            // Routes on an adapter that is gone are gone with it.
            if !(s.contains("not found")
                || s.contains("Element not found")
                || s.contains("não encontrado"))
            {
                problems.push(s);
            }
        }
    }
    if plan.dns_changed {
        if let Some(idx) = plan.if_index {
            let _ = run(
                "netsh",
                &[
                    "interface",
                    "ipv4",
                    "set",
                    "dnsservers",
                    &format!("name={idx}"),
                    "dhcp",
                ],
            );
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
