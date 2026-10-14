//! Windows: the NetTCPIP and DnsClient PowerShell cmdlets, over the IP Helper
//! API; the kill switch (WFP) is in `killswitch`. Everything is written to the ActiveStore only: nothing here
//! survives a reboot, so a crash cannot leave a machine routed into a tunnel
//! that no longer exists.

use anyhow::{anyhow, Result};

use super::{clear_plan, run, save_plan, RevertPlan, ViaRouteAdded, Wanted};

/// Runs one PowerShell statement; a failing cmdlet fails the call.
fn ps(script: &str) -> Result<String> {
    let wrapped = format!(
        "$ErrorActionPreference = 'Stop'; try {{ {script} }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
    );
    run(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &wrapped,
        ],
    )
}

/// A string literal for PowerShell: single quotes, with any quote doubled.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// The default route's next hop and interface index, lowest metric first.
fn default_route() -> Result<(String, u32)> {
    let out = ps(
        "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; if (-not $r) { throw 'no default route' }; \"$($r.NextHop) $($r.InterfaceIndex)\"",
    )?;
    let mut it = out.split_whitespace();
    match (it.next(), it.next().and_then(|s| s.parse().ok())) {
        (Some(gw), Some(idx)) => Ok((gw.to_string(), idx)),
        _ => Err(anyhow!("this machine has no default route; is it online?")),
    }
}

fn if_index(name: &str) -> Result<u32> {
    let out = ps(&format!("(Get-NetAdapter -Name {} ).ifIndex", q(name)))?;
    out.trim()
        .parse()
        .map_err(|_| anyhow!("could not find the adapter \"{name}\""))
}

fn add_route(prefix: &str, if_index: u32, next_hop: &str) -> Result<()> {
    // A leftover from a run that died is replaced, not stacked.
    let _ = ps(&format!(
        "Remove-NetRoute -DestinationPrefix {} -InterfaceIndex {if_index} -Confirm:$false -ErrorAction SilentlyContinue",
        q(prefix)
    ));
    ps(&format!(
        "New-NetRoute -DestinationPrefix {} -InterfaceIndex {if_index} -NextHop {} -RouteMetric 1 -PolicyStore ActiveStore | Out-Null",
        q(prefix),
        q(next_hop)
    ))?;
    Ok(())
}

fn remove_route(prefix: &str, if_index: Option<u32>) -> Result<()> {
    let on = if_index
        .map(|i| format!(" -InterfaceIndex {i}"))
        .unwrap_or_default();
    ps(&format!(
        "Remove-NetRoute -DestinationPrefix {}{on} -Confirm:$false",
        q(prefix)
    ))?;
    Ok(())
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
    save_plan(&plan)?;

    // The node stays reachable the ordinary way.
    if w.node_ip.is_ipv4() {
        let r = format!("{}/32", w.node_ip);
        add_route(&r, gw_idx, &gw)?;
        plan.routes_added.push(r);
        save_plan(&plan)?;
    }

    // Two-hop: the exit node's endpoint goes through the entry tunnel adapter,
    // so the inner tunnel's packets ride inside the outer one.
    for v in &w.via_tunnel {
        if v.host.is_ipv4() {
            let r = format!("{}/32", v.host);
            let vidx = if_index(&v.interface)?;
            add_route(&r, vidx, "0.0.0.0")?;
            plan.via_routes.push(ViaRouteAdded {
                prefix: r,
                interface: v.interface.clone(),
                if_index: Some(vidx),
            });
            save_plan(&plan)?;
        }
    }

    // Everything else goes into the tunnel. A TUN adapter has no gateway of
    // its own, so the next hop is the unspecified address: "on this link".
    for r in ["0.0.0.0/1", "128.0.0.0/1"] {
        add_route(r, idx, "0.0.0.0")?;
        plan.routes_added.push(r.into());
        save_plan(&plan)?;
    }
    if w.route_ipv6 {
        for r in ["::/1", "8000::/1"] {
            // IPv6 may be off on this machine; that is not a failure.
            if add_route(r, idx, "::").is_ok() {
                plan.routes_added.push(r.into());
                save_plan(&plan)?;
            }
        }
    }

    // DNS on the tunnel adapter, which has the lowest metric and so is asked
    // first; the kill switch makes it the only adapter that can be asked.
    ps(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses {}",
        q(&w.dns.to_string())
    ))?;
    plan.dns_changed = true;
    save_plan(&plan)?;
    let _ = ps("Clear-DnsClientCache");
    Ok(plan)
}

pub fn revert(plan: &RevertPlan) -> Result<()> {
    let mut problems = Vec::new();
    let gw_idx: Option<u32> = plan.gateway_if.as_deref().and_then(|s| s.parse().ok());
    for v in plan.via_routes.iter().rev() {
        if let Err(e) = remove_route(&v.prefix, v.if_index) {
            let s = e.to_string();
            // Routes on an adapter that is gone went with it.
            if !(s.contains("No matching") || s.contains("not found") || s.contains("não")) {
                problems.push(s);
            }
        }
    }
    for r in plan.routes_added.iter().rev() {
        let on = if r.ends_with("/32") {
            gw_idx
        } else {
            plan.if_index
        };
        if let Err(e) = remove_route(r, on) {
            let s = e.to_string();
            // Routes on an adapter that is gone went with it.
            if !(s.contains("No matching") || s.contains("not found") || s.contains("não")) {
                problems.push(s);
            }
        }
    }
    if plan.dns_changed {
        if let Some(idx) = plan.if_index {
            let _ = ps(&format!(
                "Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses"
            ));
        }
        let _ = ps("Clear-DnsClientCache");
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
