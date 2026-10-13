//! Linux kill switch, in one nftables table of our own (`inet hidravpn_ks`).
//!
//! The `inet` family covers IPv4 and IPv6 in the same table, so a default
//! `drop` policy blocks IPv6 the moment the table exists: nothing accepts it,
//! so nothing leaves over it. IPv4 is allowed only on the tunnel, to the node,
//! and for the few things that keep the physical link usable.

use std::io::Write;
use std::net::IpAddr;

use anyhow::{anyhow, Context, Result};

use super::KillConfig;

const TABLE: &str = "inet hidravpn_ks";

/// The nftables ruleset for this configuration. Pure, so it can be tested.
fn ruleset(cfg: &KillConfig) -> String {
    let iface = &cfg.interface;
    let dns = cfg.dns;
    // The node's endpoint: an IPv4 or IPv6 literal, matched with the right
    // address family so the one off-tunnel destination always gets through.
    let node_ip = cfg.node_endpoint.ip();
    let port = cfg.node_endpoint.port();
    let node_rule_out = match node_ip {
        IpAddr::V4(a) => format!("ip daddr {a} udp dport {port} accept"),
        IpAddr::V6(a) => format!("ip6 daddr {a} udp dport {port} accept"),
    };
    let node_rule_in = match node_ip {
        IpAddr::V4(a) => format!("ip saddr {a} udp sport {port} accept"),
        IpAddr::V6(a) => format!("ip6 saddr {a} udp sport {port} accept"),
    };

    // Optionally let the private LAN ranges through, both ways.
    let (lan_out, lan_in) = if cfg.allow_lan {
        let nets = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }";
        (
            format!("    ip daddr {nets} accept comment \"allow LAN\"\n"),
            format!("    ip saddr {nets} accept comment \"allow LAN\"\n"),
        )
    } else {
        (String::new(), String::new())
    };

    // Two-hop: the inner tunnel interface is allowed as well. Its packets go
    // into the outer tunnel, never to the physical link, so this opens no
    // new way out of the machine.
    let (extra_out, extra_in) = match &cfg.extra_interface {
        Some(x) => (
            format!("    oifname \"{x}\" accept comment \"inner tunnel\"\n"),
            format!("    iifname \"{x}\" accept comment \"inner tunnel\"\n"),
        ),
        None => (String::new(), String::new()),
    };

    format!(
        r#"table {TABLE} {{
  chain output {{
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    udp dport 53 ip daddr != {dns} drop comment "DNS only to the node"
    tcp dport 53 ip daddr != {dns} drop comment "DNS only to the node"
    {node_rule_out}
    oifname "{iface}" accept
{extra_out}    udp sport 68 udp dport 67 accept comment "DHCP client keeps the link up"
{lan_out}    ct state established,related accept
    counter drop
  }}
  chain input {{
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    {node_rule_in}
    iifname "{iface}" accept
{extra_in}    udp sport 67 udp dport 68 accept comment "DHCP offers"
{lan_in}    ct state established,related accept
    counter drop
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
  }}
}}
"#
    )
}

fn nft(input: &str) -> Result<()> {
    let mut child = std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("running nft (is nftables installed?)")?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .context("writing the ruleset to nft")?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft rejected the kill-switch ruleset: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

pub fn apply(cfg: &KillConfig) -> Result<()> {
    // Replace, never stack: a table from an earlier run is dropped first.
    let _ = remove();
    nft(&ruleset(cfg))
}

pub fn remove() -> Result<()> {
    // `delete table` fails if it is not there; that is not an error for us.
    let mut child = match std::process::Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Err(anyhow!("running nft: {e}")),
    };
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("delete table {TABLE}\n").as_bytes());
    let out = child.wait_with_output()?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("No such file or directory") || err.contains("does not exist") {
        Ok(())
    } else {
        Err(anyhow!(
            "nft could not remove the kill switch: {}",
            err.trim()
        ))
    }
}

pub fn is_active() -> bool {
    std::process::Command::new("nft")
        .args(["list", "table", "inet", "hidravpn_ks"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    fn cfg(allow_lan: bool) -> KillConfig {
        KillConfig {
            interface: "hvpn0".into(),
            node_endpoint: SocketAddr::from(([203, 0, 113, 10], 51820)),
            dns: Ipv4Addr::new(10, 77, 0, 1),
            allow_lan,
            extra_interface: None,
        }
    }

    #[test]
    fn default_policy_drops_everything() {
        let r = ruleset(&cfg(false));
        assert!(r.contains("type filter hook output priority 0; policy drop;"));
        assert!(r.contains("type filter hook input priority 0; policy drop;"));
        assert!(r.contains("type filter hook forward priority 0; policy drop;"));
        assert!(r.starts_with("table inet hidravpn_ks {"));
    }

    #[test]
    fn the_node_endpoint_is_the_only_off_tunnel_destination() {
        let r = ruleset(&cfg(false));
        assert!(r.contains("ip daddr 203.0.113.10 udp dport 51820 accept"));
        assert!(r.contains("ip saddr 203.0.113.10 udp sport 51820 accept"));
        assert!(r.contains(r#"oifname "hvpn0" accept"#));
    }

    #[test]
    fn dns_is_pinned_to_the_node_resolver() {
        let r = ruleset(&cfg(false));
        assert!(r.contains("udp dport 53 ip daddr != 10.77.0.1 drop"));
        assert!(r.contains("tcp dport 53 ip daddr != 10.77.0.1 drop"));
    }

    #[test]
    fn lan_is_off_unless_asked() {
        assert!(!ruleset(&cfg(false)).contains("allow LAN"));
        let r = ruleset(&cfg(true));
        assert!(r.contains(
            "ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"
        ));
    }

    #[test]
    fn a_second_tunnel_interface_is_allowed_both_ways_only_when_given() {
        let single = ruleset(&cfg(false));
        assert!(!single.contains("inner tunnel"));
        let mut two = cfg(false);
        two.extra_interface = Some("hvpn1".into());
        let r = ruleset(&two);
        assert!(r.contains(r#"oifname "hvpn1" accept comment "inner tunnel""#));
        assert!(r.contains(r#"iifname "hvpn1" accept comment "inner tunnel""#));
        // The entry node stays the only off-tunnel destination.
        assert!(r.contains("ip daddr 203.0.113.10 udp dport 51820 accept"));
        assert_eq!(r.matches("udp dport 51820 accept").count(), 1);
    }
}
