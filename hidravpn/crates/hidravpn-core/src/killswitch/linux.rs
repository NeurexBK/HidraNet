//! Linux kill switch, in one nftables table of our own (`inet hidravpn_ks`).
//!
//! The `inet` family covers IPv4 and IPv6 in the same table, so a default
//! `drop` policy blocks IPv6 the moment the table exists: nothing accepts it,
//! so nothing leaves over it. IPv4 is allowed only on the tunnel, to the node,
//! and for the few things that keep the physical link usable.
//!
//! Every allowed path is named in both directions, so there is no blanket
//! "established connections pass" rule: with one, a flow opened through the
//! tunnel could find its way out on the physical link once the tunnel was
//! gone, and a connection from before the VPN could carry on in the clear.
//! The one use of connection tracking is ICMP errors answering our own
//! packets (a router saying one was too big), which nothing else lets in.
//!
//! The table is always replaced in one nftables transaction — declare,
//! delete, create — never deleted and then created, so there is no instant
//! with no table while the rules change.

use std::io::Write;
use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Context, Result};

use super::KillConfig;

const TABLE: &str = "inet hidravpn_ks";

/// The one off-tunnel destination per node: its WireGuard endpoint, matched
/// with the right address family, both ways.
fn node_rules(endpoints: &[SocketAddr]) -> (String, String) {
    let mut out = String::new();
    let mut inp = String::new();
    for ep in endpoints {
        let port = ep.port();
        match ep.ip() {
            IpAddr::V4(a) => {
                out.push_str(&format!("    ip daddr {a} udp dport {port} accept\n"));
                inp.push_str(&format!("    ip saddr {a} udp sport {port} accept\n"));
            }
            IpAddr::V6(a) => {
                out.push_str(&format!("    ip6 daddr {a} udp dport {port} accept\n"));
                inp.push_str(&format!("    ip6 saddr {a} udp sport {port} accept\n"));
            }
        }
    }
    (out, inp)
}

/// The table around a set of output and input rules: loopback first, the
/// rules, then what keeps the physical link usable, then drop.
fn table(output: &str, input: &str, why_dropped: &str) -> String {
    format!(
        r#"table {TABLE} {{
  chain output {{
    type filter hook output priority 0; policy drop;
    oif "lo" accept
{output}    udp sport 68 udp dport 67 accept comment "DHCP client keeps the link up"
    meta l4proto icmp ct state related accept comment "ICMP errors about our own packets"
    counter drop comment "{why_dropped}"
  }}
  chain input {{
    type filter hook input priority 0; policy drop;
    iif "lo" accept
{input}    udp sport 67 udp dport 68 accept comment "DHCP offers"
    meta l4proto icmp ct state related accept comment "ICMP errors about our own packets"
    counter drop comment "{why_dropped}"
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
  }}
}}
"#
    )
}

/// The nftables ruleset for this configuration. Pure, so it can be tested.
fn ruleset(cfg: &KillConfig) -> String {
    let iface = &cfg.interface;
    let dns = cfg.dns;
    let (node_out, node_in) = node_rules(&[cfg.node_endpoint]);

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

    let output = format!(
        "    udp dport 53 ip daddr != {dns} drop comment \"DNS only to the node\"\n    tcp dport 53 ip daddr != {dns} drop comment \"DNS only to the node\"\n{node_out}    oifname \"{iface}\" accept\n{extra_out}{lan_out}"
    );
    let input = format!("{node_in}    iifname \"{iface}\" accept\n{extra_in}{lan_in}");
    table(&output, &input, "nothing leaves outside the tunnel")
}

/// The ruleset that holds the line while a circuit is replaced: the
/// encrypted packets to the given nodes and nothing else, no tunnel
/// interface, because there is none to trust yet.
fn hold_ruleset(endpoints: &[SocketAddr]) -> String {
    let (node_out, node_in) = node_rules(endpoints);
    table(&node_out, &node_in, "held: the circuit is being rebuilt")
}

/// `body` installed in place of whatever table is there, in one transaction:
/// the first line makes sure the table exists, the second deletes it, the
/// rest creates it again — all or nothing, with no gap.
fn replace_script(body: &str) -> String {
    format!("table {TABLE} {{}}\ndelete table {TABLE}\n{body}")
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
    // The names go into the ruleset between quotes: only what an interface
    // name can be, so none can close the quote and add a rule of its own.
    for name in std::iter::once(&cfg.interface).chain(cfg.extra_interface.as_ref()) {
        if !interface_name_ok(name) {
            return Err(anyhow!(
                "\"{name}\" is not an interface name (1-15 letters, digits, - or _)"
            ));
        }
    }
    // Replace, never stack, and never with a moment in between: a table from
    // an earlier run, or the hold of a rotation, goes in the same transaction.
    nft(&replace_script(&ruleset(cfg)))
}

fn interface_name_ok(name: &str) -> bool {
    (1..=15).contains(&name.len())
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

pub fn hold(endpoints: &[SocketAddr]) -> Result<()> {
    if endpoints.is_empty() {
        return Err(anyhow!("a hold needs at least one node endpoint to allow"));
    }
    nft(&replace_script(&hold_ruleset(endpoints)))
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
    fn only_interface_names_go_into_the_ruleset() {
        assert!(interface_name_ok("hvpn0") && interface_name_ok("hv_x-1"));
        for bad in ["", "a\" accept", "hv pn", "abcdefghijklmnop", "hv;0"] {
            assert!(!interface_name_ok(bad), "{bad}");
        }
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

    #[test]
    fn no_flow_passes_only_for_being_established() {
        // A connection opened before the VPN, or through a tunnel that is
        // gone, has a conntrack entry; that alone must open nothing. ICMP
        // errors about our own packets are the one related thing let in.
        for r in [
            ruleset(&cfg(true)),
            hold_ruleset(&[cfg(false).node_endpoint]),
        ] {
            assert!(!r.contains("established"), "{r}");
            assert_eq!(
                r.matches("meta l4proto icmp ct state related accept")
                    .count(),
                2
            );
        }
    }

    #[test]
    fn a_hold_allows_only_the_given_nodes_and_no_tunnel() {
        let old = SocketAddr::from(([203, 0, 113, 10], 51820));
        let new = SocketAddr::from(([198, 51, 100, 7], 51820));
        let r = hold_ruleset(&[old, new]);
        assert!(r.contains("ip daddr 203.0.113.10 udp dport 51820 accept"));
        assert!(r.contains("ip daddr 198.51.100.7 udp dport 51820 accept"));
        assert!(r.contains("ip saddr 198.51.100.7 udp sport 51820 accept"));
        assert!(!r.contains("oifname"), "a hold trusts no tunnel interface");
        assert!(!r.contains("dport 53"), "no DNS leaves during a hold");
        assert!(r.contains("policy drop"));
        assert!(r.contains("held: the circuit is being rebuilt"));
        assert!(
            hold(&[]).is_err(),
            "a hold with nothing to allow is refused before nft is run"
        );
    }

    #[test]
    fn the_table_is_replaced_in_one_transaction() {
        let s = replace_script(&ruleset(&cfg(false)));
        assert!(s.starts_with(
            "table inet hidravpn_ks {}\ndelete table inet hidravpn_ks\ntable inet hidravpn_ks {"
        ));
        assert_eq!(s.matches("delete table").count(), 1);
    }
}
