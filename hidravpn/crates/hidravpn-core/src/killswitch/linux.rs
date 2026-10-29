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
//! Connection tracking is used twice, both times for what comes in: ICMP
//! errors answering our own packets (a router saying one was too big), which
//! nothing else lets in, and, on the tunnels, the answers to what this
//! machine sent through them — and nothing else: every tunnel's rules end in
//! a drop, ahead of the rules that match by address (the node's endpoint,
//! DHCP, the local network), so the node at the other end cannot open a
//! connection to this machine, whatever source it puts on a packet.
//!
//! DNS goes to the node's resolver through that tunnel and nowhere else,
//! whatever the routes say and whether or not the local network is allowed:
//! a route to the resolver's address through the physical link (a network
//! that pushes one, or uses the same private range as the tunnel) must not
//! carry the machine's lookups there.
//!
//! The table is always replaced in one nftables transaction — declare,
//! delete, create — never deleted and then created, so there is no instant
//! with no table while the rules change.

use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context, Result};

use super::{Bridge, KillConfig};

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

    // Optionally let the private LAN ranges through, both ways — off the
    // tunnels only: the node's tunnel address is a private one too, and
    // what it sends in through a tunnel is not the local network.
    let (lan_out, lan_in) = if cfg.allow_lan {
        let nets = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }";
        let tunnels = std::iter::once(iface)
            .chain(cfg.extra_interface.as_ref())
            .map(|t| format!("\"{t}\""))
            .collect::<Vec<_>>()
            .join(", ");
        (
            format!(
                "    oifname != {{ {tunnels} }} ip daddr {nets} accept comment \"allow LAN\"\n"
            ),
            format!(
                "    iifname != {{ {tunnels} }} ip saddr {nets} accept comment \"allow LAN\"\n"
            ),
        )
    } else {
        (String::new(), String::new())
    };

    // Two-hop: the inner tunnel interface is allowed as well. Its packets go
    // into the outer tunnel, never to the physical link, so this opens no
    // new way out of the machine.
    let (extra_out, extra_in) = match &cfg.extra_interface {
        Some(x) => carrying_rules(x, cfg.tunnel_ipv6, " comment \"inner tunnel\""),
        None => (String::new(), String::new()),
    };

    // Two hops: the outer tunnel carries the inner tunnel's packets to the
    // exit and nothing else, so the entry never receives a packet whose
    // destination it could read; and back only the exit's answers to them.
    let (tunnel_out, tunnel_in) = match cfg.outer_peer {
        Some(peer) => {
            let (o, i) = peer_rules(iface, "udp", peer);
            (
                format!("{o}    oifname \"{iface}\" drop comment \"the outer tunnel carries only the inner one\"\n"),
                i,
            )
        }
        None => carrying_rules(iface, cfg.tunnel_ipv6, ""),
    };
    // The tunnel's own packets to the node come first: a node whose
    // WireGuard port is 53 (to get past firewalls that allow DNS) must not
    // fall to the DNS rules, which are about names, not about the tunnel.
    // Then DNS to the node's resolver, out of the tunnel that carries the
    // traffic only (the inner one of two hops), and every other packet to
    // port 53 dropped — before the local network is let through, as on
    // Windows. The node's resolver is an IPv4 address, so no query goes over
    // IPv6.
    let carrying = cfg.extra_interface.as_deref().unwrap_or(iface);
    let mut output = node_out;
    for proto in ["udp", "tcp"] {
        output.push_str(&format!(
            "    oifname \"{carrying}\" ip daddr {dns} {proto} dport 53 accept comment \"DNS to the node, through the tunnel\"\n"
        ));
    }
    for proto in ["udp", "tcp"] {
        output.push_str(&format!(
            "    {proto} dport 53 drop comment \"DNS only to the node, only through the tunnel\"\n"
        ));
    }
    output.push_str(&format!("{tunnel_out}{extra_out}{lan_out}"));
    // Each tunnel's own rules come first on the way in, each ending in a
    // drop, so nothing that arrives on a tunnel reaches the rules after
    // them: the node's endpoint, DHCP and the local network are matched by
    // address, and the node at the other end chooses the addresses of what
    // it puts inside.
    let input = format!("{tunnel_in}{extra_in}{node_in}{lan_in}");
    table(&output, &input, "nothing leaves outside the tunnel")
}

/// The tunnel that carries the traffic (the only one of one hop, the inner
/// one of two): IPv4 out, and IPv6 out only from the address the exit gave
/// it. An IPv6 packet routed into a tunnel with no address of its own leaves
/// with the machine's own address, which the exit would read when it
/// decrypts the packet; it is dropped here instead. Back in, only what
/// answers this machine's own packets (the replies, and the ICMP errors
/// path MTU discovery needs): a connection the node opens, or a datagram it
/// sends unasked, is dropped, so the node cannot reach a program listening
/// on this machine, nor learn its other addresses from what answers.
fn carrying_rules(iface: &str, tunnel6: Option<Ipv6Addr>, comment: &str) -> (String, String) {
    let mut out = format!("    oifname \"{iface}\" meta nfproto ipv4 accept{comment}\n");
    if let Some(a) = tunnel6 {
        out.push_str(&format!(
            "    oifname \"{iface}\" ip6 saddr {a} accept{comment}\n"
        ));
    }
    let inp = format!(
        "    iifname \"{iface}\" ct state established,related accept{comment}\n    iifname \"{iface}\" drop comment \"nothing comes in unasked through the tunnel\"\n"
    );
    (out, inp)
}

/// One destination on one interface: out, and back in only its answers
/// (and the ICMP errors about what went to it), then nothing else in on
/// that interface. The node at the other end of the tunnel could put the
/// destination's address on a packet of its own; this machine sends to the
/// destination first, so what it starts finds nothing open.
fn peer_rules(iface: &str, proto: &str, peer: SocketAddr) -> (String, String) {
    let fam = if peer.is_ipv4() { "ip" } else { "ip6" };
    let (a, p) = (peer.ip(), peer.port());
    (
        format!("    oifname \"{iface}\" {fam} daddr {a} {proto} dport {p} accept\n"),
        format!(
            "    iifname \"{iface}\" {fam} saddr {a} {proto} sport {p} ct state established accept\n    iifname \"{iface}\" meta l4proto icmp ct state related accept\n    iifname \"{iface}\" drop comment \"only answers come in through the tunnel\"\n"
        ),
    )
}

/// The ruleset that holds the line while a circuit is replaced: the
/// encrypted packets to the given nodes and nothing else, no tunnel
/// interface, because there is none to trust yet.
fn hold_ruleset(endpoints: &[SocketAddr]) -> String {
    let (node_out, node_in) = node_rules(endpoints);
    table(&node_out, &node_in, "held: the circuit is being rebuilt")
}

/// The hold, plus TCP to the `direct` admission ports off-tunnel and to the
/// bridge's destination through its tunnel.
fn admitting_ruleset(
    endpoints: &[SocketAddr],
    direct: &[SocketAddr],
    bridge: Option<&Bridge>,
) -> String {
    let (mut out, node_in) = node_rules(endpoints);
    // The bridge's tunnel first on the way in, as in `ruleset`.
    let mut inp = String::new();
    if let Some(b) = bridge {
        let (o, i) = peer_rules(&b.interface, "tcp", b.to);
        out.push_str(&o);
        inp.push_str(&i);
    }
    inp.push_str(&node_in);
    for d in direct {
        let fam = if d.is_ipv4() { "ip" } else { "ip6" };
        let (a, p) = (d.ip(), d.port());
        out.push_str(&format!("    {fam} daddr {a} tcp dport {p} accept\n"));
        inp.push_str(&format!("    {fam} saddr {a} tcp sport {p} accept\n"));
    }
    table(&out, &inp, "held: asking for admission")
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
    let written = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(input.as_bytes()))
        .unwrap_or(Ok(()));
    // Waited for in any case, so a failed write leaves no zombie behind.
    let out = child.wait_with_output()?;
    written.context("writing the ruleset to nft")?;
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

pub fn hold_admitting(
    endpoints: &[SocketAddr],
    direct: &[SocketAddr],
    bridge: Option<&Bridge>,
) -> Result<()> {
    if endpoints.is_empty() {
        return Err(anyhow!("a hold needs at least one node endpoint to allow"));
    }
    if let Some(b) = bridge {
        if !interface_name_ok(&b.interface) {
            return Err(anyhow!("not an interface name the kill switch accepts"));
        }
    }
    nft(&replace_script(&admitting_ruleset(
        endpoints, direct, bridge,
    )))
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
            outer_peer: None,
            tunnel_ipv6: None,
        }
    }

    #[test]
    fn with_two_hops_the_outer_tunnel_reaches_the_exit_and_nothing_else() {
        let mut two = cfg(false);
        two.extra_interface = Some("hvpn1".into());
        two.outer_peer = Some(SocketAddr::from(([198, 51, 100, 9], 51820)));
        let r = ruleset(&two);
        assert!(r.contains(r#"oifname "hvpn0" ip daddr 198.51.100.9 udp dport 51820 accept"#));
        assert!(r.contains(
            r#"iifname "hvpn0" ip saddr 198.51.100.9 udp sport 51820 ct state established accept"#
        ));
        assert!(r.contains(r#"oifname "hvpn0" drop"#));
        assert!(r.contains(r#"iifname "hvpn0" drop"#));
        assert!(!r.contains(r#"oifname "hvpn0" accept"#), "{r}");
        assert!(!r.contains(r#"iifname "hvpn0" accept"#), "{r}");
        // The drop comes after the one accept, before anything else could match.
        assert!(
            r.find(r#"oifname "hvpn0" ip daddr"#).unwrap()
                < r.find(r#"oifname "hvpn0" drop"#).unwrap()
        );
        assert!(r.contains(r#"oifname "hvpn1" meta nfproto ipv4 accept"#));
    }

    #[test]
    fn a_bridge_lets_one_tcp_destination_through_one_tunnel_and_nothing_else() {
        let entry = SocketAddr::from(([203, 0, 113, 10], 51820));
        let b = Bridge {
            interface: "hvpn0".into(),
            to: SocketAddr::from(([198, 51, 100, 9], 51821)),
        };
        let r = admitting_ruleset(&[entry], &[], Some(&b));
        assert!(r.contains("ip daddr 203.0.113.10 udp dport 51820 accept"));
        assert!(r.contains(r#"oifname "hvpn0" ip daddr 198.51.100.9 tcp dport 51821 accept"#));
        assert!(r.contains(
            r#"iifname "hvpn0" ip saddr 198.51.100.9 tcp sport 51821 ct state established accept"#
        ));
        assert!(r.contains(r#"iifname "hvpn0" drop"#));
        assert!(!r.contains(r#"oifname "hvpn0" accept"#));
        assert!(!r.contains("dport 53"), "no DNS at all while held");
        assert!(r.contains("policy drop"));
        // A first hop's admission port, off-tunnel, and nothing else.
        let adm = SocketAddr::from(([203, 0, 113, 10], 51821));
        let r = admitting_ruleset(&[entry], &[adm], None);
        assert!(r.contains("ip daddr 203.0.113.10 tcp dport 51821 accept"));
        assert!(r.contains("ip saddr 203.0.113.10 tcp sport 51821 accept"));
        assert!(!r.contains("oifname \"hvpn0\""));
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
        assert!(r.contains(r#"oifname "hvpn0" meta nfproto ipv4 accept"#));
    }

    #[test]
    fn ipv6_enters_the_tunnel_only_from_the_tunnels_own_address() {
        // No address of its own: no IPv6 into the tunnel at all, so the
        // machine's own IPv6 address is never put inside a packet the node
        // decrypts.
        let r = ruleset(&cfg(false));
        assert!(!r.contains(r#"oifname "hvpn0" accept"#), "{r}");
        assert!(!r.contains("ip6 saddr"), "{r}");
        // With one, that address and no other, and no DNS over IPv6.
        let mut c = cfg(false);
        c.tunnel_ipv6 = Some("fd68:6964:7261::a4d:8".parse().unwrap());
        let r = ruleset(&c);
        assert!(r.contains(r#"oifname "hvpn0" ip6 saddr fd68:6964:7261::a4d:8 accept"#));
        // The inet table's port-53 drop takes IPv6 too, before the tunnel's
        // IPv6 accept.
        assert!(!r.contains("ip6 daddr"), "{r}");
        assert!(r.find("    udp dport 53 drop").unwrap() < r.find("ip6 saddr fd68").unwrap());
        // Two hops: on the inner tunnel, never on the outer one.
        c.extra_interface = Some("hvpn1".into());
        c.outer_peer = Some(SocketAddr::from(([198, 51, 100, 9], 51820)));
        let r = ruleset(&c);
        assert!(r.contains(r#"oifname "hvpn1" ip6 saddr fd68:6964:7261::a4d:8 accept"#));
        assert!(!r.contains(r#"oifname "hvpn0" ip6"#), "{r}");
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
        assert!(r.contains(r#"oifname "hvpn0" ip daddr 10.77.0.1 udp dport 53 accept"#));
        assert!(r.contains(r#"oifname "hvpn0" ip daddr 10.77.0.1 tcp dport 53 accept"#));
        assert!(r.contains("    udp dport 53 drop"));
        assert!(r.contains("    tcp dport 53 drop"));
        // No DNS accept that names only the address: a route sending the
        // resolver's address out the physical link must find nothing open.
        assert_eq!(r.matches("dport 53 accept").count(), 2, "{r}");
    }

    #[test]
    fn dns_never_goes_to_the_local_network_even_when_it_is_allowed() {
        // The resolver is a private address, inside the ranges "Allow LAN"
        // opens: a route through the physical link (pushed by the network,
        // or a LAN on the tunnel's own range) must not take a query there.
        // So every port-53 packet the tunnel rule did not take is dropped
        // before the LAN rule, as Windows does above its LAN permit.
        for lan in [false, true] {
            let r = ruleset(&cfg(lan));
            let drop = r.find("    udp dport 53 drop").unwrap();
            let tcp_drop = r.find("    tcp dport 53 drop").unwrap();
            if lan {
                let allow = r.find("ip daddr { 10.0.0.0/8").unwrap();
                assert!(drop < allow && tcp_drop < allow, "{r}");
            }
            let first_dns = r.find("dport 53").unwrap();
            assert!(r[first_dns..].starts_with("dport 53 accept"), "{r}");
        }
        // Two hops: through the inner tunnel, never the outer one.
        let mut two = cfg(true);
        two.extra_interface = Some("hvpn1".into());
        two.outer_peer = Some(SocketAddr::from(([198, 51, 100, 9], 51820)));
        let r = ruleset(&two);
        assert!(r.contains(r#"oifname "hvpn1" ip daddr 10.77.0.1 udp dport 53 accept"#));
        assert!(!r.contains(r#"oifname "hvpn0" ip daddr 10.77.0.1"#), "{r}");
    }

    #[test]
    fn a_node_on_port_53_is_reached_before_the_dns_rules() {
        let mut c = cfg(false);
        c.node_endpoint = SocketAddr::from(([203, 0, 113, 10], 53));
        let r = ruleset(&c);
        let node = r.find("ip daddr 203.0.113.10 udp dport 53 accept").unwrap();
        let dns = r.find("    udp dport 53 drop").unwrap();
        assert!(node < dns, "{r}");
    }

    #[test]
    fn lan_is_off_unless_asked() {
        assert!(!ruleset(&cfg(false)).contains("allow LAN"));
        let r = ruleset(&cfg(true));
        assert!(r.contains(
            r#"oifname != { "hvpn0" } ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"#
        ));
        assert!(r.contains(
            r#"iifname != { "hvpn0" } ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept"#
        ));
        // Never a tunnel interface: the nodes' tunnel addresses are private
        // too, and what they send through a tunnel is not the local network.
        let mut two = cfg(true);
        two.extra_interface = Some("hvpn1".into());
        two.outer_peer = Some(SocketAddr::from(([198, 51, 100, 9], 51820)));
        let r = ruleset(&two);
        assert!(
            r.contains(r#"iifname != { "hvpn0", "hvpn1" } ip saddr { 10.0.0.0/8"#),
            "{r}"
        );
    }

    #[test]
    fn nothing_comes_in_through_the_tunnel_unasked() {
        // Only what answers this machine's own packets comes back in through
        // the tunnel that carries the traffic; a connection or a datagram the
        // node starts is dropped there, "Allow LAN" or not.
        for lan in [false, true] {
            let r = ruleset(&cfg(lan));
            let ok = r#"iifname "hvpn0" ct state established,related accept"#;
            let drop = r#"iifname "hvpn0" drop"#;
            assert!(r.contains(ok), "{r}");
            assert!(r.find(ok).unwrap() < r.find(drop).unwrap(), "{r}");
            assert!(!r.contains(r#"iifname "hvpn0" accept"#), "{r}");
            if lan {
                assert!(
                    r.find(drop).unwrap() < r.find("iifname != {").unwrap(),
                    "{r}"
                );
            }
        }
        // Two hops: the inner tunnel the same way; the outer one lets in
        // only the exit's answers to the inner tunnel's packets (and the
        // ICMP errors about them).
        let mut two = cfg(true);
        two.extra_interface = Some("hvpn1".into());
        two.outer_peer = Some(SocketAddr::from(([198, 51, 100, 9], 51820)));
        let r = ruleset(&two);
        assert!(r.contains(
            r#"iifname "hvpn1" ct state established,related accept comment "inner tunnel""#
        ));
        assert!(r.contains(r#"iifname "hvpn1" drop"#));
        assert!(!r.contains(r#"iifname "hvpn1" accept"#), "{r}");
        let outer: Vec<&str> = r
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with(r#"iifname "hvpn0""#))
            .collect();
        assert_eq!(
            outer,
            [
                r#"iifname "hvpn0" ip saddr 198.51.100.9 udp sport 51820 ct state established accept"#,
                r#"iifname "hvpn0" meta l4proto icmp ct state related accept"#,
                r#"iifname "hvpn0" drop comment "only answers come in through the tunnel""#,
            ],
            "{r}"
        );
    }

    #[test]
    fn what_comes_in_on_a_tunnel_never_reaches_the_rules_that_match_by_address() {
        // The node chooses the source of what it puts inside a tunnel: its
        // own endpoint's address and port, a DHCP server's port, a private
        // address. Each tunnel's drop comes before the rules that let those
        // in off the tunnel, in every shape the table takes.
        let node_in = "ip saddr 203.0.113.10 udp sport 51820 accept";
        let one = cfg(true);
        let mut inner_only = cfg(true);
        inner_only.extra_interface = Some("hvpn1".into());
        let mut two = inner_only.clone();
        two.outer_peer = Some(SocketAddr::from(([198, 51, 100, 9], 51820)));
        let bridge = Bridge {
            interface: "hvpn0".into(),
            to: SocketAddr::from(([198, 51, 100, 9], 51821)),
        };
        for (r, tunnels) in [
            (ruleset(&one), &["hvpn0"][..]),
            (ruleset(&inner_only), &["hvpn0", "hvpn1"][..]),
            (ruleset(&two), &["hvpn0", "hvpn1"][..]),
            (
                admitting_ruleset(&[one.node_endpoint], &[], Some(&bridge)),
                &["hvpn0"][..],
            ),
        ] {
            let input = &r[r.find("chain input").unwrap()..r.find("chain forward").unwrap()];
            for t in tunnels {
                let drop = input
                    .find(&format!("iifname \"{t}\" drop"))
                    .unwrap_or_else(|| panic!("no drop for {t}: {input}"));
                for later in [node_in, "udp sport 67 udp dport 68 accept", "allow LAN"] {
                    if let Some(at) = input.find(later) {
                        assert!(drop < at, "{t}: {later} comes first: {input}");
                    }
                }
                // And nothing on that interface after its drop.
                assert!(
                    !input[drop + 1..].contains(&format!("iifname \"{t}\"")),
                    "{input}"
                );
            }
            assert!(input.contains(node_in), "{input}");
        }
    }

    #[test]
    fn a_second_tunnel_interface_is_allowed_both_ways_only_when_given() {
        let single = ruleset(&cfg(false));
        assert!(!single.contains("inner tunnel"));
        let mut two = cfg(false);
        two.extra_interface = Some("hvpn1".into());
        let r = ruleset(&two);
        assert!(r.contains(r#"oifname "hvpn1" meta nfproto ipv4 accept comment "inner tunnel""#));
        assert!(r.contains(
            r#"iifname "hvpn1" ct state established,related accept comment "inner tunnel""#
        ));
        // The entry node stays the only off-tunnel destination.
        assert!(r.contains("ip daddr 203.0.113.10 udp dport 51820 accept"));
        assert_eq!(r.matches("udp dport 51820 accept").count(), 1);
    }

    #[test]
    fn no_flow_passes_only_for_being_established() {
        // A connection opened before the VPN, or through a tunnel that is
        // gone, has a conntrack entry; that alone must open nothing. ICMP
        // errors about our own packets are the one related thing let in
        // anywhere; answers are let in only on the tunnel that carries the
        // traffic, and nothing goes out for being established.
        for r in [
            ruleset(&cfg(true)),
            hold_ruleset(&[cfg(false).node_endpoint]),
        ] {
            for line in r.lines().filter(|l| l.contains("established")) {
                assert!(
                    line.trim_start().starts_with(r#"iifname "hvpn0" ct state"#),
                    "{line}"
                );
            }
            assert_eq!(
                r.matches("meta l4proto icmp ct state related accept")
                    .count(),
                2
            );
        }
        assert!(!hold_ruleset(&[cfg(false).node_endpoint]).contains("established"));
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
