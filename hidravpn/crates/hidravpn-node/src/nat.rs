//! Forwarding and NAT, in one nftables table of our own, so that removing it
//! removes everything and nothing else on the machine is touched.
//!
//! Clients cannot reach each other through the node: a VPN is for reaching
//! the internet, and the other people on the same node are strangers. Nor
//! can they reach what is behind the node's outside interface on a private
//! or reserved address (the provider's network, the metadata service), and
//! nothing from outside reaches a client unless the client started it.

use std::io::Write;

use anyhow::{anyhow, Context, Result};

const TABLE: &str = "inet hidravpn";

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

/// Turns IPv4 forwarding on and returns whether it was on before, so that
/// `restore_forwarding` can leave the host as it found it.
pub fn enable_forwarding() -> Result<bool> {
    let was_on = std::fs::read_to_string(IP_FORWARD)
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    std::fs::write(IP_FORWARD, "1\n").context("enabling IPv4 forwarding")?;
    Ok(was_on)
}

/// Turns forwarding back off when it was off before the node started; when
/// something else on the host had it on, it stays on.
pub fn restore_forwarding(was_on: bool) -> Result<()> {
    if !was_on {
        std::fs::write(IP_FORWARD, "0\n").context("restoring IPv4 forwarding")?;
    }
    Ok(())
}

const IP6_FORWARD: &str = "/proc/sys/net/ipv6/conf/all/forwarding";

/// How the host's IPv6 was before the node turned forwarding on, so that
/// `restore_forwarding6` can put it back.
#[derive(Debug, Clone)]
pub struct Forwarding6 {
    was_on: bool,
    /// The outside interface's `accept_ra` when it was 1, which forwarding
    /// would turn into "ignore router advertisements": a host that gets its
    /// IPv6 route from them would lose it. It is set to 2 (take them even
    /// while forwarding) and put back.
    accept_ra: Option<(String, String)>,
}

fn accept_ra_path(iface: &str) -> String {
    format!("/proc/sys/net/ipv6/conf/{iface}/accept_ra")
}

/// Whether this host can carry IPv6 for clients: it has IPv6 at all, and an
/// IPv6 default route out.
pub fn host_has_ipv6_route() -> bool {
    if !std::path::Path::new(IP6_FORWARD).exists() {
        return false;
    }
    std::process::Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// Turns IPv6 forwarding on, keeping the outside interface's router
/// advertisements working, and says how it was.
pub fn enable_forwarding6(out_if: &str) -> Result<Forwarding6> {
    let was_on = std::fs::read_to_string(IP6_FORWARD)
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    let mut accept_ra = None;
    if interface_name_ok(out_if) {
        let p = accept_ra_path(out_if);
        if std::fs::read_to_string(&p)
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
        {
            std::fs::write(&p, "2\n")
                .context("keeping router advertisements on the outside interface")?;
            accept_ra = Some((p, "1\n".into()));
        }
    }
    std::fs::write(IP6_FORWARD, "1\n").context("enabling IPv6 forwarding")?;
    Ok(Forwarding6 { was_on, accept_ra })
}

/// Puts IPv6 forwarding and the outside interface back as they were.
pub fn restore_forwarding6(f: &Forwarding6) -> Result<()> {
    if !f.was_on {
        std::fs::write(IP6_FORWARD, "0\n").context("restoring IPv6 forwarding")?;
    }
    if let Some((p, v)) = &f.accept_ra {
        std::fs::write(p, v).context("restoring router advertisements")?;
    }
    Ok(())
}

/// An interface name that is safe in a /proc path and a ruleset.
fn interface_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && name != "."
        && name != ".."
}

/// The interface the default route leaves through.
pub fn default_interface() -> Result<String> {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let words: Vec<&str> = s.lines().next().unwrap_or("").split_whitespace().collect();
    words
        .iter()
        .position(|w| *w == "dev")
        .and_then(|i| words.get(i + 1))
        .map(|d| d.to_string())
        .ok_or_else(|| anyhow!("no default route: set out_interface in the settings"))
}

/// What a node's firewall lets clients reach.
pub struct Policy<'a> {
    /// "entry", "exit" or "both".
    pub role: &'a str,
    /// `forward_private_destinations`: no destination filter at all.
    pub forward_private: bool,
}

/// Destinations no client reaches through a node, whatever its role: "this
/// network", the private ranges, carriers' shared space, loopback,
/// link-local (where clouds serve instance metadata), the IETF, 6to4-relay,
/// documentation and benchmarking ranges, multicast and the reserved rest,
/// broadcast included. Whatever answers on them behind the node's outside
/// interface — the provider's network, the metadata service — belongs to
/// the host, not to its clients.
const PRIVATE4: &str = "0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4";

/// The same for IPv6: unspecified and loopback, IPv4-mapped, the NAT64
/// prefixes (which lead to IPv4 addresses, private ones too), discard,
/// benchmarking, both documentation ranges (the old one and 3fff::/20),
/// the segment routing range a provider uses inside its own network,
/// unique local (the node's own client subnet among them), link-local, the
/// old site-local, and multicast.
const PRIVATE6: &str = "::/127, ::ffff:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001:2::/48, 2001:db8::/32, 3fff::/20, 5f00::/16, fc00::/7, fe80::/10, fec0::/10, ff00::/8";

/// Admission requests one client may have open at once through a node that
/// relays them (an entry, or a node that is both): a client makes one at a
/// time, and asks again only after an answer. Without it, a few clients of
/// an entry could hold every connection an exit grants that entry's
/// address, and with it every two-hop client's way in.
const RELAYED_PER_CLIENT: u32 = 2;

/// And how fast one client may open them: one a second, after a few at
/// once. Counting open connections alone lets a client open and drop them
/// as fast as it likes; an exit holds each that sends nothing for two
/// seconds whatever the entry thinks of it.
const RELAYED_RATE: &str = "1/second burst 3 packets";

/// The table the relay limits are tried in, alone, when the node's table
/// does not load: no packet ever passes through it.
const PROBE: &str = "inet hidravpn_probe";

/// The sets and the rules that hold each client of a relaying node to a
/// few admission requests at once, and to a slow pace.
fn relay_limits(tun_if: &str, out_if: &str) -> (String, String) {
    let adm = hidravpn_core::admission::DEFAULT_ADMISSION_PORT;
    (
        "  set relayed {\n    type ipv4_addr; size 65535; flags dynamic;\n  }\n  set relayed_rate {\n    type ipv4_addr; size 65535; flags dynamic; timeout 1m;\n  }\n".to_string(),
        format!(
            r#"    iifname "{tun_if}" oifname "{out_if}" tcp dport {adm} ct state new add @relayed_rate {{ ip saddr limit rate over {RELAYED_RATE} }} reject with tcp reset comment "admission requests at a client's pace, not a script's"
    iifname "{tun_if}" oifname "{out_if}" tcp dport {adm} ct state new add @relayed {{ ip saddr ct count over {RELAYED_PER_CLIENT} }} reject with tcp reset comment "a few admission requests open at once per client"
"#
        ),
    )
}

/// The relay limits alone, in a table of their own with a chain no packet
/// passes through: the kernel loads their modules all the same, so this
/// says whether it can count and rate connections at all.
fn probe_ruleset() -> String {
    let (sets, rules) = relay_limits("hvpn0", "eth0");
    format!("table {PROBE} {{\n{sets}  chain limits {{\n{rules}  }}\n}}\n")
}

fn ruleset(
    tun_if: &str,
    out_if: &str,
    cidr: &str,
    policy: &Policy,
    cidr6: Option<&str>,
    limit_relayed: bool,
) -> String {
    // What may leave the tunnel. An entry carries nothing but WireGuard to
    // other nodes, and the one request a client makes to an exit's admission
    // port through it — so the exit is asked from the entry's address, never
    // the client's; an exit carries the internet, minus mail and the ports
    // abuse comes from. Only the standard WireGuard and admission ports are
    // relayed: a client never picks an exit on another one behind an entry
    // (`pocket::entry_can_reach`). The node has no list of nodes, so an
    // entry forwards those two ports to any public address.
    let (wg, adm) = (
        hidravpn_core::admission::DEFAULT_WIREGUARD_PORT,
        hidravpn_core::admission::DEFAULT_ADMISSION_PORT,
    );
    let role = policy.role;
    let private = if policy.forward_private {
        String::new()
    } else {
        format!(
            r#"    iifname "{tun_if}" oifname "{out_if}" ip daddr {{ {PRIVATE4} }} drop comment "no private, link-local or reserved destination: what is behind the node is the host's"
    iifname "{tun_if}" oifname "{out_if}" ip6 daddr {{ {PRIVATE6} }} drop comment "nor an IPv6 one"
"#
        )
    };
    let (relayed_set, relayed) = if relays(role) && limit_relayed {
        relay_limits(tun_if, out_if)
    } else {
        (String::new(), String::new())
    };
    let exits = if role.eq_ignore_ascii_case("entry") {
        format!(
            r#"    iifname "{tun_if}" oifname "{out_if}" udp dport {wg} accept comment "an entry forwards only WireGuard"
    iifname "{tun_if}" oifname "{out_if}" tcp dport {adm} accept comment "and admission requests to exits, so an exit never sees the client's address"
    iifname "{tun_if}" oifname "{out_if}" drop comment "entry policy: nothing else leaves"
"#
        )
    } else {
        format!(
            r#"    iifname "{tun_if}" oifname "{out_if}" tcp dport {{ 25, 135-139, 445, 1433, 3389 }} drop comment "exit policy: mail and the usual abuse ports never leave a node"
    iifname "{tun_if}" oifname "{out_if}" udp dport {{ 135-139, 445 }} drop comment "exit policy"
    iifname "{tun_if}" oifname "{out_if}" accept
"#
        )
    };
    // Clients' IPv6 leaves with the host's own address, as their IPv4 does;
    // the unique local subnet is never seen outside.
    let nat6 = cidr6
        .map(|c| format!("    ip6 saddr {c} oifname \"{out_if}\" masquerade\n"))
        .unwrap_or_default();
    format!(
        r#"table {TABLE} {{
{relayed_set}  chain input {{
    type filter hook input priority filter; policy accept;
    iifname "{tun_if}" udp dport 53 accept comment "the node's DNS forwarder"
    iifname "{tun_if}" tcp dport 53 accept comment "the node's DNS forwarder"
    iifname "{tun_if}" icmp type echo-request accept comment "a client may ping the node"
    iifname "{tun_if}" icmpv6 type echo-request accept comment "a client may ping the node"
    iifname "{tun_if}" drop comment "no other service of this host is reachable from the tunnel"
  }}
  chain forward {{
    type filter hook forward priority filter; policy accept;
    iifname "{tun_if}" oifname "{tun_if}" drop comment "clients do not see each other"
{private}{relayed}{exits}    iifname "{tun_if}" drop comment "the tunnel reaches the outside interface and nothing else of this host"
    iifname "{out_if}" oifname "{tun_if}" ct state established,related accept
    oifname "{tun_if}" drop comment "nothing reaches a client that it did not start"
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {cidr} oifname "{out_if}" masquerade
{nat6}  }}
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
    child.stdin.take().unwrap().write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "nft: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

pub fn apply(
    tun_if: &str,
    out_if: &str,
    cidr: &str,
    policy: &Policy,
    cidr6: Option<&str>,
) -> Result<()> {
    // Replace, never stack: a table from an earlier run is dropped first.
    let _ = remove();
    match nft(&ruleset(tun_if, out_if, cidr, policy, cidr6, true)) {
        Ok(()) => Ok(()),
        // Counting and rating connections needs the kernel's
        // connection-count and limit modules; a node whose kernel lacks
        // them still relays, without those limits, rather than not start at
        // all. Only then: any other failure stays a failure.
        Err(e) if relays(policy.role) => match probe() {
            Ok(()) => Err(e),
            Err(why) => {
                let _ = remove();
                nft(&ruleset(tun_if, out_if, cidr, policy, cidr6, false)).map_err(|_| e)?;
                tracing::warn!("this kernel cannot count or rate connections in nftables ({why:#}): relayed admission requests are not limited per client");
                Ok(())
            }
        },
        Err(e) => Err(e),
    }
}

/// Whether a node of this role relays admission requests to exits.
fn relays(role: &str) -> bool {
    !role.eq_ignore_ascii_case("exit")
}

/// Loads the relay limits alone (`probe_ruleset`), and removes them again.
fn probe() -> Result<()> {
    let _ = nft(&format!("delete table {PROBE}\n"));
    let r = nft(&probe_ruleset());
    let _ = nft(&format!("delete table {PROBE}\n"));
    r
}

pub fn remove() -> Result<()> {
    nft(&format!("delete table {TABLE}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(role: &str, cidr6: Option<&str>) -> String {
        let p = Policy {
            role,
            forward_private: false,
        };
        ruleset("hvpn0", "eth0", "10.77.0.0/16", &p, cidr6, true)
    }

    /// The forward chain's rules, in order.
    fn forward(r: &str) -> Vec<&str> {
        let start = r.find("chain forward").unwrap();
        let end = start + r[start..].find("chain postrouting").unwrap();
        r[start..end].lines().map(str::trim).collect()
    }

    fn position(lines: &[&str], what: &str) -> usize {
        lines
            .iter()
            .position(|l| l.contains(what))
            .unwrap_or_else(|| panic!("no rule with {what:?} in {lines:#?}"))
    }

    #[test]
    fn the_ruleset_isolates_clients_and_masquerades_their_subnet() {
        let r = rules("both", None);
        assert!(r.contains(r#"iifname "hvpn0" oifname "hvpn0" drop"#));
        assert!(r.contains(r#"ip saddr 10.77.0.0/16 oifname "eth0" masquerade"#));
        assert!(r.starts_with("table inet hidravpn {"));
        assert!(!r.contains("ip6 saddr"), "no IPv6 translation unless asked");
    }

    #[test]
    fn clients_ipv6_leaves_with_the_hosts_own_address() {
        let r = rules("exit", Some("fd68:6964:7261:7670::/64"));
        assert!(r.contains(r#"ip6 saddr fd68:6964:7261:7670::/64 oifname "eth0" masquerade"#));
        // The same isolation and exit policy hold for IPv6: the forward
        // rules name no address family.
        assert!(r.contains(r#"iifname "hvpn0" oifname "hvpn0" drop"#));
        assert!(r.contains("tcp dport { 25, 135-139, 445, 1433, 3389 } drop"));
        assert!(r.contains("icmpv6 type echo-request accept"));
        assert!(
            !interface_name_ok("../all") && !interface_name_ok("") && interface_name_ok("eth0")
        );
    }

    #[test]
    fn an_exit_forwards_the_internet_minus_abuse_ports_and_an_entry_only_wireguard() {
        let exit = rules("exit", None);
        assert!(exit.contains("tcp dport { 25, 135-139, 445, 1433, 3389 } drop"));
        assert!(exit.contains(r#"iifname "hvpn0" oifname "eth0" accept"#));
        let entry = rules("entry", None);
        assert!(entry.contains(r#"iifname "hvpn0" oifname "eth0" udp dport 51820 accept"#));
        assert!(entry.contains(r#"iifname "hvpn0" oifname "eth0" tcp dport 51821 accept"#));
        assert!(entry.contains(r#"iifname "hvpn0" oifname "eth0" drop"#));
        assert!(
            !entry.contains(r#"iifname "hvpn0" oifname "eth0" accept"#),
            "nothing else leaves an entry"
        );
        // The reply direction stays open for both; nothing from the tunnel
        // reaches another interface of the host, and on the host itself only
        // the DNS forwarder (and a ping) answers the tunnel.
        for r in [&exit, &entry] {
            assert!(r.contains("ct state established,related accept"));
            assert!(r.contains(
                r#"iifname "hvpn0" drop comment "the tunnel reaches the outside interface"#
            ));
            assert!(r.contains(r#"iifname "hvpn0" udp dport 53 accept"#));
            assert!(r.contains(r#"iifname "hvpn0" drop comment "no other service of this host"#));
            let input = r.find("chain input").unwrap();
            let forward = r.find("chain forward").unwrap();
            assert!(input < forward);
        }
    }

    #[test]
    fn nothing_from_outside_reaches_a_client_unless_the_client_started_it() {
        for role in ["entry", "exit", "both"] {
            let r = rules(role, Some("fd68:6964:7261:7670::/64"));
            let f = forward(&r);
            let replies = position(&f, "ct state established,related accept");
            let drop = position(
                &f,
                r#"oifname "hvpn0" drop comment "nothing reaches a client"#,
            );
            assert!(replies < drop, "{role}: replies first, then the drop");
            // The drop names no interface it comes from, and no family:
            // IPv4 and IPv6, from outside or from any other interface.
            assert!(
                f[drop].starts_with(r#"oifname "hvpn0" drop"#),
                "{}",
                f[drop]
            );
            assert_eq!(
                f.get(drop + 1),
                Some(&"}"),
                "{role}: and it is the last rule"
            );
        }
    }

    #[test]
    fn no_client_reaches_a_private_link_local_or_reserved_destination() {
        for role in ["entry", "exit", "both"] {
            let r = rules(role, Some("fd68:6964:7261:7670::/64"));
            let f = forward(&r);
            let v4 = position(&f, "ip daddr {");
            let v6 = position(&f, "ip6 daddr {");
            for range in [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "100.64.0.0/10",
                "127.0.0.0/8",
                "0.0.0.0/8",
                "224.0.0.0/4",
                "240.0.0.0/4",
            ] {
                assert!(f[v4].contains(range), "{role}: {range}");
            }
            for range in [
                "::/127",
                "fc00::/7",
                "fe80::/10",
                "ff00::/8",
                "::ffff:0:0/96",
                "64:ff9b::/96",
            ] {
                assert!(f[v6].contains(range), "{role}: {range}");
            }
            assert!(f[v4].ends_with(r#"drop comment "no private, link-local or reserved destination: what is behind the node is the host's""#));
            // Before anything that lets traffic out.
            let first_accept = f
                .iter()
                .position(|l| {
                    l.starts_with(r#"iifname "hvpn0" oifname "eth0""#) && l.contains("accept")
                })
                .unwrap();
            assert!(v4 < first_accept && v6 < first_accept, "{role}");
        }
        // Only an operator's explicit setting lifts it.
        let open = ruleset(
            "hvpn0",
            "eth0",
            "10.77.0.0/16",
            &Policy {
                role: "exit",
                forward_private: true,
            },
            None,
            true,
        );
        assert!(!open.contains("daddr"), "{open}");
    }

    /// Whether `addr` is in one of the prefixes of `set` ("a/n, b/m, ...").
    fn in_set(set: &str, addr: std::net::IpAddr) -> bool {
        let bits = |a: std::net::IpAddr| match a {
            std::net::IpAddr::V4(a) => (u128::from(u32::from(a)) << 96, 32),
            std::net::IpAddr::V6(a) => (u128::from(a), 128),
        };
        let (want, len) = bits(addr);
        set.split(", ").any(|p| {
            let (net, n) = p.split_once('/').unwrap();
            let (net, l) = bits(net.parse().unwrap());
            let n: u32 = n.parse().unwrap();
            let mask = if n == 0 { 0 } else { u128::MAX << (128 - n) };
            l == len && (want & mask) == (net & mask)
        })
    }

    #[test]
    fn the_filter_takes_in_every_range_that_is_not_the_internet_and_no_more() {
        // An address from each block IANA's special-purpose registries say
        // is not globally reachable, the newer ones too.
        for a in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.31.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.251",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(in_set(PRIVATE4, a.parse().unwrap()), "{a}");
        }
        for a in [
            "::",
            "::1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b:1::1",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "3fff::1",
            "3fff:fff::1",
            "5f00::1",
            "fc00::1",
            "fd68:6964:7261:7670::a4d:2",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ] {
            assert!(in_set(PRIVATE6, a.parse().unwrap()), "{a}");
        }
        // And the open internet passes, the blocks next to these too.
        for a in [
            "1.1.1.1",
            "8.8.8.8",
            "100.128.0.1",
            "192.0.1.1",
            "198.20.0.1",
            "223.255.255.255",
        ] {
            assert!(!in_set(PRIVATE4, a.parse().unwrap()), "{a}");
        }
        for a in [
            "2001:3::1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "2a00:1:2:3::4",
            "3fff:1000::1",
            "5e00::1",
        ] {
            assert!(!in_set(PRIVATE6, a.parse().unwrap()), "{a}");
        }
    }

    #[test]
    fn a_relaying_node_lets_a_client_hold_a_few_admission_requests_open_at_once() {
        for role in ["entry", "both"] {
            let r = rules(role, None);
            assert!(r.contains("set relayed {"));
            assert!(r.contains("set relayed_rate {"));
            let f = forward(&r);
            let rate = position(
                &f,
                "add @relayed_rate { ip saddr limit rate over 1/second burst 3 packets }",
            );
            let limit = position(&f, "add @relayed { ip saddr ct count over 2 }");
            for l in [rate, limit] {
                assert!(f[l]
                    .starts_with(r#"iifname "hvpn0" oifname "eth0" tcp dport 51821 ct state new"#));
                assert!(f[l].contains("reject with tcp reset"));
            }
            let first_accept = f
                .iter()
                .position(|l| l.starts_with(r#"iifname "hvpn0""#) && l.contains(" accept"))
                .unwrap();
            assert!(
                rate < first_accept && limit < first_accept,
                "{role}: before the accepts"
            );
        }
        let exit = rules("exit", None);
        assert!(!exit.contains("relayed"), "an exit relays nothing");
        // And without the kernel's counting, the same ruleset without it.
        let p = Policy {
            role: "entry",
            forward_private: false,
        };
        let plain = ruleset("hvpn0", "eth0", "10.77.0.0/16", &p, None, false);
        assert!(!plain.contains("relayed"));
        assert!(plain.contains("ip daddr {"));
    }

    #[test]
    fn the_probe_holds_the_relay_limits_and_nothing_a_packet_passes() {
        let probe = probe_ruleset();
        let entry = rules("entry", None);
        assert!(probe.starts_with("table inet hidravpn_probe {"));
        assert!(!probe.contains("hook"), "a chain no packet passes: {probe}");
        for line in probe.lines().filter(|l| l.contains("add @relayed")) {
            assert!(entry.contains(line), "the same rule as the node's: {line}");
        }
        assert_eq!(probe.matches("add @relayed").count(), 2);
        assert!(probe.contains("set relayed {") && probe.contains("set relayed_rate {"));
    }
}
