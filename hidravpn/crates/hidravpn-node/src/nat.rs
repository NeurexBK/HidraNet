//! Forwarding and NAT, in one nftables table of our own, so that removing it
//! removes everything and nothing else on the machine is touched.
//!
//! Clients cannot reach each other through the node: a VPN is for reaching
//! the internet, and the other people on the same node are strangers.

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

fn ruleset(tun_if: &str, out_if: &str, cidr: &str, role: &str, cidr6: Option<&str>) -> String {
    // What may leave the tunnel. An entry carries nothing but WireGuard to
    // other nodes, and the one request a client makes to an exit's admission
    // port through it — so the exit is asked from the entry's address, never
    // the client's; an exit carries the internet, minus mail and the ports
    // abuse comes from. Only the standard WireGuard and admission ports are
    // relayed: a client never picks an exit on another one behind an entry
    // (`pocket::entry_can_reach`).
    let (wg, adm) = (
        hidravpn_core::admission::DEFAULT_WIREGUARD_PORT,
        hidravpn_core::admission::DEFAULT_ADMISSION_PORT,
    );
    let policy = if role.eq_ignore_ascii_case("entry") {
        format!(
            r#"    iifname "{tun_if}" oifname "{out_if}" udp dport {wg} accept comment "an entry forwards only WireGuard, to other nodes"
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
  chain input {{
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
{policy}    iifname "{tun_if}" drop comment "the tunnel reaches the outside interface and nothing else of this host"
    iifname "{out_if}" oifname "{tun_if}" ct state established,related accept
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
    role: &str,
    cidr6: Option<&str>,
) -> Result<()> {
    // Replace, never stack: a table from an earlier run is dropped first.
    let _ = remove();
    nft(&ruleset(tun_if, out_if, cidr, role, cidr6))
}

pub fn remove() -> Result<()> {
    nft(&format!("delete table {TABLE}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ruleset_isolates_clients_and_masquerades_their_subnet() {
        let r = ruleset("hvpn0", "eth0", "10.77.0.0/16", "both", None);
        assert!(r.contains(r#"iifname "hvpn0" oifname "hvpn0" drop"#));
        assert!(r.contains(r#"ip saddr 10.77.0.0/16 oifname "eth0" masquerade"#));
        assert!(r.starts_with("table inet hidravpn {"));
        assert!(!r.contains("ip6 saddr"), "no IPv6 translation unless asked");
    }

    #[test]
    fn clients_ipv6_leaves_with_the_hosts_own_address() {
        let r = ruleset(
            "hvpn0",
            "eth0",
            "10.77.0.0/16",
            "exit",
            Some("fd68:6964:7261:7670::/64"),
        );
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
        let exit = ruleset("hvpn0", "eth0", "10.77.0.0/16", "exit", None);
        assert!(exit.contains("tcp dport { 25, 135-139, 445, 1433, 3389 } drop"));
        assert!(exit.contains(r#"iifname "hvpn0" oifname "eth0" accept"#));
        let entry = ruleset("hvpn0", "eth0", "10.77.0.0/16", "entry", None);
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
}
