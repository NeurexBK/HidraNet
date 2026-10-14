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

fn ruleset(tun_if: &str, out_if: &str, cidr: &str, role: &str) -> String {
    // What may leave the tunnel. An entry carries nothing but WireGuard to
    // other nodes; an exit carries the internet, minus mail and the ports
    // abuse comes from.
    let policy = if role.eq_ignore_ascii_case("entry") {
        format!(
            r#"    iifname "{tun_if}" oifname "{out_if}" udp dport 51820 accept comment "an entry forwards only WireGuard, to other nodes"
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
    format!(
        r#"table {TABLE} {{
  chain input {{
    type filter hook input priority filter; policy accept;
    iifname "{tun_if}" udp dport 53 accept comment "the node's DNS forwarder"
    iifname "{tun_if}" tcp dport 53 accept comment "the node's DNS forwarder"
    iifname "{tun_if}" icmp type echo-request accept comment "a client may ping the node"
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

pub fn apply(tun_if: &str, out_if: &str, cidr: &str, role: &str) -> Result<()> {
    // Replace, never stack: a table from an earlier run is dropped first.
    let _ = remove();
    nft(&ruleset(tun_if, out_if, cidr, role))
}

pub fn remove() -> Result<()> {
    nft(&format!("delete table {TABLE}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ruleset_isolates_clients_and_masquerades_their_subnet() {
        let r = ruleset("hvpn0", "eth0", "10.77.0.0/16", "both");
        assert!(r.contains(r#"iifname "hvpn0" oifname "hvpn0" drop"#));
        assert!(r.contains(r#"ip saddr 10.77.0.0/16 oifname "eth0" masquerade"#));
        assert!(r.starts_with("table inet hidravpn {"));
    }

    #[test]
    fn an_exit_forwards_the_internet_minus_abuse_ports_and_an_entry_only_wireguard() {
        let exit = ruleset("hvpn0", "eth0", "10.77.0.0/16", "exit");
        assert!(exit.contains("tcp dport { 25, 135-139, 445, 1433, 3389 } drop"));
        assert!(exit.contains(r#"iifname "hvpn0" oifname "eth0" accept"#));
        let entry = ruleset("hvpn0", "eth0", "10.77.0.0/16", "entry");
        assert!(entry.contains(r#"iifname "hvpn0" oifname "eth0" udp dport 51820 accept"#));
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
