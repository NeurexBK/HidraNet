//! Forwarding and NAT, in one nftables table of our own, so that removing it
//! removes everything and nothing else on the machine is touched.
//!
//! Clients cannot reach each other through the node: a VPN is for reaching
//! the internet, and the other people on the same node are strangers.

use std::io::Write;

use anyhow::{anyhow, Context, Result};

const TABLE: &str = "inet hidravpn";

pub fn enable_forwarding() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1\n").context("enabling IPv4 forwarding")?;
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

fn ruleset(tun_if: &str, out_if: &str, cidr: &str) -> String {
    format!(
        r#"table {TABLE} {{
  chain forward {{
    type filter hook forward priority filter; policy accept;
    iifname "{tun_if}" oifname "{tun_if}" drop comment "clients do not see each other"
    iifname "{tun_if}" oifname "{out_if}" accept
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

pub fn apply(tun_if: &str, out_if: &str, cidr: &str) -> Result<()> {
    // Replace, never stack: a table from an earlier run is dropped first.
    let _ = remove();
    nft(&ruleset(tun_if, out_if, cidr))
}

pub fn remove() -> Result<()> {
    nft(&format!("delete table {TABLE}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ruleset_isolates_clients_and_masquerades_their_subnet() {
        let r = ruleset("hvpn0", "eth0", "10.77.0.0/16");
        assert!(r.contains(r#"iifname "hvpn0" oifname "hvpn0" drop"#));
        assert!(r.contains(r#"ip saddr 10.77.0.0/16 oifname "eth0" masquerade"#));
        assert!(r.starts_with("table inet hidravpn {"));
    }
}
