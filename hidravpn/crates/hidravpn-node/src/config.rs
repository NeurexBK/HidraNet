//! The node's settings: its key, where it listens, the tunnel subnet, where
//! DNS goes. Written once by `init`, read by everything else.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use wireguard_control::Key;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub name: String,
    /// WireGuard private key, base64. Readable by root only.
    pub private_key: String,
    pub listen_port: u16,
    /// The address clients are told to connect to.
    pub public_endpoint: SocketAddr,
    /// Clients get addresses here; the node takes the first.
    pub tunnel_cidr: String,
    #[serde(default = "default_interface")]
    pub interface: String,
    /// Where traffic leaves. Detected from the default route when absent.
    pub out_interface: Option<String>,
    /// DNS upstreams, tried in order: https://host/path@ip[,ip...] or udp://ip.
    pub dns: Vec<String>,
    /// "entry", "exit" or "both": what this node lets itself be used as. An
    /// entry's firewall forwards only WireGuard to other nodes; an exit's
    /// forwards the internet (minus mail and the usual abuse ports).
    #[serde(default = "default_role")]
    pub role: String,
    /// Who runs this node, for clients and lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// How to reach that person: an address, a page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// Where the node is, two letters (ISO 3166-1 alpha-2), as lists show it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// "manual": the operator admits by hand. "open": any client that asks
    /// on the admission port is admitted (rate-limited, capped). "pass": a
    /// client that redeems a pass is. Anything else is taken as "manual".
    #[serde(default = "default_admission")]
    pub admission: String,
    /// TCP port of the admission service (it also describes the node).
    #[serde(default = "default_admission_port")]
    pub admission_port: u16,
    /// How many clients may hold a lease at once.
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
    /// An openly admitted client that has not completed a handshake for this
    /// long loses its lease, so the subnet is not used up by people who
    /// tried once. Manually admitted clients are never expired. An entry
    /// gives no lasting leases; one it holds from an older version lapses
    /// as a session does, ten minutes after its last sign of life.
    #[serde(default = "default_idle_days")]
    pub idle_days: u32,
    /// How many bits of proof of work a session admission must carry
    /// (`hidravpn_core::admission::work`): about a second of one core at the
    /// default. Raise it if scripts fill the node.
    #[serde(default = "default_admission_work_bits")]
    pub admission_work_bits: u8,
    /// With `admission = "pass"`: the issuer keys whose passes this node
    /// takes, copied from the signed list (`hidravpn-node pass-key add`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pass_keys: Vec<hidravpn_core::pass::PassKeyRecord>,
    /// Hours without a handshake after which a lease won with a pass goes.
    /// Short: every connection brings a pass of its own.
    #[serde(default = "default_pass_idle_hours")]
    pub pass_idle_hours: u32,
    /// IPv6 for clients. "auto" (the default): an exit gives each client an
    /// address of `tunnel_cidr6` and carries its IPv6 out through this host's
    /// own, translated as IPv4 is, when it runs the kernel's WireGuard and
    /// the host has an IPv6 default route. "off": never; clients then block
    /// their own IPv6 while connected. An entry never carries IPv6: it
    /// forwards only WireGuard to other nodes.
    #[serde(default = "default_ipv6")]
    pub ipv6: String,
    /// The unique local subnet clients' IPv6 addresses come from. A client's
    /// is the subnet with its IPv4 tunnel address as the last 32 bits, so a
    /// lease needs nothing more than it holds today.
    #[serde(default = "default_tunnel_cidr6")]
    pub tunnel_cidr6: String,
    /// False (the default): clients' traffic to private, loopback,
    /// link-local (where clouds serve instance metadata), shared
    /// (100.64.0.0/10), multicast, reserved and documentation addresses,
    /// IPv4 and IPv6, is dropped here, so a client reaches the open internet
    /// through the node and never what sits behind its outside interface.
    /// True forwards those too: for a test network or a private deployment
    /// whose "internet" is a private range, never for a public node.
    #[serde(default)]
    pub forward_private_destinations: bool,
    /// On an exit: the addresses of the entries that relay their clients'
    /// admission requests here (the entries of the signed list). Every
    /// two-hop client of an entry comes from that entry's address, so each
    /// of these may hold far more connections open at once than any other
    /// address (`admission.rs`). `init --admission-relay` writes it; an
    /// open or pass-admitting node that is not an entry warns at start
    /// while it is empty.
    #[serde(default)]
    pub admission_relays: Vec<IpAddr>,
}

fn default_interface() -> String {
    "hvpn0".into()
}
fn default_role() -> String {
    "both".into()
}
fn default_admission() -> String {
    "manual".into()
}
fn default_admission_port() -> u16 {
    hidravpn_core::admission::DEFAULT_ADMISSION_PORT
}
fn default_max_clients() -> u32 {
    4000
}
fn default_idle_days() -> u32 {
    30
}
fn default_admission_work_bits() -> u8 {
    hidravpn_core::admission::work::DEFAULT_BITS
}
fn default_pass_idle_hours() -> u32 {
    6
}
fn default_ipv6() -> String {
    "auto".into()
}
fn default_tunnel_cidr6() -> String {
    "fd68:6964:7261:7670::/64".into()
}

/// The IPv6 tunnel subnet, worked out once.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TunnelNet6 {
    pub network: Ipv6Addr,
    pub prefix: u8,
    /// The node's own: the subnet with the node's IPv4 tunnel address.
    pub node_ip: Ipv6Addr,
}

impl TunnelNet6 {
    /// The IPv6 address that goes with an IPv4 tunnel address: the subnet,
    /// with the IPv4 address as its last 32 bits.
    pub fn address_for(&self, v4: Ipv4Addr) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.network) | u128::from(u32::from(v4)))
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", self.network, self.prefix)
    }
}

/// The tunnel subnet, worked out once.
pub struct TunnelNet {
    pub cidr: String,
    pub network: Ipv4Addr,
    pub prefix: u8,
    pub node_ip: Ipv4Addr,
}

impl NodeConfig {
    pub fn default_dns() -> Vec<String> {
        vec![
            "https://dns.quad9.net/dns-query@9.9.9.9,149.112.112.112".into(),
            "https://cloudflare-dns.com/dns-query@1.1.1.1,1.0.0.1".into(),
        ]
    }

    pub fn fresh(
        name: String,
        public_endpoint: SocketAddr,
        listen_port: u16,
        tunnel_cidr: &str,
        dns: Vec<String>,
        out_interface: Option<String>,
    ) -> Result<Self> {
        if !public_endpoint.is_ipv4() {
            return Err(anyhow!(
                "the endpoint {public_endpoint} is an IPv6 address; clients reach a node over IPv4 in this phase (an IPv6 endpoint would route their tunnel's own packets into the tunnel)"
            ));
        }
        let cfg = Self {
            name,
            private_key: Key::generate_private().to_base64(),
            listen_port,
            public_endpoint,
            tunnel_cidr: tunnel_cidr.to_string(),
            interface: default_interface(),
            out_interface,
            dns,
            role: default_role(),
            operator: None,
            contact: None,
            country: None,
            admission: default_admission(),
            admission_port: default_admission_port(),
            max_clients: default_max_clients(),
            idle_days: default_idle_days(),
            admission_work_bits: default_admission_work_bits(),
            pass_keys: Vec::new(),
            pass_idle_hours: default_pass_idle_hours(),
            ipv6: default_ipv6(),
            tunnel_cidr6: default_tunnel_cidr6(),
            forward_private_destinations: false,
            admission_relays: Vec::new(),
        };
        let net = cfg.tunnel_network()?;
        // A client refuses an invite whose tunnel is not a private network
        // (its resolver would be an address on the open internet), so a node
        // is never made with one.
        let o = net.network.octets();
        if !(net.network.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64)) {
            return Err(anyhow!(
                "the tunnel subnet {} is not private: use one inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10",
                net.cidr
            ));
        }
        for d in &cfg.dns {
            crate::dns::parse_upstream(d)?;
        }
        cfg.tunnel_network6()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| {
            format!(
                "reading {} — run `hidravpn-node init` first",
                path.display()
            )
        })?;
        let cfg: Self = toml::from_str(&s).context("the settings file is not valid")?;
        Key::from_base64(&cfg.private_key)
            .map_err(|_| anyhow!("the private key in the settings is not valid"))?;
        Ok(cfg)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            let _ =
                std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("writing {}", path.display()))?;
        f.write_all(toml::to_string_pretty(self)?.as_bytes())?;
        Ok(())
    }

    pub fn admission_is_open(&self) -> bool {
        self.admission.trim().eq_ignore_ascii_case("open")
    }

    /// Admits a client that redeems a pass under one of `pass_keys`.
    pub fn admits_with_passes(&self) -> bool {
        self.admission.trim().eq_ignore_ascii_case("pass")
    }

    /// Rewrites the settings in place (a new pass key, say), atomically and
    /// readable by root only.
    pub fn save_over(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("toml.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(toml::to_string_pretty(self)?.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    pub fn is_entry(&self) -> bool {
        self.role.trim().eq_ignore_ascii_case("entry")
    }

    /// How many leases won through open admission and kept (`nodes join`)
    /// this node holds at most. None on an entry: a client only ever asks
    /// an entry for a key for one connection. A quarter of `max_clients`
    /// elsewhere, so that whoever piles up lasting leases, which cost no
    /// work, the rest of the places stay for sessions.
    pub fn lasting_open_cap(&self) -> usize {
        if self.is_entry() {
            0
        } else {
            (self.max_clients / 4) as usize
        }
    }

    pub fn set_role(&mut self, role: &str) -> Result<()> {
        let r = role.trim().to_ascii_lowercase();
        if !matches!(r.as_str(), "entry" | "exit" | "both") {
            return Err(anyhow!("the role must be entry, exit or both"));
        }
        self.role = r;
        Ok(())
    }

    /// How a signed list would describe this node.
    pub fn record(&self) -> Result<hidravpn_core::NodeRecord> {
        Ok(hidravpn_core::NodeRecord {
            node_name: self.name.clone(),
            node_public_key: self.public_key()?,
            endpoint: self.public_endpoint.to_string(),
            operator: self.operator.clone(),
            contact: self.contact.clone(),
            role: Some(self.role.clone()),
            admission: Some(
                if self.admission_is_open() {
                    "open"
                } else if self.admits_with_passes() {
                    "pass"
                } else {
                    "manual"
                }
                .into(),
            ),
            admission_port: if self.admission_port == default_admission_port() {
                None
            } else {
                Some(self.admission_port)
            },
            country: self.country.clone(),
            features: self.features(),
        })
    }

    /// What this node's software does beyond phase 4, as its record and its
    /// invites list it: session keys with a proof of work, and, as an entry,
    /// relaying a client's admission request to an exit.
    pub fn features(&self) -> Vec<String> {
        use hidravpn_core::directory::features;
        let mut f = vec![features::SESSIONS.to_string()];
        if !self.role.eq_ignore_ascii_case("exit") {
            f.push(features::ADMISSION_RELAY.to_string());
        }
        f
    }

    pub fn public_key(&self) -> Result<String> {
        Ok(Key::from_base64(&self.private_key)
            .map_err(|_| anyhow!("invalid private key"))?
            .get_public()
            .to_base64())
    }

    pub fn tunnel_network(&self) -> Result<TunnelNet> {
        let (net, prefix) = self
            .tunnel_cidr
            .split_once('/')
            .ok_or_else(|| anyhow!("tunnel_cidr must be a.b.c.d/prefix"))?;
        let network: Ipv4Addr = net.parse().context("tunnel_cidr is not IPv4")?;
        let prefix: u8 = prefix
            .parse()
            .context("tunnel_cidr prefix is not a number")?;
        if !(8..=30).contains(&prefix) {
            return Err(anyhow!("the tunnel prefix must be between /8 and /30"));
        }
        let mask = u32::MAX << (32 - prefix);
        let base = u32::from(network) & mask;
        if base != u32::from(network) {
            return Err(anyhow!(
                "tunnel_cidr {} is not a network address",
                self.tunnel_cidr
            ));
        }
        Ok(TunnelNet {
            cidr: format!("{}/{}", Ipv4Addr::from(base), prefix),
            network: Ipv4Addr::from(base),
            prefix,
            node_ip: Ipv4Addr::from(base + 1),
        })
    }

    /// The IPv6 tunnel subnet, when these settings let this node carry
    /// clients' IPv6 at all: not when `ipv6` is "off", and never as an entry.
    /// Whether the host can is decided when the node starts.
    pub fn tunnel_network6(&self) -> Result<Option<TunnelNet6>> {
        match self.ipv6.trim().to_ascii_lowercase().as_str() {
            "off" => return Ok(None),
            "auto" => {}
            other => return Err(anyhow!("ipv6 must be \"auto\" or \"off\", not \"{other}\"")),
        }
        if self.role.eq_ignore_ascii_case("entry") {
            return Ok(None);
        }
        let (net, prefix) = self
            .tunnel_cidr6
            .split_once('/')
            .ok_or_else(|| anyhow!("tunnel_cidr6 must be address/prefix"))?;
        let network: Ipv6Addr = net.parse().context("tunnel_cidr6 is not IPv6")?;
        let prefix: u8 = prefix
            .parse()
            .context("tunnel_cidr6 prefix is not a number")?;
        // The last 32 bits hold the IPv4 tunnel address; a client takes only
        // a unique local address.
        if !(48..=96).contains(&prefix) {
            return Err(anyhow!(
                "the IPv6 tunnel prefix must be between /48 and /96"
            ));
        }
        if network.segments()[0] & 0xfe00 != 0xfc00 {
            return Err(anyhow!(
                "tunnel_cidr6 {} is not a unique local subnet (inside fc00::/7)",
                self.tunnel_cidr6
            ));
        }
        let host_bits = u128::MAX >> prefix;
        if u128::from(network) & host_bits != 0 {
            return Err(anyhow!(
                "tunnel_cidr6 {} is not a network address",
                self.tunnel_cidr6
            ));
        }
        let mut net6 = TunnelNet6 {
            network,
            prefix,
            node_ip: network,
        };
        net6.node_ip = net6.address_for(self.tunnel_network()?.node_ip);
        Ok(Some(net6))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_takes_the_first_address() {
        let cfg = NodeConfig::fresh(
            "n".into(),
            "192.0.2.4:51820".parse().unwrap(),
            51820,
            "10.77.0.0/16",
            NodeConfig::default_dns(),
            None,
        )
        .unwrap();
        let net = cfg.tunnel_network().unwrap();
        assert_eq!(net.node_ip, Ipv4Addr::new(10, 77, 0, 1));
        assert_eq!(net.prefix, 16);
        assert_eq!(net.cidr, "10.77.0.0/16");
    }

    #[test]
    fn a_clients_ipv6_address_is_its_ipv4_one_inside_the_ula_subnet() {
        let mut cfg = NodeConfig::fresh(
            "n".into(),
            "192.0.2.4:51820".parse().unwrap(),
            51820,
            "10.77.0.0/16",
            NodeConfig::default_dns(),
            None,
        )
        .unwrap();
        let net6 = cfg.tunnel_network6().unwrap().unwrap();
        assert_eq!(net6.cidr(), "fd68:6964:7261:7670::/64");
        assert_eq!(
            net6.node_ip,
            "fd68:6964:7261:7670::a4d:1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            net6.address_for(Ipv4Addr::new(10, 77, 0, 8)),
            "fd68:6964:7261:7670::a4d:8".parse::<Ipv6Addr>().unwrap()
        );
        // An entry never carries IPv6, and "off" means off.
        cfg.set_role("entry").unwrap();
        assert_eq!(cfg.tunnel_network6().unwrap(), None);
        cfg.set_role("exit").unwrap();
        cfg.ipv6 = "off".into();
        assert_eq!(cfg.tunnel_network6().unwrap(), None);
        cfg.ipv6 = "yes".into();
        assert!(cfg.tunnel_network6().is_err());
        cfg.ipv6 = "auto".into();
        // Only a unique local network, wide enough for an IPv4 address.
        for bad in [
            "2001:db8::/64",
            "fd00::5/64",
            "fd00::/112",
            "fd00::",
            "10.0.0.0/8",
        ] {
            cfg.tunnel_cidr6 = bad.into();
            assert!(cfg.tunnel_network6().is_err(), "{bad}");
        }
        // Settings written before IPv6 existed read as "auto".
        let mut old = toml::to_string(
            &NodeConfig::fresh(
                "n".into(),
                "192.0.2.4:51820".parse().unwrap(),
                51820,
                "10.77.0.0/16",
                NodeConfig::default_dns(),
                None,
            )
            .unwrap(),
        )
        .unwrap();
        old = old
            .lines()
            .filter(|l| !l.starts_with("ipv6") && !l.starts_with("tunnel_cidr6"))
            .collect::<Vec<_>>()
            .join("\n");
        let back: NodeConfig = toml::from_str(&old).unwrap();
        assert!(back.tunnel_network6().unwrap().is_some());
    }

    #[test]
    fn a_host_address_is_not_a_network() {
        assert!(NodeConfig::fresh(
            "n".into(),
            "192.0.2.4:1".parse().unwrap(),
            1,
            "10.77.0.5/16",
            NodeConfig::default_dns(),
            None
        )
        .is_err());
    }

    #[test]
    fn an_ipv6_endpoint_is_refused_at_init() {
        let e = NodeConfig::fresh(
            "n".into(),
            "[2001:db8::4]:51820".parse().unwrap(),
            51820,
            "10.77.0.0/16",
            NodeConfig::default_dns(),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("IPv6") && e.contains("IPv4"), "{e}");
    }

    #[test]
    fn a_tunnel_subnet_on_the_open_internet_is_refused() {
        for cidr in ["198.18.0.0/15", "203.0.113.0/24"] {
            assert!(NodeConfig::fresh(
                "n".into(),
                "192.0.2.4:51820".parse().unwrap(),
                51820,
                cidr,
                NodeConfig::default_dns(),
                None
            )
            .is_err());
        }
    }

    #[test]
    fn lasting_leases_take_a_quarter_of_the_places_and_none_on_an_entry() {
        let mut cfg = NodeConfig::fresh(
            "n".into(),
            "192.0.2.4:51820".parse().unwrap(),
            51820,
            "10.77.0.0/16",
            NodeConfig::default_dns(),
            None,
        )
        .unwrap();
        assert_eq!(cfg.lasting_open_cap(), 1000, "both: a quarter of 4000");
        cfg.set_role("exit").unwrap();
        cfg.max_clients = 41;
        assert_eq!(cfg.lasting_open_cap(), 10);
        cfg.set_role("entry").unwrap();
        assert_eq!(cfg.lasting_open_cap(), 0, "an entry gives sessions only");
    }

    #[test]
    fn settings_from_before_the_destination_filter_read_with_it_on() {
        let cfg = NodeConfig::fresh(
            "n".into(),
            "192.0.2.4:51820".parse().unwrap(),
            51820,
            "10.77.0.0/16",
            NodeConfig::default_dns(),
            None,
        )
        .unwrap();
        let old = toml::to_string(&cfg)
            .unwrap()
            .lines()
            .filter(|l| {
                !l.starts_with("forward_private_destinations") && !l.starts_with("admission_relays")
            })
            .collect::<Vec<_>>()
            .join("\n");
        let back: NodeConfig = toml::from_str(&old).unwrap();
        assert!(
            !back.forward_private_destinations,
            "private destinations stay blocked"
        );
        assert!(back.admission_relays.is_empty());
        let relays: NodeConfig =
            toml::from_str(&format!("{old}\nadmission_relays = [\"203.0.113.9\"]\n")).unwrap();
        assert_eq!(
            relays.admission_relays,
            vec!["203.0.113.9".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn settings_round_trip() {
        let cfg = NodeConfig::fresh(
            "n".into(),
            "192.0.2.4:51820".parse().unwrap(),
            51820,
            "10.77.0.0/16",
            NodeConfig::default_dns(),
            None,
        )
        .unwrap();
        let again: NodeConfig = toml::from_str(&toml::to_string_pretty(&cfg).unwrap()).unwrap();
        assert_eq!(again.public_key().unwrap(), cfg.public_key().unwrap());
    }
}
