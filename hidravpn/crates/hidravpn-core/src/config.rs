//! What a client needs to know to reach a node.
//!
//! An `Invite` is what the node hands out when it admits a client: the node's
//! public key and endpoint, the address the client gets inside the tunnel, and
//! the DNS server to use there. It carries no secret and nothing about the
//! person, so it can travel over any channel. It comes from the node's
//! administrator, from open admission, or in exchange for a pass.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::keys::{public_key_from_base64, ClientKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// Shown to the user; never used for anything else.
    pub node_name: String,
    /// The node's WireGuard public key, base64.
    pub node_public_key: String,
    /// Where the node listens, `ip:port`.
    pub endpoint: String,
    /// The client's address inside the tunnel, `a.b.c.d/prefix`.
    pub client_address: String,
    /// The client's IPv6 address inside the tunnel, `ula/prefix`, when the
    /// node carries IPv6 out through its own; absent, the client's IPv6 is
    /// blocked while connected. Always a unique local address (fc00::/7):
    /// the node translates it to its own public one, as it does IPv4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_address6: Option<String>,
    /// The DNS server inside the tunnel (the node itself).
    pub dns: Ipv4Addr,
    /// What is routed through the tunnel. Phase 1 is always everything.
    #[serde(default = "default_allowed")]
    pub allowed_ips: Vec<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Seconds between keepalives, so the node's NAT mapping stays open.
    #[serde(default = "default_keepalive")]
    pub keepalive: u16,
    /// Who runs the node, as the node says. Two hops under one operator are
    /// one operator's view, and the client is told so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// "entry", "exit" or "both": what the node's own firewall lets it be.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Where the node is, two letters, as the signed list says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// "open" when the node admits any client on request, as the signed list
    /// says; such a node, as the exit of two hops, is asked for a fresh
    /// admission through the entry on every connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<String>,
    /// The node's admission port, when the list names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_port: Option<u16>,
    /// This invite's lease is for the key shown to the node behind an entry
    /// (`hidravpn pubkey --node K --behind`): it serves only as the exit of
    /// two hops, never as a one-hop node.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub behind: bool,
    /// What the node can do, as its record lists it (`directory::features`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// Set by this client, never by a node, for an invite it won by
    /// redeeming a pass: the fresh key that pass admitted, which the tunnel
    /// shows instead of the key derived from the master key. Kept in the
    /// pocket, which only root reads; a node's answer that carries one is
    /// stripped of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pass: Option<PassBinding>,
}

/// What an invite won with a pass remembers: the key it admitted and where
/// to redeem the next pass.
#[derive(Clone, Serialize, Deserialize)]
pub struct PassBinding {
    /// The secret half of the fresh WireGuard key, base64.
    pub client_secret: String,
    /// The node's admission port, when not the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_port: Option<u16>,
    /// When the pass was redeemed (seconds since the epoch).
    #[serde(default)]
    pub redeemed_at: u64,
    /// When a circuit last went up or down with this key; 0 until it is
    /// first used. A node drops a pass's lease fifteen minutes after it was
    /// granted when it never saw a handshake, and some hours after the last
    /// one; these two say whether the lease is likely still there.
    #[serde(default)]
    pub used_at: u64,
    /// Whether the pass was redeemed through the entry of two hops (true)
    /// or from this machine's own address (false). None in a pocket written
    /// before this was recorded: where it was redeemed is not known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behind: Option<bool>,
}

/// A lease never used is gone this long after it was granted (the node's
/// fifteen minutes, with margin).
pub const UNUSED_LEASE_SECS: u64 = 600;
/// A lease last used this long ago may be gone (the node's default is six
/// hours without a handshake).
pub const IDLE_LEASE_SECS: u64 = 5 * 3600;

impl PassBinding {
    /// Redeemed from this machine's own address: the node has seen the key
    /// arrive from it, and may be shown it from there again. A key the node
    /// saw arrive through an entry never is, nor one whose origin is not
    /// known: shown from this address, it would tie the two-hop sessions it
    /// carried to this machine.
    pub fn direct(&self) -> bool {
        self.behind == Some(false)
    }

    /// Redeemed and never used yet, recently enough that its lease stands:
    /// connecting with it spends nothing, and it shows the node a key it has
    /// not seen.
    pub fn fresh(&self, now_unix: u64) -> bool {
        self.used_at == 0 && now_unix.saturating_sub(self.redeemed_at) < UNUSED_LEASE_SECS
    }

    /// Whether the node likely still holds this key's lease.
    pub fn lease_likely_alive(&self, now_unix: u64) -> bool {
        self.fresh(now_unix)
            || (self.used_at > 0 && now_unix.saturating_sub(self.used_at) < IDLE_LEASE_SECS)
    }
}

impl std::fmt::Debug for PassBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PassBinding(..)")
    }
}

fn default_allowed() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
}
fn default_mtu() -> u16 {
    1420
}
fn default_keepalive() -> u16 {
    25
}

impl Invite {
    pub fn from_json(s: &str) -> Result<Self> {
        let inv: Invite = serde_json::from_str(s).context("the invite is not valid JSON")?;
        inv.validate()?;
        Ok(inv)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("an invite always serialises")
    }

    /// Everything `validate_shape` checks, and that the resolver is the node
    /// inside the tunnel (`check_dns`). What every invite that arrives —
    /// from a node, a file or the control channel — must pass.
    pub fn validate(&self) -> Result<()> {
        self.validate_shape()?;
        self.check_dns()
    }

    /// The invite is well formed: a key, an IPv4 endpoint, a client address,
    /// a sane MTU. What a pocket written by an older version is read with:
    /// an invite that fails only `check_dns` stays in the file, and is
    /// refused when a circuit is built with it, with the reason.
    pub fn validate_shape(&self) -> Result<()> {
        public_key_from_base64(&self.node_public_key)?;
        let endpoint = self.endpoint_addr()?;
        if !endpoint.is_ipv4() {
            // The client routes all of IPv6 into the tunnel, so the tunnel's
            // own packets to an IPv6 node would go into the tunnel too and
            // never reach it. Refused here, where the invite is read, rather
            // than failing silently when the circuit comes up.
            return Err(anyhow!(
                "the endpoint \"{}\" is an IPv6 address; a node is reached over IPv4 in this phase",
                self.endpoint
            ));
        }
        self.client_ip()?;
        self.client_ip6()?;
        if let Some(c) = self.country.as_deref() {
            crate::directory::normalise_country(c)?;
        }
        if self.mtu < 1280 || self.mtu > 1500 {
            return Err(anyhow!("the MTU must be between 1280 and 1500"));
        }
        Ok(())
    }

    pub fn endpoint_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .parse()
            .with_context(|| format!("the endpoint \"{}\" is not ip:port", self.endpoint))
    }

    /// The client's tunnel address and prefix length.
    pub fn client_ip(&self) -> Result<(Ipv4Addr, u8)> {
        let (ip, prefix) = self
            .client_address
            .split_once('/')
            .ok_or_else(|| anyhow!("the client address must be a.b.c.d/prefix"))?;
        let ip: Ipv4Addr = ip.parse().context("the client address is not IPv4")?;
        let prefix: u8 = prefix
            .parse()
            .context("the client prefix is not a number")?;
        if prefix > 32 {
            return Err(anyhow!("the client prefix is larger than 32"));
        }
        Ok((ip, prefix))
    }

    /// The client's IPv6 tunnel address and prefix length, when the node gave
    /// one. Only a unique local address is taken: a node that handed out an
    /// address of the open internet would have every packet the client sends
    /// over IPv6 name that address.
    pub fn client_ip6(&self) -> Result<Option<(Ipv6Addr, u8)>> {
        let Some(a) = self.client_address6.as_deref() else {
            return Ok(None);
        };
        let (ip, prefix) = a
            .split_once('/')
            .ok_or_else(|| anyhow!("the client IPv6 address must be address/prefix"))?;
        let ip: Ipv6Addr = ip.parse().context("the client IPv6 address is not IPv6")?;
        let prefix: u8 = prefix
            .parse()
            .context("the client IPv6 prefix is not a number")?;
        if !(48..=127).contains(&prefix) {
            return Err(anyhow!(
                "the client IPv6 prefix /{prefix} is not a tunnel subnet (between /48 and /127)"
            ));
        }
        if ip.segments()[0] & 0xfe00 != 0xfc00 {
            return Err(anyhow!(
                "the client IPv6 address {ip} is not a unique local address (fc00::/7)"
            ));
        }
        Ok(Some((ip, prefix)))
    }

    /// The resolver must be the node itself, inside the tunnel: an address
    /// of the client's own tunnel subnet, private, and not the client's own.
    /// An invite travels over channels nobody authenticates (open admission
    /// is plain HTTP), and the kill switch lets DNS go to this one address
    /// only, so a resolver out on the internet would hand every name this
    /// machine looks up to whoever wrote it in. Inside the subnet, a query
    /// can only reach the node: the node forwards nothing from one client to
    /// another.
    fn check_dns(&self) -> Result<()> {
        let (ip, prefix) = self.client_ip()?;
        if !(8..=30).contains(&prefix) {
            return Err(anyhow!(
                "the client prefix /{prefix} is not a tunnel subnet (between /8 and /30)"
            ));
        }
        let private = |a: Ipv4Addr| {
            let o = a.octets();
            a.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        };
        if !private(ip) {
            return Err(anyhow!(
                "the client address {ip} is not a private tunnel address"
            ));
        }
        let mask = u32::MAX << (32 - prefix);
        let same_subnet = (u32::from(self.dns) & mask) == (u32::from(ip) & mask);
        if !same_subnet || self.dns == ip || !private(self.dns) {
            return Err(anyhow!(
                "the invite's DNS server {} is not the node inside the tunnel ({}): refusing an invite that would send this machine's lookups elsewhere",
                self.dns,
                self.client_address
            ));
        }
        Ok(())
    }

    pub fn endpoint_ip(&self) -> Result<IpAddr> {
        Ok(self.endpoint_addr()?.ip())
    }

    /// Whether the node admits any client on request.
    pub fn admits_openly(&self) -> bool {
        self.admission
            .as_deref()
            .is_some_and(|a| a.trim().eq_ignore_ascii_case("open"))
    }

    /// Whether the node's record lists this feature.
    pub fn has(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    /// Whether the node admits a client that redeems a pass (phase 5), as
    /// the signed list says, or as the pass this invite was won with shows.
    pub fn takes_passes(&self) -> bool {
        self.pass.is_some()
            || self
                .admission
                .as_deref()
                .is_some_and(|a| a.trim().eq_ignore_ascii_case("pass"))
    }

    /// The pass this invite was won with, when this machine may show its
    /// key from its own address again: one redeemed from here. None for a
    /// key redeemed through an entry, or whose origin is not known.
    pub fn direct_pass(&self) -> Option<&PassBinding> {
        self.pass.as_ref().filter(|p| p.direct())
    }

    /// Whether the node is asked for a key for each connection: it admits
    /// openly and its software can.
    pub fn admits_sessions(&self) -> bool {
        self.admits_openly() && self.has(crate::directory::features::SESSIONS)
    }

    /// The node as a list would describe it, for an admission request.
    pub fn record(&self) -> crate::directory::NodeRecord {
        crate::directory::NodeRecord {
            node_name: self.node_name.clone(),
            node_public_key: self.node_public_key.clone(),
            endpoint: self.endpoint.clone(),
            operator: self.operator.clone(),
            contact: None,
            role: self.role.clone(),
            admission: self.admission.clone(),
            admission_port: self.admission_port,
            country: self.country.clone(),
            features: self.features.clone(),
        }
    }

    /// Where the node takes admission requests.
    pub fn admission_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::new(
            self.endpoint_ip()?,
            self.admission_port
                .unwrap_or(crate::admission::DEFAULT_ADMISSION_PORT),
        ))
    }
}

/// Which key a tunnel shows its node.
#[derive(Debug, Clone)]
pub enum ShownKey {
    /// Derived from the master key for this node: a node reached from the
    /// client's own address (the entry of two hops, the node of one).
    Direct,
    /// Derived with the other salt: an exit admitted by hand, reached
    /// through an entry.
    Behind,
    /// This key exactly: a fresh key made for one connection and admitted
    /// through the entry.
    Exact(ClientKey),
}

/// An invite plus the client's master key: everything the tunnel needs.
pub struct ClientConfig {
    pub invite: Invite,
    /// The master key. The tunnel never presents it: it presents
    /// `node_key`, derived for the invite's node or made for the connection.
    pub key: ClientKey,
    /// Which key the node is shown.
    pub shown: ShownKey,
}

impl ClientConfig {
    /// A node reached from the client's own address, shown its derived key.
    pub fn direct(invite: Invite, key: ClientKey) -> Self {
        Self {
            invite,
            key,
            shown: ShownKey::Direct,
        }
    }

    /// The key this node is shown: never the master key's public half.
    pub fn node_key(&self) -> Result<ClientKey> {
        // A key made for this one connection is shown as it is; so is the
        // key a pass admitted. Otherwise the key derived for the node.
        if let ShownKey::Exact(k) = &self.shown {
            return Ok(k.clone());
        }
        // A pass's key is shown only the way it was admitted: one redeemed
        // through an entry never from this machine's own address, one
        // redeemed from here never behind an entry, and one whose origin is
        // not known neither way.
        if let Some(p) = &self.invite.pass {
            let fits = match &self.shown {
                ShownKey::Behind => p.behind == Some(true),
                _ => p.direct(),
            };
            if !fits {
                let (how, never) = match &self.shown {
                    ShownKey::Behind => ("from this machine's own address", "behind an entry"),
                    _ => ("through an entry", "from this machine's own address"),
                };
                return Err(anyhow!(
                    "{}: the key of its last pass was admitted {how} (or by an older version that did not write down how); it is never shown {never}, and a new pass is needed",
                    self.invite.node_name
                ));
            }
            return ClientKey::from_base64(&p.client_secret)
                .context("the key of the pass this invite was won with");
        }
        match &self.shown {
            ShownKey::Behind => self
                .key
                .for_node_behind_base64(&self.invite.node_public_key),
            _ => self.key.for_node_base64(&self.invite.node_public_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Invite {
        Invite {
            node_name: "test".into(),
            node_public_key: ClientKey::generate().unwrap().public_base64(),
            endpoint: "203.0.113.10:51820".into(),
            client_address: "10.77.0.2/16".into(),
            client_address6: None,
            dns: Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: default_allowed(),
            mtu: 1420,
            keepalive: 25,
            operator: None,
            role: None,
            pass: None,
            country: None,
            admission: None,
            admission_port: None,
            behind: false,
            features: Vec::new(),
        }
    }

    #[test]
    fn an_ipv6_tunnel_address_must_be_a_unique_local_one() {
        let mut inv = sample();
        assert_eq!(
            inv.client_ip6().unwrap(),
            None,
            "absent is fine: IPv6 is then blocked"
        );
        inv.client_address6 = Some("fd68:6964:7261:7670::a4d:2/64".into());
        inv.validate().unwrap();
        assert_eq!(
            inv.client_ip6().unwrap(),
            Some(("fd68:6964:7261:7670::a4d:2".parse().unwrap(), 64))
        );
        let back = Invite::from_json(&inv.to_json()).unwrap();
        assert_eq!(back.client_address6, inv.client_address6);
        // An address of the open internet, a missing or silly prefix, or
        // not IPv6 at all: refused when the invite is read.
        for bad in [
            "2001:db8::2/64",
            "fd68::2",
            "fd68::2/200",
            "fd68::2/8",
            "10.77.0.2/16",
        ] {
            inv.client_address6 = Some(bad.into());
            assert!(inv.validate().is_err(), "{bad}");
        }
        // An invite from a node that does not know the field still reads.
        let old = r#"{"node_name":"n","node_public_key":"KEY","endpoint":"203.0.113.10:51820","client_address":"10.77.0.2/16","dns":"10.77.0.1"}"#
            .replace("KEY", &sample().node_public_key);
        assert_eq!(Invite::from_json(&old).unwrap().client_address6, None);
    }

    #[test]
    fn an_invite_round_trips() {
        let inv = sample();
        let again = Invite::from_json(&inv.to_json()).unwrap();
        assert_eq!(again.endpoint_addr().unwrap().port(), 51820);
        assert_eq!(
            again.client_ip().unwrap(),
            (Ipv4Addr::new(10, 77, 0, 2), 16)
        );
    }

    #[test]
    fn a_pass_key_is_shown_only_the_way_it_was_admitted() {
        let key = ClientKey::generate().unwrap();
        let pass_key = ClientKey::generate().unwrap();
        let with = |behind: Option<bool>| {
            let mut inv = sample();
            inv.pass = Some(PassBinding {
                client_secret: pass_key.secret_base64(),
                admission_port: None,
                redeemed_at: 1,
                used_at: 0,
                behind,
            });
            inv
        };
        let shown = |inv: Invite, shown: ShownKey| {
            ClientConfig {
                invite: inv,
                key: key.clone(),
                shown,
            }
            .node_key()
        };
        let direct = shown(with(Some(false)), ShownKey::Direct).unwrap();
        assert_eq!(direct.public_base64(), pass_key.public_base64());
        let behind = shown(with(Some(true)), ShownKey::Behind).unwrap();
        assert_eq!(behind.public_base64(), pass_key.public_base64());
        // A key the node saw arrive through an entry is never shown from
        // this machine's address, nor one an older pocket did not mark; one
        // it saw from here is never shown behind an entry.
        for (b, s) in [
            (Some(true), ShownKey::Direct),
            (None, ShownKey::Direct),
            (Some(false), ShownKey::Behind),
            (None, ShownKey::Behind),
        ] {
            let e = shown(with(b), s.clone()).unwrap_err().to_string();
            assert!(e.contains("a new pass is needed"), "{b:?} {s:?}: {e}");
        }
        // A key made for this connection is shown as it is, whatever the
        // invite remembers.
        let fresh = ClientKey::generate().unwrap();
        let exact = shown(with(Some(true)), ShownKey::Exact(fresh.clone())).unwrap();
        assert_eq!(exact.public_base64(), fresh.public_base64());
    }

    #[test]
    fn a_pass_binding_from_an_older_pocket_reads_and_says_its_origin_is_not_known() {
        let b: PassBinding =
            serde_json::from_str(r#"{"client_secret":"x","redeemed_at":5,"used_at":7}"#).unwrap();
        assert_eq!(b.behind, None);
        assert!(!b.direct());
        let again = serde_json::to_string(&b).unwrap();
        assert!(!again.contains("behind"), "{again}");
        let marked = PassBinding {
            behind: Some(true),
            ..b
        };
        let json = serde_json::to_string(&marked).unwrap();
        assert!(json.contains(r#""behind":true"#), "{json}");
        let back: PassBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back.behind, Some(true));
    }

    #[test]
    fn the_tunnel_key_is_the_one_derived_for_the_invites_node_not_the_master() {
        let key = ClientKey::generate().unwrap();
        let inv = sample();
        let cfg = ClientConfig::direct(inv.clone(), key.clone());
        let shown = cfg.node_key().unwrap();
        assert_ne!(shown.public_base64(), key.public_base64());
        assert_eq!(
            shown.public_base64(),
            key.for_node_base64(&inv.node_public_key)
                .unwrap()
                .public_base64()
        );
        let mut other = sample();
        other.node_public_key = ClientKey::generate().unwrap().public_base64();
        let other_shown = ClientConfig::direct(other, key.clone()).node_key().unwrap();
        assert_ne!(other_shown.public_base64(), shown.public_base64());
        // Behind an entry the same node is shown another key; a key made for
        // one connection is shown as it is.
        let behind = ClientConfig {
            invite: inv.clone(),
            key: key.clone(),
            shown: ShownKey::Behind,
        }
        .node_key()
        .unwrap();
        assert_ne!(behind.public_base64(), shown.public_base64());
        let fresh = ClientKey::generate().unwrap();
        let exact = ClientConfig {
            invite: inv,
            key,
            shown: ShownKey::Exact(fresh.clone()),
        }
        .node_key()
        .unwrap();
        assert_eq!(exact.public_base64(), fresh.public_base64());
    }

    #[test]
    fn a_bad_invite_is_refused() {
        let mut inv = sample();
        inv.node_public_key = "short".into();
        assert!(inv.validate().is_err());
        let mut inv = sample();
        inv.endpoint = "nowhere".into();
        assert!(inv.validate().is_err());
        let mut inv = sample();
        inv.client_address = "10.77.0.2".into();
        assert!(inv.validate().is_err());
        // An IPv6 endpoint parses, and is refused with the reason: the
        // tunnel's own packets would be routed into the tunnel.
        let mut inv = sample();
        inv.endpoint = "[2001:db8::10]:51820".into();
        let e = inv.validate().unwrap_err().to_string();
        assert!(e.contains("IPv6") && e.contains("IPv4"), "{e}");
    }

    #[test]
    fn the_resolver_must_be_the_node_inside_the_tunnel() {
        sample().validate().unwrap();
        // Carrier-grade NAT space is a private tunnel subnet too.
        let mut inv = sample();
        inv.client_address = "100.64.3.9/10".into();
        inv.dns = Ipv4Addr::new(100, 64, 0, 1);
        inv.validate().unwrap();
        for (dns, client) in [
            ("198.51.100.53", "10.77.0.2/16"),    // a resolver on the internet
            ("10.78.0.1", "10.77.0.2/16"),        // outside the client's subnet
            ("10.77.0.2", "10.77.0.2/16"),        // the client itself
            ("198.51.100.53", "198.51.100.2/24"), // a public "tunnel"
            ("10.0.0.1", "10.0.0.2/1"),           // a prefix that spans everything
        ] {
            let mut inv = sample();
            inv.dns = dns.parse().unwrap();
            inv.client_address = client.into();
            let e = inv.validate().unwrap_err().to_string();
            assert!(
                e.contains("DNS") || e.contains("tunnel"),
                "{dns} {client}: {e}"
            );
        }
    }
}
