//! Where a relay will connect on a stranger's behalf.
//!
//! A relay opens two kinds of connection because a client asked it to: the
//! next hop of a circuit, and, at the exit, the destination itself. Both are
//! chosen by whoever built the circuit, and that can be anyone. Left open,
//! the exit is a door into the operator's own machine and network: services
//! bound to 127.0.0.1, the router's admin page, the rest of the LAN, and on a
//! cloud host the metadata service at 169.254.169.254, which hands out the
//! machine's credentials to anything that asks from inside it.
//!
//! So by default a relay only connects to addresses on the public internet.
//! A hostname is resolved here, every address it resolves to is checked, and
//! the connection goes to the checked address itself — never to the name
//! again, which a hostile DNS server could answer differently the second
//! time.
//!
//! A test network on one machine needs loopback hops, and a lab may need
//! private ones; those are separate switches an operator turns on knowingly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// What this relay agrees to connect to for others.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExitPolicy {
    /// Accept a circuit's next hop on a non-public address.
    pub private_hops: bool,
    /// Accept an exit destination on a non-public address.
    pub private_targets: bool,
}

impl ExitPolicy {
    /// Public addresses only, for hops and destinations. The default.
    pub const STRICT: ExitPolicy = ExitPolicy {
        private_hops: false,
        private_targets: false,
    };

    /// Anything goes. For tests and single-machine networks only; the
    /// running node builds its policy from its configuration instead.
    #[allow(dead_code)]
    pub const ALLOW_PRIVATE: ExitPolicy = ExitPolicy {
        private_hops: true,
        private_targets: true,
    };

    /// May the circuit continue to this next hop?
    pub fn permits_hop(&self, addr: &SocketAddr) -> bool {
        self.private_hops || is_public(addr.ip())
    }

    /// May the exit connect to this address?
    pub fn permits_target(&self, ip: IpAddr) -> bool {
        self.private_targets || is_public(ip)
    }

    /// Resolve an exit destination to the addresses a connection may try, in
    /// the resolver's order.
    ///
    /// Refuses the whole name if any address it resolves to is refused: a
    /// name that points both outside and inside is not one to guess about.
    /// All of them are returned, not the first: a name with an IPv6 address
    /// listed before its IPv4 one used to fail outright on an exit with no
    /// IPv6, which is most of them.
    pub async fn resolve_target(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        if port == 0 {
            return Err("destination port 0 refused".into());
        }
        let addrs: Vec<SocketAddr> = match tokio::net::lookup_host((host, port)).await {
            Ok(it) => it.collect(),
            Err(e) => return Err(format!("could not resolve destination: {e}")),
        };
        self.choose(&addrs)
    }

    fn choose(&self, addrs: &[SocketAddr]) -> Result<Vec<SocketAddr>, String> {
        if addrs.is_empty() {
            return Err("destination did not resolve".into());
        }
        if addrs.iter().any(|a| !self.permits_target(a.ip())) {
            return Err("destination refused by this relay's exit policy".into());
        }
        Ok(addrs.to_vec())
    }

    /// The addresses of a DNS answer that the policy would let a client use.
    ///
    /// Internal addresses are dropped: what a relay's own resolver knows
    /// about its network is not something to hand to strangers.
    pub fn filter_answer(&self, ips: Vec<IpAddr>) -> Vec<IpAddr> {
        ips.into_iter()
            .filter(|ip| self.permits_target(*ip))
            .collect()
    }
}

/// Is this an address on the public internet?
///
/// Everything the IANA special-purpose registries set aside is refused:
/// loopback, private and shared ranges, link-local (the cloud metadata
/// service lives there), multicast, documentation, benchmarking and reserved
/// space, and the IPv6 forms that carry an IPv4 address inside them are
/// judged by that address.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0                                   // 0.0.0.0/8 "this network"
        || (o[0] == 100 && (o[1] & 0xc0) == 64)        // 100.64.0.0/10 shared (CGNAT)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24 protocol assignments
        || (o[0] == 192 && o[1] == 88 && o[2] == 99)   // 192.88.99.0/24 6to4 relay
        || (o[0] == 198 && (o[1] & 0xfe) == 18)        // 198.18.0.0/15 benchmarking
        || o[0] >= 240) // 240.0.0.0/4 reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    // An IPv4 address in IPv6 clothing is judged as the IPv4 address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    // ::a.b.c.d (deprecated IPv4-compatible) and 64:ff9b::/96 (NAT64).
    if (s[0..6] == [0, 0, 0, 0, 0, 0] && !(ip.is_unspecified() || ip.is_loopback()))
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0])
    {
        let v4 = Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8);
        return is_public_v4(v4);
    }
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00                   // fc00::/7 unique local
        || (s[0] & 0xffc0) == 0xfe80                   // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0                   // fec0::/10 site-local (deprecated)
        || (s[0] == 0x2001 && s[1] == 0x0db8)          // 2001:db8::/32 documentation
        || (s[0] == 0x2001 && s[1] < 0x0200)           // 2001::/23 IETF protocol assignments
        || s[0] == 0x2002                              // 2002::/16 6to4, embeds IPv4
        || (s[0] == 0x0100 && s[1..4] == [0, 0, 0])) // 100::/64 discard
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn refuses_what_is_inside_the_operators_machine_and_network() {
        for s in [
            "127.0.0.1",
            "127.8.9.10",
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "100.127.255.255",
            "192.0.0.170",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a9fe:a9fe",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
            "100::1",
        ] {
            assert!(!is_public(ip(s)), "{s} must be refused");
        }
    }

    #[test]
    fn accepts_the_public_internet() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "192.169.0.1",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "2a00:1450:4001::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(is_public(ip(s)), "{s} must be accepted");
        }
    }

    #[test]
    fn strict_by_default() {
        assert_eq!(ExitPolicy::default(), ExitPolicy::STRICT);
        let lo: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        assert!(!ExitPolicy::STRICT.permits_hop(&lo));
        assert!(!ExitPolicy::STRICT.permits_target(lo.ip()));
        assert!(ExitPolicy::ALLOW_PRIVATE.permits_hop(&lo));
        assert!(ExitPolicy::ALLOW_PRIVATE.permits_target(lo.ip()));
        let hops_only = ExitPolicy {
            private_hops: true,
            private_targets: false,
        };
        assert!(hops_only.permits_hop(&lo));
        assert!(!hops_only.permits_target(lo.ip()));
    }

    #[test]
    fn a_name_pointing_both_outside_and_inside_is_refused() {
        let mixed: Vec<SocketAddr> = vec![
            "93.184.216.34:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        ];
        assert!(ExitPolicy::STRICT.choose(&mixed).is_err());
        let public: Vec<SocketAddr> = vec!["93.184.216.34:80".parse().unwrap()];
        assert_eq!(ExitPolicy::STRICT.choose(&public).unwrap(), public);
        let both: Vec<SocketAddr> = vec![
            "[2606:2800:220:1:248:1893:25c8:1946]:80".parse().unwrap(),
            "93.184.216.34:80".parse().unwrap(),
        ];
        assert_eq!(ExitPolicy::STRICT.choose(&both).unwrap(), both, "every allowed address, in order");
        assert!(ExitPolicy::STRICT.choose(&[]).is_err());
    }

    #[tokio::test]
    async fn resolving_localhost_is_refused_and_port_zero_too() {
        assert!(ExitPolicy::STRICT
            .resolve_target("localhost", 80)
            .await
            .is_err());
        assert!(ExitPolicy::STRICT
            .resolve_target("127.0.0.1", 80)
            .await
            .is_err());
        assert!(ExitPolicy::STRICT
            .resolve_target("169.254.169.254", 80)
            .await
            .is_err());
        assert!(ExitPolicy::STRICT.resolve_target("::1", 80).await.is_err());
        assert!(ExitPolicy::ALLOW_PRIVATE
            .resolve_target("127.0.0.1", 80)
            .await
            .is_ok());
        assert!(ExitPolicy::ALLOW_PRIVATE
            .resolve_target("127.0.0.1", 0)
            .await
            .is_err());
    }

    #[test]
    fn dns_answers_lose_their_internal_addresses() {
        let got = ExitPolicy::STRICT.filter_answer(vec![ip("10.0.0.5"), ip("8.8.8.8"), ip("::1")]);
        assert_eq!(got, vec![ip("8.8.8.8")]);
    }
}
