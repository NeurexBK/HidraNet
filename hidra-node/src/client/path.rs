//! Which relays may share a circuit.
//!
//! A circuit protects a user only while its relays are run by different
//! people. Nothing proves who runs a relay, but relays in the same network
//! are likely to have one operator, or one hosting provider who can watch
//! them all; such a pair, as entry and exit, sees both ends of the circuit.
//! So no two hops of a circuit may be in the same IPv4 /16 or IPv6 /32, the
//! rule Tor uses.

use std::net::{IpAddr, SocketAddr};

use rand::seq::SliceRandom;

use crate::error::{HidraError, Result};
use crate::p2p::dht::descriptor::VerifiedRelay;

/// The same IPv4 /16 or IPv6 /32. Loopback is exempt: it is one machine by
/// definition, which only a test or a local experiment builds circuits on.
pub fn same_network(a: &SocketAddr, b: &SocketAddr) -> bool {
    match (a.ip(), b.ip()) {
        (x, y) if x.is_loopback() && y.is_loopback() => false,
        (IpAddr::V4(x), IpAddr::V4(y)) => x.octets()[..2] == y.octets()[..2],
        (IpAddr::V6(x), IpAddr::V6(y)) => x.octets()[..4] == y.octets()[..4],
        _ => false,
    }
}

/// Two relays that may both be hops of one circuit.
pub fn may_share_circuit(a: &VerifiedRelay, b: &VerifiedRelay) -> bool {
    a.addr() != b.addr()
        && a.transport_key() != b.transport_key()
        && !same_network(&a.addr(), &b.addr())
}

/// Every pair of hops in `path` may share a circuit.
pub fn check_path(path: &[VerifiedRelay]) -> Result<()> {
    for (i, a) in path.iter().enumerate() {
        for b in &path[..i] {
            if a.addr() == b.addr() || a.transport_key() == b.transport_key() {
                return Err(HidraError::Circuit(
                    "a relay appears twice in the path".into(),
                ));
            }
            if same_network(&a.addr(), &b.addr()) {
                return Err(HidraError::Circuit(
                    "two hops of the path are in the same network".into(),
                ));
            }
        }
    }
    Ok(())
}

/// A three-hop path that starts at `guard` and ends at `exit`, or at a
/// random relay if `exit` is `None`, with a random middle. Every hop is in
/// a network of its own.
pub fn choose_path(
    relays: &[VerifiedRelay],
    guard: &VerifiedRelay,
    exit: Option<&VerifiedRelay>,
) -> Result<Vec<VerifiedRelay>> {
    let mut rng = rand::thread_rng();
    let exit = match exit {
        Some(e) if may_share_circuit(guard, e) => e.clone(),
        Some(_) => {
            return Err(HidraError::Circuit(
                "the exit and the guard cannot share a circuit".into(),
            ));
        }
        None => relays
            .iter()
            .filter(|r| may_share_circuit(guard, r))
            .collect::<Vec<_>>()
            .choose(&mut rng)
            .map(|r| (*r).clone())
            .ok_or_else(|| {
                HidraError::Circuit("no exit in another network than the guard".into())
            })?,
    };
    let middle = relays
        .iter()
        .filter(|r| may_share_circuit(guard, r) && may_share_circuit(&exit, r))
        .collect::<Vec<_>>()
        .choose(&mut rng)
        .map(|r| (*r).clone())
        .ok_or_else(|| HidraError::Circuit("no middle relay in a network of its own".into()))?;
    Ok(vec![guard.clone(), middle, exit])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(addr: &str, key: u8) -> VerifiedRelay {
        VerifiedRelay::pinned(addr.parse().unwrap(), [key; 32])
    }

    #[test]
    fn networks_are_ipv4_slash_16_and_ipv6_slash_32() {
        let a: SocketAddr = "198.51.100.1:9001".parse().unwrap();
        assert!(same_network(&a, &"198.51.7.7:9001".parse().unwrap()));
        assert!(!same_network(&a, &"198.52.100.1:9001".parse().unwrap()));
        let v6: SocketAddr = "[2001:db8:1::1]:9001".parse().unwrap();
        assert!(same_network(
            &v6,
            &"[2001:db8:ffff::2]:9001".parse().unwrap()
        ));
        assert!(!same_network(&v6, &"[2001:db9::1]:9001".parse().unwrap()));
        assert!(!same_network(&a, &v6));
        let lo: SocketAddr = "127.0.0.2:9001".parse().unwrap();
        assert!(!same_network(&lo, &"127.0.0.3:9001".parse().unwrap()));
    }

    #[test]
    fn a_path_with_two_hops_in_one_network_is_refused() {
        let ok = [
            relay("198.51.100.1:9001", 1),
            relay("203.0.113.1:9001", 2),
            relay("192.0.2.1:9001", 3),
        ];
        assert!(check_path(&ok).is_ok());
        let bad = [
            relay("198.51.100.1:9001", 1),
            relay("203.0.113.1:9001", 2),
            relay("198.51.200.9:9001", 3),
        ];
        assert!(check_path(&bad).is_err());
        let twice = [relay("198.51.100.1:9001", 1), relay("203.0.113.1:9001", 1)];
        assert!(check_path(&twice).is_err());
    }

    /// Over many draws, a path always starts at the guard, ends at the exit
    /// asked for, and never puts two hops in one network, even when most of
    /// the relays known share one.
    #[test]
    fn chosen_paths_start_at_the_guard_and_keep_networks_apart() {
        let mut relays = vec![
            relay("198.51.100.1:9001", 1),
            relay("203.0.113.1:9001", 2),
            relay("192.0.2.1:9001", 3),
        ];
        for i in 0..20u8 {
            relays.push(relay(&format!("198.51.{i}.9:9001"), 10 + i));
        }
        let guard = relays[1].clone();
        for _ in 0..500 {
            let path = choose_path(&relays, &guard, None).unwrap();
            assert_eq!(path[0], guard);
            assert!(check_path(&path).is_ok());
        }
        let exit = relays[2].clone();
        for _ in 0..100 {
            let path = choose_path(&relays, &guard, Some(&exit)).unwrap();
            assert_eq!((&path[0], &path[2]), (&guard, &exit));
            assert!(check_path(&path).is_ok());
        }
        // An exit in the guard's own network cannot be used with that guard.
        let near = relay("203.0.9.9:9001", 99);
        assert!(choose_path(&relays, &guard, Some(&near)).is_err());
    }
}
