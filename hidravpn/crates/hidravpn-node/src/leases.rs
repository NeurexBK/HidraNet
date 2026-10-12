//! Who is admitted and which tunnel address they hold.
//!
//! Kept in /run, which is RAM: a reboot forgets every client, and that is
//! the intent of a node that stores nothing. In phase 5 admission comes
//! from a pass and a lease lives as long as the connection; this file is
//! the phase-1 stand-in, written by an administrator's `admit`.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use wireguard_control::Key;

use crate::config::TunnelNet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub name: String,
    pub public_key: String,
    pub ip: Ipv4Addr,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Leases {
    leases: Vec<Lease>,
}

fn path() -> PathBuf {
    PathBuf::from("/run/hidravpn/peers.json")
}

impl Leases {
    pub fn load() -> Result<Self> {
        match std::fs::read(path()) {
            Ok(b) => Ok(serde_json::from_slice(&b).context("the leases file is unreadable")?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self) -> Result<()> {
        let p = path();
        std::fs::create_dir_all(p.parent().unwrap())?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &Lease> {
        self.leases.iter()
    }

    pub fn find(&self, public_key: &str) -> Option<&Lease> {
        let k = public_key.trim();
        self.leases.iter().find(|l| l.public_key == k)
    }

    /// Admits a key, or returns the lease it already has.
    pub fn admit(&mut self, name: &str, public_key: &str, net: &TunnelNet) -> Result<Lease> {
        let key = public_key.trim();
        Key::from_base64(key).map_err(|_| anyhow!("that is not a valid WireGuard public key"))?;
        if let Some(l) = self.find(key) {
            return Ok(l.clone());
        }
        let name = name.trim();
        if name.is_empty()
            || name.len() > 32
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("the name must be 1-32 letters, digits, - or _"));
        }
        let ip = self.next_free(net)?;
        let lease = Lease {
            name: name.to_string(),
            public_key: key.to_string(),
            ip,
        };
        self.leases.push(lease.clone());
        Ok(lease)
    }

    pub fn revoke(&mut self, public_key: &str) -> bool {
        let before = self.leases.len();
        let k = public_key.trim();
        self.leases.retain(|l| l.public_key != k);
        self.leases.len() != before
    }

    /// The lowest unused address after the node's own.
    fn next_free(&self, net: &TunnelNet) -> Result<Ipv4Addr> {
        let hosts = 1u32 << (32 - net.prefix);
        let base = u32::from(net.network);
        for off in 2..hosts - 1 {
            let ip = Ipv4Addr::from(base + off);
            if !self.leases.iter().any(|l| l.ip == ip) {
                return Ok(ip);
            }
        }
        Err(anyhow!("the tunnel subnet is full"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> TunnelNet {
        TunnelNet {
            cidr: "10.77.0.0/16".into(),
            network: Ipv4Addr::new(10, 77, 0, 0),
            prefix: 16,
            node_ip: Ipv4Addr::new(10, 77, 0, 1),
        }
    }

    #[test]
    fn addresses_are_handed_out_in_order_and_kept() {
        let mut l = Leases::default();
        let a = Key::generate_private().get_public().to_base64();
        let b = Key::generate_private().get_public().to_base64();
        assert_eq!(
            l.admit("a", &a, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 2)
        );
        assert_eq!(
            l.admit("b", &b, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 3)
        );
        // Admitting the same key again changes nothing.
        assert_eq!(
            l.admit("a-again", &a, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 2)
        );
        assert!(l.revoke(&a));
        assert!(!l.revoke(&a));
        // The freed address is reused.
        let c = Key::generate_private().get_public().to_base64();
        assert_eq!(
            l.admit("c", &c, &net()).unwrap().ip,
            Ipv4Addr::new(10, 77, 0, 2)
        );
    }

    #[test]
    fn bad_input_is_refused() {
        let mut l = Leases::default();
        assert!(l.admit("x", "not-a-key", &net()).is_err());
        let k = Key::generate_private().get_public().to_base64();
        assert!(l.admit("has space", &k, &net()).is_err());
    }
}
