//! What a client needs to know to reach a node.
//!
//! An `Invite` is what the node hands out when it admits a client: the node's
//! public key and endpoint, the address the client gets inside the tunnel, and
//! the DNS server to use there. It carries no secret and nothing about the
//! person, so it can travel over any channel. In phase 5 it will be issued in
//! exchange for a pass instead of by an administrator.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

    pub fn validate(&self) -> Result<()> {
        public_key_from_base64(&self.node_public_key)?;
        self.endpoint_addr()?;
        self.client_ip()?;
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

    pub fn endpoint_ip(&self) -> Result<IpAddr> {
        Ok(self.endpoint_addr()?.ip())
    }
}

/// An invite plus the client's master key: everything the tunnel needs.
pub struct ClientConfig {
    pub invite: Invite,
    /// The master key. The tunnel never presents it: it presents
    /// `node_key`, derived for the invite's node.
    pub key: ClientKey,
}

impl ClientConfig {
    /// The key this node is shown: the master key derived for the invite's
    /// node public key. This is the only key a tunnel ever uses, so the
    /// master key's public half reaches no node.
    pub fn node_key(&self) -> Result<ClientKey> {
        self.key.for_node_base64(&self.invite.node_public_key)
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
            dns: Ipv4Addr::new(10, 77, 0, 1),
            allowed_ips: default_allowed(),
            mtu: 1420,
            keepalive: 25,
            operator: None,
            role: None,
        }
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
    fn the_tunnel_key_is_the_one_derived_for_the_invites_node_not_the_master() {
        let key = ClientKey::generate().unwrap();
        let inv = sample();
        let cfg = ClientConfig {
            invite: inv.clone(),
            key: key.clone(),
        };
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
        let other_shown = ClientConfig { invite: other, key }.node_key().unwrap();
        assert_ne!(other_shown.public_base64(), shown.public_base64());
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
    }
}
