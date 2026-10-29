//! Windows kill switch, on the Windows Filtering Platform (WFP) — the same
//! mechanism the official WireGuard client uses, so it does not disturb the
//! user's own Windows Firewall rules and cannot be seen or switched off from
//! the firewall UI.
//!
//! All the rules live under one provider and one sublayer of ours, both with
//! fixed GUIDs, and every filter has a fixed GUID too, so turning the kill
//! switch off is just deleting those known keys — nothing to enumerate, and a
//! half-removed state can always be finished by calling `remove` again.
//!
//! The sublayer is given the top weight so its decision is final. At the
//! connect-authorisation layers, and at the receive-accept layers (a
//! connection or datagram from a host this machine did not send to first),
//! the default is to BLOCK; a handful of higher-weight PERMIT filters open
//! just what must stay open: loopback, the tunnel interface (outbound only:
//! nothing comes in through it unasked, so the node cannot reach a program
//! listening here; a block on each tunnel interface, above the inbound
//! permits that match by address, keeps it so, and only the ICMP errors
//! path MTU discovery needs are let in above it), the encrypted packets to
//! the node, and DHCP. IPv6 has the
//! loopback exception and, when the exit gave the tunnel an IPv6 address,
//! the tunnel that carries the traffic (the only one of one hop, the inner
//! one of two), so it never leaves the machine off the tunnel. Windows sends
//! from an interface's own addresses only (the strong host model), so IPv6
//! into that tunnel carries the tunnel's address, never the machine's own.
//! DNS to anything but the node is not permitted, so it is blocked with
//! everything else.

#![allow(clippy::missing_safety_doc)]

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, bail, Result};
use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmProviderAdd0,
    FwpmProviderDeleteByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER0, FWPM_SUBLAYER0, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_CONDITION_FLAG_IS_LOOPBACK,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::{Bridge, KillConfig};

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

// Fixed identity for everything we add, so removal is deterministic. The last
// nibble distinguishes the objects; keep them unique.
const PROVIDER_KEY: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0000_0001);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0000_0002);
const F_BLOCK_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0001_0001);
const F_BLOCK_V6: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0001_0002);
const F_LOOPBACK_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0002_0001);
const F_LOOPBACK_V6: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0002_0002);
const F_TUNNEL_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0003_0001);
/// The nodes reached off-tunnel: one for a circuit, two while one circuit
/// is replaced by another (`hold`), with room to spare.
const F_NODE_V4: [GUID; 4] = [
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0004_0001),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0004_0002),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0004_0003),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0004_0004),
];
const F_DHCP_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0005_0001);
/// IPv6 on the tunnel that carries the traffic, when the exit carries IPv6.
const F_TUNNEL_V6: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000a_0001);
/// The inner tunnel interface of a two-hop circuit.
const F_TUNNEL2_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0003_0002);
/// One destination through one tunnel interface: the outer tunnel of two
/// hops towards the exit, or towards an exit's admission port.
const F_PEERED_V4: [GUID; 2] = [
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0006_0001),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0006_0002),
];
/// A first hop's admission port, off-tunnel, while a circuit is replaced.
const F_DIRECT_TCP_V4: [GUID; 2] = [
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0007_0001),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0007_0002),
];

/// "Allow LAN": the private ranges, as on Linux (`LAN_V4`).
const F_LAN_V4: [GUID; 4] = [
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0008_0001),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0008_0002),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0008_0003),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0008_0004),
];
/// …but never DNS to them: names go to the node, LAN or not.
const F_LAN_DNS_V4: [GUID; 4] = [
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0009_0001),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0009_0002),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0009_0003),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0009_0004),
];
/// Connections from outside, at the receive-accept layers: the same catch-all
/// blocks and fewer openings (loopback, DHCP, "Allow LAN"), so a program
/// listening on this machine is reached by nobody else, the node at the
/// other end of a tunnel included. Replies to what this machine sent belong
/// to the flow its connect opened, and pass without these. See `inbound`.
const F_IN_BLOCK_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0001);
const F_IN_BLOCK_V6: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0002);
const F_IN_LOOPBACK_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0003);
const F_IN_LOOPBACK_V6: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0004);
/// Inbound blocks on the tunnel interfaces, above DHCP and "Allow LAN",
/// whose permits match by address: the node at the other end of a tunnel
/// chooses the addresses of what it puts inside. Older versions put inbound
/// permits under these keys, which let the node open connections here;
/// every key is deleted before any is added, so those go.
const F_IN_TUNNEL_V4: [GUID; 2] = [
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0005),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0006),
];
/// Retired: the inbound IPv6 permit on the tunnel. Nothing permits IPv6 in
/// but loopback, so the catch-all blocks it on the tunnel too. Still
/// deleted with the rest, so a kill switch an older version armed is
/// replaced whole.
const F_IN_TUNNEL_V6: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0007);
const F_IN_DHCP_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0008);
const F_IN_LAN_V4: [GUID; 4] = [
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0009),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_000a),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_000b),
    GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_000c),
];
/// The ICMP errors let in through each tunnel interface, above its block,
/// one key per tunnel and per `TUNNEL_ICMP_ERRORS` entry.
const F_IN_TUNNEL_ICMP: [[GUID; 3]; 2] = [
    [
        GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_000d),
        GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_000e),
        GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_000f),
    ],
    [
        GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0010),
        GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0011),
        GUID::from_u128(0x4849_4452_4156_504e_0000_0000_000b_0012),
    ],
];
/// The ICMP errors path MTU discovery and a failed connection need, by
/// layer, protocol and type: destination unreachable (fragmentation needed
/// is one of its codes) and, for IPv6, packet too big. An error answers a
/// packet this machine sent and opens nothing (nothing answers an ICMP
/// error); Linux lets the same in as `ct state related`. Echo requests,
/// redirects and the rest stay blocked.
const TUNNEL_ICMP_ERRORS: [(GUID, u8, u16, &str); 3] = [
    (
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        IPPROTO_ICMP,
        3,
        "ICMP destination unreachable through the tunnel",
    ),
    (
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        IPPROTO_ICMPV6,
        1,
        "ICMPv6 destination unreachable through the tunnel",
    ),
    (
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        IPPROTO_ICMPV6,
        2,
        "ICMPv6 packet too big through the tunnel",
    ),
];

/// The private ranges "Allow LAN" opens: address and mask, host order.
const LAN_V4: [(u32, u32); 4] = [
    (0x0A00_0000, 0xFF00_0000), // 10.0.0.0/8
    (0xAC10_0000, 0xFFF0_0000), // 172.16.0.0/12
    (0xC0A8_0000, 0xFFFF_0000), // 192.168.0.0/16
    (0xA9FE_0000, 0xFFFF_0000), // 169.254.0.0/16
];

const ALL_FILTER_KEYS: [GUID; 42] = [
    F_BLOCK_V4,
    F_BLOCK_V6,
    F_LOOPBACK_V4,
    F_LOOPBACK_V6,
    F_TUNNEL_V4,
    F_TUNNEL_V6,
    F_TUNNEL2_V4,
    F_NODE_V4[0],
    F_NODE_V4[1],
    F_NODE_V4[2],
    F_NODE_V4[3],
    F_DHCP_V4,
    F_PEERED_V4[0],
    F_PEERED_V4[1],
    F_DIRECT_TCP_V4[0],
    F_DIRECT_TCP_V4[1],
    F_LAN_V4[0],
    F_LAN_V4[1],
    F_LAN_V4[2],
    F_LAN_V4[3],
    F_LAN_DNS_V4[0],
    F_LAN_DNS_V4[1],
    F_LAN_DNS_V4[2],
    F_LAN_DNS_V4[3],
    F_IN_BLOCK_V4,
    F_IN_BLOCK_V6,
    F_IN_LOOPBACK_V4,
    F_IN_LOOPBACK_V6,
    F_IN_TUNNEL_V4[0],
    F_IN_TUNNEL_V4[1],
    F_IN_TUNNEL_V6,
    F_IN_DHCP_V4,
    F_IN_LAN_V4[0],
    F_IN_LAN_V4[1],
    F_IN_LAN_V4[2],
    F_IN_LAN_V4[3],
    F_IN_TUNNEL_ICMP[0][0],
    F_IN_TUNNEL_ICMP[0][1],
    F_IN_TUNNEL_ICMP[0][2],
    F_IN_TUNNEL_ICMP[1][0],
    F_IN_TUNNEL_ICMP[1][1],
    F_IN_TUNNEL_ICMP[1][2],
];

fn ok(code: u32) -> Result<()> {
    if code == ERROR_SUCCESS.0 {
        Ok(())
    } else {
        Err(anyhow!("WFP call failed (code {code})"))
    }
}

/// A UTF-16, NUL-terminated copy of a string, kept alive by the caller.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn display(name: &mut Vec<u16>) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: windows::core::PWSTR(name.as_mut_ptr()),
        description: windows::core::PWSTR::null(),
    }
}

fn weight_u8(w: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: w },
    }
}

fn open_engine() -> Result<HANDLE> {
    let mut engine = HANDLE::default();
    let code =
        unsafe { FwpmEngineOpen0(PCWSTR::null(), RPC_C_AUTHN_WINNT, None, None, &mut engine) };
    ok(code)?;
    Ok(engine)
}

fn luid_of(interface: &str) -> Result<u64> {
    let w = wide(interface);
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(w.as_ptr()), &mut luid) };
    if code.0 != ERROR_SUCCESS.0 {
        bail!(
            "the tunnel interface \"{interface}\" was not found (code {})",
            code.0
        );
    }
    // NET_LUID_LH is a union over a u64.
    Ok(unsafe { luid.Value })
}

/// What a rule set lets through besides loopback and DHCP.
struct Allow<'a> {
    /// Tunnel interfaces, by alias: the outer (or only) one first. One that
    /// is not up yet is skipped, with a warning (see below).
    tunnels: &'a [&'a str],
    /// The nodes reached off-tunnel, IPv4: one for a circuit, the old and
    /// the new first hop while a circuit is replaced.
    nodes: &'a [SocketAddr],
    /// One destination through one tunnel interface, by protocol.
    peered: &'a [(&'a str, u8, SocketAddr)],
    /// TCP destinations off-tunnel: a first hop's admission port.
    direct_tcp: &'a [SocketAddr],
    /// "Allow LAN": the private ranges off-tunnel, never their DNS.
    lan: bool,
    /// The tunnel that carries the traffic, by alias, when the exit gave it
    /// an IPv6 address: IPv6 is allowed on it.
    tunnel_v6: Option<&'a str>,
}

/// An IPv4 endpoint in the host order WFP wants for UINT32.
fn v4(ep: &SocketAddr) -> Result<(u32, u16)> {
    match ep.ip() {
        IpAddr::V4(a) => Ok((u32::from(a), ep.port())),
        IpAddr::V6(_) => bail!("the kill switch needs IPv4 endpoints in this phase"),
    }
}

/// The whole kill switch, for a running circuit (`apply`) or for the hold
/// across a rotation (`hold`): the catch-all blocks, loopback, the tunnel
/// interfaces given, the nodes given, DHCP.
fn install(allow: &Allow<'_>) -> Result<()> {
    if allow.nodes.len() > F_NODE_V4.len()
        || allow.tunnels.len() > [F_TUNNEL_V4, F_TUNNEL2_V4].len()
        || allow.peered.len() > F_PEERED_V4.len()
        || allow.direct_tcp.len() > F_DIRECT_TCP_V4.len()
    {
        bail!("the kill switch was asked to allow more destinations than it has rules for");
    }
    let nodes = allow.nodes.iter().map(v4).collect::<Result<Vec<_>>>()?;
    let direct_tcp = allow
        .direct_tcp
        .iter()
        .map(v4)
        .collect::<Result<Vec<_>>>()?;
    let mut peered = Vec::with_capacity(allow.peered.len());
    for (iface, proto, ep) in allow.peered {
        // Unlike a whole tunnel, a peered destination is the point of the
        // rule: an interface that is not up is an error, not a skip.
        peered.push((luid_of(iface)?, *proto, v4(ep)?));
    }
    // Every tunnel interface that is up, allowed whole or towards one
    // destination, for the inbound blocks. One that is not up yet has
    // nothing coming in on it.
    let mut tunnel_luids: Vec<u64> = Vec::new();
    for luid in allow
        .tunnels
        .iter()
        .filter_map(|t| luid_of(t).ok())
        .chain(peered.iter().map(|(l, _, _)| *l))
    {
        if !tunnel_luids.contains(&luid) {
            tunnel_luids.push(luid);
        }
    }
    let inbound = inbound(allow.lan, &tunnel_luids)?;

    let engine = open_engine()?;
    let result = (|| -> Result<()> {
        ok(unsafe { FwpmTransactionBegin0(engine, 0) })?;

        // The old filters go in the same transaction the new ones come in,
        // as Linux replaces its table: there is no moment with none, and a
        // failure below aborts the whole of it, leaving the old ones in
        // place (blocked, never open). "Not found" is fine.
        for key in ALL_FILTER_KEYS.iter() {
            let _ = unsafe { FwpmFilterDeleteByKey0(engine, key) };
        }

        // Provider.
        let mut prov_name = wide("HidraVPN");
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display(&mut prov_name),
            // Not persistent: these objects survive the service dying (so a
            // dropped tunnel stays blocked), but are cleared on reboot, so a
            // crash-then-reboot restores connectivity instead of bricking the
            // machine. This matches the Linux nftables table, which is kernel
            // state that a reboot also clears.
            flags: 0,
            ..Default::default()
        };
        // Already-exists is fine.
        let _ = unsafe { FwpmProviderAdd0(engine, &provider, None) };

        // Sublayer, top weight so our decision wins arbitration.
        let mut sub_name = wide("HidraVPN kill switch");
        let mut provider_key = PROVIDER_KEY;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            displayData: display(&mut sub_name),
            flags: 0,
            providerKey: &mut provider_key,
            weight: 0xFFFF,
            ..Default::default()
        };
        let _ = unsafe { FwpmSubLayerAdd0(engine, &sublayer, None) };

        // The catch-all blocks: lowest weight, no conditions, at both layers.
        add_filter(
            engine,
            &Filter {
                key: F_BLOCK_V4,
                name: "block all IPv4",
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                weight: 0,
                block: true,
                conditions: &[],
            },
        )?;
        add_filter(
            engine,
            &Filter {
                key: F_BLOCK_V6,
                name: "block all IPv6",
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                weight: 0,
                block: true,
                conditions: &[],
            },
        )?;

        // Loopback stays open, both families.
        add_filter(
            engine,
            &Filter {
                key: F_LOOPBACK_V4,
                name: "allow loopback IPv4",
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                weight: 12,
                block: false,
                conditions: &[Cond::LoopbackFlag],
            },
        )?;
        add_filter(
            engine,
            &Filter {
                key: F_LOOPBACK_V6,
                name: "allow loopback IPv6",
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                weight: 12,
                block: false,
                conditions: &[Cond::LoopbackFlag],
            },
        )?;

        // Everything on the tunnel interfaces — but only those already up.
        // When the kill switch is armed on its own (diagnostics) there is no
        // tunnel yet, so there is nothing to allow; in the normal flow the
        // interface exists by the time we get here. Linux is the same: its
        // rule matches by name and simply catches nothing until the interface
        // appears. The inner tunnel of a two-hop circuit sends into the outer
        // tunnel, never to the physical link.
        for (i, iface) in allow.tunnels.iter().enumerate() {
            let (key, name) = if i == 0 {
                (F_TUNNEL_V4, "allow the tunnel interface")
            } else {
                (F_TUNNEL2_V4, "allow the inner tunnel interface")
            };
            match luid_of(iface) {
                Ok(luid) => add_filter(
                    engine,
                    &Filter {
                        key,
                        name,
                        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        weight: 10,
                        block: false,
                        conditions: &[Cond::LocalInterface(luid)],
                    },
                )?,
                Err(e) => {
                    tracing::warn!(
                        "tunnel interface {iface} not up yet; its allow rule is skipped ({e})"
                    );
                }
            }
        }

        // IPv6 on the tunnel that carries the traffic, when the exit carries
        // it. Unlike the IPv4 rule this one is not skipped: the interface
        // exists by the time a circuit arms the kill switch.
        if let Some(iface) = allow.tunnel_v6 {
            add_filter(
                engine,
                &Filter {
                    key: F_TUNNEL_V6,
                    name: "allow IPv6 on the tunnel interface",
                    layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    weight: 10,
                    block: false,
                    conditions: &[Cond::LocalInterface(luid_of(iface)?)],
                },
            )?;
        }

        // The encrypted WireGuard packets to the node(s).
        for (i, (addr, port)) in nodes.iter().enumerate() {
            add_filter(
                engine,
                &Filter {
                    key: F_NODE_V4[i],
                    name: "allow WireGuard to the node",
                    layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    weight: 11,
                    block: false,
                    conditions: &[
                        Cond::Protocol(IPPROTO_UDP),
                        Cond::RemoteAddrV4(*addr),
                        Cond::RemotePort(*port),
                    ],
                },
            )?;
        }

        // One destination through a tunnel interface: the outer tunnel of
        // two hops carries the inner one to the exit and nothing else, so
        // the entry never receives a packet whose destination it could read.
        for (i, (luid, proto, (addr, port))) in peered.iter().enumerate() {
            add_filter(
                engine,
                &Filter {
                    key: F_PEERED_V4[i],
                    name: "allow one destination through the tunnel",
                    layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    weight: 10,
                    block: false,
                    conditions: &[
                        Cond::LocalInterface(*luid),
                        Cond::Protocol(*proto),
                        Cond::RemoteAddrV4(*addr),
                        Cond::RemotePort(*port),
                    ],
                },
            )?;
        }

        // A first hop's admission port, while a circuit is replaced.
        for (i, (addr, port)) in direct_tcp.iter().enumerate() {
            add_filter(
                engine,
                &Filter {
                    key: F_DIRECT_TCP_V4[i],
                    name: "allow an admission request to the node",
                    layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    weight: 11,
                    block: false,
                    conditions: &[
                        Cond::Protocol(IPPROTO_TCP),
                        Cond::RemoteAddrV4(*addr),
                        Cond::RemotePort(*port),
                    ],
                },
            )?;
        }

        // "Allow LAN": the private ranges off-tunnel, at a weight below
        // every tunnel and node permit; and above it, a block of DNS to
        // those ranges, so a router's resolver is never asked. DNS inside
        // the tunnel is permitted earlier, by its interface.
        if allow.lan {
            for (i, (addr, mask)) in LAN_V4.iter().enumerate() {
                add_filter(
                    engine,
                    &Filter {
                        key: F_LAN_DNS_V4[i],
                        name: "no DNS to the local network",
                        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        weight: 9,
                        block: true,
                        conditions: &[Cond::RemoteSubnetV4(*addr, *mask), Cond::RemotePort(53)],
                    },
                )?;
                add_filter(
                    engine,
                    &Filter {
                        key: F_LAN_V4[i],
                        name: "allow the local network",
                        layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        weight: 8,
                        block: false,
                        conditions: &[Cond::RemoteSubnetV4(*addr, *mask)],
                    },
                )?;
            }
        }

        // DHCP so the physical link can keep its address: from the client
        // port to the server port, broadcast only, as the official client
        // allows it. Any UDP to port 67 would have let a program reach a
        // host of its choosing off the tunnel, from the machine's own
        // address; a broadcast stays on the local link.
        add_filter(
            engine,
            &Filter {
                key: F_DHCP_V4,
                name: "allow DHCP",
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                weight: 10,
                block: false,
                conditions: &[
                    Cond::Protocol(IPPROTO_UDP),
                    Cond::LocalPort(68),
                    Cond::RemotePort(67),
                    Cond::RemoteAddrV4(u32::MAX),
                ],
            },
        )?;

        // Connections from outside, at the receive-accept layers.
        for f in &inbound {
            add_filter(
                engine,
                &Filter {
                    key: f.key,
                    name: f.name,
                    layer: f.layer,
                    weight: f.weight,
                    block: f.block,
                    conditions: &f.conditions,
                },
            )?;
        }

        ok(unsafe { FwpmTransactionCommit0(engine) })?;
        Ok(())
    })();

    if result.is_err() {
        let _ = unsafe { FwpmTransactionAbort0(engine) };
    }
    let _ = unsafe { FwpmEngineClose0(engine) };
    result
}

/// A filter for the receive-accept layers, built before the transaction.
struct InFilter {
    key: GUID,
    name: &'static str,
    layer: GUID,
    weight: u8,
    block: bool,
    conditions: Vec<Cond>,
}

/// The receive-accept filters. Replies to what this machine sent belong to
/// the flow its connect opened, and pass; an unsolicited connection, or a
/// datagram from a host this machine never sent to, reaches a listening
/// program only from loopback, as a DHCP answer, or from the local network
/// when "Allow LAN" is on — and never through a tunnel: the node at its
/// other end chooses what comes out of it, its addresses included (the
/// node's own tunnel address is a private one, inside what "Allow LAN"
/// opens), and would otherwise reach every program listening here and
/// learn the machine from what answers. So each tunnel interface has a
/// block above the DHCP and "Allow LAN" permits, below loopback; the
/// physical link has the catch-all. Above each tunnel's block, the ICMP
/// errors path MTU discovery needs (`TUNNEL_ICMP_ERRORS`), as Linux lets
/// in related ICMP: before the block they came in with the rest of the
/// tunnel, and without them a path narrower than the tunnel would stall
/// large transfers. What these block, Windows Firewall cannot let in,
/// whatever profile Windows gave an adapter.
fn inbound(lan: bool, tunnels: &[u64]) -> Result<Vec<InFilter>> {
    if tunnels.len() > F_IN_TUNNEL_V4.len() || tunnels.len() > F_IN_TUNNEL_ICMP.len() {
        bail!("the kill switch was given more tunnel interfaces than it has rules for");
    }
    let mut v = Vec::new();
    for (key, layer, name) in [
        (
            F_IN_BLOCK_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            "block all inbound IPv4",
        ),
        (
            F_IN_BLOCK_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "block all inbound IPv6",
        ),
    ] {
        v.push(InFilter {
            key,
            name,
            layer,
            weight: 0,
            block: true,
            conditions: Vec::new(),
        });
    }
    for (key, layer, name) in [
        (
            F_IN_LOOPBACK_V4,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            "allow inbound loopback IPv4",
        ),
        (
            F_IN_LOOPBACK_V6,
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            "allow inbound loopback IPv6",
        ),
    ] {
        v.push(InFilter {
            key,
            name,
            layer,
            weight: 12,
            block: false,
            conditions: vec![Cond::LoopbackFlag],
        });
    }
    for (i, luid) in tunnels.iter().enumerate() {
        v.push(InFilter {
            key: F_IN_TUNNEL_V4[i],
            name: "nothing in through the tunnel unasked",
            layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            weight: 11,
            block: true,
            conditions: vec![Cond::LocalInterface(*luid)],
        });
        // WFP carries an ICMP message's type in the local port field (the
        // SDK's FWPM_CONDITION_ICMP_TYPE is that field under another name).
        // Weight 12 is loopback's too; a packet on a tunnel interface is
        // never loopback, so the two never both match.
        for (key, (layer, proto, kind, name)) in F_IN_TUNNEL_ICMP[i].iter().zip(TUNNEL_ICMP_ERRORS)
        {
            v.push(InFilter {
                key: *key,
                name,
                layer,
                weight: 12,
                block: false,
                conditions: vec![
                    Cond::LocalInterface(*luid),
                    Cond::Protocol(proto),
                    Cond::LocalPort(kind),
                ],
            });
        }
    }
    // The DHCP server answers from its own address, not the broadcast the
    // request went to, so its answer is a new remote: from the server port
    // to the client port, and nothing else.
    v.push(InFilter {
        key: F_IN_DHCP_V4,
        name: "allow DHCP answers",
        layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        weight: 10,
        block: false,
        conditions: vec![
            Cond::Protocol(IPPROTO_UDP),
            Cond::LocalPort(68),
            Cond::RemotePort(67),
        ],
    });
    if lan {
        for (i, (addr, mask)) in LAN_V4.iter().enumerate() {
            v.push(InFilter {
                key: F_IN_LAN_V4[i],
                name: "allow the local network inbound",
                layer: FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                weight: 8,
                block: false,
                conditions: vec![Cond::RemoteSubnetV4(*addr, *mask)],
            });
        }
    }
    Ok(v)
}

pub fn apply(cfg: &KillConfig) -> Result<()> {
    // Two hops: the inner tunnel is allowed whole, the outer one only
    // towards the exit. One hop: the one tunnel, whole.
    let (tunnels, peered): (Vec<&str>, Vec<(&str, u8, SocketAddr)>) =
        match (&cfg.extra_interface, cfg.outer_peer) {
            (Some(inner), Some(exit)) => (
                vec![inner.as_str()],
                vec![(cfg.interface.as_str(), IPPROTO_UDP, exit)],
            ),
            (Some(inner), None) => (vec![cfg.interface.as_str(), inner.as_str()], Vec::new()),
            (None, _) => (vec![cfg.interface.as_str()], Vec::new()),
        };
    // The tunnel that carries the traffic: the inner one of two hops.
    let carrying = cfg.extra_interface.as_deref().unwrap_or(&cfg.interface);
    install(&Allow {
        tunnels: &tunnels,
        nodes: &[cfg.node_endpoint],
        peered: &peered,
        direct_tcp: &[],
        lan: cfg.allow_lan,
        tunnel_v6: cfg.tunnel_ipv6.map(|_| carrying),
    })
}

/// The hold, plus the admission requests a connection needs: TCP to a
/// first hop's admission port off-tunnel, and to an exit's through the
/// outer tunnel.
pub fn hold_admitting(
    endpoints: &[SocketAddr],
    direct: &[SocketAddr],
    bridge: Option<&Bridge>,
) -> Result<()> {
    if endpoints.is_empty() {
        bail!("a hold needs at least one node endpoint to allow");
    }
    let peered: Vec<(&str, u8, SocketAddr)> = bridge
        .map(|b| (b.interface.as_str(), IPPROTO_TCP, b.to))
        .into_iter()
        .collect();
    install(&Allow {
        tunnels: &[],
        nodes: endpoints,
        peered: &peered,
        direct_tcp: direct,
        lan: false,
        tunnel_v6: None,
    })
}

/// The hold across a rotation: the given nodes and nothing else, no tunnel
/// interface, because there is none to trust yet.
pub fn hold(endpoints: &[SocketAddr]) -> Result<()> {
    if endpoints.is_empty() {
        bail!("a hold needs at least one node endpoint to allow");
    }
    install(&Allow {
        tunnels: &[],
        nodes: endpoints,
        peered: &[],
        direct_tcp: &[],
        lan: false,
        tunnel_v6: None,
    })
}

pub fn remove() -> Result<()> {
    let engine = open_engine()?;
    let r = (|| -> Result<()> {
        ok(unsafe { FwpmTransactionBegin0(engine, 0) })?;
        for key in ALL_FILTER_KEYS.iter() {
            // Ignore "not found"; we delete whatever is there.
            let _ = unsafe { FwpmFilterDeleteByKey0(engine, key) };
        }
        let _ = unsafe { FwpmSubLayerDeleteByKey0(engine, &SUBLAYER_KEY) };
        let _ = unsafe { FwpmProviderDeleteByKey0(engine, &PROVIDER_KEY) };
        ok(unsafe { FwpmTransactionCommit0(engine) })?;
        Ok(())
    })();
    if r.is_err() {
        let _ = unsafe { FwpmTransactionAbort0(engine) };
    }
    let _ = unsafe { FwpmEngineClose0(engine) };
    r
}

pub fn is_active() -> bool {
    // The sublayer exists only while the kill switch is on: looking it up is
    // enough.
    match open_engine() {
        Ok(engine) => {
            let mut present = false;
            // The sublayer is there exactly while the kill switch is.
            use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerGetByKey0;
            let mut out = std::ptr::null_mut();
            let code = unsafe { FwpmSubLayerGetByKey0(engine, &SUBLAYER_KEY, &mut out) };
            if code == ERROR_SUCCESS.0 {
                present = true;
                if !out.is_null() {
                    use windows::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFreeMemory0;
                    unsafe { FwpmFreeMemory0(&mut (out as *mut core::ffi::c_void)) };
                }
            }
            let _ = unsafe { FwpmEngineClose0(engine) };
            present
        }
        Err(_) => false,
    }
}

// ---- filter building ------------------------------------------------------

enum Cond {
    LoopbackFlag,
    LocalInterface(u64),
    Protocol(u8),
    RemoteAddrV4(u32),
    RemotePort(u16),
    LocalPort(u16),
    /// An address and a mask, host order.
    RemoteSubnetV4(u32, u32),
}

struct Filter<'a> {
    key: GUID,
    name: &'a str,
    layer: GUID,
    weight: u8,
    block: bool,
    conditions: &'a [Cond],
}

fn add_filter(engine: HANDLE, f: &Filter) -> Result<()> {
    // Backing storage that must outlive the FwpmFilterAdd0 call. Its
    // capacity is set once, so the pointers into it stay where they are.
    let mut luid_store: u64 = 0;
    let mut masks: Vec<FWP_V4_ADDR_AND_MASK> = Vec::with_capacity(f.conditions.len());
    let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(f.conditions.len());
    for c in f.conditions {
        conds.push(build_condition(c, &mut luid_store, &mut masks));
    }

    let mut name = wide(f.name);
    let action = FWPM_ACTION0 {
        r#type: if f.block {
            FWP_ACTION_BLOCK
        } else {
            FWP_ACTION_PERMIT
        },
        Anonymous: FWPM_ACTION0_0 {
            filterType: GUID::default(),
        },
    };
    let filter = FWPM_FILTER0 {
        filterKey: f.key,
        displayData: display(&mut name),
        flags: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAGS(0),
        layerKey: f.layer,
        subLayerKey: SUBLAYER_KEY,
        weight: weight_u8(f.weight),
        numFilterConditions: conds.len() as u32,
        filterCondition: if conds.is_empty() {
            std::ptr::null_mut()
        } else {
            conds.as_mut_ptr()
        },
        action,
        ..Default::default()
    };
    ok(unsafe { FwpmFilterAdd0(engine, &filter, None, None) })
}

fn build_condition(
    c: &Cond,
    luid_store: &mut u64,
    masks: &mut Vec<FWP_V4_ADDR_AND_MASK>,
) -> FWPM_FILTER_CONDITION0 {
    match c {
        Cond::LoopbackFlag => FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                },
            },
        },
        Cond::LocalInterface(luid) => {
            *luid_store = *luid;
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        uint64: luid_store as *mut u64,
                    },
                },
            }
        }
        Cond::Protocol(p) => FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *p },
            },
        },
        Cond::RemoteAddrV4(a) => FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: *a },
            },
        },
        Cond::RemotePort(p) => FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *p },
            },
        },
        Cond::RemoteSubnetV4(addr, mask) => {
            debug_assert!(masks.len() < masks.capacity(), "pointers must not move");
            masks.push(FWP_V4_ADDR_AND_MASK {
                addr: *addr,
                mask: *mask,
            });
            let last = masks.last_mut().expect("just pushed") as *mut FWP_V4_ADDR_AND_MASK;
            FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_V4_ADDR_MASK,
                    Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: last },
                },
            }
        }
        Cond::LocalPort(p) => FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_PORT,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *p },
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_retired_tunnel_permits_are_still_removed() {
        // A kill switch an older version armed let the node in through the
        // tunnel; arming this one, or turning it off, deletes those too.
        for k in F_IN_TUNNEL_V4.iter().chain([&F_IN_TUNNEL_V6]) {
            assert!(ALL_FILTER_KEYS.contains(k));
        }
    }

    const TUN: u64 = 0x11;
    const OUTER: u64 = 0x12;
    const PHYS: u64 = 0x13;

    /// A connection or datagram at the receive-accept layer, IPv4 unless
    /// `v6`. For ICMP, WFP puts the type in the local port and the code in
    /// the remote one.
    struct In {
        luid: u64,
        loopback: bool,
        proto: u8,
        remote: [u8; 4],
        rport: u16,
        lport: u16,
        v6: bool,
    }

    fn from(luid: u64, remote: [u8; 4], proto: u8, rport: u16, lport: u16) -> In {
        In {
            luid,
            loopback: false,
            proto,
            remote,
            rport,
            lport,
            v6: false,
        }
    }

    /// An ICMP message of this type and code from the node's tunnel address,
    /// ICMPv6 if `v6`.
    fn icmp(luid: u64, v6: bool, kind: u16, code: u16) -> In {
        let proto = if v6 { IPPROTO_ICMPV6 } else { IPPROTO_ICMP };
        In {
            v6,
            ..from(luid, [10, 77, 0, 1], proto, code, kind)
        }
    }

    /// What the sublayer decides, as WFP arbitrates inside one: the
    /// matching filter of the highest weight. Two of the same weight that
    /// both match would leave the order to WFP; none may.
    fn permitted(filters: &[InFilter], p: &In) -> bool {
        let remote = u32::from_be_bytes(p.remote);
        let layer = if p.v6 {
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
        } else {
            FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
        };
        let matching: Vec<&InFilter> = filters
            .iter()
            .filter(|f| f.layer == layer)
            .filter(|f| {
                f.conditions.iter().all(|c| match c {
                    Cond::LoopbackFlag => p.loopback,
                    Cond::LocalInterface(l) => p.luid == *l,
                    Cond::Protocol(x) => p.proto == *x,
                    Cond::RemoteAddrV4(a) => remote == *a,
                    Cond::RemotePort(x) => p.rport == *x,
                    Cond::LocalPort(x) => p.lport == *x,
                    Cond::RemoteSubnetV4(a, m) => remote & m == *a,
                })
            })
            .collect();
        let top = matching
            .iter()
            .map(|f| f.weight)
            .max()
            .expect("a catch-all");
        let at_top: Vec<_> = matching.iter().filter(|f| f.weight == top).collect();
        assert_eq!(at_top.len(), 1, "two filters of weight {top} match");
        !at_top[0].block
    }

    #[test]
    fn nothing_comes_in_through_a_tunnel_unasked_allow_lan_or_not() {
        for lan in [false, true] {
            let f = inbound(lan, &[TUN]).unwrap();
            // The node, at its tunnel address (a private one, inside what
            // "Allow LAN" opens), or at any other address it puts on a
            // packet: a listener, a DHCP client's port.
            for p in [
                from(TUN, [10, 77, 0, 1], IPPROTO_UDP, 40000, 9902),
                from(TUN, [10, 77, 0, 1], IPPROTO_TCP, 40000, 445),
                from(TUN, [192, 168, 1, 1], IPPROTO_UDP, 137, 137),
                from(TUN, [203, 0, 113, 10], IPPROTO_UDP, 51820, 9902),
                from(TUN, [10, 77, 0, 1], IPPROTO_UDP, 67, 68),
            ] {
                assert!(!permitted(&f, &p), "lan={lan}: {:?}", p.remote);
            }
            // Off the tunnel: the local network only with "Allow LAN",
            // DHCP answers always, the internet never.
            assert_eq!(
                permitted(&f, &from(PHYS, [192, 168, 1, 5], IPPROTO_TCP, 50000, 445)),
                lan
            );
            assert!(permitted(
                &f,
                &from(PHYS, [192, 168, 1, 1], IPPROTO_UDP, 67, 68)
            ));
            assert!(!permitted(
                &f,
                &from(PHYS, [198, 51, 100, 7], IPPROTO_TCP, 50000, 445)
            ));
            let mut lo = from(0x1, [127, 0, 0, 1], IPPROTO_TCP, 50000, 8080);
            lo.loopback = true;
            assert!(permitted(&f, &lo));
        }
    }

    #[test]
    fn both_tunnels_of_two_hops_are_closed_inbound() {
        let f = inbound(true, &[TUN, OUTER]).unwrap();
        for luid in [TUN, OUTER] {
            assert!(!permitted(
                &f,
                &from(luid, [10, 77, 0, 1], IPPROTO_UDP, 40000, 9902)
            ));
        }
        assert!(permitted(
            &f,
            &from(PHYS, [10, 1, 2, 3], IPPROTO_UDP, 40000, 9902)
        ));
        assert!(inbound(true, &[TUN, OUTER, PHYS]).is_err());
    }

    #[test]
    fn the_icmp_errors_path_mtu_discovery_needs_come_in_through_the_tunnels_and_nothing_else() {
        for lan in [false, true] {
            let f = inbound(lan, &[TUN, OUTER]).unwrap();
            for luid in [TUN, OUTER] {
                // Fragmentation needed, and the rest of destination
                // unreachable; IPv6's packet too big and destination
                // unreachable.
                assert!(permitted(&f, &icmp(luid, false, 3, 4)), "lan={lan}");
                assert!(permitted(&f, &icmp(luid, false, 3, 1)), "lan={lan}");
                assert!(permitted(&f, &icmp(luid, true, 2, 0)), "lan={lan}");
                assert!(permitted(&f, &icmp(luid, true, 1, 4)), "lan={lan}");
                // Not an echo request, a redirect, a timestamp request,
                // an IPv6 echo request or a router advertisement.
                for kind in [8, 5, 13] {
                    assert!(!permitted(&f, &icmp(luid, false, kind, 0)), "{kind}");
                }
                for kind in [128, 134] {
                    assert!(!permitted(&f, &icmp(luid, true, kind, 0)), "{kind}");
                }
                // Nor anything else that has those numbers in its ports.
                assert!(!permitted(
                    &f,
                    &from(luid, [10, 77, 0, 1], IPPROTO_UDP, 4, 3)
                ));
                let mut udp6 = from(luid, [10, 77, 0, 1], IPPROTO_UDP, 0, 2);
                udp6.v6 = true;
                assert!(!permitted(&f, &udp6));
            }
            // Off the tunnels nothing changes: from the internet the
            // catch-all decides, as before.
            for v6 in [false, true] {
                let mut far = icmp(PHYS, v6, if v6 { 2 } else { 3 }, 4);
                far.remote = [198, 51, 100, 7];
                assert!(!permitted(&f, &far), "lan={lan} v6={v6}");
            }
        }
        // No tunnel, no ICMP permit: a hold lets none in.
        let held = inbound(false, &[]).unwrap();
        assert!(held.iter().all(|x| !x
            .conditions
            .iter()
            .any(|c| matches!(c, Cond::Protocol(IPPROTO_ICMP | IPPROTO_ICMPV6)))));
        assert!(!permitted(&held, &icmp(TUN, false, 3, 4)));
    }

    #[test]
    fn every_filter_has_its_own_key_and_is_removed_with_the_rest() {
        let mut keys: Vec<u128> = ALL_FILTER_KEYS.iter().map(|g| g.to_u128()).collect();
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), ALL_FILTER_KEYS.len(), "two filters share a key");
        assert!(ALL_FILTER_KEYS.contains(&F_TUNNEL_V6));
        for k in [
            F_IN_BLOCK_V4,
            F_IN_BLOCK_V6,
            F_IN_LOOPBACK_V4,
            F_IN_LOOPBACK_V6,
            F_IN_DHCP_V4,
        ]
        .iter()
        .chain(F_IN_LAN_V4.iter())
        .chain(F_IN_TUNNEL_ICMP.iter().flatten())
        {
            assert!(
                ALL_FILTER_KEYS.contains(k),
                "an inbound filter is not removed with the rest"
            );
        }
    }
}
