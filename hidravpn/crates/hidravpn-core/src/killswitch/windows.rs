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
//! connect-authorisation layers the default is to BLOCK; a handful of higher-
//! weight PERMIT filters open just what must stay open: loopback, the tunnel
//! interface, the encrypted packets to the node, and DHCP. IPv6 has only the
//! loopback exception, so it cannot leave the machine at all. DNS to anything
//! but the node is not permitted, so it is blocked with everything else.

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
    FWPM_CONDITION_FLAGS, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0, FWPM_SUBLAYER0, FWP_ACTION_BLOCK,
    FWP_ACTION_PERMIT, FWP_CONDITION_FLAG_IS_LOOPBACK,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_MATCH_FLAGS_ALL_SET,
    FWP_VALUE0, FWP_VALUE0_0,
};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_UINT16, FWP_UINT32, FWP_UINT64, FWP_UINT8,
};
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

use super::{Bridge, KillConfig};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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

const ALL_FILTER_KEYS: [GUID; 15] = [
    F_BLOCK_V4,
    F_BLOCK_V6,
    F_LOOPBACK_V4,
    F_LOOPBACK_V6,
    F_TUNNEL_V4,
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

        // DHCP so the physical link can keep its address.
        add_filter(
            engine,
            &Filter {
                key: F_DHCP_V4,
                name: "allow DHCP",
                layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                weight: 10,
                block: false,
                conditions: &[Cond::Protocol(IPPROTO_UDP), Cond::RemotePort(67)],
            },
        )?;

        ok(unsafe { FwpmTransactionCommit0(engine) })?;
        Ok(())
    })();

    if result.is_err() {
        let _ = unsafe { FwpmTransactionAbort0(engine) };
    }
    let _ = unsafe { FwpmEngineClose0(engine) };
    result
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
    install(&Allow {
        tunnels: &tunnels,
        nodes: &[cfg.node_endpoint],
        peered: &peered,
        direct_tcp: &[],
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
    // The sublayer exists only while the kill switch is on. Opening the engine
    // and trying to read it is enough; we keep it simple and just report
    // whether the engine opens and our block filter can be looked up.
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
    // Backing storage that must outlive the FwpmFilterAdd0 call.
    let mut luid_store: u64 = 0;
    let mut conds: Vec<FWPM_FILTER_CONDITION0> = Vec::with_capacity(f.conditions.len());
    for c in f.conditions {
        conds.push(build_condition(c, &mut luid_store));
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

fn build_condition(c: &Cond, luid_store: &mut u64) -> FWPM_FILTER_CONDITION0 {
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
    }
}
