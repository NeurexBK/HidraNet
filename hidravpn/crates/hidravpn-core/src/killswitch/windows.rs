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

use std::net::IpAddr;

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

use super::KillConfig;

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
const F_NODE_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0004_0001);
const F_DHCP_V4: GUID = GUID::from_u128(0x4849_4452_4156_504e_0000_0000_0005_0001);

const ALL_FILTER_KEYS: [GUID; 7] = [
    F_BLOCK_V4,
    F_BLOCK_V6,
    F_LOOPBACK_V4,
    F_LOOPBACK_V6,
    F_TUNNEL_V4,
    F_NODE_V4,
    F_DHCP_V4,
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
    let code = unsafe {
        FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            None,
            &mut engine,
        )
    };
    ok(code)?;
    Ok(engine)
}

fn luid_of(interface: &str) -> Result<u64> {
    let w = wide(interface);
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceAliasToLuid(PCWSTR(w.as_ptr()), &mut luid) };
    if code.0 != ERROR_SUCCESS.0 {
        bail!("the tunnel interface \"{interface}\" was not found (code {})", code.0);
    }
    // NET_LUID_LH is a union over a u64.
    Ok(unsafe { luid.Value })
}

pub fn apply(cfg: &KillConfig) -> Result<()> {
    // Start clean so a half-applied earlier run cannot leave stray filters.
    let _ = remove();

    let node_ip = match cfg.node_endpoint.ip() {
        IpAddr::V4(a) => a,
        IpAddr::V6(_) => bail!("the kill switch needs an IPv4 node endpoint in this phase"),
    };
    let node_addr_be = u32::from(node_ip); // host order; WFP wants host order for UINT32
    let port = cfg.node_endpoint.port();

    let engine = open_engine()?;
    let result = (|| -> Result<()> {
        ok(unsafe { FwpmTransactionBegin0(engine, 0) })?;

        // Provider.
        let mut prov_name = wide("HidraVPN");
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            displayData: display(&mut prov_name),
            flags: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER_FLAG_PERSISTENT,
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
            flags: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            weight: 0xFFFF,
            ..Default::default()
        };
        let _ = unsafe { FwpmSubLayerAdd0(engine, &sublayer, None) };

        // The catch-all blocks: lowest weight, no conditions, at both layers.
        add_filter(engine, &Filter {
            key: F_BLOCK_V4,
            name: "block all IPv4",
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            weight: 0,
            block: true,
            conditions: &[],
        })?;
        add_filter(engine, &Filter {
            key: F_BLOCK_V6,
            name: "block all IPv6",
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            weight: 0,
            block: true,
            conditions: &[],
        })?;

        // Loopback stays open, both families.
        add_filter(engine, &Filter {
            key: F_LOOPBACK_V4,
            name: "allow loopback IPv4",
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            weight: 12,
            block: false,
            conditions: &[Cond::LoopbackFlag],
        })?;
        add_filter(engine, &Filter {
            key: F_LOOPBACK_V6,
            name: "allow loopback IPv6",
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            weight: 12,
            block: false,
            conditions: &[Cond::LoopbackFlag],
        })?;

        // Everything on the tunnel interface — but only if it is already up.
        // When the kill switch is armed on its own (diagnostics) there is no
        // tunnel yet, so there is nothing to allow; in the normal flow the
        // interface exists by the time we get here. Linux is the same: its
        // rule matches by name and simply catches nothing until the interface
        // appears.
        match luid_of(&cfg.interface) {
            Ok(luid) => {
                add_filter(engine, &Filter {
                    key: F_TUNNEL_V4,
                    name: "allow the tunnel interface",
                    layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    weight: 10,
                    block: false,
                    conditions: &[Cond::LocalInterface(luid)],
                })?;
            }
            Err(e) => {
                tracing::warn!("tunnel interface not up yet; its allow rule is skipped ({e})");
            }
        }

        // The encrypted WireGuard packets to the node.
        add_filter(engine, &Filter {
            key: F_NODE_V4,
            name: "allow WireGuard to the node",
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            weight: 11,
            block: false,
            conditions: &[
                Cond::Protocol(IPPROTO_UDP),
                Cond::RemoteAddrV4(node_addr_be),
                Cond::RemotePort(port),
            ],
        })?;

        // DHCP so the physical link can keep its address.
        add_filter(engine, &Filter {
            key: F_DHCP_V4,
            name: "allow DHCP",
            layer: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            weight: 10,
            block: false,
            conditions: &[Cond::Protocol(IPPROTO_UDP), Cond::RemotePort(67)],
        })?;

        ok(unsafe { FwpmTransactionCommit0(engine) })?;
        Ok(())
    })();

    if result.is_err() {
        let _ = unsafe { FwpmTransactionAbort0(engine) };
    }
    let _ = unsafe { FwpmEngineClose0(engine) };
    result
}

pub fn remove() -> Result<()> {
    let engine = match open_engine() {
        Ok(e) => e,
        Err(e) => return Err(e),
    };
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
            // A cheap existence check: try to delete-by-key inside an aborted
            // transaction would change state, so instead re-add is wrong too.
            // Use the sublayer getter.
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
        r#type: if f.block { FWP_ACTION_BLOCK } else { FWP_ACTION_PERMIT },
        Anonymous: FWPM_ACTION0_0 {
            filterType: GUID::default(),
        },
    };
    let filter = FWPM_FILTER0 {
        filterKey: f.key,
        displayData: display(&mut name),
        flags: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_PERSISTENT,
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
