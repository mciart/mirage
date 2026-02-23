use crate::Result;
use std::net::IpAddr;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::Mutex;
use tracing::{debug, info, warn};

/// Windows process creation flag to suppress console window.
const CREATE_NO_WINDOW: u32 = 0x08000000;
use wintun_bindings::Adapter;

/// Hold the WFP DNS lock alive for the duration of the VPN session.
static WFP_DNS_LOCK: Mutex<Option<WfpDnsLock>> = Mutex::new(None);

/// Sets DNS servers on the TUN adapter and activates WFP DNS lock.
///
/// DNS leak prevention via WFP kernel filters:
/// - Permits DNS (port 53) to VPN DNS servers only
/// - Blocks DNS (port 53) to all other servers
/// - Both IPv4 and IPv6
/// - Dynamic session — auto-cleaned by OS on crash
pub fn add_dns_servers(dns_servers: &[IpAddr], interface_name: &str) -> Result<()> {
    // Step 1: Set DNS on TUN adapter (native WinTun API)
    let wintun = unsafe {
        wintun_bindings::load().map_err(|e| crate::error::DnsError::PlatformError {
            message: format!("failed to load WinTun library: {e}"),
        })?
    };

    let adapter = Adapter::open(&wintun, interface_name).map_err(|e| {
        crate::error::DnsError::PlatformError {
            message: format!("failed to open adapter: {e}"),
        }
    })?;
    adapter
        .set_dns_servers(dns_servers)
        .map_err(|_e| crate::error::DnsError::ConfigurationFailed)?;

    let dns_list: String = dns_servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    info!("DNS servers set on TUN adapter: [{}]", dns_list);

    // Step 2: WFP DNS lock — block DNS to non-VPN servers (IPv4 + IPv6)
    match WfpDnsLock::create(dns_servers) {
        Ok(lock) => {
            *WFP_DNS_LOCK.lock().unwrap() = Some(lock);
        }
        Err(e) => {
            warn!("WFP DNS lock failed: {}", e);
        }
    }

    // Step 3: Flush DNS cache
    flush_dns_cache();

    Ok(())
}

/// Cleans up DNS settings and releases WFP DNS lock.
pub fn delete_dns_servers() -> Result<()> {
    // Release WFP DNS lock (if any)
    if let Some(lock) = WFP_DNS_LOCK.lock().unwrap().take() {
        lock.destroy();
    }

    flush_dns_cache();
    info!("DNS cleanup complete");
    Ok(())
}

/// Flushes the Windows DNS resolver cache and re-registers DNS.
fn flush_dns_cache() {
    let _ = Command::new("ipconfig")
        .arg("/flushdns")
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = Command::new("ipconfig")
        .arg("/registerdns")
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    debug!("DNS cache flushed and re-registered");
}

// ─── WFP DNS Lock ────────────────────────────────────────────────────
//
// Blocks DNS (port 53) to non-VPN servers on IPv4 + IPv6.
// Uses dynamic WFP session — auto-cleaned by OS on process exit / crash.

use windows::core::GUID;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;

// Raw FFI — windows crate 0.52 missing wrapper
#[link(name = "fwpuclnt")]
extern "system" {
    fn FwpmEngineOpen0(
        serverName: *const u16,
        authnService: u32,
        authIdentity: *const std::ffi::c_void,
        session: *const FWPM_SESSION0,
        engineHandle: *mut HANDLE,
    ) -> u32;
}

const RPC_C_AUTHN_WINNT: u32 = 10;

const MIRAGE_DNS_SUBLAYER_GUID: GUID = GUID::from_values(
    0x4d697261,
    0x6765,
    0x444e,
    [0x53, 0x4c, 0x4f, 0x43, 0x4b, 0x44, 0x4e, 0x53],
);

/// Holds an active WFP DNS lock session.
struct WfpDnsLock {
    engine: HANDLE,
}

impl WfpDnsLock {
    /// Create a WFP DNS lock that only permits DNS to the given VPN servers.
    fn create(dns_servers: &[IpAddr]) -> std::result::Result<Self, String> {
        unsafe {
            // Open WFP engine with DYNAMIC flag
            let session_opts = FWPM_SESSION0 {
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                ..Default::default()
            };
            let mut engine = HANDLE::default();
            let result = FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session_opts,
                &mut engine,
            );
            if result != 0 {
                return Err(format!("FwpmEngineOpen0 failed: 0x{:08x}", result));
            }

            // Begin transaction
            let result = FwpmTransactionBegin0(engine, 0);
            if result != 0 {
                let _ = FwpmEngineClose0(engine);
                return Err(format!("FwpmTransactionBegin0 failed: 0x{:08x}", result));
            }

            // Add sublayer
            let sublayer_name: Vec<u16> = "Mirage DNS Lock\0".encode_utf16().collect();
            let sublayer = FWPM_SUBLAYER0 {
                subLayerKey: MIRAGE_DNS_SUBLAYER_GUID,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: windows::core::PWSTR(sublayer_name.as_ptr() as *mut u16),
                    description: windows::core::PWSTR::null(),
                },
                providerKey: std::ptr::null_mut(),
                weight: 0xFFFF,
                ..Default::default()
            };
            let result = FwpmSubLayerAdd0(engine, &sublayer, None);
            if result != 0 && result != 0x80320009 {
                let _ = FwpmTransactionAbort0(engine);
                let _ = FwpmEngineClose0(engine);
                return Err(format!("FwpmSubLayerAdd0 failed: 0x{:08x}", result));
            }

            let mut fid = 0u64;
            let mut cnt = 0u32;

            let layers = [
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            ];

            for layer in layers {
                let is_v4 = layer == FWPM_LAYER_ALE_AUTH_CONNECT_V4;
                let tag = if is_v4 { "V4" } else { "V6" };

                // ─── Permit DNS to each VPN DNS server (weight=12) ───
                for dns_ip in dns_servers {
                    if is_v4 {
                        if let IpAddr::V4(v4) = dns_ip {
                            let ip = u32::from_be_bytes(v4.octets());
                            let mut addr = FWP_V4_ADDR_AND_MASK {
                                addr: ip,
                                mask: 0xFFFFFFFF,
                            };
                            let n: Vec<u16> = format!("Mirage Permit DNS {} V4\0", dns_ip)
                                .encode_utf16()
                                .collect();
                            let mut conds = [
                                FWPM_FILTER_CONDITION0 {
                                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                    matchType: FWP_MATCH_EQUAL,
                                    conditionValue: FWP_CONDITION_VALUE0 {
                                        r#type: FWP_V4_ADDR_MASK,
                                        Anonymous: FWP_CONDITION_VALUE0_0 {
                                            v4AddrMask: &mut addr,
                                        },
                                    },
                                },
                                FWPM_FILTER_CONDITION0 {
                                    fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                                    matchType: FWP_MATCH_EQUAL,
                                    conditionValue: FWP_CONDITION_VALUE0 {
                                        r#type: FWP_UINT16,
                                        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: 53 },
                                    },
                                },
                            ];
                            let f = FWPM_FILTER0 {
                                displayData: FWPM_DISPLAY_DATA0 {
                                    name: windows::core::PWSTR(n.as_ptr() as *mut u16),
                                    description: windows::core::PWSTR::null(),
                                },
                                layerKey: layer,
                                subLayerKey: MIRAGE_DNS_SUBLAYER_GUID,
                                weight: FWP_VALUE0 {
                                    r#type: FWP_UINT8,
                                    Anonymous: FWP_VALUE0_0 { uint8: 12 },
                                },
                                action: FWPM_ACTION0 {
                                    r#type: FWP_ACTION_PERMIT,
                                    ..Default::default()
                                },
                                flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                                numFilterConditions: 2,
                                filterCondition: conds.as_mut_ptr(),
                                ..Default::default()
                            };
                            if FwpmFilterAdd0(engine, &f, None, Some(&mut fid)) == 0 {
                                cnt += 1;
                            }
                        }
                    } else if let IpAddr::V6(v6) = dns_ip {
                        let mut addr = FWP_V6_ADDR_AND_MASK {
                            addr: v6.octets(),
                            prefixLength: 128,
                        };
                        let n: Vec<u16> = format!("Mirage Permit DNS {} V6\0", dns_ip)
                            .encode_utf16()
                            .collect();
                        let mut conds = [
                            FWPM_FILTER_CONDITION0 {
                                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_V6_ADDR_MASK,
                                    Anonymous: FWP_CONDITION_VALUE0_0 {
                                        v6AddrMask: &mut addr,
                                    },
                                },
                            },
                            FWPM_FILTER_CONDITION0 {
                                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                                matchType: FWP_MATCH_EQUAL,
                                conditionValue: FWP_CONDITION_VALUE0 {
                                    r#type: FWP_UINT16,
                                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: 53 },
                                },
                            },
                        ];
                        let f = FWPM_FILTER0 {
                            displayData: FWPM_DISPLAY_DATA0 {
                                name: windows::core::PWSTR(n.as_ptr() as *mut u16),
                                description: windows::core::PWSTR::null(),
                            },
                            layerKey: layer,
                            subLayerKey: MIRAGE_DNS_SUBLAYER_GUID,
                            weight: FWP_VALUE0 {
                                r#type: FWP_UINT8,
                                Anonymous: FWP_VALUE0_0 { uint8: 12 },
                            },
                            action: FWPM_ACTION0 {
                                r#type: FWP_ACTION_PERMIT,
                                ..Default::default()
                            },
                            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
                            numFilterConditions: 2,
                            filterCondition: conds.as_mut_ptr(),
                            ..Default::default()
                        };
                        if FwpmFilterAdd0(engine, &f, None, Some(&mut fid)) == 0 {
                            cnt += 1;
                        }
                    }
                }

                // ─── Block ALL other DNS (port 53) (weight=0) ───────
                let n: Vec<u16> = format!("Mirage Block DNS {}\0", tag)
                    .encode_utf16()
                    .collect();
                let mut cond = FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: FWP_MATCH_EQUAL,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_UINT16,
                        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: 53 },
                    },
                };
                let f = FWPM_FILTER0 {
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: windows::core::PWSTR(n.as_ptr() as *mut u16),
                        description: windows::core::PWSTR::null(),
                    },
                    layerKey: layer,
                    subLayerKey: MIRAGE_DNS_SUBLAYER_GUID,
                    weight: FWP_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_VALUE0_0 { uint8: 0 },
                    },
                    action: FWPM_ACTION0 {
                        r#type: FWP_ACTION_BLOCK,
                        ..Default::default()
                    },
                    numFilterConditions: 1,
                    filterCondition: &mut cond,
                    ..Default::default()
                };
                if FwpmFilterAdd0(engine, &f, None, Some(&mut fid)) == 0 {
                    cnt += 1;
                }
            }

            // Commit
            let result = FwpmTransactionCommit0(engine);
            if result != 0 {
                let _ = FwpmEngineClose0(engine);
                return Err(format!("FwpmTransactionCommit0 failed: 0x{:08x}", result));
            }

            info!(
                "WFP DNS lock: {} filters active (permit VPN DNS, block others)",
                cnt
            );
            Ok(WfpDnsLock { engine })
        }
    }

    fn destroy(self) {
        unsafe {
            let _ = FwpmEngineClose0(self.engine);
        }
        info!("WFP DNS lock released");
    }
}
