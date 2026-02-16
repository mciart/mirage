use crate::Result;
use std::net::IpAddr;
use std::sync::OnceLock;
use tracing::{debug, info, warn};
use wintun_bindings::Adapter;

/// Fixed GUID for our NRPT rule — same across sessions for predictable cleanup.
const NRPT_RULE_GUID: &str = "{4D6172-6167-6500-0000-4D6972616765}";

/// Registry path for DNS policy configuration (NRPT)
const NRPT_BASE_PATH: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

/// Track whether NRPT rule is active (for cleanup on drop/panic)
static NRPT_ACTIVE: OnceLock<std::sync::atomic::AtomicBool> = OnceLock::new();

fn nrpt_is_active() -> bool {
    NRPT_ACTIVE
        .get_or_init(|| std::sync::atomic::AtomicBool::new(false))
        .load(std::sync::atomic::Ordering::Relaxed)
}

fn set_nrpt_active(active: bool) {
    NRPT_ACTIVE
        .get_or_init(|| std::sync::atomic::AtomicBool::new(false))
        .store(active, std::sync::atomic::Ordering::Relaxed);
}

/// Adds DNS servers to the TUN interface and enables NRPT leak prevention.
///
/// This performs three steps:
/// 1. Sets DNS servers on the TUN adapter via WinTun API
/// 2. Adds NRPT rule to force all DNS queries through VPN DNS servers
/// 3. Flushes the system DNS cache
pub fn add_dns_servers(dns_servers: &[IpAddr], interface_name: &str) -> Result<()> {
    // Step 1: Set DNS on TUN adapter
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

    // Step 2: Add NRPT rule to prevent DNS leaks
    if let Err(e) = add_nrpt_rule(dns_servers) {
        warn!("Failed to add NRPT rule (DNS may leak): {}", e);
    }

    // Step 3: Flush DNS cache so new rules take effect immediately
    flush_dns_cache();

    Ok(())
}

/// Removes DNS servers and cleans up NRPT rules.
pub fn delete_dns_servers() -> Result<()> {
    // Remove NRPT rule first
    if let Err(e) = remove_nrpt_rule() {
        warn!("Failed to remove NRPT rule: {}", e);
    }

    // Flush DNS cache to restore normal resolution
    flush_dns_cache();

    Ok(())
}

/// Adds an NRPT (Name Resolution Policy Table) rule via Windows Registry.
///
/// This creates a registry key under DnsPolicyConfig that forces Windows to
/// route ALL DNS queries (Name=".") through the specified VPN DNS servers,
/// preventing DNS leaks through non-VPN interfaces (Smart Multi-Homed Name Resolution).
///
/// Registry structure:
/// ```text
/// HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{GUID}
///   Name              = "."                           (REG_SZ)
///   GenericDNSServers = "1.1.1.1,8.8.8.8"            (REG_SZ)
///   ConfigOptions     = 0x8                           (REG_DWORD)
/// ```
fn add_nrpt_rule(dns_servers: &[IpAddr]) -> Result<()> {
    use windows::core::PCSTR;
    use windows::Win32::System::Registry::*;

    let dns_list: String = dns_servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(";");

    let key_path = format!("{}\\{}", NRPT_BASE_PATH, NRPT_RULE_GUID);
    let key_path_cstr = format!("{}\0", key_path);

    unsafe {
        // Create or open the registry key
        let mut hkey = HKEY::default();
        let mut disposition = 0u32;

        let result = RegCreateKeyExA(
            HKEY_LOCAL_MACHINE,
            PCSTR(key_path_cstr.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_ALL_ACCESS,
            None,
            &mut hkey,
            Some(&mut disposition),
        );

        if result.is_err() {
            return Err(crate::error::DnsError::PlatformError {
                message: format!("Failed to create NRPT registry key: {:?}", result),
            }
            .into());
        }

        // Set Name = "." (match all domains)
        let name_value = ".\0";
        let result = RegSetValueExA(
            hkey,
            PCSTR(b"Name\0".as_ptr()),
            0,
            REG_SZ,
            Some(name_value.as_bytes()),
        );
        if result.is_err() {
            warn!("Failed to set NRPT Name value: {:?}", result);
        }

        // Set GenericDNSServers = "ip1;ip2"
        let dns_value = format!("{}\0", dns_list);
        let result = RegSetValueExA(
            hkey,
            PCSTR(b"GenericDNSServers\0".as_ptr()),
            0,
            REG_SZ,
            Some(dns_value.as_bytes()),
        );
        if result.is_err() {
            warn!("Failed to set NRPT GenericDNSServers value: {:?}", result);
        }

        // Set ConfigOptions = 0x8 (enforce NRPT policy)
        let config_options: u32 = 0x8;
        let result = RegSetValueExA(
            hkey,
            PCSTR(b"ConfigOptions\0".as_ptr()),
            0,
            REG_DWORD,
            Some(&config_options.to_ne_bytes()),
        );
        if result.is_err() {
            warn!("Failed to set NRPT ConfigOptions value: {:?}", result);
        }

        let _ = RegCloseKey(hkey);
    }

    set_nrpt_active(true);
    info!("NRPT DNS leak prevention enabled: all DNS → [{}]", dns_list);

    Ok(())
}

/// Removes the NRPT rule from the registry.
fn remove_nrpt_rule() -> Result<()> {
    if !nrpt_is_active() {
        debug!("NRPT rule not active, skipping removal");
        return Ok(());
    }

    use windows::core::PCSTR;
    use windows::Win32::System::Registry::*;

    let key_path = format!("{}\\{}\0", NRPT_BASE_PATH, NRPT_RULE_GUID);

    unsafe {
        let result = RegDeleteKeyA(HKEY_LOCAL_MACHINE, PCSTR(key_path.as_ptr()));

        if result.is_err() {
            // Key might not exist, that's fine
            debug!("NRPT key deletion result: {:?}", result);
        } else {
            info!("NRPT DNS leak prevention rule removed");
        }
    }

    set_nrpt_active(false);
    Ok(())
}

/// Flushes the Windows DNS resolver cache.
///
/// This ensures NRPT rule changes take effect immediately without waiting
/// for cached DNS entries to expire.
fn flush_dns_cache() {
    // Use DnsFlushResolverCache via ipconfig /flushdns
    match std::process::Command::new("ipconfig")
        .arg("/flushdns")
        .output()
    {
        Ok(output) => {
            if output.status.success() {
                debug!("DNS resolver cache flushed");
            } else {
                warn!(
                    "ipconfig /flushdns failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
        Err(e) => {
            warn!("Failed to flush DNS cache: {}", e);
        }
    }
}
