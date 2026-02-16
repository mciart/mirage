use crate::Result;
use std::net::IpAddr;
use std::sync::OnceLock;
use tracing::{debug, info, warn};
use wintun_bindings::Adapter;

/// Fixed GUID for our NRPT rule — same across sessions for predictable cleanup.
const NRPT_RULE_GUID: &str = "{4D617261-6765-0000-0000-4D6972616765}";

/// Registry path for DNS policy configuration (NRPT)
const NRPT_BASE_PATH: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";

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

/// Adds an NRPT (Name Resolution Policy Table) rule via `reg.exe`.
///
/// Creates a registry key that forces Windows to route ALL DNS queries
/// through the specified VPN DNS servers, preventing DNS leaks.
///
/// Registry structure:
/// ```text
/// HKLM\...\DnsPolicyConfig\{GUID}
///   Name              = "."                       (REG_SZ)
///   GenericDNSServers = "1.1.1.1;8.8.8.8"        (REG_SZ)
///   ConfigOptions     = 0x8                       (REG_DWORD)
/// ```
fn add_nrpt_rule(dns_servers: &[IpAddr]) -> Result<()> {
    let dns_list: String = dns_servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(";");

    let key_path = format!("{}\\{}", NRPT_BASE_PATH, NRPT_RULE_GUID);

    // Create key and set values using reg.exe (works on all Windows versions)
    // reg add "KEY" /v Name /t REG_SZ /d "." /f
    let commands = [
        vec![
            "reg", "add", &key_path, "/v", "Name", "/t", "REG_SZ", "/d", ".", "/f",
        ],
        vec![
            "reg",
            "add",
            &key_path,
            "/v",
            "GenericDNSServers",
            "/t",
            "REG_SZ",
            "/d",
            &dns_list,
            "/f",
        ],
        vec![
            "reg",
            "add",
            &key_path,
            "/v",
            "ConfigOptions",
            "/t",
            "REG_DWORD",
            "/d",
            "8",
            "/f",
        ],
    ];

    for cmd in &commands {
        let output = std::process::Command::new(cmd[0])
            .args(&cmd[1..])
            .output()
            .map_err(|e| crate::error::DnsError::PlatformError {
                message: format!("Failed to run reg.exe: {}", e),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("reg.exe command failed: {}", stderr);
            return Err(crate::error::DnsError::PlatformError {
                message: format!("NRPT registry write failed: {}", stderr),
            }
            .into());
        }
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

    let key_path = format!("{}\\{}", NRPT_BASE_PATH, NRPT_RULE_GUID);

    let output = std::process::Command::new("reg")
        .args(["delete", &key_path, "/f"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            info!("NRPT DNS leak prevention rule removed");
        }
        Ok(o) => {
            debug!(
                "NRPT key deletion result: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
        Err(e) => {
            debug!("Failed to run reg.exe for NRPT cleanup: {}", e);
        }
    }

    set_nrpt_active(false);
    Ok(())
}

/// Flushes the Windows DNS resolver cache.
fn flush_dns_cache() {
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
