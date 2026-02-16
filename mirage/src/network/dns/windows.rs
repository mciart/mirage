use crate::Result;
use std::net::IpAddr;
use std::sync::OnceLock;
use tracing::{debug, info, warn};
use wintun_bindings::Adapter;

/// Track whether DNS leak prevention is active
static DNS_PROTECTION_ACTIVE: OnceLock<std::sync::atomic::AtomicBool> = OnceLock::new();

fn is_protection_active() -> bool {
    DNS_PROTECTION_ACTIVE
        .get_or_init(|| std::sync::atomic::AtomicBool::new(false))
        .load(std::sync::atomic::Ordering::Relaxed)
}

fn set_protection_active(active: bool) {
    DNS_PROTECTION_ACTIVE
        .get_or_init(|| std::sync::atomic::AtomicBool::new(false))
        .store(active, std::sync::atomic::Ordering::Relaxed);
}

/// Adds DNS servers to the TUN interface and enables NRPT leak prevention.
///
/// Two layers of protection:
/// 1. Set DNS on TUN adapter (WinTun API)
/// 2. NRPT rule via PowerShell (forces all DNS through VPN servers)
///
/// Note: Windows Firewall rules are NOT used because block rules override
/// allow rules, which would break VPN DNS resolution.
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

    // Step 2: Add NRPT rule via PowerShell (officially supported, notifies DNS service)
    if let Err(e) = add_nrpt_rule(dns_servers) {
        warn!("Failed to add NRPT rule: {}", e);
    }

    // Step 3: Flush + re-register DNS
    flush_dns_cache();

    set_protection_active(true);
    Ok(())
}

/// Removes DNS leak prevention (NRPT rules).
pub fn delete_dns_servers() -> Result<()> {
    if !is_protection_active() {
        return Ok(());
    }

    // Remove NRPT rule
    if let Err(e) = remove_nrpt_rule() {
        warn!("Failed to remove NRPT rule: {}", e);
    }

    // Flush DNS cache to restore normal resolution
    flush_dns_cache();

    set_protection_active(false);
    Ok(())
}

/// Adds NRPT rule using PowerShell `Add-DnsClientNrptRule`.
///
/// This is the officially supported API that properly notifies the DNS Client
/// service to reload its policy table, unlike raw registry writes.
fn add_nrpt_rule(dns_servers: &[IpAddr]) -> Result<()> {
    let servers: String = dns_servers
        .iter()
        .map(|ip| format!("'{}'", ip))
        .collect::<Vec<_>>()
        .join(",");

    let ps_cmd = format!(
        "Add-DnsClientNrptRule -Namespace '.' -NameServers {} -Comment 'Mirage VPN'",
        servers
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps_cmd])
        .output()
        .map_err(|e| crate::error::DnsError::PlatformError {
            message: format!("Failed to run PowerShell: {}", e),
        })?;

    if output.status.success() {
        let dns_list = dns_servers
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(";");
        info!("NRPT DNS leak prevention enabled: all DNS → [{}]", dns_list);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("NRPT rule creation failed: {}", stderr);
    }

    Ok(())
}

/// Removes all Mirage NRPT rules.
fn remove_nrpt_rule() -> Result<()> {
    let ps_cmd =
        "Get-DnsClientNrptRule | Where-Object {$_.Comment -eq 'Mirage VPN'} | Remove-DnsClientNrptRule -Force";

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", ps_cmd])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            info!("NRPT DNS leak prevention rule removed");
        }
        Ok(o) => {
            debug!(
                "NRPT removal result: {}",
                String::from_utf8_lossy(&o.stderr)
            );
        }
        Err(e) => {
            warn!("Failed to remove NRPT rule: {}", e);
        }
    }

    Ok(())
}

/// Flushes the Windows DNS resolver cache and re-registers DNS.
fn flush_dns_cache() {
    let _ = std::process::Command::new("ipconfig")
        .arg("/flushdns")
        .output();
    let _ = std::process::Command::new("ipconfig")
        .arg("/registerdns")
        .output();
    debug!("DNS cache flushed and re-registered");
}
