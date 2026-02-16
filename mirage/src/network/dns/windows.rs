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

/// Firewall rule names for cleanup
const FW_BLOCK_UDP: &str = "Mirage-BlockDNS-UDP";
const FW_BLOCK_TCP: &str = "Mirage-BlockDNS-TCP";
const FW_ALLOW_UDP: &str = "Mirage-AllowVPNDNS-UDP";
const FW_ALLOW_TCP: &str = "Mirage-AllowVPNDNS-TCP";

/// Adds DNS servers to the TUN interface and enables full DNS leak prevention.
///
/// Three layers of protection:
/// 1. Set DNS on TUN adapter (WinTun API)
/// 2. NRPT rule via PowerShell (forces all DNS through VPN servers)
/// 3. Firewall rules to block DNS on non-VPN paths
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

    // Step 3: Add firewall rules to block non-VPN DNS traffic
    if let Err(e) = add_dns_firewall_rules(dns_servers) {
        warn!("Failed to add DNS firewall rules: {}", e);
    }

    // Step 4: Flush + re-register DNS
    flush_dns_cache();

    set_protection_active(true);
    Ok(())
}

/// Removes DNS leak prevention (NRPT + firewall rules).
pub fn delete_dns_servers() -> Result<()> {
    if !is_protection_active() {
        return Ok(());
    }

    // Remove NRPT rule
    if let Err(e) = remove_nrpt_rule() {
        warn!("Failed to remove NRPT rule: {}", e);
    }

    // Remove firewall rules
    remove_dns_firewall_rules();

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

/// Adds Windows Firewall rules to block DNS traffic except to VPN DNS servers.
///
/// This is a belt-and-suspenders approach alongside NRPT, catching cases where
/// applications bypass the system DNS resolver (e.g., browsers with built-in DoH).
fn add_dns_firewall_rules(dns_servers: &[IpAddr]) -> Result<()> {
    let dns_ips: String = dns_servers
        .iter()
        .map(|ip| ip.to_string())
        .collect::<Vec<_>>()
        .join(",");

    // Remove any stale rules first
    remove_dns_firewall_rules();

    // Allow DNS to VPN DNS servers (must be added BEFORE block rules)
    let allow_rules = [
        (FW_ALLOW_UDP, "udp", &dns_ips),
        (FW_ALLOW_TCP, "tcp", &dns_ips),
    ];

    for (name, proto, ips) in &allow_rules {
        let output = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", name),
                "dir=out",
                &format!("protocol={}", proto),
                "remoteport=53",
                &format!("remoteip={}", ips),
                "action=allow",
            ])
            .output();

        if let Ok(o) = output {
            if !o.status.success() {
                warn!(
                    "Firewall allow rule '{}' failed: {}",
                    name,
                    String::from_utf8_lossy(&o.stderr)
                );
            }
        }
    }

    // Block all other DNS
    let block_rules = [(FW_BLOCK_UDP, "udp"), (FW_BLOCK_TCP, "tcp")];

    for (name, proto) in &block_rules {
        let output = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "add",
                "rule",
                &format!("name={}", name),
                "dir=out",
                &format!("protocol={}", proto),
                "remoteport=53",
                "action=block",
            ])
            .output();

        if let Ok(o) = output {
            if !o.status.success() {
                warn!(
                    "Firewall block rule '{}' failed: {}",
                    name,
                    String::from_utf8_lossy(&o.stderr)
                );
            }
        }
    }

    info!(
        "DNS firewall rules added (allow: {}, block: all others)",
        dns_ips
    );
    Ok(())
}

/// Removes all Mirage DNS firewall rules.
fn remove_dns_firewall_rules() {
    for name in [FW_BLOCK_UDP, FW_BLOCK_TCP, FW_ALLOW_UDP, FW_ALLOW_TCP] {
        let _ = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                &format!("name={}", name),
            ])
            .output();
    }
    debug!("DNS firewall rules removed");
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
