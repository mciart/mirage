use crate::error::DnsError;
use crate::utils::command::run_command;
use crate::Result;
use std::io::Write;
use std::net::IpAddr;

const RESOLVCONF_COMMAND: &str = "resolvconf";

/// Adds a list of DNS servers to the given interface.
///
/// ### Arguments
/// - `dns_servers` - the DNS servers to be added
/// - `interface_name` - the name of the interface to add the DNS servers to
/// Adds a list of DNS servers to the given interface.
///
/// ### Arguments
/// - `dns_servers` - the DNS servers to be added
/// - `interface_name` - the name of the interface to add the DNS servers to
pub fn add_dns_servers(dns_servers: &[IpAddr], interface_name: &str) -> Result<()> {
    // Attempt 1: Try `resolvconf` (Debian/Ubuntu legacy)
    if let Err(e) = add_dns_via_resolvconf(dns_servers, interface_name) {
        tracing::warn!("Failed to configure DNS via resolvconf: {}", e);
        
        // Attempt 2: Try `resolvectl` (systemd-resolved)
        if let Err(e) = add_dns_via_resolvectl(dns_servers, interface_name) {
             tracing::warn!("Failed to configure DNS via resolvectl: {}", e);
             tracing::error!("Could not configure DNS. Please manually set DNS if needed.");
             // We returning Ok here to avoid crashing the client if DNS setup fails.
             // Connectivity might still work via IP.
        }
    }

    Ok(())
}

fn add_dns_via_resolvconf(dns_servers: &[IpAddr], interface_name: &str) -> Result<()> {
    let set_args = ["-a", interface_name, "-x"];
    let input = dns_servers
        .iter()
        .map(|ip| format!("nameserver {ip}"))
        .collect::<Vec<_>>()
        .join("\n");

    let mut process =
        run_command(RESOLVCONF_COMMAND, set_args).map_err(|e| DnsError::PlatformError {
            message: format!("failed to execute resolvconf: {e}"),
        })?;

    if let Some(mut stdin) = process.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| DnsError::PlatformError {
                message: format!("failed to write to resolvconf stdin: {e}"),
            })?;
    } else {
        return Err(DnsError::PlatformError {
            message: "failed to open resolvconf stdin".to_string(),
        }
        .into());
    }

    let output = process
        .wait_with_output()
        .map_err(|e| DnsError::PlatformError {
            message: format!("failed to wait for resolvconf: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(DnsError::PlatformError{
            message: format!("resolvconf failed: {}", stderr)
        }.into());
    }

    Ok(())
}

fn add_dns_via_resolvectl(dns_servers: &[IpAddr], interface_name: &str) -> Result<()> {
    // resolvectl dns <interface> <ip1> <ip2>...
    let mut args = vec!["dns", interface_name];
    let ip_strings: Vec<String> = dns_servers.iter().map(|ip| ip.to_string()).collect();
    for ip in &ip_strings {
        args.push(ip);
    }

    let output = run_command("resolvectl", args)
        .map_err(|e| DnsError::PlatformError {
             message: format!("failed to execute resolvectl: {}", e)
        })?
        .wait_with_output()
        .map_err(|e| DnsError::PlatformError {
            message: format!("failed to wait for resolvectl: {}", e)
        })?;

    if !output.status.success() {
         let stderr = String::from_utf8_lossy(&output.stderr);
         return Err(DnsError::PlatformError{
             message: format!("resolvectl failed: {}", stderr)
         }.into());
    }
    
    // Also set the domain if needed, but for now just setting DNS is enough 
    // to start routing queries.
    
    Ok(())
}

/// Deletes all DNS servers from the given interface.
///
/// No-op on Linux/FreeBSD as interface destruction handles it, 
/// usually.
pub fn delete_dns_servers() -> Result<()> {
    // This is a no-op on Linux and FreeBSD as the interface is deleted when the process exits
    // along with its routes and DNS servers
    Ok(())
}
