use std::process::Command;
use tracing::{debug, info, warn};

use crate::config::NatConfig;

/// Manages NAT configuration (Masquerading, Forwarding, Policy Routing)
pub struct NatManager {
    config: NatConfig,
    tun_interface: String,
    tunnel_network_v4: String,         // CIDR, e.g. "10.0.0.1/24"
    tunnel_network_v6: Option<String>, // CIDR, e.g. "fd00::1/64"
    active_rules: Vec<String>,         // Track added rules for cleanup (simplified description)
    /// Dynamically chosen fwmark / routing table ID (same value for both)
    rt_id: String,
}

/// Pick a routing table ID and fwmark that won't collide with existing rules.
///
/// Strategy: derive from the TUN interface index (stable, unique per interface).
/// If that collides or the interface index is unavailable, scan `ip rule` output
/// and pick the first free ID in the 100..252 range.
/// (0-2 are reserved by the kernel, 253=default, 254=main, 255=local.)
fn pick_rt_id(tun_interface: &str) -> u32 {
    // Try using the TUN interface index as the base
    let c_name = std::ffi::CString::new(tun_interface).ok();
    let if_index = c_name
        .map(|n| unsafe { libc::if_nametoindex(n.as_ptr()) })
        .unwrap_or(0);

    // Candidate based on interface index (offset into the 100..252 range)
    let candidate = if if_index > 0 {
        100 + (if_index % 153) // Maps to 100..252
    } else {
        100
    };

    // Collect table IDs already in use by `ip rule`
    let used = collect_used_table_ids();

    if !used.contains(&candidate) {
        return candidate;
    }

    // Linear scan for a free slot
    for id in 100..253u32 {
        if !used.contains(&id) {
            return id;
        }
    }

    // Extremely unlikely fallback
    candidate
}

/// Parse `ip rule show` output to find table IDs already in use.
fn collect_used_table_ids() -> Vec<u32> {
    let output = Command::new("ip")
        .args(["rule", "show"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // Lines look like: "0:  from all lookup local"  or  "32766:  from all lookup main"
    // or "100:  from all fwmark 0x64 lookup 100"
    // We extract the table number after "lookup"
    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            parts
                .iter()
                .position(|&w| w == "lookup")
                .and_then(|i| parts.get(i + 1))
                .and_then(|s| s.parse::<u32>().ok())
        })
        .collect()
}

impl NatManager {
    pub fn new(
        config: NatConfig,
        tun_interface: String,
        tunnel_network_v4: String,
        tunnel_network_v6: Option<String>,
    ) -> Self {
        let rt_id = pick_rt_id(&tun_interface);
        info!(
            "NAT policy routing: selected table/fwmark ID {} for interface {}",
            rt_id, tun_interface
        );

        Self {
            config,
            tun_interface,
            tunnel_network_v4,
            tunnel_network_v6,
            active_rules: Vec::new(),
            rt_id: rt_id.to_string(),
        }
    }

    /// Set up NAT and Forwarding rules
    pub fn setup(&mut self) {
        // Clone values to avoid borrowing self while mutating self
        let ipv4_iface = self.config.ipv4_interface.clone();
        let ipv6_iface = self.config.ipv6_interface.clone();
        let v6_net = self.tunnel_network_v6.clone();

        if let Some(iface) = ipv4_iface {
            info!("Configuring IPv4 NAT on interface: {}", iface);
            self.setup_ipv4(&iface);
        }

        if let Some(iface) = ipv6_iface {
            if let Some(net) = v6_net {
                info!("Configuring IPv6 NAT on interface: {}", iface);
                self.setup_ipv6(&iface, &net);
            } else {
                warn!("IPv6 NAT interface specified but IPv6 tunnel network is mostly disabled.");
            }
        }
    }

    fn setup_ipv4(&mut self, outbound_iface: &str) {
        let tun_iface = self.tun_interface.clone();
        let tunnel_net = self.tunnel_network_v4.clone();

        // 1. Enable forwarding
        if let Err(e) = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]) {
            warn!("Failed to enable IPv4 forwarding: {}", e);
        }

        // 2. Allow FORWARD chain (Core VPN traffic)
        self.add_rule(
            "iptables",
            &["-I", "FORWARD", "-i", &tun_iface, "-j", "ACCEPT"],
        );
        self.add_rule(
            "iptables",
            &["-I", "FORWARD", "-o", &tun_iface, "-j", "ACCEPT"],
        );

        // 3. Masquerade (NAT)
        self.add_rule(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                &tunnel_net,
                "-o",
                outbound_iface,
                "-j",
                "MASQUERADE",
            ],
        );

        // 4. Policy routing: route VPN client traffic through the specified interface
        //    This is essential when the outbound interface is not the default route
        //    (e.g. wg0, tun1, or any other tunnel interface).
        self.setup_policy_routing_v4(outbound_iface, &tunnel_net);
    }

    /// Set up fwmark-based policy routing for IPv4.
    ///
    /// Without this, even if MASQUERADE is set on the target interface,
    /// the kernel routes traffic via the default route (usually eth0).
    /// The policy routing chain:
    ///   1. mangle/PREROUTING marks packets from the tunnel network with fwmark
    ///   2. `ip rule` directs marked packets to a custom routing table
    ///   3. The custom table has a default route via the specified interface
    fn setup_policy_routing_v4(&mut self, outbound_iface: &str, tunnel_net: &str) {
        let fwmark = self.rt_id.clone();
        let table = self.rt_id.clone();

        info!(
            "Setting up IPv4 policy routing: {} -> {} (fwmark/table={})",
            tunnel_net, outbound_iface, fwmark
        );

        // Mark packets from tunnel network
        self.add_rule(
            "iptables",
            &[
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-s",
                tunnel_net,
                "-j",
                "MARK",
                "--set-mark",
                fwmark,
            ],
        );

        // Add ip rule: marked packets use custom routing table
        // (check if it already exists first to avoid duplicates)
        if Command::new("ip")
            .args(["rule", "show", "fwmark", fwmark, "table", table])
            .output()
            .ok()
            .filter(|o| !o.stdout.is_empty())
            .is_none()
        {
            match run_cmd("ip", &["rule", "add", "fwmark", fwmark, "table", table]) {
                Ok(_) => {
                    debug!("Added ip rule: fwmark {} -> table {}", fwmark, table);
                    self.active_rules
                        .push(format!("ip rule del fwmark {} table {}", fwmark, table));
                }
                Err(e) => warn!("Failed to add ip rule: {}", e),
            }
        }

        // Add default route in custom table via the specified interface
        // (replace if exists to handle restarts cleanly)
        let _ = run_cmd(
            "ip",
            &[
                "route",
                "replace",
                "default",
                "dev",
                outbound_iface,
                "table",
                table,
            ],
        );
        // Track for cleanup
        self.active_rules.push(format!(
            "ip route del default dev {} table {}",
            outbound_iface, table
        ));

        info!(
            "IPv4 policy routing configured: fwmark={} table={} dev={}",
            fwmark, table, outbound_iface
        );
    }

    fn setup_ipv6(&mut self, outbound_iface: &str, v6_net: &str) {
        let tun_iface = self.tun_interface.clone();
        // 1. Enable forwarding
        if let Err(e) = run_cmd("sysctl", &["-w", "net.ipv6.conf.all.forwarding=1"]) {
            warn!("Failed to enable IPv6 forwarding: {}", e);
        }

        // 2. Allow FORWARD chain
        self.add_rule(
            "ip6tables",
            &["-I", "FORWARD", "-i", &tun_iface, "-j", "ACCEPT"],
        );
        self.add_rule(
            "ip6tables",
            &["-I", "FORWARD", "-o", &tun_iface, "-j", "ACCEPT"],
        );

        // 3. Masquerade (NAT)
        self.add_rule(
            "ip6tables",
            &[
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                v6_net,
                "-o",
                outbound_iface,
                "-j",
                "MASQUERADE",
            ],
        );

        // 4. Policy routing for IPv6
        self.setup_policy_routing_v6(outbound_iface, v6_net);
    }

    /// Set up fwmark-based policy routing for IPv6.
    fn setup_policy_routing_v6(&mut self, outbound_iface: &str, v6_net: &str) {
        let fwmark = self.rt_id.clone();
        let table = self.rt_id.clone();

        info!(
            "Setting up IPv6 policy routing: {} -> {} (fwmark/table={})",
            v6_net, outbound_iface, fwmark
        );

        // Mark packets from tunnel v6 network
        self.add_rule(
            "ip6tables",
            &[
                "-t",
                "mangle",
                "-A",
                "PREROUTING",
                "-s",
                v6_net,
                "-j",
                "MARK",
                "--set-mark",
                fwmark,
            ],
        );

        // Add ip -6 rule
        if Command::new("ip")
            .args(["-6", "rule", "show", "fwmark", fwmark, "table", table])
            .output()
            .ok()
            .filter(|o| !o.stdout.is_empty())
            .is_none()
        {
            match run_cmd(
                "ip",
                &["-6", "rule", "add", "fwmark", fwmark, "table", table],
            ) {
                Ok(_) => {
                    debug!("Added ip -6 rule: fwmark {} -> table {}", fwmark, table);
                    self.active_rules
                        .push(format!("ip -6 rule del fwmark {} table {}", fwmark, table));
                }
                Err(e) => warn!("Failed to add ip -6 rule: {}", e),
            }
        }

        // Add default route in custom table
        let _ = run_cmd(
            "ip",
            &[
                "-6",
                "route",
                "replace",
                "default",
                "dev",
                outbound_iface,
                "table",
                table,
            ],
        );
        self.active_rules.push(format!(
            "ip -6 route del default dev {} table {}",
            outbound_iface, table
        ));

        info!(
            "IPv6 policy routing configured: fwmark={} table={} dev={}",
            fwmark, table, outbound_iface
        );
    }

    /// Add a rule and track it for cleanup
    fn add_rule(&mut self, cmd: &str, args: &[&str]) {
        // Construct delete command: Find -I or -A and flip to -D
        let mut delete_args = args.to_vec();
        for arg in delete_args.iter_mut() {
            if *arg == "-I" || *arg == "-A" {
                *arg = "-D";
                // Only replace the first occurrence (the action)
                break;
            }
        }

        // Run add command
        match run_cmd(cmd, args) {
            Ok(_) => {
                debug!("Added rule: {} {:?}", cmd, args);
                // Store delete command
                let full_cmd = format!("{} {}", cmd, delete_args.join(" "));
                self.active_rules.push(full_cmd);
            }
            Err(e) => {
                warn!("Failed to add rule '{} {:?}': {}", cmd, args, e);
            }
        }
    }

    /// Remove all added rules (LIFO order usually best)
    pub fn cleanup(&self) {
        info!("Cleaning up NAT rules...");
        for rule_cmd in self.active_rules.iter().rev() {
            let parts: Vec<&str> = rule_cmd.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let cmd = parts[0];
            let args = &parts[1..];

            if let Err(e) = run_cmd(cmd, args) {
                // It's possible the rule was already removed or modified
                debug!("Failed to cleanup rule '{}': {}", rule_cmd, e);
            } else {
                debug!("Removed rule: {}", rule_cmd);
            }
        }
    }
}

// Ensure cleanup on Drop
impl Drop for NatManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn run_cmd(cmd: &str, args: &[&str]) -> std::result::Result<(), String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to execute {}: {}", cmd, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed: {}", stderr));
    }
    Ok(())
}
