use std::process::Command;
use tracing::{debug, info, warn};

use crate::config::NatConfig;

/// Manages NAT configuration (Masquerading, Forwarding, Policy Routing)
pub struct NatManager {
    config: NatConfig,
    tun_interface: String,
    tunnel_network_v4: String,         // CIDR, e.g. "10.0.0.1/24"
    tunnel_network_v6: Option<String>, // CIDR, e.g. "fd00::1/64"
    active_rules: Vec<String>,         // Track added rules for cleanup (LIFO)
    /// Dynamically chosen fwmark / routing table ID (same value for both)
    rt_id: String,
}

/// Pick a stable routing table ID based on the TUN interface name.
///
/// Uses a simple hash of the interface name to deterministically map to the
/// 100..252 range. This ensures the same interface always gets the same ID,
/// enabling reliable cleanup of stale rules from previous runs.
fn stable_rt_id(tun_interface: &str) -> u32 {
    let hash: u32 = tun_interface
        .bytes()
        .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    100 + (hash % 153) // Maps to 100..252
}

/// Detect the default gateway for an interface from the system routing table.
///
/// Parses `ip [-6] route show default [dev <iface>]` to extract the `via` address.
/// Falls back to querying without device filter if the first attempt yields nothing.
/// Returns `None` for point-to-point links or when no gateway is configured.
fn get_default_gateway(outbound_iface: &str, ipv6: bool) -> Option<String> {
    let base: &[&str] = if ipv6 { &["-6"] } else { &[] };

    // Try with device filter first, then without (fallback for single-route systems)
    for with_dev in [true, false] {
        let mut args: Vec<&str> = base.to_vec();
        args.extend_from_slice(&["route", "show", "default"]);
        if with_dev {
            args.extend_from_slice(&["dev", outbound_iface]);
        }

        let output = Command::new("ip").args(&args).output().ok()?;
        if !output.status.success() {
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse: "default via 10.0.0.1 dev eth0 ..."
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&p| p == "via") {
                if let Some(gw) = parts.get(pos + 1) {
                    return Some(gw.to_string());
                }
            }
        }
    }

    None
}

/// Clean up stale rules from previous Mirage runs that used the same fwmark/table ID.
/// This prevents rule accumulation when the process crashes without running Drop.
fn cleanup_stale_rules(
    rt_id: &str,
    tun_interface: &str,
    tunnel_net_v4: &str,
    tunnel_net_v6: Option<&str>,
) {
    info!("Cleaning up stale NAT rules for fwmark/table {}...", rt_id);

    // Remove stale IPv4 mangle mark rules for our tunnel network
    loop {
        if run_cmd(
            "iptables",
            &[
                "-t",
                "mangle",
                "-D",
                "PREROUTING",
                "-s",
                tunnel_net_v4,
                "-j",
                "MARK",
                "--set-mark",
                rt_id,
            ],
        )
        .is_err()
        {
            break; // No more matching rules
        }
        debug!("Removed stale IPv4 mangle rule for {}", tunnel_net_v4);
    }

    // Remove stale IPv4 ip rule
    loop {
        if run_cmd("ip", &["rule", "del", "fwmark", rt_id, "table", rt_id]).is_err() {
            break;
        }
        debug!("Removed stale IPv4 ip rule for fwmark {}", rt_id);
    }

    // Remove stale IPv4 route in custom table (ignore errors)
    let _ = run_cmd("ip", &["route", "flush", "table", rt_id]);

    // Remove stale IPv4 NAT MASQUERADE rules for our tunnel network
    // (We loop to remove all matching rules regardless of -o interface)
    loop {
        if run_cmd(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                tunnel_net_v4,
                "-j",
                "MASQUERADE",
            ],
        )
        .is_err()
        {
            break;
        }
        debug!("Removed stale IPv4 NAT rule for {}", tunnel_net_v4);
    }

    // Remove stale IPv4 FORWARD rules for our TUN interface
    loop {
        if run_cmd(
            "iptables",
            &["-D", "FORWARD", "-i", tun_interface, "-j", "ACCEPT"],
        )
        .is_err()
        {
            break;
        }
    }
    loop {
        if run_cmd(
            "iptables",
            &["-D", "FORWARD", "-o", tun_interface, "-j", "ACCEPT"],
        )
        .is_err()
        {
            break;
        }
    }

    // IPv6 cleanup
    if let Some(v6_net) = tunnel_net_v6 {
        loop {
            if run_cmd(
                "ip6tables",
                &[
                    "-t",
                    "mangle",
                    "-D",
                    "PREROUTING",
                    "-s",
                    v6_net,
                    "-j",
                    "MARK",
                    "--set-mark",
                    rt_id,
                ],
            )
            .is_err()
            {
                break;
            }
            debug!("Removed stale IPv6 mangle rule for {}", v6_net);
        }

        loop {
            if run_cmd(
                "ip",
                &["-6", "rule", "del", "fwmark", rt_id, "table", rt_id],
            )
            .is_err()
            {
                break;
            }
            debug!("Removed stale IPv6 ip rule for fwmark {}", rt_id);
        }

        let _ = run_cmd("ip", &["-6", "route", "flush", "table", rt_id]);

        loop {
            if run_cmd(
                "ip6tables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    v6_net,
                    "-j",
                    "MASQUERADE",
                ],
            )
            .is_err()
            {
                break;
            }
            debug!("Removed stale IPv6 NAT rule for {}", v6_net);
        }
    }

    info!("Stale rule cleanup complete.");
}

impl NatManager {
    pub fn new(
        config: NatConfig,
        tun_interface: String,
        tunnel_network_v4: String,
        tunnel_network_v6: Option<String>,
    ) -> Self {
        let rt_id = stable_rt_id(&tun_interface);
        info!(
            "NAT policy routing: using table/fwmark ID {} for interface {}",
            rt_id, tun_interface
        );

        // Clean up stale rules from previous runs BEFORE adding new ones
        cleanup_stale_rules(
            &rt_id.to_string(),
            &tun_interface,
            &tunnel_network_v4,
            tunnel_network_v6.as_deref(),
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

        // 2. Disable reverse path filtering on the outbound interface
        //    Required for policy routing to work with tunnel interfaces (e.g. wg0)
        let rp_filter_key = format!("net.ipv4.conf.{}.rp_filter=0", outbound_iface);
        if let Err(e) = run_cmd("sysctl", &["-w", &rp_filter_key]) {
            warn!("Failed to disable rp_filter on {}: {}", outbound_iface, e);
        }
        if let Err(e) = run_cmd("sysctl", &["-w", "net.ipv4.conf.all.rp_filter=0"]) {
            warn!("Failed to disable global rp_filter: {}", e);
        }

        // 3. Allow FORWARD chain (Core VPN traffic)
        self.add_rule(
            "iptables",
            &["-I", "FORWARD", "-i", &tun_iface, "-j", "ACCEPT"],
        );
        self.add_rule(
            "iptables",
            &["-I", "FORWARD", "-o", &tun_iface, "-j", "ACCEPT"],
        );

        // 3b. TCP MSS clamping — automatically adjust MSS to match path MTU
        //     Prevents packet-too-large drops with double encapsulation (e.g. Mirage + WireGuard)
        self.add_rule(
            "iptables",
            &[
                "-t",
                "mangle",
                "-A",
                "FORWARD",
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
        );

        // 4. Masquerade (NAT)
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

        // 5. Policy routing: route VPN client traffic through the specified interface
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
    ///      (including the gateway address for proper next-hop resolution)
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
                &fwmark,
            ],
        );

        // Add ip rule: marked packets use custom routing table
        match run_cmd("ip", &["rule", "add", "fwmark", &fwmark, "table", &table]) {
            Ok(_) => {
                debug!("Added ip rule: fwmark {} -> table {}", fwmark, table);
                self.active_rules
                    .push(format!("ip rule del fwmark {} table {}", fwmark, table));
            }
            Err(e) => warn!("Failed to add ip rule: {}", e),
        }

        // Add default route in custom table via the specified interface.
        // We must include the gateway (via) for the kernel to resolve the next-hop
        // correctly — without it, packets are silently dropped on many systems.
        let gateway = get_default_gateway(outbound_iface, false);

        let route_result = if let Some(ref gw) = gateway {
            info!(
                "Detected IPv4 gateway {} on interface {}",
                gw, outbound_iface
            );
            run_cmd(
                "ip",
                &[
                    "route",
                    "replace",
                    "default",
                    "via",
                    gw,
                    "dev",
                    outbound_iface,
                    "table",
                    &table,
                ],
            )
        } else {
            // Fallback: no gateway detected (point-to-point link, etc.)
            warn!(
                "No IPv4 gateway detected on {}, using device-only route (may not work on all systems)",
                outbound_iface
            );
            run_cmd(
                "ip",
                &[
                    "route",
                    "replace",
                    "default",
                    "dev",
                    outbound_iface,
                    "table",
                    &table,
                ],
            )
        };

        if let Err(e) = route_result {
            warn!("Failed to add default route in table {}: {}", table, e);
        }

        // Track for cleanup
        self.active_rules.push(format!(
            "ip route del default dev {} table {}",
            outbound_iface, table
        ));

        info!(
            "IPv4 policy routing configured: fwmark={} table={} dev={} gateway={:?}",
            fwmark, table, outbound_iface, gateway
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

        // 2b. TCP MSS clamping for IPv6
        self.add_rule(
            "ip6tables",
            &[
                "-t",
                "mangle",
                "-A",
                "FORWARD",
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
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
                &fwmark,
            ],
        );

        // Add ip -6 rule
        match run_cmd(
            "ip",
            &["-6", "rule", "add", "fwmark", &fwmark, "table", &table],
        ) {
            Ok(_) => {
                debug!("Added ip -6 rule: fwmark {} -> table {}", fwmark, table);
                self.active_rules
                    .push(format!("ip -6 rule del fwmark {} table {}", fwmark, table));
            }
            Err(e) => warn!("Failed to add ip -6 rule: {}", e),
        }

        // Add default route in custom table (with gateway if available)
        let gateway = get_default_gateway(outbound_iface, true);

        let route_result = if let Some(ref gw) = gateway {
            info!(
                "Detected IPv6 gateway {} on interface {}",
                gw, outbound_iface
            );
            run_cmd(
                "ip",
                &[
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "via",
                    gw,
                    "dev",
                    outbound_iface,
                    "table",
                    &table,
                ],
            )
        } else {
            warn!(
                "No IPv6 gateway detected on {}, using device-only route",
                outbound_iface
            );
            run_cmd(
                "ip",
                &[
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "dev",
                    outbound_iface,
                    "table",
                    &table,
                ],
            )
        };

        if let Err(e) = route_result {
            warn!("Failed to add IPv6 default route in table {}: {}", table, e);
        }

        self.active_rules.push(format!(
            "ip -6 route del default dev {} table {}",
            outbound_iface, table
        ));

        info!(
            "IPv6 policy routing configured: fwmark={} table={} dev={} gateway={:?}",
            fwmark, table, outbound_iface, gateway
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
