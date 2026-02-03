use std::process::Command;
use tracing::{debug, info, warn};

use mirage::config::NatConfig;

/// Manages NAT configuration (Masquerading, Forwarding)
pub struct NatManager {
    config: NatConfig,
    tun_interface: String,
    tunnel_network_v4: String,         // CIDR, e.g. "10.0.0.1/24"
    tunnel_network_v6: Option<String>, // CIDR, e.g. "fd00::1/64"
    active_rules: Vec<String>,         // Track added rules for cleanup (simplified description)
}

impl NatManager {
    pub fn new(
        config: NatConfig,
        tun_interface: String,
        tunnel_network_v4: String,
        tunnel_network_v6: Option<String>,
    ) -> Self {
        Self {
            config,
            tun_interface,
            tunnel_network_v4,
            tunnel_network_v6,
            active_rules: Vec::new(),
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
    }

    /// Add a rule and track it for cleanup (Cleanup is tricky without exact matching or ID)
    /// For this version, we will just execute the command.
    /// Real cleanup usually requires -D instead of -A/-I.
    /// We can store the 'delete' command equivalent.
    fn add_rule(&mut self, cmd: &str, args: &[&str]) {
        // Construct delete command: -I -> -D, -A -> -D
        let mut delete_args = args.to_vec();
        if delete_args[0] == "-I" || delete_args[0] == "-A" {
            delete_args[0] = "-D";
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
