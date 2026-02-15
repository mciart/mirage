//! Default value functions for serde deserialization.

use ipnet::IpNet;
use std::net::IpAddr;
use std::path::PathBuf;

use super::AuthType;

pub fn default_log_level() -> String {
    "info".to_string()
}

pub fn default_bind_address() -> IpAddr {
    "0.0.0.0".parse().expect("Default address is valid")
}

pub fn default_bind_port() -> u16 {
    443 // Standard HTTPS port for stealth
}

pub fn default_buffer_size() -> u64 {
    2097152
}

pub fn default_mtu() -> u16 {
    // 1280 = IPv6 minimum MTU, universally supported
    // Lower MTU reduces IP fragmentation and TCP-over-TCP congestion conflicts
    1280
}

pub fn default_outer_mtu() -> u16 {
    // 1350 is a safe value for WAN (below 1500 - PPPoE overhead)
    1350
}

pub fn default_timeout_s() -> u64 {
    30
}

pub fn default_keep_alive_interval_s() -> u64 {
    25
}

pub fn default_retry_interval_s() -> u64 {
    5
}

pub fn default_auth_type() -> AuthType {
    AuthType::UsersFile
}

pub fn default_routes() -> Vec<IpNet> {
    Vec::new()
}

pub fn default_dns_servers() -> Vec<IpAddr> {
    Vec::new()
}

pub fn default_true_fn() -> bool {
    true
}

pub fn default_false_fn() -> bool {
    false
}

pub fn default_trusted_certificate_paths() -> Vec<PathBuf> {
    Vec::new()
}

pub fn default_trusted_certificates() -> Vec<String> {
    Vec::new()
}

pub fn default_reality_sni() -> String {
    "www.microsoft.com".to_string()
}

pub fn default_enabled_protocols() -> Vec<String> {
    vec!["reality".to_string()]
}

pub fn default_parallel_connections() -> u8 {
    1 // Default to single connection for backward compatibility
}

pub fn default_zero_fn() -> u64 {
    0
}

pub fn default_padding_probability() -> f64 {
    0.05
}

pub fn default_padding_min() -> usize {
    100
}

pub fn default_padding_max() -> usize {
    1000
}

pub fn default_jitter_min() -> u64 {
    0
}

pub fn default_jitter_max() -> u64 {
    20
}
