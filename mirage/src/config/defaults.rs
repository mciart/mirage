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
    2 * 1024 * 1024 // 2 MiB
}

pub fn default_mtu() -> u16 {
    // 1280 = IPv6 minimum MTU, universally supported
    // Lower MTU reduces IP fragmentation and TCP-over-TCP congestion conflicts
    1280
}

pub fn default_outer_mtu() -> u16 {
    // 1420 = 1500 (Ethernet) - ~80 (IP/UDP/QUIC overhead)
    // Optimal for standard broadband; QUIC PMTU discovery auto-reduces if needed
    1420
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

pub fn default_camouflage_sni() -> String {
    "www.microsoft.com".to_string()
}

pub fn default_camouflage_mode() -> String {
    "mirage".to_string()
}

pub fn default_server_port() -> u16 {
    443
}

pub fn default_protocols() -> Vec<super::TransportProtocol> {
    vec![super::TransportProtocol::Tcp]
}
pub fn default_parallel_connections() -> u8 {
    1 // Single connection to stay within iOS 15MB extension memory limit
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

pub fn default_connection_max_lifetime_s() -> u64 {
    300 // 5 minutes default to counter long-connection fingerprinting
}

pub fn default_connection_lifetime_jitter_s() -> u64 {
    60 // ±60s randomization to avoid synchronized rotation
}

pub fn default_mux_mode() -> String {
    "round_robin".to_string()
}
