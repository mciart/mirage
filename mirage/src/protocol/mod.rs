//! Protocol abstraction layer for the Mirage VPN system.
//!
//! This module organizes protocol-specific logic into dedicated submodules,
//! providing a clean separation between QUIC, TCP-TLS, and Reality protocols.

pub mod quic;
pub mod reality;
pub mod tcp_tls;
pub mod tls_detect;
