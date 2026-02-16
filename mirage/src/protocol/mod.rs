//! Protocol abstraction layer for the Mirage VPN system.
//!
//! This module organizes protocol-specific logic into dedicated submodules,
//! providing a clean separation between TCP, UDP (QUIC), and Camouflage protocols.

pub mod camouflage;
pub mod tcp;
pub mod tls_detect;
pub mod udp;
