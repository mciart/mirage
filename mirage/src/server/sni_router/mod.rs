//! SNI-based port multiplexer for Mirage server.
//!
//! Routes incoming connections (TCP and UDP/QUIC) to different backends
//! based on the TLS Server Name Indication (SNI).
//!
//! - `tcp` — TCP SNI dispatch (TLS ClientHello peek)
//! - `udp` — UDP/QUIC SNI routing (QUIC Initial packet decryption)
//! - `quic_sni` — QUIC Initial packet SNI extractor (RFC 9001)

mod quic_sni;
pub mod tcp;
pub mod udp;

// Re-export the main types for use by server/mod.rs
pub use tcp::{proxy_connection, DispatchResult, TlsDispatcher};
pub use udp::UdpSniRouter;
