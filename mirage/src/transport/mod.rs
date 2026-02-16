//! Transport layer module for TCP/TLS connections.
//!
//! This module provides the core transport abstraction for Mirage,
//! replacing QUIC with TCP/TLS using BoringSSL.

pub mod framed;
pub mod jitter;
pub mod mux;
pub mod quic;
pub mod tcp;

pub use framed::FramedStream;
pub use quic::QuicStream;
