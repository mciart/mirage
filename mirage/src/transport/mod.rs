//! Transport layer module for TCP/TLS connections.
//!
//! This module provides the core transport abstraction for Mirage,
//! replacing QUIC with TCP/TLS using BoringSSL.

mod framed;

pub use framed::FramedStream;
