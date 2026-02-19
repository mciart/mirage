use std::io::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A wrapper around a QUIC stream (SendStream + RecvStream)
/// that implements AsyncRead and AsyncWrite.
pub struct QuicStream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.recv)
            .poll_read(cx, buf)
            .map_err(std::io::Error::other)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(std::io::Error::other)
    }
}

// Ensure QuicStream is compatible with our needs
unsafe impl Send for QuicStream {}
unsafe impl Sync for QuicStream {}

/// Creates a QUIC transport configuration.
///
/// When `constrained` is true (e.g. iOS Network Extension with 50 MB jetsam limit),
/// uses small window sizes (~1.5 MB total) to stay within memory limits.
/// Otherwise uses large Hysteria 2-style windows for maximum throughput.
pub fn common_transport_config(
    keep_alive_interval_s: u64,
    idle_timeout_s: u64,
    outer_mtu: u16,
    constrained: bool,
) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();

    // 1. Use BBR Congestion Control
    transport.congestion_controller_factory(std::sync::Arc::new(
        quinn::congestion::BbrConfig::default(),
    ));

    if constrained {
        // iOS / memory-constrained mode: tiny windows to stay under 50 MB jetsam limit.
        // Total potential buffer: ~1.5 MB vs ~100 MB in unconstrained mode.
        let stream_rw = 256 * 1024; // 256 KB
        transport
            .stream_receive_window(u32::try_from(stream_rw).expect("stream_rw fits u32").into());

        let conn_rw = 512 * 1024; // 512 KB
        transport.receive_window(u32::try_from(conn_rw).expect("conn_rw fits u32").into());
        transport.send_window(u64::try_from(conn_rw).expect("conn_rw fits u64"));

        transport.datagram_receive_buffer_size(Some(64 * 1024)); // 64 KB
        transport.max_concurrent_bidi_streams(4u32.into());
        transport.max_concurrent_uni_streams(4u32.into());
    } else {
        // Desktop / server mode: large windows for maximum throughput.
        let stream_rw = 20 * 1024 * 1024;
        transport
            .stream_receive_window(u32::try_from(stream_rw).expect("stream_rw fits u32").into());

        let conn_rw = 40 * 1024 * 1024;
        transport.receive_window(u32::try_from(conn_rw).expect("conn_rw fits u32").into());
        transport.send_window(u64::try_from(conn_rw).expect("conn_rw fits u64"));

        transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
        transport.max_concurrent_bidi_streams(10_000u32.into());
        transport.max_concurrent_uni_streams(10_000u32.into());
    }

    // Keep-alive, timeout
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(keep_alive_interval_s)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(idle_timeout_s))
            .expect("idle timeout within range"),
    ));

    // 7. Outer MTU / UDP Payload Size
    // Strictly cap MTU to prevent WSAEMSGSIZE (error 10040) on Windows.
    // Windows does not support UDP GSO/USO, so quinn-udp's segment batching
    // can produce oversized sendmsg() calls. We pin min_mtu = initial_mtu = outer_mtu
    // and cap MTU discovery to the same value, ensuring every UDP packet fits.
    let mtu = u16::max(1200, outer_mtu); // QUIC requires at least 1200
    transport.initial_mtu(mtu);
    transport.min_mtu(mtu); // Prevent quinn from probing below our target

    // Cap MTU discovery upper bound to our outer_mtu (no probing above)
    let mut mtu_config = quinn::MtuDiscoveryConfig::default();
    mtu_config.upper_bound(mtu);
    transport.mtu_discovery_config(Some(mtu_config));

    transport
}

/// Helper to configure QUIC client
pub fn configure_client(outer_mtu: u16) -> Result<quinn::ClientConfig> {
    // We'll use a dummy certificate verifier for now since we handle
    // verification logic in the connection later, or we can trust system roots.
    // However, quinn requires a crypto config.
    // For simplicity, we can use rustls defaults or insecure if needed.

    // For now, let's create a standard configuration.
    // Note: Verification will be handled by rustls mostly.

    // We rely on platform certs or custom roots.
    // This part might need adjustment based on how we want to handle auth.
    // For now, let's return a basic config that can be modified.

    let crypto = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    let mut client_config = quinn::ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("valid QUIC crypto config"),
    ));

    // Apply high-performance transport config
    // Default keep-alive: 25s, Timeout: 30s, MTU: user-defined
    let transport = common_transport_config(25, 30, outer_mtu, false);
    client_config.transport_config(std::sync::Arc::new(transport));

    Ok(client_config)
}
