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

/// Helper to configure QUIC client
pub fn configure_client() -> Result<quinn::ClientConfig> {
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
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap(),
    ));

    // Performance tuning
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
    ));
    client_config.transport_config(std::sync::Arc::new(transport));

    Ok(client_config)
}
