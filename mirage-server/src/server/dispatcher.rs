use mirage::network::tls_detect::{parse_client_hello, ClientHelloInfo};
use mirage::Result;
use mirage::{config::ServerConfig, MirageError};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub enum DispatchResult {
    /// Matched VPN traffic (authorized). Process as VPN.
    Accept(Box<dyn AsyncIo>),
    /// Matched probe traffic (valid SNI, invalid auth). Proxy to real target.
    Proxy(Box<dyn AsyncIo>, String),
    /// Standard traffic (invalid SNI or generic). Fallback to standard TLS.
    Fallback(Box<dyn AsyncIo>),
}

pub struct TlsDispatcher {
    target_sni: String,
    valid_tokens: Vec<String>,
}

impl TlsDispatcher {
    pub fn new(config: &ServerConfig) -> Self {
        let valid_tokens = config.reality.short_ids.clone();

        Self {
            target_sni: config.reality.target_sni.clone(),
            valid_tokens,
        }
    }

    /// Inspects the initial bytes of a TCP stream to decide how to route it.
    pub async fn dispatch(&self, mut stream: TcpStream) -> Result<DispatchResult> {
        // [新增] 强制开启 TCP_NODELAY，这对降低延迟至关重要
        // 否则在 Buffer 模式下，小包（如 Ping）会被 OS 卡住等待合并
        if let Err(e) = stream.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY on incoming connection: {}", e);
        }

        let mut buf = Vec::with_capacity(4096);
        let mut temp_buf = [0u8; 1024];

        // Loop until we have enough data to decide or fail
        loop {
            // Check if we hit size limit to prevent DoS
            if buf.len() > 16384 {
                return Ok(DispatchResult::Fallback(Box::new(PrefixedStream::new(
                    buf, stream,
                ))));
            }

            let n = stream.read(&mut temp_buf).await?;
            if n == 0 {
                // EOF
                if buf.is_empty() {
                    // Empty stream, just return generic Fallback (will likely close)
                    return Ok(DispatchResult::Fallback(Box::new(stream)));
                } else {
                    return Ok(DispatchResult::Fallback(Box::new(PrefixedStream::new(
                        buf, stream,
                    ))));
                }
            }

            buf.extend_from_slice(&temp_buf[..n]);

            match parse_client_hello(&buf) {
                Ok(Some(info)) => {
                    let prefixed_stream = Box::new(PrefixedStream::new(buf, stream));
                    return self.decide(prefixed_stream, info);
                }
                Ok(None) => {
                    // Incomplete, continue reading
                    debug!("ClientHello incomplete, buffered {} bytes", buf.len());
                    continue;
                }
                Err(e) => {
                    warn!(
                        "TLS Parse Failed: {}. Buffer size: {}. First 16 bytes: {:02x?}",
                        e,
                        buf.len(),
                        &buf[..std::cmp::min(16, buf.len())]
                    );
                    // Not a valid ClientHello or protocol mismatch -> Fallback
                    let prefixed_stream = Box::new(PrefixedStream::new(buf, stream));
                    return Ok(DispatchResult::Fallback(prefixed_stream));
                }
            }
        }
    }

    fn decide(&self, stream: Box<dyn AsyncIo>, info: ClientHelloInfo) -> Result<DispatchResult> {
        if let Some(sni) = &info.sni {
            if sni == &self.target_sni {
                // SNI matches the disguised domain!

                if let Some(alpns) = &info.alpn {
                    // Check if any ALPN string matches a valid token using constant-time comparison
                    // This prevents timing side-channel attacks that could leak valid tokens
                    for proto in alpns {
                        for valid_token in &self.valid_tokens {
                            if proto.as_bytes().ct_eq(valid_token.as_bytes()).into() {
                                debug!("Reality Match: SNI={} ALPN={} -> VPN", sni, proto);
                                return Ok(DispatchResult::Accept(stream));
                            }
                        }
                    }
                }

                info!(
                    "Reality Probe Detected: SNI={} No Valid Auth Token -> Proxying to {}",
                    sni, self.target_sni
                );
                return Ok(DispatchResult::Proxy(stream, self.target_sni.clone()));
            }
        }

        // SNI mismatch or no SNI -> Fallback
        debug!("Fallback traffic: SNI={:?}", info.sni);
        Ok(DispatchResult::Fallback(stream))
    }
}

/// A wrapper that makes `TcpStream` compatible with `dyn AsyncIo`
/// Not stricly necessary if we use generics, but simplifies `DispatchResult` to use `Box<dyn AsyncIo>`
pub trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> AsyncIo for T {}

/// A stream that reads from a prefix buffer first, then the underlying stream.
pub struct PrefixedStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    stream: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, stream: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            stream,
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // First try to read from prefix
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            let b = self.prefix.get_ref();
            let pos = self.prefix.position() as usize;
            let available = &b[pos..];

            let to_read = std::cmp::min(available.len(), buf.remaining());
            buf.put_slice(&available[..to_read]);
            self.prefix.set_position((pos + to_read) as u64);
            return std::task::Poll::Ready(Ok(()));
        }

        // If prefix exhausted, read from stream
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Proxies a TCP connection to a remote target.
/// This acts as a transparent TCP pipe.
pub async fn proxy_connection(source: Box<dyn AsyncIo>, target_host: &str) -> Result<()> {
    // Resolve target
    let target_addr = format!("{}:443", target_host);
    info!("Proxying connection to {}", target_addr);

    let mut target = TcpStream::connect(&target_addr).await.map_err(|e| {
        MirageError::connection_failed(format!(
            "Failed to connect to proxy target {}: {}",
            target_addr, e
        ))
    })?;

    // Enable TCP_NODELAY on both sides for responsiveness
    // Note: source is boxed trait object, we can't easily set nodelay unless we downcast
    // or assume it was already set. For `TcpStream` it was set.
    // For `PrefixedStream`, we should set it on inner `TcpStream` *before* boxing.
    // We'll skip setting it on source here for now.
    let _ = target.set_nodelay(true);

    // Bidirectional copy
    let (mut source_read, mut source_write) = tokio::io::split(source);
    let (mut target_read, mut target_write) = target.split();

    // Use tokio::io::copy for efficient piping
    let client_to_server = tokio::io::copy(&mut source_read, &mut target_write);
    let server_to_client = tokio::io::copy(&mut target_read, &mut source_write);

    // Run both directions
    match tokio::try_join!(client_to_server, server_to_client) {
        Ok(_) => {
            debug!("Proxy connection closed normally");
            Ok(())
        }
        Err(e) => {
            warn!("Proxy connection ended with error: {}", e);
            Ok(())
        }
    }
}
