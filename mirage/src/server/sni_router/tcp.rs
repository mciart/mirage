use crate::config::SniRouterConfig;
use crate::protocol::tls_detect::{parse_client_hello, ClientHelloInfo};
use crate::Result;
use crate::{config::ServerConfig, MirageError};
use subtle::ConstantTimeEq;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub enum DispatchResult {
    /// Matched VPN traffic (authorized). Process as VPN.
    Accept(Box<dyn AsyncIo>),
    /// Proxy to a remote backend (host:port).
    Proxy(Box<dyn AsyncIo>, String),
    /// Standard traffic (fallback to standard TLS).
    Fallback(Box<dyn AsyncIo>),
}

pub struct TlsDispatcher {
    target_sni: String,
    valid_tokens: Vec<String>,
    sni_router: SniRouterConfig,
}

impl TlsDispatcher {
    pub fn new(config: &ServerConfig) -> Self {
        let valid_tokens = config.camouflage.short_ids.clone();

        Self {
            target_sni: config.camouflage.target_sni.clone(),
            valid_tokens,
            sni_router: config.sni_router.clone(),
        }
    }

    /// Inspects the initial bytes of a TCP stream to decide how to route it.
    pub async fn dispatch(&self, mut stream: TcpStream) -> Result<DispatchResult> {
        if let Err(e) = stream.set_nodelay(true) {
            warn!("Failed to set TCP_NODELAY on incoming connection: {}", e);
        }

        let mut buf = Vec::with_capacity(4096);
        let mut temp_buf = [0u8; 1024];

        loop {
            if buf.len() > 16384 {
                return self.handle_non_tls(buf, stream);
            }

            let n = stream.read(&mut temp_buf).await?;
            if n == 0 {
                if buf.is_empty() {
                    return Ok(DispatchResult::Fallback(Box::new(stream)));
                } else {
                    return self.handle_non_tls(buf, stream);
                }
            }

            buf.extend_from_slice(&temp_buf[..n]);

            match parse_client_hello(&buf) {
                Ok(Some(info)) => {
                    let prefixed_stream = Box::new(PrefixedStream::new(buf, stream));
                    return self.decide(prefixed_stream, info);
                }
                Ok(None) => {
                    debug!("ClientHello incomplete, buffered {} bytes", buf.len());
                    continue;
                }
                Err(e) => {
                    debug!(
                        "Not a TLS ClientHello: {}. Buffer: {} bytes, first 16: {:02x?}",
                        e,
                        buf.len(),
                        &buf[..std::cmp::min(16, buf.len())]
                    );
                    // Not TLS at all → non_tls route
                    return self.handle_non_tls(buf, stream);
                }
            }
        }
    }

    /// Route non-TLS traffic (Minecraft, SSH, HTTP plaintext, etc.)
    fn handle_non_tls(&self, buf: Vec<u8>, stream: TcpStream) -> Result<DispatchResult> {
        let prefixed = Box::new(PrefixedStream::new(buf, stream));

        if !self.sni_router.enabled {
            return Ok(DispatchResult::Fallback(prefixed));
        }

        if let Some(ref cfg) = self.sni_router.non_tls {
            if let Some(ref backend) = cfg.backend {
                info!("SNI Router: non-TLS traffic → {}", backend);
                return Ok(DispatchResult::Proxy(prefixed, backend.clone()));
            }
        }

        debug!("SNI Router: non-TLS traffic, no backend configured → reject");
        Ok(DispatchResult::Fallback(prefixed))
    }

    fn decide(&self, stream: Box<dyn AsyncIo>, info: ClientHelloInfo) -> Result<DispatchResult> {
        // ── SNI Router (if enabled) ──
        if self.sni_router.enabled {
            match &info.sni {
                Some(sni) => {
                    // Check SNI route table first
                    match self.sni_router.find_route(sni) {
                        Some(Some(backend)) => {
                            // SNI matches a route with a remote backend
                            info!("SNI Router: {} → {}", sni, backend);
                            return Ok(DispatchResult::Proxy(stream, backend.to_string()));
                        }
                        Some(None) => {
                            // SNI matches a route for local handling → continue to VPN logic below
                            debug!("SNI Router: {} → local Mirage", sni);
                        }
                        None => {
                            // SNI not in route table → check unknown_sni fallback
                            // But first check if it matches the camouflage target_sni
                            // (handles case where target_sni is not in route table)
                            if sni != &self.target_sni {
                                if let Some(ref cfg) = self.sni_router.unknown_sni {
                                    if let Some(ref backend) = cfg.backend {
                                        info!("SNI Router: unknown SNI {} → {}", sni, backend);
                                        return Ok(DispatchResult::Proxy(stream, backend.clone()));
                                    }
                                }
                            }
                            // Fall through to camouflage logic
                        }
                    }
                }
                None => {
                    // TLS but no SNI → tls_no_sni fallback
                    if let Some(ref cfg) = self.sni_router.tls_no_sni {
                        if let Some(ref backend) = cfg.backend {
                            info!("SNI Router: TLS without SNI → {}", backend);
                            return Ok(DispatchResult::Proxy(stream, backend.clone()));
                        }
                    }
                    // Fall through to camouflage logic
                }
            }
        }

        // ── Original camouflage logic ──
        if let Some(sni) = &info.sni {
            if sni == &self.target_sni {
                if let Some(alpns) = &info.alpn {
                    for proto in alpns {
                        for valid_token in &self.valid_tokens {
                            if proto.as_bytes().ct_eq(valid_token.as_bytes()).into() {
                                debug!("Camouflage Match: SNI={} ALPN={} → VPN", sni, proto);
                                return Ok(DispatchResult::Accept(stream));
                            }
                        }
                    }
                }

                info!(
                    "Camouflage Probe Detected: SNI={} No Valid Auth Token → Proxying to {}",
                    sni, self.target_sni
                );
                return Ok(DispatchResult::Proxy(stream, self.target_sni.clone()));
            }
        }

        debug!("Fallback traffic: SNI={:?}", info.sni);
        Ok(DispatchResult::Fallback(stream))
    }
}

/// A wrapper that makes `TcpStream` compatible with `dyn AsyncIo`
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
        if self.prefix.position() < self.prefix.get_ref().len() as u64 {
            let b = self.prefix.get_ref();
            let pos = self.prefix.position() as usize;
            let available = &b[pos..];

            let to_read = std::cmp::min(available.len(), buf.remaining());
            buf.put_slice(&available[..to_read]);
            self.prefix.set_position((pos + to_read) as u64);
            return std::task::Poll::Ready(Ok(()));
        }

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
/// `target_host` should be in `host:port` format. Falls back to `:443` if no port specified.
pub async fn proxy_connection(source: Box<dyn AsyncIo>, target_host: &str) -> Result<()> {
    // If target already has a port, use as-is; otherwise append :443
    let target_addr = if target_host.contains(':') {
        target_host.to_string()
    } else {
        format!("{}:443", target_host)
    };
    info!("Proxying connection to {}", target_addr);

    let mut target = TcpStream::connect(&target_addr).await.map_err(|e| {
        MirageError::connection_failed(format!(
            "Failed to connect to proxy target {}: {}",
            target_addr, e
        ))
    })?;

    let _ = target.set_nodelay(true);

    let (mut source_read, mut source_write) = tokio::io::split(source);
    let (mut target_read, mut target_write) = target.split();

    let client_to_server = tokio::io::copy(&mut source_read, &mut target_write);
    let server_to_client = tokio::io::copy(&mut target_read, &mut source_write);

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
