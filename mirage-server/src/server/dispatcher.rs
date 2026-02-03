use mirage::Result;
use mirage::network::tls_detect::{parse_client_hello, ClientHelloInfo};
use mirage::{MirageError, config::ServerConfig};

use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub enum DispatchResult {
    /// Matched VPN traffic (authorized). Process as VPN.
    Accept(TcpStream),
    /// Matched probe traffic (valid SNI, invalid auth). Proxy to real target.
    Proxy(TcpStream, String),
    /// Standard traffic (invalid SNI or generic). Fallback to standard TLS.
    Fallback(TcpStream),
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
    /// 
    /// This function reads the start of the stream to parse the ClientHello.
    /// It then reconstructs the stream (by combining the read buffer with the stream)
    /// so that subsequent handlers see the full data.
    pub async fn dispatch(&self, stream: TcpStream) -> Result<DispatchResult> {
        let mut buf = vec![0u8; 4096];
        
        // Peek at the data without consuming it from the socket's perspective?
        // TcpStream::peek is available but might be platform specific or limited.
        // A more robust way in async Rust is to read into a buffer, parse it,
        // and then return a composite reader.
        // However, since we need to pass a raw `TcpStream` to `tokio_boring::accept`,
        // we cannot easily wrap it in a `Chain<Cursor<Vec<u8>>, TcpStream>`.
        //
        // FORTUNATELY, `tokio` TcpStream allows `peek`.
        // Let's try `peek` first. If it fails to return enough data, we wait.
        
        // Wait for readable
        stream.readable().await?;
        
        let n = stream.peek(&mut buf).await?;
        if n == 0 {
            // EOF or empty
            return Ok(DispatchResult::Fallback(stream));
        }

        match parse_client_hello(&buf[..n]) {
            Ok(Some(info)) => self.decide(stream, info),
            Ok(None) => {
                // Incomplete, but we scraped what we could. 
                // If it's not enough to be a ClientHello, assume fallback.
                Ok(DispatchResult::Fallback(stream))
            }
            Err(_) => {
                // Not a valid ClientHello or protocol mismatch -> Fallback
                Ok(DispatchResult::Fallback(stream))
            }
        }
    }

    fn decide(&self, stream: TcpStream, info: ClientHelloInfo) -> Result<DispatchResult> {
        if let Some(sni) = &info.sni {
            if sni == &self.target_sni {
                // SNI matches the disguised domain!
                // Step 2: Check ALPN for Auth Token
                
                if let Some(alpns) = &info.alpn {
                     // Check if any ALPN string is in our valid_tokens list
                     for proto in alpns {
                         if self.valid_tokens.contains(proto) {
                             debug!("Reality Match: SNI={} ALPN={} -> VPN", sni, proto);
                             return Ok(DispatchResult::Accept(stream));
                         }
                     }
                }
                
                info!("Reality Probe Detected: SNI={} No Valid Auth Token -> Proxying to {}", sni, self.target_sni);
                return Ok(DispatchResult::Proxy(stream, self.target_sni.clone()));
            }
        }

        // SNI mismatch or no SNI -> Fallback
        debug!("Fallback traffic: SNI={:?}", info.sni);
        Ok(DispatchResult::Fallback(stream))
    }
}

/// Proxies a TCP connection to a remote target.
/// This acts as a transparent TCP pipe.
pub async fn proxy_connection(mut source: TcpStream, target_host: &str) -> Result<()> {
    // Resolve target
    // Note: In production code, we should cache DNS or use a specific resolver.
    // Here we rely on system resolver for simplicity.
    let target_addr = format!("{}:443", target_host);
    info!("Proxying connection to {}", target_addr);

    let mut target = TcpStream::connect(&target_addr).await.map_err(|e| {
        MirageError::connection_failed(format!("Failed to connect to proxy target {}: {}", target_addr, e))
    })?;

    // Enable TCP_NODELAY on both sides for responsiveness
    let _ = source.set_nodelay(true);
    let _ = target.set_nodelay(true);

    // Bidirectional copy
    let (mut source_read, mut source_write) = source.split();
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
            // It's normal for proxy connections to be cut abruptly
            Ok(())
        }
    }
}
