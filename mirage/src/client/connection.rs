//! Connection establishment for the Mirage VPN client.
//!
//! Handles TCP (with Happy Eyeballs RFC 8305), TLS, and QUIC connection
//! establishment, DNS resolution, and endpoint caching.

use crate::config::TransportProtocol;
#[cfg(not(target_os = "ios"))]
use crate::network::socket_protect;
use crate::transport::quic::QuicStream;
use crate::{MirageError, Result};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use super::{MirageClient, TransportStream};

// ─── Happy Eyeballs (RFC 8305) ──────────────────────────────────────────────

/// Raw TCP connect to a single address with optional socket protection.
/// Standalone — no `&mut self` needed, safe to call concurrently.
pub(super) async fn tcp_connect_raw(
    addr: SocketAddr,
    #[cfg_attr(target_os = "ios", allow(unused))] physical_interface: Option<&str>,
) -> Result<TcpStream> {
    let tcp_socket = if addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4()
    } else {
        tokio::net::TcpSocket::new_v6()
    }
    .map_err(|e| MirageError::connection_failed(format!("Failed to create TCP socket: {e}")))?;

    // Bind socket to physical interface (anti-loop protection)
    #[cfg(not(target_os = "ios"))]
    if let Some(iface) = physical_interface {
        #[cfg(unix)]
        let raw_fd = {
            use std::os::fd::AsRawFd;
            tcp_socket.as_raw_fd()
        };
        #[cfg(windows)]
        let raw_fd = {
            use std::os::windows::io::AsRawSocket;
            tcp_socket.as_raw_socket()
        };
        if let Err(e) = socket_protect::protect_socket(raw_fd, iface, addr.is_ipv6()) {
            warn!(
                "Socket protect failed ({}), continuing without binding: {}",
                iface, e
            );
        }
    }

    tcp_socket
        .connect(addr)
        .await
        .map_err(|e| MirageError::connection_failed(format!("TCP connect to {addr}: {e}")))
}

/// Happy Eyeballs (RFC 8305): race TCP connections with staggered starts.
///
/// 1. Start connecting to `addrs[0]`
/// 2. After `attempt_delay` (250ms), if not done, *also* start `addrs[1]`
/// 3. Continue staggering until one succeeds or all fail
/// 4. First success cancels all others
pub(super) async fn happy_eyeballs_tcp(
    addrs: &[SocketAddr],
    physical_interface: Option<&str>,
    attempt_delay: Duration,
    overall_timeout: Duration,
) -> Result<(TcpStream, SocketAddr)> {
    use std::pin::Pin;
    use tokio::time::sleep;

    if addrs.is_empty() {
        return Err(MirageError::connection_failed("No addresses to connect to"));
    }

    // Single address — no racing needed
    if addrs.len() == 1 {
        let stream = tokio::time::timeout(
            overall_timeout,
            tcp_connect_raw(addrs[0], physical_interface),
        )
        .await
        .map_err(|_| {
            MirageError::connection_failed(format!(
                "Connection to {} timed out after {}s",
                addrs[0],
                overall_timeout.as_secs()
            ))
        })??;
        return Ok((stream, addrs[0]));
    }

    // Multiple addresses — race with staggered starts (RFC 8305 §5)
    #[allow(unused_assignments)]
    let mut last_error: Option<crate::error::MirageError> = None;
    #[allow(clippy::type_complexity)]
    let mut pending_futures: Vec<
        Pin<Box<dyn Future<Output = (usize, Result<TcpStream>)> + Send>>,
    > = Vec::new();
    let mut next_addr_idx = 1; // First attempt started immediately below

    // Start the first connection attempt immediately
    let iface = physical_interface.map(|s| s.to_owned());
    let addr = addrs[0];
    let iface_clone = iface.clone();
    pending_futures.push(Box::pin(async move {
        let result = tcp_connect_raw(addr, iface_clone.as_deref()).await;
        (0usize, result)
    }));
    info!("Happy Eyeballs: started attempt 0 → {}", addrs[0]);

    let deadline = tokio::time::Instant::now() + overall_timeout;

    loop {
        // Build the stagger delay (250ms until next attempt, or until deadline)
        let stagger = if next_addr_idx < addrs.len() {
            Some(sleep(attempt_delay))
        } else {
            None // No more addresses to start
        };

        tokio::select! {
            biased;

            // Check if any pending connections completed
            result = async {
                // Poll all pending futures, return the first to complete
                // We use a simple approach: select on the first few futures
                // Since we can't use FuturesUnordered without &mut, we use a custom approach
                poll_any(&mut pending_futures).await
            } => {
                let (idx, connect_result) = result;
                match connect_result {
                    Ok(stream) => {
                        info!(
                            "Happy Eyeballs: attempt {} succeeded → {} (first to connect)",
                            idx, addrs[idx]
                        );
                        // Drop all other pending futures (cancels them)
                        return Ok((stream, addrs[idx]));
                    }
                    Err(e) => {
                        warn!(
                            "Happy Eyeballs: attempt {} failed → {}: {}",
                            idx, addrs[idx], e
                        );
                        last_error = Some(e);

                        // If no more pending and no more to start, give up
                        if pending_futures.is_empty() && next_addr_idx >= addrs.len() {
                            break;
                        }

                        // If stagger timer already fired for this round, start next immediately
                        if next_addr_idx < addrs.len() && pending_futures.is_empty() {
                            let addr = addrs[next_addr_idx];
                            let idx = next_addr_idx;
                            let iface_clone = iface.clone();
                            pending_futures.push(Box::pin(async move {
                                let result = tcp_connect_raw(addr, iface_clone.as_deref()).await;
                                (idx, result)
                            }));
                            info!("Happy Eyeballs: started attempt {} → {}", idx, addr);
                            next_addr_idx += 1;
                        }
                    }
                }
            }

            // Stagger timer: start the next connection attempt
            _ = async { stagger.unwrap().await }, if stagger.is_some() => {
                if next_addr_idx < addrs.len() {
                    let addr = addrs[next_addr_idx];
                    let idx = next_addr_idx;
                    let iface_clone = iface.clone();
                    pending_futures.push(Box::pin(async move {
                        let result = tcp_connect_raw(addr, iface_clone.as_deref()).await;
                        (idx, result)
                    }));
                    info!("Happy Eyeballs: started attempt {} → {} (after {}ms stagger)", idx, addr, attempt_delay.as_millis());
                    next_addr_idx += 1;
                }
            }

            // Overall deadline
            _ = tokio::time::sleep_until(deadline) => {
                warn!("Happy Eyeballs: overall timeout ({}s) reached", overall_timeout.as_secs());
                return Err(MirageError::connection_failed(format!(
                    "All connection attempts timed out after {}s",
                    overall_timeout.as_secs()
                )));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        MirageError::connection_failed("All Happy Eyeballs connection attempts failed")
    }))
}

/// Poll a vec of boxed futures, returning the first to complete.
/// Removes the completed future from the vec.
async fn poll_any<T>(futures: &mut Vec<std::pin::Pin<Box<dyn Future<Output = T> + Send>>>) -> T {
    use std::task::Poll;
    use tokio::macros::support::poll_fn;

    assert!(!futures.is_empty(), "poll_any called with empty futures");

    poll_fn(|cx| {
        for i in 0..futures.len() {
            if let Poll::Ready(val) = futures[i].as_mut().poll(cx) {
                drop(futures.swap_remove(i));
                return Poll::Ready(val);
            }
        }
        Poll::Pending
    })
    .await
}

// ─── MirageClient Connection Methods ────────────────────────────────────────

impl MirageClient {
    /// Resolves the server address, potentially returning multiple IP addresses (IPv4 and IPv6)
    /// if Dual Stack is enabled.
    pub(super) async fn resolve_server_address(&self) -> Result<Vec<SocketAddr>> {
        let connection_string = self.config.server.to_connection_string();

        let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&connection_string)
            .await
            .map_err(|e| {
                MirageError::connection_failed(format!(
                    "Failed to resolve server address '{}': {}",
                    connection_string, e
                ))
            })?
            .collect();

        if addrs.is_empty() {
            return Err(MirageError::connection_failed(format!(
                "Could not resolve any address for '{}'",
                connection_string
            )));
        }

        // Happy Eyeballs (RFC 8305): interleave IPv6 and IPv4 addresses.
        // IPv6 gets first shot, but if it fails instantly (e.g. "Network unreachable"
        // on IPv4-only networks), we immediately try IPv4 without waiting.
        let v6: Vec<SocketAddr> = addrs.iter().filter(|a| a.is_ipv6()).cloned().collect();
        let v4: Vec<SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).cloned().collect();
        let mut addrs = Vec::with_capacity(v6.len() + v4.len());
        let max_len = std::cmp::max(v6.len(), v4.len());
        for i in 0..max_len {
            if i < v6.len() {
                addrs.push(v6[i]);
            }
            if i < v4.len() {
                addrs.push(v4[i]);
            }
        }

        info!(
            "Resolved addresses (Happy Eyeballs interleaved): {:?}",
            addrs
        );

        Ok(addrs)
    }

    /// Connects to the server using the configured protocols.
    /// For TCP: uses Happy Eyeballs (RFC 8305) to race connections concurrently.
    /// For QUIC: tries addresses sequentially (endpoint reuse constraint).
    pub(super) async fn connect_to_server(
        &mut self,
        resolved_addrs: &[SocketAddr],
    ) -> Result<(TransportStream, SocketAddr, String)> {
        let connection_string = self.config.server.to_connection_string();

        let protocols = self.config.transport.protocols.clone();
        if protocols.is_empty() {
            return Err(MirageError::config_error(
                "No transport protocols specified in configuration",
            ));
        }

        info!(
            "Connection Strategy: Resolved addresses: {:?}, Protocols: {:?}",
            resolved_addrs, protocols
        );

        let connect_timeout = Duration::from_secs(self.config.connection.timeout_s.min(10));
        let mut last_error = None;

        for protocol in &protocols {
            match protocol {
                TransportProtocol::Tcp => {
                    // ── TCP: Happy Eyeballs (RFC 8305) ──
                    info!(
                        "TCP Happy Eyeballs: racing {} addresses with 250ms stagger",
                        resolved_addrs.len()
                    );

                    match happy_eyeballs_tcp(
                        resolved_addrs,
                        self.physical_interface.as_deref(),
                        Duration::from_millis(250), // RFC 8305 §5: 250ms stagger
                        connect_timeout,
                    )
                    .await
                    {
                        Ok((tcp_stream, winner_addr)) => {
                            // Apply TCP optimizations on the winning connection
                            crate::transport::tcp::apply_all_optimizations(
                                &tcp_stream,
                                self.config.transport.tcp_nodelay,
                            );

                            debug!("TCP connection established to {}", winner_addr);

                            // TLS handshake
                            let mut connector_builder =
                                crate::protocol::tcp::build_connector(&self.config)?;

                            let sni = if self.config.camouflage.is_mirage() {
                                crate::protocol::camouflage::configure(
                                    &mut connector_builder,
                                    &self.config,
                                )?
                            } else {
                                let host = crate::protocol::tcp::resolve_sni(
                                    &self.config,
                                    &connection_string,
                                );
                                connector_builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;
                                host.to_string()
                            };

                            let connector = connector_builder.build();
                            let mut ssl_config = connector.configure().map_err(|e| {
                                MirageError::system(format!("Failed to configure SSL: {e}"))
                            })?;

                            if self.config.camouflage.is_mirage() || self.config.transport.insecure
                            {
                                ssl_config.set_verify_hostname(false);
                                debug!("Hostname verification disabled");
                            }

                            let tls_stream = tokio_boring::connect(ssl_config, &sni, tcp_stream)
                                .await
                                .map_err(|e| {
                                    MirageError::connection_failed(format!(
                                        "TLS handshake failed: {e}"
                                    ))
                                })?;

                            info!(
                                "TLS connection established: {} (Protocol: TCP, Winner: {})",
                                connection_string, winner_addr
                            );

                            return Ok((Box::new(tls_stream), winner_addr, protocol.to_string()));
                        }
                        Err(e) => {
                            warn!("TCP Happy Eyeballs failed: {}", e);
                            last_error = Some(e);
                        }
                    }
                }
                TransportProtocol::Udp => {
                    // ── QUIC: sequential (endpoint reuse constraint) ──
                    for server_addr in resolved_addrs {
                        info!(
                            "Attempting QUIC connection to {} (timeout: {}s)",
                            server_addr,
                            connect_timeout.as_secs()
                        );

                        match tokio::time::timeout(
                            connect_timeout,
                            self.connect_quic(*server_addr, &connection_string),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => {
                                info!(
                                    "QUIC connection established: {} (Winner: {})",
                                    connection_string, server_addr
                                );
                                return Ok((stream, *server_addr, protocol.to_string()));
                            }
                            Ok(Err(e)) => {
                                warn!("QUIC connect to {} failed: {}", server_addr, e);
                                last_error = Some(e);
                            }
                            Err(_) => {
                                warn!(
                                    "QUIC connect to {} timed out after {}s",
                                    server_addr,
                                    connect_timeout.as_secs()
                                );
                                last_error = Some(MirageError::connection_failed(format!(
                                    "QUIC connect to {} timed out",
                                    server_addr
                                )));
                            }
                        }
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            MirageError::connection_failed(format!(
                "All connection attempts to {:?} failed",
                resolved_addrs
            ))
        }))
    }

    /// QUIC connection handler. Manages endpoint caching, port hopping, and connection reuse.
    pub(super) async fn connect_quic(
        &mut self,
        server_addr: SocketAddr,
        connection_string: &str,
    ) -> Result<TransportStream> {
        info!(
            "Connecting via QUIC: {} → {}",
            connection_string, server_addr
        );

        // Check for Port Hopping Rotation
        if let Some(last_refresh) = self.last_quic_refresh {
            if self.config.transport.port_hopping_interval_s > 0
                && last_refresh.elapsed()
                    > std::time::Duration::from_secs(self.config.transport.port_hopping_interval_s)
            {
                info!("Port Hopping: Rotating QUIC connection and endpoint to new port...");
                self.quic_connection = None;
                self.quic_endpoint = None;
                self.last_quic_refresh = None;
            }
        }

        // QUIC Connection - Attempt Reuse
        if let Some(conn) = &self.quic_connection {
            if conn.close_reason().is_none() {
                match conn.open_bi().await {
                    Ok((send, recv)) => {
                        debug!("Reusing existing QUIC connection to {}", server_addr);
                        let stream = QuicStream::new(send, recv);
                        return Ok(Box::new(stream));
                    }
                    Err(e) => {
                        warn!(
                            "Failed to open stream on cached connection: {}, reconnecting...",
                            e
                        );
                        self.quic_connection = None;
                    }
                }
            } else {
                self.quic_connection = None;
            }
        }

        // Get or Create Endpoint (invalidate if address family changed)
        let endpoint =
            if let Some(endpoint) = &self.quic_endpoint {
                let cached_is_ipv6 = endpoint.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
                if cached_is_ipv6 != server_addr.is_ipv6() {
                    info!(
                    "QUIC endpoint address family mismatch (cached: {}, target: {}), recreating",
                    if cached_is_ipv6 { "IPv6" } else { "IPv4" },
                    if server_addr.is_ipv6() { "IPv6" } else { "IPv4" }
                );
                    self.quic_connection = None;
                    let endpoint = crate::protocol::udp::create_endpoint_with_protect(
                        &self.config,
                        server_addr,
                        self.physical_interface.as_deref(),
                    )?;
                    self.quic_endpoint = Some(endpoint.clone());
                    endpoint
                } else {
                    endpoint.clone()
                }
            } else {
                let endpoint = crate::protocol::udp::create_endpoint_with_protect(
                    &self.config,
                    server_addr,
                    self.physical_interface.as_deref(),
                )?;
                self.quic_endpoint = Some(endpoint.clone());
                endpoint
            };

        let host = crate::protocol::udp::resolve_sni(&self.config, connection_string);

        info!(
            "Connecting via QUIC to {} ({}, SNI: {}, JLS: {})",
            server_addr,
            if server_addr.is_ipv4() {
                "IPv4"
            } else {
                "IPv6"
            },
            host,
            if self.config.camouflage.is_jls() {
                "enabled"
            } else {
                "disabled"
            },
        );

        let connection = endpoint
            .connect(server_addr, host)
            .map_err(|e| {
                MirageError::connection_failed(format!(
                    "Failed to initiate QUIC connection to {} ({}): {}",
                    server_addr,
                    if server_addr.is_ipv4() {
                        "IPv4"
                    } else {
                        "IPv6"
                    },
                    e
                ))
            })?
            .await
            .map_err(|e| {
                MirageError::connection_failed(format!(
                    "QUIC handshake failed to {} ({}, JLS: {}): {:?}",
                    server_addr,
                    if server_addr.is_ipv4() {
                        "IPv4"
                    } else {
                        "IPv6"
                    },
                    if self.config.camouflage.is_jls() {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    e
                ))
            })?;

        info!("QUIC connection established with {}", server_addr);

        // Cache the connection
        self.quic_connection = Some(connection.clone());
        if self.last_quic_refresh.is_none() {
            self.last_quic_refresh = Some(std::time::Instant::now());
        }

        let (send, recv) = connection.open_bi().await.map_err(|e| {
            MirageError::connection_failed(format!("Failed to open QUIC stream: {}", e))
        })?;

        let stream = QuicStream::new(send, recv);
        Ok(Box::new(stream))
    }
}
