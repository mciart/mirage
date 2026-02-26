//! UDP/QUIC SNI-based router.
//!
//! Receives raw UDP datagrams on the QUIC port, parses QUIC Initial packets
//! to extract the TLS SNI, then either forwards to a remote backend or delivers
//! to the local quinn endpoint.
//!
//! For non-Initial packets (short header, handshake, etc.), uses a session table
//! keyed by (src_addr) to route to the correct backend.

use super::quic_sni;
use crate::config::SniRouterConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Session entry for a UDP relay (one per client source address).
struct UdpSession {
    /// Backend address to forward to
    backend: SocketAddr,
    /// Socket used to communicate with the backend
    relay_socket: Arc<UdpSocket>,
    /// Last activity time for session expiry
    last_seen: Instant,
}

/// UDP SNI Router: sits in front of the QUIC listener and routes by SNI.
pub struct UdpSniRouter {
    /// The frontend socket (client-facing, bound to the public port)
    listen_socket: Arc<UdpSocket>,
    /// Internal socket where local (quinn) traffic is forwarded
    local_addr: SocketAddr,
    /// SNI routing configuration
    sni_config: SniRouterConfig,
    /// Active relay sessions: src_addr → session
    sessions: Arc<RwLock<HashMap<SocketAddr, UdpSession>>>,
}

impl UdpSniRouter {
    /// Creates and binds the UDP SNI router.
    ///
    /// - `listen_addr`: the public address to listen on (e.g., 0.0.0.0:443)
    /// - `local_addr`: internal address where quinn is listening (e.g., 127.0.0.1:44301)
    /// - `sni_config`: the SNI routing configuration
    pub async fn new(
        listen_addr: SocketAddr,
        local_addr: SocketAddr,
        sni_config: SniRouterConfig,
    ) -> std::io::Result<Self> {
        let listen_socket = UdpSocket::bind(listen_addr).await?;
        info!("UDP SNI Router listening on {}", listen_addr);
        info!("UDP SNI Router: local quinn at {}", local_addr);

        Ok(Self {
            listen_socket: Arc::new(listen_socket),
            local_addr,
            sni_config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Runs the UDP SNI router event loop.
    pub async fn run(self) -> crate::Result<()> {
        let mut buf = vec![0u8; 65535];

        // Spawn session cleanup task (every 60s, expire sessions idle > 120s)
        let sessions_for_cleanup = self.sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mut sessions = sessions_for_cleanup.write().await;
                let before = sessions.len();
                sessions.retain(|_, s| s.last_seen.elapsed() < Duration::from_secs(120));
                let removed = before - sessions.len();
                if removed > 0 {
                    debug!("UDP SNI Router: cleaned up {} expired sessions", removed);
                }
            }
        });

        loop {
            let (n, src_addr) = match self.listen_socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(e) => {
                    warn!("UDP SNI Router: recv error: {}", e);
                    continue;
                }
            };
            let datagram = &buf[..n];

            // Check if we have an existing session for this source
            {
                let sessions = self.sessions.read().await;
                if let Some(session) = sessions.get(&src_addr) {
                    // Forward to known backend
                    let _ = session
                        .relay_socket
                        .send_to(datagram, session.backend)
                        .await;
                    // Update last_seen (we'll do this outside the read lock)
                    drop(sessions);
                    let mut sessions = self.sessions.write().await;
                    if let Some(session) = sessions.get_mut(&src_addr) {
                        session.last_seen = Instant::now();
                    }
                    continue;
                }
            }

            // No session — try to extract SNI from this datagram
            let target = self.resolve_target(datagram);

            match target {
                RouteTarget::Local => {
                    // Forward to local quinn endpoint
                    let local_socket = UdpSocket::bind("0.0.0.0:0").await.ok();
                    if let Some(relay_socket) = local_socket {
                        let relay_socket = Arc::new(relay_socket);
                        let _ = relay_socket.send_to(datagram, self.local_addr).await;

                        // Spawn reverse relay (backend → client)
                        self.spawn_reverse_relay(src_addr, self.local_addr, relay_socket.clone());

                        // Store session
                        let mut sessions = self.sessions.write().await;
                        sessions.insert(
                            src_addr,
                            UdpSession {
                                backend: self.local_addr,
                                relay_socket,
                                last_seen: Instant::now(),
                            },
                        );
                    }
                }
                RouteTarget::Remote(backend_addr) => {
                    // Forward to remote backend
                    let relay_socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                        Err(e) => {
                            warn!("UDP SNI Router: failed to create relay socket: {}", e);
                            continue;
                        }
                    };
                    let _ = relay_socket.send_to(datagram, backend_addr).await;

                    // Spawn reverse relay (backend → client)
                    self.spawn_reverse_relay(src_addr, backend_addr, relay_socket.clone());

                    // Store session
                    let mut sessions = self.sessions.write().await;
                    sessions.insert(
                        src_addr,
                        UdpSession {
                            backend: backend_addr,
                            relay_socket,
                            last_seen: Instant::now(),
                        },
                    );

                    info!(
                        "UDP SNI Router: new session {} → {}",
                        src_addr, backend_addr
                    );
                }
                RouteTarget::Drop => {
                    debug!("UDP SNI Router: dropping datagram from {}", src_addr);
                }
            }
        }
    }

    /// Spawns a task that relays packets from the backend back to the client.
    fn spawn_reverse_relay(
        &self,
        client_addr: SocketAddr,
        _backend_addr: SocketAddr,
        relay_socket: Arc<UdpSocket>,
    ) {
        let listen_socket = self.listen_socket.clone();
        let sessions = self.sessions.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let result = tokio::time::timeout(
                    Duration::from_secs(120),
                    relay_socket.recv_from(&mut buf),
                )
                .await;

                match result {
                    Ok(Ok((n, _from))) => {
                        // Send back to client via the frontend socket
                        let _ = listen_socket.send_to(&buf[..n], client_addr).await;

                        // Update last_seen
                        let mut sessions = sessions.write().await;
                        if let Some(session) = sessions.get_mut(&client_addr) {
                            session.last_seen = Instant::now();
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(
                            "UDP SNI Router: reverse relay error for {}: {}",
                            client_addr, e
                        );
                        break;
                    }
                    Err(_timeout) => {
                        debug!("UDP SNI Router: reverse relay timeout for {}", client_addr);
                        break;
                    }
                }
            }

            // Clean up session
            let mut sessions = sessions.write().await;
            sessions.remove(&client_addr);
            debug!("UDP SNI Router: session cleaned up for {}", client_addr);
        });
    }

    /// Resolves the routing target for a UDP datagram by parsing QUIC Initial.
    fn resolve_target(&self, datagram: &[u8]) -> RouteTarget {
        // Try to extract SNI from QUIC Initial packet
        let sni = quic_sni::extract_quic_sni(datagram);

        match sni {
            Some(sni_str) => {
                // Check SNI route table
                match self.sni_config.find_route(&sni_str) {
                    Some(Some(backend)) => {
                        // Route to remote backend
                        // Only route if protocol is "udp" or "both"
                        let route = self
                            .sni_config
                            .routes
                            .iter()
                            .find(|r| r.sni.iter().any(|s| s == &sni_str));
                        if let Some(r) = route {
                            if r.protocol == "tcp" {
                                debug!(
                                    "UDP SNI Router: SNI {} matched but protocol=tcp, treating as local",
                                    sni_str
                                );
                                return RouteTarget::Local;
                            }
                        }

                        // Resolve backend address
                        match resolve_backend(backend) {
                            Some(addr) => {
                                info!("UDP SNI Router: QUIC SNI {} → {}", sni_str, addr);
                                RouteTarget::Remote(addr)
                            }
                            None => {
                                warn!(
                                    "UDP SNI Router: failed to resolve backend '{}' for SNI {}",
                                    backend, sni_str
                                );
                                RouteTarget::Local
                            }
                        }
                    }
                    Some(None) => {
                        // Local handling
                        debug!("UDP SNI Router: QUIC SNI {} → local", sni_str);
                        RouteTarget::Local
                    }
                    None => {
                        // Unknown SNI
                        if let Some(ref cfg) = self.sni_config.unknown_sni {
                            if let Some(ref backend) = cfg.backend {
                                if let Some(addr) = resolve_backend(backend) {
                                    info!(
                                        "UDP SNI Router: unknown QUIC SNI {} → {}",
                                        sni_str, addr
                                    );
                                    return RouteTarget::Remote(addr);
                                }
                            }
                        }
                        // Default to local
                        RouteTarget::Local
                    }
                }
            }
            None => {
                // Can't extract SNI (not an Initial packet, or parsing failed)
                // Default to local
                RouteTarget::Local
            }
        }
    }
}

#[allow(dead_code)]
enum RouteTarget {
    Local,
    Remote(SocketAddr),
    Drop,
}

/// Resolves a backend string ("host:port") to a SocketAddr.
fn resolve_backend(backend: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    backend.to_socket_addrs().ok()?.next()
}
