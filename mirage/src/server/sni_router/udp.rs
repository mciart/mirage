//! UDP/QUIC SNI-based router.
//!
//! Receives raw UDP datagrams on the QUIC port, parses QUIC Initial packets
//! to extract the TLS SNI, then either forwards to a remote backend or delivers
//! to the local quinn endpoint.
//!
//! Performance: uses DashMap for lock-free session lookup and AtomicU64 for
//! lock-free last_seen updates. Each forwarded packet does one lock-free map
//! lookup + one atomic store — zero contention under load.

use super::quic_sni;
use crate::config::SniRouterConfig;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::time::Duration;
use tracing::{debug, info, warn};

/// Monotonic clock base — all last_seen values are relative to this.
static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn now_ms() -> u64 {
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_millis() as u64
}

/// Session entry for a UDP relay (one per client source address).
struct UdpSession {
    /// Backend address to forward to
    backend: SocketAddr,
    /// Socket used to communicate with the backend
    relay_socket: Arc<UdpSocket>,
    /// Last activity time (milliseconds since EPOCH, atomic for lock-free update)
    last_seen_ms: AtomicU64,
}

impl UdpSession {
    fn touch(&self) {
        self.last_seen_ms.store(now_ms(), Ordering::Relaxed);
    }

    fn idle_ms(&self) -> u64 {
        now_ms().saturating_sub(self.last_seen_ms.load(Ordering::Relaxed))
    }
}

/// UDP SNI Router: sits in front of the QUIC listener and routes by SNI.
pub struct UdpSniRouter {
    /// The frontend socket (client-facing, bound to the public port)
    listen_socket: Arc<UdpSocket>,
    /// Internal socket where local (quinn) traffic is forwarded
    local_addr: SocketAddr,
    /// SNI routing configuration
    sni_config: SniRouterConfig,
    /// Active relay sessions: src_addr → session (lock-free concurrent map)
    sessions: Arc<DashMap<SocketAddr, UdpSession>>,
}

impl UdpSniRouter {
    /// Creates and binds the UDP SNI router.
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
            sessions: Arc::new(DashMap::new()),
        })
    }

    /// Runs the UDP SNI router event loop.
    pub async fn run(self) -> crate::Result<()> {
        let mut buf = vec![0u8; 65535];

        // Spawn session cleanup task (every 60s, expire sessions idle > 120s)
        let sessions_cleanup = self.sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let before = sessions_cleanup.len();
                sessions_cleanup.retain(|_, s| s.idle_ms() < 120_000);
                let removed = before - sessions_cleanup.len();
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

            // Fast path: existing session (lock-free DashMap lookup + atomic touch)
            if let Some(session) = self.sessions.get(&src_addr) {
                let _ = session
                    .relay_socket
                    .send_to(datagram, session.backend)
                    .await;
                session.touch();
                continue;
            }

            // Slow path: new connection — extract SNI and create session
            let target = self.resolve_target(datagram);

            match target {
                RouteTarget::Local => {
                    self.create_session(src_addr, self.local_addr, datagram)
                        .await;
                }
                RouteTarget::Remote(backend_addr) => {
                    self.create_session(src_addr, backend_addr, datagram).await;
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

    /// Creates a new relay session and forwards the first datagram.
    async fn create_session(
        &self,
        client_addr: SocketAddr,
        backend_addr: SocketAddr,
        first_datagram: &[u8],
    ) {
        let relay_socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                warn!("UDP SNI Router: failed to create relay socket: {}", e);
                return;
            }
        };

        // Forward first datagram
        let _ = relay_socket.send_to(first_datagram, backend_addr).await;

        // Spawn reverse relay (backend → client)
        let listen_socket = self.listen_socket.clone();
        let sessions = self.sessions.clone();
        let relay_clone = relay_socket.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let result =
                    tokio::time::timeout(Duration::from_secs(120), relay_clone.recv_from(&mut buf))
                        .await;

                match result {
                    Ok(Ok((n, _))) => {
                        let _ = listen_socket.send_to(&buf[..n], client_addr).await;
                        // Touch session (lock-free)
                        if let Some(session) = sessions.get(&client_addr) {
                            session.touch();
                        }
                    }
                    Ok(Err(e)) => {
                        debug!(
                            "UDP SNI Router: reverse relay error for {}: {}",
                            client_addr, e
                        );
                        break;
                    }
                    Err(_) => {
                        debug!("UDP SNI Router: reverse relay timeout for {}", client_addr);
                        break;
                    }
                }
            }
            sessions.remove(&client_addr);
            debug!("UDP SNI Router: session ended for {}", client_addr);
        });

        // Store session
        self.sessions.insert(
            client_addr,
            UdpSession {
                backend: backend_addr,
                relay_socket,
                last_seen_ms: AtomicU64::new(now_ms()),
            },
        );
    }

    /// Resolves the routing target for a UDP datagram by parsing QUIC Initial.
    fn resolve_target(&self, datagram: &[u8]) -> RouteTarget {
        let sni = quic_sni::extract_quic_sni(datagram);

        match sni {
            Some(sni_str) => match self.sni_config.find_route(&sni_str) {
                Some(Some(backend)) => {
                    // Check protocol filter
                    let route = self
                        .sni_config
                        .routes
                        .iter()
                        .find(|r| r.sni.iter().any(|s| s == &sni_str));
                    if let Some(r) = route {
                        if r.protocol == "tcp" {
                            debug!(
                                "UDP SNI Router: SNI {} matched but protocol=tcp → local",
                                sni_str
                            );
                            return RouteTarget::Local;
                        }
                    }

                    match resolve_backend(backend) {
                        Some(addr) => {
                            info!("UDP SNI Router: QUIC SNI {} → {}", sni_str, addr);
                            RouteTarget::Remote(addr)
                        }
                        None => {
                            warn!(
                                "UDP SNI Router: can't resolve '{}' for SNI {}",
                                backend, sni_str
                            );
                            RouteTarget::Local
                        }
                    }
                }
                Some(None) => {
                    debug!("UDP SNI Router: QUIC SNI {} → local", sni_str);
                    RouteTarget::Local
                }
                None => {
                    if let Some(ref cfg) = self.sni_config.unknown_sni {
                        if let Some(ref backend) = cfg.backend {
                            if let Some(addr) = resolve_backend(backend) {
                                info!("UDP SNI Router: unknown QUIC SNI {} → {}", sni_str, addr);
                                return RouteTarget::Remote(addr);
                            }
                        }
                    }
                    RouteTarget::Local
                }
            },
            None => RouteTarget::Local,
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
