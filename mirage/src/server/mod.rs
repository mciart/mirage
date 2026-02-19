//! Mirage VPN Server implementation.
//!
//! This module provides the main MirageServer that listens for TCP/TLS connections
//! and handles authenticated client connections with packet relay.

pub mod address_pool;
mod connection;
mod dispatcher;
mod handler;
mod nat;
mod quic;
mod session;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::auth::server_auth::AuthServer;
use crate::config::ObfuscationConfig;
use crate::config::ServerConfig;
use crate::constants::{PACKET_BUFFER_SIZE, PACKET_CHANNEL_SIZE, TLS_ALPN_PROTOCOLS};
use crate::network::interface::{Interface, InterfaceIO};
use crate::network::packet::Packet;
use crate::users_file::UsersFileServerAuthenticator;
use crate::utils::tasks::abort_all;
use crate::{MirageError, Result};
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use bytes::Bytes;
use dashmap::DashMap;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, info, warn};

use self::address_pool::AddressPool;
use self::dispatcher::{proxy_connection, DispatchResult, TlsDispatcher};
use self::nat::NatManager;
use self::session::SessionContext;

type ConnectionQueues = Arc<DashMap<IpAddr, Sender<Bytes>>>;
/// Maps session_id to session context for connection pooling
type SessionQueues = Arc<DashMap<[u8; 8], SessionContext>>;

/// Represents a Mirage server encapsulating connections and TUN interface IO.
pub struct MirageServer {
    config: ServerConfig,
    connection_queues: ConnectionQueues,
    session_queues: SessionQueues,
    address_pool: Arc<AddressPool>,
}

impl MirageServer {
    /// Creates a new instance of the Mirage server.
    pub fn new(config: ServerConfig) -> Result<Self> {
        let address_pool = AddressPool::new(config.tunnel_network, config.tunnel_network_v6);

        Ok(Self {
            config,
            connection_queues: Arc::new(DashMap::new()),
            session_queues: Arc::new(DashMap::new()),
            address_pool: Arc::new(address_pool),
        })
    }

    /// Starts the server and listens for incoming connections.
    pub async fn run<I: InterfaceIO>(&self) -> Result<()> {
        let interface: Interface<I> = Interface::create(
            self.config.tunnel_network,
            self.config.tunnel_network_v6,
            self.config.connection.mtu,
            Some(self.config.tunnel_network.network()),
            self.config.tunnel_network_v6.map(|n| n.network()),
            self.config.interface_name.clone(),
            None,
            None,
        )?;
        let interface = Arc::new(interface);

        // Configure NAT if requested
        // Variable is named _nat_manager to keep it alive until the end of the function (RAII cleanup)
        // We mute unused warning because we only need it for Drop
        #[allow(unused_variables)]
        let mut _nat_manager = NatManager::new(
            self.config.nat.clone(),
            interface.name().unwrap_or_else(|| "unknown".to_string()),
            self.config.tunnel_network.to_string(),
            self.config.tunnel_network_v6.map(|n| n.to_string()),
        );
        _nat_manager.setup();

        let authenticator = Box::new(UsersFileServerAuthenticator::new(
            &self.config.authentication,
            self.address_pool.clone(),
        )?);
        let auth_server = Arc::new(AuthServer::new(
            authenticator,
            self.config.tunnel_network,
            self.config.tunnel_network_v6,
            Duration::from_secs(self.config.connection.timeout_s),
        ));

        let (sender, receiver) = channel(PACKET_CHANNEL_SIZE);

        let mut tasks = FuturesUnordered::new();

        tasks.extend([
            tokio::spawn(Self::process_outbound_traffic(
                interface.clone(),
                self.connection_queues.clone(),
            )),
            tokio::spawn(Self::process_inbound_traffic(
                self.connection_queues.clone(),
                interface,
                receiver,
                self.config.isolate_clients,
            )),
        ]);

        if self.config.quic_enabled {
            tasks.push(tokio::spawn(quic::run_quic_listener(
                self.config.clone(),
                auth_server.clone(),
                sender.clone(),
                self.connection_queues.clone(),
                self.session_queues.clone(),
                self.address_pool.clone(),
            )));
        }

        let handler_task = self.handle_connections(auth_server, sender);

        let result = tokio::select! {
            handler_task_result = handler_task => handler_task_result,
            Some(task_result) = tasks.next() => task_result?,
        };

        let _ = abort_all(tasks).await;

        result
    }

    /// Handles incoming TCP/TLS connections.
    async fn handle_connections(
        &self,
        auth_server: Arc<AuthServer>,
        ingress_queue: Sender<Packet>,
    ) -> Result<()> {
        // Create TLS acceptor with BoringSSL
        let acceptor = self.create_tls_acceptor()?;
        let acceptor = Arc::new(acceptor);

        // Bind TCP listener
        let bind_addr = SocketAddr::new(self.config.bind_address, self.config.bind_port);
        let listener = TcpListener::bind(bind_addr).await?;

        info!("Starting TLS server on: {}", bind_addr);

        let mut connection_tasks = FuturesUnordered::new();

        loop {
            tokio::select! {
                // New TCP connections
                accept_result = listener.accept() => {
                    let (tcp_stream, remote_addr) = match accept_result {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("Failed to accept TCP connection: {e}");
                            continue;
                        }
                    };

                    debug!("Received incoming connection from '{}'", remote_addr.ip());

                    // Apply TCP optimizations (best-effort, logged on failure)
                    crate::transport::tcp::apply_all_optimizations(
                        &tcp_stream,
                        self.config.connection.tcp_nodelay,
                    );

                    // Dispatch traffic (Camouflage / Standard / Proxy)
                    let dispatcher = TlsDispatcher::new(&self.config);

                    // Dispatch logic needs to be robust against probing
                    // We dispatch in a separate spawn to not block the acceptor loop
                    // while waiting for peek bytes.
                    let auth_server = auth_server.clone();
                    let ingress_queue = ingress_queue.clone();
                    let connection_queues = self.connection_queues.clone();
                    let session_queues = self.session_queues.clone();
                    let address_pool = self.address_pool.clone();
                    let acceptor = acceptor.clone();
                    let obfuscation = self.config.obfuscation.clone();
                    let inner_key = self.config.camouflage.inner_key.clone();

                    connection_tasks.push(tokio::spawn(async move {
                        match dispatcher.dispatch(tcp_stream).await {
                            Ok(DispatchResult::Accept(stream)) | Ok(DispatchResult::Fallback(stream)) => {
                                // Proceed with VPN Handshake
                                let tls_stream = match tokio_boring::accept(&acceptor, stream).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        warn!("TLS handshake failed: {e}");
                                        return Ok(());
                                    }
                                };

                                Self::handle_client(
                                    tls_stream,
                                    remote_addr,
                                    auth_server,
                                    ingress_queue,
                                    connection_queues,
                                    session_queues,
                                    address_pool,
                                    obfuscation.clone(),
                                    inner_key,
                                ).await
                            }
                            Ok(DispatchResult::Proxy(stream, target)) => {
                                // Proxy to real target
                                debug!("Proxying connection from {} to {}", remote_addr, target);
                                if let Err(e) = proxy_connection(stream, &target).await {
                                    warn!("Proxy error: {}", e);
                                }
                                Ok(())
                            }
                            Err(e) => {
                                warn!("Dispatch error for {}: {}", remote_addr, e);
                                Ok(())
                            }
                        }
                    }));
                }

                // Connection tasks completion
                Some(result) = connection_tasks.next() => {
                    if let Err(e) = result {
                        warn!("Connection task failed: {e}");
                    }
                }

                // Shutdown signal
                _ = signal::ctrl_c() => {
                    info!("Received shutdown signal, shutting down");
                    let _ = abort_all(connection_tasks).await;
                    return Ok(());
                }
            }
        }
    }

    /// Handles a single client connection: auth + packet relay.
    #[allow(clippy::too_many_arguments)]
    async fn handle_client<S>(
        stream: S,
        remote_addr: SocketAddr,
        auth_server: Arc<AuthServer>,
        ingress_queue: Sender<Packet>,
        connection_queues: ConnectionQueues,
        session_queues: SessionQueues,
        address_pool: Arc<AddressPool>,
        obfuscation: ObfuscationConfig,
        inner_key: Option<String>,
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        handler::handle_authenticated_stream(
            stream,
            remote_addr,
            "TLS",
            auth_server,
            ingress_queue,
            connection_queues,
            session_queues,
            address_pool,
            obfuscation,
            inner_key,
        )
        .await
    }

    /// Creates a TLS acceptor with BoringSSL.
    fn create_tls_acceptor(&self) -> Result<SslAcceptor> {
        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .map_err(|e| MirageError::system(format!("Failed to create SSL acceptor: {e}")))?;

        // Load certificate chain (including intermediate certificates)
        // IMPORTANT: Use set_certificate_chain_file instead of set_certificate_file
        // to load the complete chain (server cert + intermediate certs)
        acceptor_builder
            .set_certificate_chain_file(&self.config.certificate_file)
            .map_err(|e| MirageError::system(format!("Failed to load certificate chain: {e}")))?;

        // Load private key
        acceptor_builder
            .set_private_key_file(&self.config.certificate_key_file, SslFiletype::PEM)
            .map_err(|e| MirageError::system(format!("Failed to load private key: {e}")))?;

        // Set ALPN protocols (Chrome order)
        let alpn_protocols: Vec<u8> = TLS_ALPN_PROTOCOLS
            .iter()
            .flat_map(|p| {
                let mut v = vec![p.len() as u8];
                v.extend_from_slice(p);
                v
            })
            .collect();
        acceptor_builder
            .set_alpn_protos(&alpn_protocols)
            .map_err(|e| MirageError::system(format!("Failed to set ALPN: {e}")))?;

        // Don't require client certificates
        acceptor_builder.set_verify(SslVerifyMode::NONE);

        Ok(acceptor_builder.build())
    }

    /// Reads from TUN interface and routes to appropriate client connections.
    async fn process_outbound_traffic(
        interface: Arc<Interface<impl InterfaceIO>>,
        connection_queues: ConnectionQueues,
    ) -> Result<()> {
        debug!("Started tunnel outbound traffic task (interface -> connection queue)");

        loop {
            // OPTIMIZATION: Batch read from TUN interface
            let packets = interface.read_packets().await?;

            for packet in packets {
                let dest_addr = match packet.destination() {
                    Ok(addr) => addr,
                    Err(e) => {
                        warn!("Received packet with malformed header structure: {e}");
                        continue;
                    }
                };

                debug!("Destination address for packet: {dest_addr}");

                let connection_queue = match connection_queues.get(&dest_addr) {
                    Some(connection_queue) => connection_queue,
                    None => continue,
                };

                // Non-blocking send: if one client's channel is full, drop the packet
                // rather than blocking the TUN reader for ALL clients.
                if let Err(e) = connection_queue.try_send(packet.into()) {
                    match e {
                        tokio::sync::mpsc::error::TrySendError::Full(_) => {
                            debug!("Channel full for client {dest_addr}, dropping packet");
                        }
                        tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                            debug!("Channel closed for client {dest_addr}, removing from queue");
                            drop(connection_queue);
                            connection_queues.remove(&dest_addr);
                        }
                    }
                }
            }
        }
    }

    /// Receives packets from client connections and writes to TUN interface.
    async fn process_inbound_traffic(
        connection_queues: ConnectionQueues,
        interface: Arc<Interface<impl InterfaceIO>>,
        ingress_queue: Receiver<Packet>,
        isolate_clients: bool,
    ) -> Result<()> {
        debug!("Started tunnel inbound traffic task (tunnel queue -> interface)");

        if isolate_clients {
            relay_isolated(connection_queues, interface, ingress_queue).await
        } else {
            relay_unisolated(connection_queues, interface, ingress_queue).await
        }
    }
}

#[inline]
async fn relay_isolated(
    connection_queues: ConnectionQueues,
    interface: Arc<Interface<impl InterfaceIO>>,
    mut ingress_queue: Receiver<Packet>,
) -> Result<()> {
    loop {
        let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);
        ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        let filtered_packets = packets
            .into_iter()
            .filter(|packet| {
                let dest_addr = match packet.destination() {
                    Ok(addr) => addr,
                    Err(e) => {
                        warn!("Received packet with malformed header structure: {e}");
                        return false;
                    }
                };
                !connection_queues.contains_key(&dest_addr)
            })
            .collect::<Vec<_>>();

        interface.write_packets(filtered_packets).await?;
    }
}

#[inline]
async fn relay_unisolated(
    connection_queues: ConnectionQueues,
    interface: Arc<Interface<impl InterfaceIO>>,
    mut ingress_queue: Receiver<Packet>,
) -> Result<()> {
    loop {
        let mut packets = Vec::with_capacity(PACKET_BUFFER_SIZE);

        ingress_queue
            .recv_many(&mut packets, PACKET_BUFFER_SIZE)
            .await;

        for packet in packets {
            let dest_addr = match packet.destination() {
                Ok(addr) => addr,
                Err(e) => {
                    warn!("Received packet with malformed header structure: {e}");
                    continue;
                }
            };

            match connection_queues.get(&dest_addr) {
                // Send the packet to the appropriate TLS connection (non-blocking)
                Some(connection_queue) => {
                    if let Err(e) = connection_queue.try_send(packet.into()) {
                        match e {
                            tokio::sync::mpsc::error::TrySendError::Full(_) => {
                                debug!("Channel full for relay to {dest_addr}, dropping packet");
                            }
                            tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                                debug!("Channel closed for relay to {dest_addr}");
                                drop(connection_queue);
                                connection_queues.remove(&dest_addr);
                            }
                        }
                    }
                }
                // Send the packet to the TUN interface
                None => interface.write_packet(packet).await?,
            }
        }
    }
}
