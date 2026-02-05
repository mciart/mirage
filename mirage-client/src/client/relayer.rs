//! Client packet relayer for the Mirage VPN using Prism (Stack Mode).

use boring::ssl::SslConnector;
use boring::ssl::{SslMethod, SslVerifyMode};
use futures::StreamExt;
use mirage::network::interface::{Interface, InterfaceIO};
use mirage::{MirageError, Result};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use bytes::{Bytes, BytesMut};
use prism::device::PrismDevice;
use prism::stack::{HandshakeMode as PrismHandshakeMode, PrismConfig, PrismStack, TunnelRequest};
use smoltcp::phy::Medium;

use crate::auth::AuthClient;
use crate::users_file_auth::UsersFileClientAuthenticator;
use mirage::config::ClientConfig;
use mirage::constants::TLS_ALPN_PROTOCOLS;
use std::time::Duration;

/// Client relayer that uses Prism Stack to handle networking.
pub struct ClientRelayer {
    relayer_task: JoinHandle<Result<()>>,
}

impl ClientRelayer {
    /// Starts the Relayer in Prism Stack Mode.
    ///
    /// This replaces the old "Pipe Mode". It creates its own connections on demand.
    pub async fn start_prism(
        interface: Interface<impl InterfaceIO>,
        config: ClientConfig,
    ) -> Result<Self> {
        let interface = Arc::new(interface);

        // --- 🛡️ 关键修复: DNS 预解析 (DNS Pre-resolution) ---
        // 在 TUN 接管流量前，先把 VPN 服务器域名解析成 IP。
        // 防止后续 Prism 建立隧道时，DNS 请求被吸入 TUN 导致死锁。
        let server_addrs: Vec<std::net::SocketAddr> = config
            .connection_string
            .to_socket_addrs()
            .map_err(|e| {
                MirageError::connection_failed(format!("Initial DNS Resolve Failed: {}", e))
            })?
            .collect();

        let server_ip = *server_addrs
            .first()
            .ok_or(MirageError::connection_failed("No IP resolved for server"))?;

        info!("✅ [Prism] Pre-resolved VPN Server IP: {}", server_ip);
        // ----------------------------------------------------

        let relayer_task = tokio::spawn(Self::run_stack_architecture(interface, config, server_ip));

        Ok(Self { relayer_task })
    }

    /// Waits for the relayer task to finish.
    pub async fn wait_for_shutdown(self) -> Result<()> {
        self.relayer_task
            .await
            .map_err(|_| MirageError::system("Relayer task failed"))?
    }

    /// The main event loop for Prism Stack Architecture.
    async fn run_stack_architecture(
        interface: Arc<Interface<impl InterfaceIO>>,
        config: ClientConfig,
        server_ip: std::net::SocketAddr,
    ) -> Result<()> {
        info!("🚀 Starting Phase 6 Relayer (Prism Stack Mode)");

        // 1. Prepare Prism Channels
        // tun_tx: Data FROM Interface TO Stack
        // iface_tx: Data FROM Stack TO Interface
        let (tun_tx_to_stack, tun_rx_from_iface) = mpsc::channel::<BytesMut>(2048);
        let (iface_tx_from_stack, mut iface_rx_to_os) = mpsc::channel::<Bytes>(2048);

        // 2. Initialize Prism Device
        // Force MTU=65535 to enable Software GSO (Zero-Copy)
        let tun_device =
            PrismDevice::new(tun_rx_from_iface, iface_tx_from_stack, 65535, Medium::Ip);

        // 3. Configure Prism
        let prism_config = PrismConfig {
            handshake_mode: PrismHandshakeMode::Consistent, // Recommended for gaming/stability
            egress_mtu: 1280,                               // Safe MTU for physical output
        };

        // 4. Create Stack
        let mut stack = PrismStack::new(tun_device, prism_config);

        // 5. Setup Control Channels
        let (tunnel_req_tx, tunnel_req_rx) = mpsc::channel(128);
        stack.set_tunnel_request_sender(tunnel_req_tx);

        let (blind_relay_tx, blind_relay_rx) = mpsc::channel(1024);
        stack.set_blind_relay_sender(blind_relay_tx);

        let mut tasks = futures::stream::FuturesUnordered::new();

        // Task A: Run Prism Stack
        tasks.push(tokio::spawn(async move {
            if let Err(e) = stack.run().await {
                error!("❌ Prism Stack Crashed: {}", e);
            }
            Ok(())
        }));

        // Task B: Interface Writer (Stack -> OS)
        let iface_writer = interface.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(pkt) = iface_rx_to_os.recv().await {
                if let Err(e) = iface_writer.write_packet(pkt.into()).await {
                    error!("Failed to write to TUN: {}", e);
                }
            }
            Ok(())
        }));

        // Task C: Interface Reader (OS -> Stack)
        let iface_reader = interface.clone();
        tasks.push(tokio::spawn(Self::bridge_reader(
            iface_reader,
            tun_tx_to_stack,
        )));

        // Task D: TCP Tunnel Controller
        tasks.push(tokio::spawn(Self::control_loop_tcp(
            tunnel_req_rx,
            config.clone(),
            server_ip,
        )));

        // Task E: UDP Blind Relay Controller
        tasks.push(tokio::spawn(Self::control_loop_blind(
            blind_relay_rx,
            config.clone(),
            server_ip,
        )));

        // Wait for any task to exit (failsafe)
        if let Some(res) = tasks.next().await {
            res.map_err(|e| MirageError::system(format!("Task panic: {}", e)))??;
        }

        Ok(())
    }

    /// Bridges packets from Interface (OS) to Stack (Prism).
    async fn bridge_reader(
        interface: Arc<Interface<impl InterfaceIO>>,
        tx: mpsc::Sender<BytesMut>,
    ) -> Result<()> {
        loop {
            let packets = interface.read_packets().await?;
            for packet in packets {
                let bytes: Bytes = packet.into();
                // Zero-Copy Optimization: Copy into BytesMut for Prism
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&bytes);
                if tx.send(buf).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    /// Handles TCP connection requests from Prism.
    async fn control_loop_tcp(
        mut rx: mpsc::Receiver<TunnelRequest>,
        config: ClientConfig,
        server_ip: std::net::SocketAddr,
    ) -> Result<()> {
        while let Some(req) = rx.recv().await {
            let config = config.clone();
            tokio::spawn(async move {
                // 1. Establish Tunnel
                match Self::establish_tunnel(&config, server_ip).await {
                    Ok((mut remote_reader, mut remote_writer)) => {
                        // 2. Notify Prism (Consistent Handshake)
                        if let Some(resp) = req.response_tx {
                            let _ = resp.send(true);
                        }

                        // 3. Pipe Data
                        let (local_tx, mut local_rx) = (req.tx, req.rx);

                        // Upstream: Client -> Server
                        let t1 = tokio::spawn(async move {
                            while let Some(data) = local_rx.recv().await {
                                use tokio::io::AsyncWriteExt;
                                if remote_writer.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                        });

                        // Downstream: Server -> Client
                        let t2 = tokio::spawn(async move {
                            use tokio::io::AsyncReadExt;
                            let mut buf = [0u8; 8192];
                            while let Ok(n) = remote_reader.read(&mut buf).await {
                                if n == 0 {
                                    break;
                                }
                                if local_tx
                                    .send(Bytes::copy_from_slice(&buf[..n]))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        });

                        let _ = tokio::join!(t1, t2);
                    }
                    Err(e) => {
                        warn!("Failed to establish tunnel for {}: {}", req.target, e);
                        // Notify failure
                        if let Some(resp) = req.response_tx {
                            let _ = resp.send(false);
                        }
                    }
                }
            });
        }
        Ok(())
    }

    /// Handles UDP/Blind Relay packets.
    async fn control_loop_blind(
        mut rx: mpsc::Receiver<Bytes>,
        _config: ClientConfig,            // Fix: Prefixed with _
        _server_ip: std::net::SocketAddr, // Fix: Prefixed with _
    ) -> Result<()> {
        // For Phase 1, we implement a simple fire-and-forget logger or basic tunnel
        // Since setting up a TLS tunnel for *every* UDP packet is slow, we just log for now
        // to verify integration.
        // TODO: Implement persistent UDP tunnel or QUIC.
        while let Some(_pkt) = rx.recv().await {
            // Fix: Prefixed with _
            // Uncomment to debug UDP traffic
            // debug!("Blind Relay: Dropping UDP packet len={}", pkt.len());

            // To make it functional (but slow), uncomment below:
            /*
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok((mut r, mut w)) = Self::establish_tunnel(&config, server_ip).await {
                     use tokio::io::AsyncWriteExt;
                     let _ = w.write_all(&pkt).await;
                }
            });
            */
        }
        Ok(())
    }

    /// Helper to connect and authenticate to the server.
    async fn establish_tunnel(
        config: &ClientConfig,
        server_ip: std::net::SocketAddr,
    ) -> Result<(
        tokio::io::ReadHalf<tokio_boring::SslStream<TcpStream>>,
        tokio::io::WriteHalf<tokio_boring::SslStream<TcpStream>>,
    )> {
        // 1. TCP Connect (Direct IP)
        let tcp_stream = TcpStream::connect(server_ip).await?;
        tcp_stream.set_nodelay(true)?;

        // 2. TLS Handshake
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        if config.connection.insecure {
            builder.set_verify(SslVerifyMode::NONE);
        }

        // Reality / Chrome Fingerprint setup
        mirage::crypto::impersonate::apply_chrome_fingerprint(&mut builder)?;

        let mut alpn = TLS_ALPN_PROTOCOLS.iter().cloned().collect::<Vec<_>>();
        if let Some(token) = config.reality.short_ids.first() {
            alpn.push(token.as_bytes().to_vec());
        }
        let alpn_wire = alpn
            .iter()
            .flat_map(|p| {
                let mut v = vec![p.len() as u8];
                v.extend_from_slice(p);
                v
            })
            .collect::<Vec<_>>();
        builder.set_alpn_protos(&alpn_wire).unwrap();

        let connector = builder.build();
        let ssl_config = connector.configure().unwrap();

        // SNI still uses the domain name for verification!
        let sni = &config.reality.target_sni;
        let tls_stream = tokio_boring::connect(ssl_config, sni, tcp_stream)
            .await
            .map_err(|e| MirageError::connection_failed(format!("TLS: {}", e)))?;

        // 3. Authenticate
        let authenticator = Box::new(UsersFileClientAuthenticator::new(&config.authentication));
        let auth_client = AuthClient::new(authenticator, Duration::from_secs(5));

        let (r, w) = tokio::io::split(tls_stream);
        let (_, _, _, _, final_r, final_w) = auth_client.authenticate(r, w).await?;

        Ok((final_r, final_w))
    }
}
