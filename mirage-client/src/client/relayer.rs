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
use tracing::{debug, error, info, warn}; // 确保 debug 被引入

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
    pub async fn start_prism(
        interface: Interface<impl InterfaceIO>,
        config: ClientConfig,
    ) -> Result<Self> {
        let interface = Arc::new(interface);

        // DNS Pre-resolution
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

        let relayer_task = tokio::spawn(Self::run_stack_architecture(interface, config, server_ip));

        Ok(Self { relayer_task })
    }

    pub async fn wait_for_shutdown(self) -> Result<()> {
        self.relayer_task
            .await
            .map_err(|_| MirageError::system("Relayer task failed"))?
    }

    async fn run_stack_architecture(
        interface: Arc<Interface<impl InterfaceIO>>,
        config: ClientConfig,
        server_ip: std::net::SocketAddr,
    ) -> Result<()> {
        info!("🚀 Starting Phase 6 Relayer (Prism Stack Mode)");

        // Channels
        let (tun_tx_to_stack, tun_rx_from_iface) = mpsc::channel::<BytesMut>(2048);
        let (iface_tx_from_stack, mut iface_rx_to_os) = mpsc::channel::<Bytes>(2048);

        // Device (MTU 65535 for GSO)
        let tun_device =
            PrismDevice::new(tun_rx_from_iface, iface_tx_from_stack, 65535, Medium::Ip);

        // Config
        let prism_config = PrismConfig {
            handshake_mode: PrismHandshakeMode::Consistent,
            egress_mtu: 1280,
        };

        // Stack
        let mut stack = PrismStack::new(tun_device, prism_config);

        // Control Channels
        let (tunnel_req_tx, tunnel_req_rx) = mpsc::channel(128);
        stack.set_tunnel_request_sender(tunnel_req_tx);

        let (blind_relay_tx, blind_relay_rx) = mpsc::channel(1024);
        stack.set_blind_relay_sender(blind_relay_tx);

        let mut tasks = futures::stream::FuturesUnordered::new();

        // 1. Run Stack
        tasks.push(tokio::spawn(async move {
            if let Err(e) = stack.run().await {
                error!("❌ Prism Stack Crashed: {}", e);
            }
            Ok(())
        }));

        // 2. Interface Writer
        let iface_writer = interface.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(pkt) = iface_rx_to_os.recv().await {
                if let Err(e) = iface_writer.write_packet(pkt.into()).await {
                    error!("Failed to write to TUN: {}", e);
                }
            }
            Ok(())
        }));

        // 3. Interface Reader
        let iface_reader = interface.clone();
        let tun_tx_for_bridge = tun_tx_to_stack.clone(); // Clone for bridge
        tasks.push(tokio::spawn(Self::bridge_reader(
            iface_reader,
            tun_tx_for_bridge,
        )));

        // 4. TCP Controller
        tasks.push(tokio::spawn(Self::control_loop_tcp(
            tunnel_req_rx,
            config.clone(),
            server_ip,
        )));

        // 5. UDP/Blind Relay Controller (核心修复点)
        // 传入 tun_tx_to_stack 以便将回包写回 TUN
        tasks.push(tokio::spawn(Self::control_loop_blind(
            blind_relay_rx,
            config.clone(),
            server_ip,
            tun_tx_to_stack,
        )));

        if let Some(res) = tasks.next().await {
            res.map_err(|e| MirageError::system(format!("Task panic: {}", e)))??;
        }

        Ok(())
    }

    async fn bridge_reader(
        interface: Arc<Interface<impl InterfaceIO>>,
        tx: mpsc::Sender<BytesMut>,
    ) -> Result<()> {
        loop {
            let packets = interface.read_packets().await?;
            for packet in packets {
                let bytes: Bytes = packet.into();
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&bytes);
                if tx.send(buf).await.is_err() {
                    return Ok(());
                }
            }
        }
    }

    async fn control_loop_tcp(
        mut rx: mpsc::Receiver<TunnelRequest>,
        config: ClientConfig,
        server_ip: std::net::SocketAddr,
    ) -> Result<()> {
        while let Some(req) = rx.recv().await {
            let config = config.clone();
            tokio::spawn(async move {
                match Self::establish_tunnel(&config, server_ip).await {
                    Ok((mut remote_reader, mut remote_writer)) => {
                        if let Some(resp) = req.response_tx {
                            let _ = resp.send(true);
                        }
                        let (local_tx, mut local_rx) = (req.tx, req.rx);

                        let t1 = tokio::spawn(async move {
                            while let Some(data) = local_rx.recv().await {
                                use tokio::io::AsyncWriteExt;
                                if remote_writer.write_all(&data).await.is_err() {
                                    break;
                                }
                            }
                        });

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
                        warn!("TCP Tunnel failed: {}", e);
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
    /// 修复: 解除了注释，现在真正建立连接并转发数据。
    async fn control_loop_blind(
        mut rx: mpsc::Receiver<Bytes>,
        config: ClientConfig,
        server_ip: std::net::SocketAddr,
        tun_tx: mpsc::Sender<BytesMut>, // 新增: 用于回注数据
    ) -> Result<()> {
        while let Some(pkt) = rx.recv().await {
            // [修复] 移除下划线，使用这些变量
            let config = config.clone();
            let tun_tx = tun_tx.clone();

            tokio::spawn(async move {
                // 简单的调试日志，证明 UDP 正在工作
                debug!("Blind Relay: Forwarding {} bytes", pkt.len());

                // 建立新的隧道用于转发此包
                match Self::establish_tunnel(&config, server_ip).await {
                    Ok((mut r, mut w)) => {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};

                        // 1. 发送 UDP/ICMP 包 (通过 TLS 封装)
                        if w.write_all(&pkt).await.is_ok() {
                            // 2. 等待回包 (带超时)
                            // UDP 是无连接的，但 DNS/Ping 通常会立刻回包。
                            // 我们保持连接 5 秒，收到回包就转发回去。
                            let mut buf = [0u8; 2048];
                            // 简单的超时逻辑
                            let timeout = tokio::time::sleep(Duration::from_secs(5));
                            tokio::pin!(timeout);

                            loop {
                                tokio::select! {
                                    res = r.read(&mut buf) => {
                                        match res {
                                            Ok(n) if n > 0 => {
                                                // 3. 将回包注入回 Prism/TUN
                                                let mut response = BytesMut::new();
                                                response.extend_from_slice(&buf[..n]);
                                                if tun_tx.send(response).await.is_err() {
                                                    break;
                                                }
                                            }
                                            _ => break, // EOF 或 错误
                                        }
                                    }
                                    _ = &mut timeout => {
                                        break; // 超时
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // 连接失败 (可能是网络抖动)
                        debug!("Blind Relay connect failed: {}", e);
                    }
                }
            });
        }
        Ok(())
    }

    async fn establish_tunnel(
        config: &ClientConfig,
        server_ip: std::net::SocketAddr,
    ) -> Result<(
        tokio::io::ReadHalf<tokio_boring::SslStream<TcpStream>>,
        tokio::io::WriteHalf<tokio_boring::SslStream<TcpStream>>,
    )> {
        let tcp_stream = TcpStream::connect(server_ip).await?;
        tcp_stream.set_nodelay(true)?;

        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        if config.connection.insecure {
            builder.set_verify(SslVerifyMode::NONE);
        }
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
        let sni = &config.reality.target_sni;

        let tls_stream = tokio_boring::connect(ssl_config, sni, tcp_stream)
            .await
            .map_err(|e| MirageError::connection_failed(format!("TLS: {}", e)))?;

        let authenticator = Box::new(UsersFileClientAuthenticator::new(&config.authentication));
        let auth_client = AuthClient::new(authenticator, Duration::from_secs(5));
        let (r, w) = tokio::io::split(tls_stream);
        let (_, _, _, _, final_r, final_w) = auth_client.authenticate(r, w).await?;

        Ok((final_r, final_w))
    }
}
