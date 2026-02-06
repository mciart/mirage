#![windows_subsystem = "windows"]

use clap::Parser;
use mirage::config::{ClientConfig, FromPath};
use mirage::network::interface::tun_rs::TunRsInterface;
use mirage::{MirageError, Result};
use mirage_client::client::MirageClient;
use mirage_gui::gui::GuiError;
use mirage_gui::ipc::{ClientStatus, ConnectionMetrics, ConnectionStatus, IpcClient, IpcMessage};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "mirage-client-daemon")]
pub struct Args {
    #[arg(long)]
    pub instance_name: String,
    #[arg(long)]
    pub config_path: PathBuf,
    #[arg(long)]
    pub socket_path: PathBuf,
    #[arg(long)]
    pub log_path: PathBuf,
    #[arg(long, default_value = "MIRAGE_")]
    pub env_prefix: String,
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

#[derive(Clone, Default)]
struct ConnectionState {
    start_time: Option<Instant>,
    client_address: Option<ipnet::IpNet>,
    server_address: Option<ipnet::IpNet>,
    is_running: bool,
}

struct ClientDaemon {
    state: Arc<Mutex<ConnectionState>>,
    instance_name: String,
    shutdown_tx: broadcast::Sender<()>,
}

impl ClientDaemon {
    fn new(instance_name: String) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            state: Arc::new(Mutex::new(ConnectionState::default())),
            instance_name,
            shutdown_tx,
        }
    }

    async fn start_client_cancellable(
        &self,
        config_path: PathBuf,
        env_prefix: &str,
        mut cancel_rx: oneshot::Receiver<()>,
    ) -> Result<bool> {
        let state = self.state.clone();

        {
            let state_guard = state.lock().await;
            if state_guard.is_running {
                return Err(MirageError::system("Client is already running"));
            }
        }

        let config = ClientConfig::from_path(&config_path, env_prefix)?;
        let mut client = MirageClient::new(config);

        let (tx, rx) = oneshot::channel();
        let state_clone = state.clone();

        let client_task = tokio::spawn(async move {
            // [修复] 传入 None 作为 shutdown_signal, Some(tx) 作为 connection_event_tx
            // 这里使用 std::future::Pending<()> 显式指定泛型 F
            let result = client
                .start::<TunRsInterface, std::future::Pending<()>>(None, Some(tx))
                .await;

            let mut state_guard = state_clone.lock().await;
            state_guard.is_running = false;
            state_guard.start_time = None;
            state_guard.client_address = None;
            state_guard.server_address = None;

            result
        });

        tokio::select! {
            _ = rx => {
                info!("Connection established successfully!");
                let mut state_guard = state.lock().await;
                state_guard.is_running = true;
                state_guard.start_time = Some(Instant::now());
                Ok(true)
            }
            task_res = client_task => {
                match task_res {
                    Ok(Ok(())) => {
                        info!("Client finished normally");
                        Ok(false)
                    }
                    Ok(Err(e)) => {
                        error!("Client failed: {}", e);
                        Err(e)
                    }
                    Err(e) => {
                        error!("Client task panicked: {}", e);
                        Err(MirageError::system("Client task panicked"))
                    }
                }
            }
            _ = &mut cancel_rx => {
                info!("Client start cancelled");
                Ok(false)
            }
        }
    }

    async fn stop_client(&self) -> Result<()> {
        let mut state_guard = self.state.lock().await;

        if state_guard.is_running {
            state_guard.is_running = false;
            state_guard.start_time = None;
            state_guard.client_address = None;
            state_guard.server_address = None;
            info!("Client stopped successfully");
        }

        Ok(())
    }

    async fn get_status(&self) -> ClientStatus {
        let state_guard = self.state.lock().await;

        if state_guard.is_running {
            let connection_duration = state_guard
                .start_time
                .map(|start| start.elapsed())
                .unwrap_or_default();

            ClientStatus {
                status: ConnectionStatus::Connected,
                metrics: Some(ConnectionMetrics {
                    bytes_sent: 0,
                    bytes_received: 0,
                    packets_sent: 0,
                    packets_received: 0,
                    connection_duration,
                    client_address: state_guard.client_address,
                    server_address: state_guard.server_address,
                }),
            }
        } else {
            ClientStatus {
                status: ConnectionStatus::Disconnected,
                metrics: None,
            }
        }
    }

    async fn run_ipc_client(&self, socket_path: &Path, config_path: &Path) -> Result<()> {
        let mut ipc_client = self.connect_to_gui_server(socket_path).await?;
        info!("Connected to GUI IPC server");

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("IPC client received shutdown signal");
                    break;
                }
                result = ipc_client.recv() => {
                    match result {
                        Ok(message) => {
                            let should_exit = self.handle_message_with_cancel(
                                message,
                                &mut ipc_client,
                                config_path,
                            ).await?;
                            if should_exit {
                                break;
                            }
                        }
                        Err(e) => {
                            info!("IPC connection closed by GUI: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        info!("IPC client shutdown complete");
        Ok(())
    }

    async fn handle_message_with_cancel(
        &self,
        message: IpcMessage,
        ipc_client: &mut IpcClient,
        config_path: &Path,
    ) -> Result<bool> {
        match message {
            IpcMessage::StartClient {
                config_path: cfg_path,
            } => {
                let path = if cfg_path.as_os_str().is_empty() {
                    config_path.to_path_buf()
                } else {
                    cfg_path
                };

                let (cancel_tx, cancel_rx) = oneshot::channel();
                let cancel_tx = Arc::new(Mutex::new(Some(cancel_tx)));
                let cancel_tx_clone = cancel_tx.clone();
                let shutdown_tx = self.shutdown_tx.clone();

                let daemon = self.clone();
                let path_clone = path.clone();

                let mut connect_handle = tokio::spawn(async move {
                    daemon
                        .start_client_cancellable(path_clone, "MIRAGE_", cancel_rx)
                        .await
                });

                loop {
                    tokio::select! {
                        result = &mut connect_handle => {
                            match result {
                                Ok(Ok(true)) => {
                                    let status = self.get_status().await;
                                    if let Err(e) = ipc_client.send(&IpcMessage::StatusUpdate(status)).await {
                                        error!("Failed to send status: {}", e);
                                    }
                                    break Ok(false);
                                }
                                Ok(Ok(false)) => {
                                    if let Err(e) = ipc_client
                                        .send(&IpcMessage::Error(GuiError::other(
                                            "Connection cancelled",
                                        )))
                                        .await
                                    {
                                        error!("Failed to send cancel response: {}", e);
                                    }
                                    break Ok(true);
                                }
                                Ok(Err(e)) => {
                                    if let Err(send_err) = ipc_client
                                        .send(&IpcMessage::Error(e.into()))
                                        .await
                                    {
                                        error!("Failed to send error: {}", send_err);
                                    }
                                    break Ok(false);
                                }
                                Err(e) => {
                                    error!("Connect task panicked: {}", e);
                                    break Ok(true);
                                }
                            }
                        }
                        msg_result = ipc_client.recv() => {
                            match msg_result {
                                Ok(IpcMessage::Shutdown) | Ok(IpcMessage::StopClient) => {
                                    info!("Received cancel/shutdown while connecting");
                                    if let Some(tx) = cancel_tx_clone.lock().await.take() {
                                        let _ = tx.send(());
                                    }
                                    let _ = shutdown_tx.send(());
                                    break Ok(true);
                                }
                                Ok(IpcMessage::GetStatus) => {
                                    let status = ClientStatus {
                                        status: ConnectionStatus::Connecting,
                                        metrics: None,
                                    };
                                    if let Err(e) = ipc_client.send(&IpcMessage::StatusUpdate(status)).await {
                                        error!("Failed to send status: {}", e);
                                    }
                                }
                                Ok(other) => {
                                    debug!("Ignoring message while connecting: {:?}", other);
                                }
                                Err(e) => {
                                    info!("IPC connection lost while connecting: {}", e);
                                    if let Some(tx) = cancel_tx_clone.lock().await.take() {
                                        let _ = tx.send(());
                                    }
                                    break Ok(true);
                                }
                            }
                        }
                    }
                }
            }
            IpcMessage::StopClient => {
                let response = self.handle_stop_client_message().await;
                ipc_client.send(&response).await?;
                Ok(false)
            }
            IpcMessage::GetStatus => {
                let status = self.get_status().await;
                ipc_client.send(&IpcMessage::StatusUpdate(status)).await?;
                Ok(false)
            }
            IpcMessage::Shutdown => {
                let response = self.handle_shutdown_message().await;
                ipc_client.send(&response).await?;
                Ok(true)
            }
            _ => {
                ipc_client
                    .send(&IpcMessage::Error(GuiError::ipc("Invalid message")))
                    .await?;
                Ok(false)
            }
        }
    }

    async fn connect_to_gui_server(&self, socket_path: &Path) -> Result<IpcClient> {
        const MAX_RETRIES: u32 = 30;
        const RETRY_DELAY: Duration = Duration::from_millis(500);

        for attempt in 1..=MAX_RETRIES {
            match IpcClient::connect(socket_path).await {
                Ok(client) => {
                    info!(
                        "Successfully connected to GUI server on attempt {}",
                        attempt
                    );
                    return Ok(client);
                }
                Err(e) => {
                    if attempt == MAX_RETRIES {
                        error!(
                            "Failed to connect to GUI server after {} attempts: {}",
                            MAX_RETRIES, e
                        );
                        return Err(e);
                    }
                    debug!(
                        "Connection attempt {} failed, retrying in {:?}: {}",
                        attempt, RETRY_DELAY, e
                    );
                    sleep(RETRY_DELAY).await;
                }
            }
        }

        unreachable!()
    }

    async fn handle_stop_client_message(&self) -> IpcMessage {
        match self.stop_client().await {
            Ok(()) => {
                let status = self.get_status().await;
                IpcMessage::StatusUpdate(status)
            }
            Err(e) => IpcMessage::Error(e.into()),
        }
    }

    async fn handle_shutdown_message(&self) -> IpcMessage {
        info!("Received shutdown request, stopping client and daemon");
        if let Err(e) = self.stop_client().await {
            error!("Failed to stop client during shutdown: {}", e);
        }

        if let Err(e) = self.shutdown_tx.send(()) {
            warn!("Failed to send shutdown signal: {}", e);
        }

        IpcMessage::Shutdown
    }
}

impl Clone for ClientDaemon {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
            instance_name: self.instance_name.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    initialize_logging(&args.log_level, &args.log_path);

    use mirage_gui::validation;
    validation::validate_instance_name(&args.instance_name)?;

    info!("Starting Mirage client daemon: {}", args.instance_name);

    let daemon = ClientDaemon::new(args.instance_name.clone());

    daemon
        .run_ipc_client(&args.socket_path, &args.config_path)
        .await?;

    info!("Daemon shutdown complete");
    Ok(())
}

fn initialize_logging(log_level: &str, log_path: &Path) {
    use std::fs::OpenOptions;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    if let Ok(log_file) = OpenOptions::new().create(true).append(true).open(log_path) {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(log_file)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .init();
    }
}
