use std::path::PathBuf;
use std::process::exit;

use clap::Parser;
use mirage::config::{ClientConfig, FromPath};
use mirage::network::interface::tun_rs::TunRsInterface;
use mirage::utils::tracing::log_subscriber;
use mirage::Result;
use mirage_client::client::MirageClient;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "mirage")]
pub struct Args {
    #[arg(long, default_value = "client.toml")]
    pub config_path: PathBuf,
    #[arg(long, default_value = "MIRAGE_")]
    pub env_prefix: String,
}

#[tokio::main]
async fn main() {
    let _logger = tracing::subscriber::set_default(log_subscriber("info"));

    match run_client().await {
        Ok(_) => {}
        Err(e) => {
            error!("A critical error occurred: {e}");
            exit(1);
        }
    }
}

async fn run_client() -> Result<()> {
    let args = Args::parse();
    let config = ClientConfig::from_path(&args.config_path, &args.env_prefix)?;
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let mut client = MirageClient::new(config);

    // [修改] 传入 shutdown_signal 和 None (connection_event_tx)
    client
        .start::<TunRsInterface, _>(Some(shutdown_signal()), None)
        .await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(windows)]
    {
        let ctrl_close = async {
            match tokio::signal::windows::ctrl_close() {
                Ok(mut stream) => stream.recv().await,
                Err(_) => std::future::pending::<Option<()>>().await,
            }
        };
        let ctrl_shutdown = async {
            match tokio::signal::windows::ctrl_shutdown() {
                Ok(mut stream) => stream.recv().await,
                Err(_) => std::future::pending::<Option<()>>().await,
            }
        };
        let ctrl_break = async {
            match tokio::signal::windows::ctrl_break() {
                Ok(mut stream) => stream.recv().await,
                Err(_) => std::future::pending::<Option<()>>().await,
            }
        };

        tokio::select! {
            _ = ctrl_c => { info!("Received Ctrl+C, shutting down..."); },
            _ = ctrl_close => { info!("Window closed (Ctrl+Close), cleaning up..."); },
            _ = ctrl_shutdown => { info!("System shutting down, cleaning up..."); },
            _ = ctrl_break => { info!("Received Ctrl+Break, cleaning up..."); },
        }
    }

    #[cfg(not(windows))]
    {
        let terminate = async {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut stream) => stream.recv().await,
                Err(_) => std::future::pending::<Option<()>>().await,
            }
        };

        tokio::select! {
            _ = ctrl_c => { info!("Received Ctrl+C, shutting down..."); },
            _ = terminate => { info!("Received SIGTERM, shutting down..."); },
        }
    }
}
