use std::io::Write;
use std::path::PathBuf;
use std::process::exit;

use clap::Parser;

use mirage::config::{ClientConfig, FromPath, ServerConfig};
use mirage::network::interface::tun_rs::TunRsInterface;
use mirage::utils::tracing::log_subscriber;
use mirage::Result;
use tracing::{error, info};

#[derive(Parser)]
#[command(
    name = "mirage",
    about = "Mirage VPN - Reality-based VPN with XTLS-Vision"
)]
enum Cli {
    /// Run as VPN client
    Client {
        #[arg(long, default_value = "client.toml")]
        config: PathBuf,
        #[arg(long, default_value = "MIRAGE_")]
        env_prefix: String,
    },
    /// Run as VPN server
    Server {
        #[arg(long, default_value = "server.toml")]
        config: PathBuf,
        #[arg(long, default_value = "MIRAGE_")]
        env_prefix: String,
    },
    /// Manage users
    Users {
        #[arg(short, long, group = "mode")]
        add: bool,
        #[arg(short, long, group = "mode")]
        delete: bool,
        #[arg(requires = "mode", default_value = "users")]
        users_file_path: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let _logger = tracing::subscriber::set_default(log_subscriber("info"));
    let cli = Cli::parse();

    let result = match cli {
        Cli::Client { config, env_prefix } => run_client(config, env_prefix).await,
        Cli::Server { config, env_prefix } => run_server(config, env_prefix).await,
        Cli::Users {
            add,
            delete,
            users_file_path,
        } => run_users(add, delete, users_file_path),
    };

    if let Err(e) = result {
        error!("A critical error occurred: {e}");
        exit(1);
    }
}

// ─── Client ──────────────────────────────────────────────────────────────────

async fn run_client(config_path: PathBuf, env_prefix: String) -> Result<()> {
    let config = ClientConfig::from_path(&config_path, &env_prefix)?;
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let mut client = mirage::client::MirageClient::new(config);

    // Reconnection Loop
    loop {
        match client
            .start::<TunRsInterface, _>(Some(shutdown_signal()), None)
            .await
        {
            Ok(_) => {
                info!("Client stopped gracefully.");
                break Ok(());
            }
            Err(e) => {
                error!("Connection failed: {}", e);
                let retry_interval =
                    std::time::Duration::from_secs(client.config().connection.retry_interval_s);
                info!("Reconnecting in {:?}...", retry_interval);

                tokio::select! {
                    _ = tokio::time::sleep(retry_interval) => {
                        info!("Retrying connection...");
                        continue;
                    }
                    _ = shutdown_signal() => {
                        info!("Received shutdown signal during wait, exiting.");
                        break Ok(());
                    }
                }
            }
        }
    }
}

// ─── Server ──────────────────────────────────────────────────────────────────

async fn run_server(config_path: PathBuf, env_prefix: String) -> Result<()> {
    let config = ServerConfig::from_path(&config_path, &env_prefix)?;
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let server = mirage::server::MirageServer::new(config)?;
    server.run::<TunRsInterface>().await
}

// ─── Users ───────────────────────────────────────────────────────────────────

fn run_users(add: bool, delete: bool, users_file_path: PathBuf) -> Result<()> {
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    use dashmap::DashMap;
    use mirage::users_file::{load_users_file, save_users_file, User};
    use mirage::MirageError;
    use rand_core::OsRng;
    use rpassword::prompt_password;

    fn prompt_username() -> Result<String> {
        let mut username = String::new();
        print!("Enter the username: ");
        std::io::stdout().flush()?;
        std::io::stdin().read_line(&mut username)?;
        Ok(username.trim_end().to_owned())
    }

    fn hash_password(password: String) -> Result<String> {
        let argon = Argon2::default();
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = argon
            .hash_password(password.as_bytes(), salt.as_salt())
            .map_err(|e| MirageError::system(format!("Failed to hash password: {e}")))?;
        Ok(password_hash.to_string())
    }

    fn add_user(users: DashMap<String, User>) -> Result<DashMap<String, User>> {
        let username = prompt_username()?;
        let password = prompt_password(format!("Enter password for user '{username}': "))?;
        let password_again = prompt_password(format!("Confirm password for user '{username}': "))?;

        if password != password_again {
            eprintln!("Passwords do not match");
            exit(1);
        }

        let password_hash = hash_password(password)?;
        users.insert(username.clone(), User::new(username, password_hash));
        Ok(users)
    }

    fn remove_user(users: DashMap<String, User>) -> Result<DashMap<String, User>> {
        let username = prompt_username()?;
        match users.remove(&username) {
            Some(_) => Ok(users),
            None => {
                eprintln!("User does not exist: {username}");
                exit(1);
            }
        }
    }

    let mut users = load_users_file(&users_file_path)?;

    users = match (add, delete) {
        (true, false) => add_user(users)?,
        (false, true) => remove_user(users)?,
        _ => {
            eprintln!("Either add or delete switch must be specified");
            exit(1);
        }
    };

    save_users_file(&users_file_path, users)?;
    Ok(())
}

// ─── Signal Handling ─────────────────────────────────────────────────────────

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
