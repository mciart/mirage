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
    about = "Mirage VPN - Stealth L3 VPN with Camouflage and Traffic Obfuscation"
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
        #[command(flatten)]
        opts: UsersOpts,
    },
}

/// Non-interactive options for the `users` subcommand.
#[derive(clap::Args, Debug, Default)]
struct UsersOpts {
    /// Username (skips the interactive prompt)
    #[arg(long)]
    username: Option<String>,
    /// Password (skips the prompt). With --username and no --password, a random one is generated
    #[arg(long, requires = "username")]
    password: Option<String>,
    /// After adding the user, print an access link and QR code
    #[arg(long, requires = "add")]
    link: bool,
    /// Server config TOML to read secrets from (default: ./server.toml if present)
    #[arg(long, requires = "link")]
    server_config: Option<PathBuf>,
    /// Public host (domain or IP) clients dial; required with --link
    #[arg(long, requires = "link")]
    host: Option<String>,
    /// Public port for the link (default: the server's bind_port)
    #[arg(long, requires = "link")]
    port: Option<u16>,
    /// Label shown in the app (default: host)
    #[arg(long, requires = "link")]
    name: Option<String>,
    /// Embed the server certificate PEM in the link (for self-signed servers)
    #[arg(long, requires = "link")]
    embed_cert: bool,
    /// Client routes, comma separated
    #[arg(long, requires = "link", value_delimiter = ',', default_value = "0.0.0.0/0,::/0")]
    routes: Vec<String>,
    /// Client DNS servers, comma separated
    #[arg(
        long,
        requires = "link",
        value_delimiter = ',',
        default_value = "1.1.1.1,2606:4700:4700::1111"
    )]
    dns: Vec<String>,
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
            opts,
        } => run_users(add, delete, users_file_path, opts),
    };

    if let Err(e) = result {
        error!("A critical error occurred: {e}");
        exit(1);
    }
}

// ─── Client ──────────────────────────────────────────────────────────────────

async fn run_client(config_path: PathBuf, env_prefix: String) -> Result<()> {
    let config = ClientConfig::from_path(&config_path, &env_prefix)?;
    config.validate()?;
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
    config.validate()?;
    tracing::subscriber::set_global_default(log_subscriber(&config.log.level))?;

    let server = mirage::server::MirageServer::new(config)?;
    server.run::<TunRsInterface>().await
}

// ─── Users ───────────────────────────────────────────────────────────────────

fn run_users(add: bool, delete: bool, users_file_path: PathBuf, opts: UsersOpts) -> Result<()> {
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    use dashmap::DashMap;
    use mirage::users_file::{load_users_file, save_users_file, User};
    use mirage::MirageError;
    use rand::Rng;
    use rand_core::OsRng;
    use rpassword::prompt_password;

    // Unambiguous alphanumerics (no 0/O, 1/l/I)
    const PASSWORD_CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";

    fn generate_password(len: usize) -> String {
        let mut rng = OsRng;
        (0..len)
            .map(|_| PASSWORD_CHARSET[rng.gen_range(0..PASSWORD_CHARSET.len())] as char)
            .collect()
    }

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

    /// Returns (username, password, whether the password was generated).
    fn resolve_credentials(opts: &UsersOpts) -> Result<(String, String, bool)> {
        let username = match &opts.username {
            Some(u) => u.clone(),
            None => prompt_username()?,
        };
        if username.is_empty() {
            return Err(MirageError::config_error("Username must not be empty"));
        }
        match &opts.password {
            Some(p) => Ok((username, p.clone(), false)),
            None if opts.username.is_some() => Ok((username, generate_password(20), true)),
            None => {
                let password =
                    prompt_password(format!("Enter password for user '{username}': "))?;
                let password_again =
                    prompt_password(format!("Confirm password for user '{username}': "))?;
                if password != password_again {
                    eprintln!("Passwords do not match");
                    exit(1);
                }
                Ok((username, password, false))
            }
        }
    }

    fn build_link(
        opts: &UsersOpts,
        username: &str,
        password: &str,
    ) -> Result<(String, String)> {
        use mirage::share_link::{build_share_link, ShareLinkParams};

        let host = opts.host.clone().filter(|h| !h.is_empty()).ok_or_else(|| {
            MirageError::config_error("--host <PUBLIC HOST> is required with --link")
        })?;
        let cfg_path = match &opts.server_config {
            Some(p) => p.clone(),
            None => {
                let p = PathBuf::from("server.toml");
                if !p.exists() {
                    return Err(MirageError::config_error(
                        "--link needs the server config: pass --server-config <PATH> \
                         (./server.toml not found)",
                    ));
                }
                p
            }
        };
        let server = ServerConfig::from_path(&cfg_path, "MIRAGE_")?;

        let port = opts.port.unwrap_or(server.bind_port);
        let trusted_certificates = if opts.embed_cert {
            let pem = std::fs::read_to_string(&server.certificate_file).map_err(|e| {
                MirageError::config_error(format!(
                    "Cannot read certificate {:?}: {e}",
                    server.certificate_file
                ))
            })?;
            vec![pem]
        } else {
            Vec::new()
        };

        // The client dials the same port for TCP and QUIC, so only advertise
        // UDP when the server's QUIC listener is on that port.
        let quic = server.quic_enabled && server.quic_bind_port == port;
        if server.quic_enabled && !quic {
            eprintln!(
                "Note: QUIC listens on port {} but the link port is {}; the link will use TCP only.",
                server.quic_bind_port, port
            );
        }

        let params = ShareLinkParams {
            name: opts.name.clone().unwrap_or_else(|| host.clone()),
            host,
            port,
            username: username.to_owned(),
            password: password.to_owned(),
            trusted_certificates,
            quic,
            camouflage_mode: server.camouflage.mode.clone(),
            target_sni: server.camouflage.target_sni.clone(),
            short_ids: server.camouflage.short_ids.clone(),
            jls_password: server.camouflage.jls_password.clone(),
            jls_iv: server.camouflage.jls_iv.clone(),
            inner_key: server.camouflage.inner_key.clone(),
            inner_encryption: server.obfuscation.inner_encryption,
            routes: opts.routes.clone(),
            dns_servers: opts.dns.clone(),
        };
        build_share_link(&params)
    }

    fn print_link(
        username: &str,
        password: &str,
        generated: bool,
        link: &str,
    ) {
        use qrcode::render::unicode::Dense1x2;
        use qrcode::QrCode;

        println!();
        println!("=== Credentials ===");
        println!("Username: {username}");
        if generated {
            println!("Password: {password}");
        } else {
            println!("Password: (as provided)");
        }
        println!("Note: the password is stored only as a hash; it will not be shown again.");
        println!();
        println!("=== Access link ===");
        println!("{link}");
        println!();
        println!("=== QR code ===");
        match QrCode::new(link.as_bytes()) {
            Ok(code) => {
                let qr = code
                    .render::<Dense1x2>()
                    .dark_color(Dense1x2::Light)
                    .light_color(Dense1x2::Dark)
                    .quiet_zone(true)
                    .build();
                println!("{qr}");
            }
            Err(e) => println!("Link is too long to fit in a QR code ({e}); use the link above."),
        }
    }

    fn remove_user(users: DashMap<String, User>, username: Option<String>) -> Result<DashMap<String, User>> {
        let username = match username {
            Some(u) => u,
            None => prompt_username()?,
        };
        match users.remove(&username) {
            Some(_) => Ok(users),
            None => {
                eprintln!("User does not exist: {username}");
                exit(1);
            }
        }
    }

    let mut users = match load_users_file(&users_file_path) {
        Ok(u) => u,
        Err(_) if add => {
            // If adding and file doesn't exist, start fresh
            eprintln!("Users file not found, creating new one.");
            DashMap::new()
        }
        Err(e) => return Err(e),
    };

    let mut printout: Option<(String, String, bool, String)> = None;
    users = match (add, delete) {
        (true, false) => {
            let (username, password, generated) = resolve_credentials(&opts)?;
            // Build the link first so a config error does not leave a half-done add.
            if opts.link {
                let (_toml, link) = build_link(&opts, &username, &password)?;
                printout = Some((username.clone(), password.clone(), generated, link));
            } else if generated {
                println!("Generated password for '{username}': {password}");
            }
            let password_hash = hash_password(password)?;
            users.insert(username.clone(), User::new(username, password_hash));
            users
        }
        (false, true) => remove_user(users, opts.username.clone())?,
        _ => {
            eprintln!("Either add or delete switch must be specified");
            exit(1);
        }
    };

    save_users_file(&users_file_path, users)?;
    if let Some((username, password, generated, link)) = printout {
        print_link(&username, &password, generated, &link);
    }
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
