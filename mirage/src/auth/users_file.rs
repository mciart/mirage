//! Users file based authentication for the Mirage VPN system.
//!
//! This module provides authentication structures for the users file
//! authentication method, shared between client and server.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    auth::ClientAuthenticator, config::ClientAuthenticationConfig, error::AuthError, Result,
};

/// Authentication payload for users file authentication method.
///
/// This structure is used to transmit credentials from the client
/// to the server during the authentication handshake.
///
/// The password field is automatically zeroed on drop to prevent
/// sensitive data from remaining in memory.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UsersFilePayload {
    /// The username for authentication
    pub username: String,
    /// The plaintext password (transmitted over TLS)
    pub password: String,
    /// Optional static IPv4 address requested by the client
    #[zeroize(skip)]
    pub static_client_ip: Option<std::net::IpAddr>,
    /// Optional static IPv6 address requested by the client
    #[zeroize(skip)]
    pub static_client_ip_v6: Option<std::net::IpAddr>,
}

/// Client authenticator for users file based authentication.
///
/// Generates authentication payloads containing username and password
/// credentials for transmission to the server.
///
/// Sensitive credentials are automatically zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UsersFileClientAuthenticator {
    username: String,
    password: String,
    #[zeroize(skip)]
    static_client_ip: Option<std::net::IpAddr>,
    #[zeroize(skip)]
    static_client_ip_v6: Option<std::net::IpAddr>,
}

impl UsersFileClientAuthenticator {
    /// Creates a new users file client authenticator.
    ///
    /// # Arguments
    /// * `config` - Client authentication configuration containing credentials
    /// * `static_client_ip` - Optional static IPv4 address
    /// * `static_client_ip_v6` - Optional static IPv6 address
    pub fn new(
        config: &ClientAuthenticationConfig,
        static_client_ip: Option<std::net::IpAddr>,
        static_client_ip_v6: Option<std::net::IpAddr>,
    ) -> Self {
        Self {
            username: config.username.clone(),
            password: config.password.clone(),
            static_client_ip,
            static_client_ip_v6,
        }
    }
}

#[async_trait]
impl ClientAuthenticator for UsersFileClientAuthenticator {
    async fn generate_payload(&self) -> Result<Value> {
        let payload = UsersFilePayload {
            username: self.username.clone(),
            password: self.password.clone(),
            static_client_ip: self.static_client_ip,
            static_client_ip_v6: self.static_client_ip_v6,
        };
        Ok(serde_json::to_value(payload).map_err(|_| AuthError::InvalidPayload)?)
    }
}
