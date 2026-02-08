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
}

impl UsersFileClientAuthenticator {
    /// Creates a new users file client authenticator.
    ///
    /// # Arguments
    /// * `config` - Client authentication configuration containing credentials
    pub fn new(config: &ClientAuthenticationConfig) -> Self {
        Self {
            username: config.username.clone(),
            password: config.password.clone(),
        }
    }
}

#[async_trait]
impl ClientAuthenticator for UsersFileClientAuthenticator {
    async fn generate_payload(&self) -> Result<Value> {
        let payload = UsersFilePayload {
            username: self.username.clone(),
            password: self.password.clone(),
        };
        Ok(serde_json::to_value(payload).map_err(|_| AuthError::InvalidPayload)?)
    }
}
