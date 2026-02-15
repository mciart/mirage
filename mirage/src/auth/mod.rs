pub mod client_auth;
pub mod server_auth;
pub mod stream;
pub mod users_file;

use async_trait::async_trait;
use ipnet::IpNet;
use serde_json::Value;

use crate::error::Result;

/// Represents a user authenticator for the server.
///
/// `async_trait` is used to allow usage with dynamic dispatch.
#[async_trait]
pub trait ServerAuthenticator: Send + Sync {
    /// Authenticates a user based on the provided authentication payload.
    ///
    /// # Arguments
    /// * `authentication_payload` - The authentication data submitted by the client
    ///
    /// # Returns
    /// A tuple containing the authenticated username and assigned client IP address
    ///
    /// # Errors
    /// Returns `AuthError` variants for authentication failures, including:
    /// - `InvalidCredentials` - When provided credentials are invalid
    /// - `UserNotFound` - When the username doesn't exist
    /// - `InvalidPayload` - When the payload format is malformed
    /// - `InvalidPayload` - When the payload format is malformed
    async fn authenticate_user(
        &self,
        authentication_payload: Value,
        skip_ip_allocation: bool,
    ) -> Result<(String, IpNet, Option<IpNet>)>;
}

/// Represents a user authentication payload generator for the client.
///
/// `async_trait` is used to allow usage with dynamic dispatch.
#[async_trait]
pub trait ClientAuthenticator: Send + Sync {
    /// Generates the authentication payload to send to the server.
    ///
    /// # Returns
    /// A JSON value containing the authentication credentials
    ///
    /// # Errors
    /// Returns `AuthError::InvalidPayload` if payload generation fails
    async fn generate_payload(&self) -> Result<Value>;
}
