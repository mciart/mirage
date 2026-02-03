//! Client-side authentication handling for the Mirage VPN.
//!
//! This module provides the AuthClient which handles the authentication
//! handshake with the Mirage server over TLS streams.

use std::time::Duration;

use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncWrite};

use mirage::{
    auth::{
        stream::{AuthMessage, AuthStream},
        ClientAuthenticator,
    },
    error::AuthError,
    Result,
};

/// Represents an authentication client handling initial authentication and session management.
pub struct AuthClient {
    authenticator: Box<dyn ClientAuthenticator>,
    auth_timeout: Duration,
}

impl AuthClient {
    /// Creates a new `AuthClient` with a provided authenticator.
    pub fn new(authenticator: Box<dyn ClientAuthenticator>, auth_timeout: Duration) -> Self {
        Self {
            authenticator,
            auth_timeout,
        }
    }

    /// Establishes a session with the server over a TLS stream.
    ///
    /// # Arguments
    /// * `reader` - The read half of the TLS stream
    /// * `writer` - The write half of the TLS stream
    ///
    /// # Returns
    /// A tuple containing the client and server IP addresses
    ///
    /// # Errors
    /// Returns `AuthError` variants for authentication failures:
    /// - `InvalidCredentials` - When credentials are rejected by the server
    /// - `Timeout` - When authentication times out
    /// - `StreamError` - When communication with the server fails
    pub async fn authenticate<R, W>(&self, reader: R, writer: W) -> Result<(IpNet, IpNet)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut auth_stream = AuthStream::new(reader, writer);

        let authentication_payload = self.authenticator.generate_payload().await?;
        auth_stream
            .send_message_timeout(
                AuthMessage::Authenticate {
                    payload: authentication_payload,
                },
                self.auth_timeout,
            )
            .await?;

        let auth_response = auth_stream.recv_message_timeout(self.auth_timeout).await?;

        match auth_response {
            AuthMessage::Authenticated {
                client_address,
                server_address,
            } => Ok((client_address, server_address)),
            AuthMessage::Failed => Err(AuthError::InvalidCredentials)?,
            _ => Err(AuthError::InvalidPayload)?,
        }
    }
}
