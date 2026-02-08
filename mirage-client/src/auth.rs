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

/// Result of a successful authentication, containing network configuration
/// and the reclaimed stream halves for packet relay.
pub struct AuthenticatedSession<R, W> {
    /// Client's assigned IPv4 address
    pub client_address: IpNet,
    /// Client's assigned IPv6 address (if dual-stack is enabled)
    pub client_address_v6: Option<IpNet>,
    /// Server's IPv4 address for routing
    pub server_address: IpNet,
    /// Server's IPv6 address for routing (if dual-stack is enabled)
    pub server_address_v6: Option<IpNet>,
    /// Session ID for connection pooling
    pub session_id: [u8; 8],
    /// Read half of the authenticated stream
    pub reader: R,
    /// Write half of the authenticated stream
    pub writer: W,
}

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
    /// An `AuthenticatedSession` containing network configuration and stream halves
    ///
    /// # Errors
    /// Returns `AuthError` variants for authentication failures:
    /// - `InvalidCredentials` - When credentials are rejected by the server
    /// - `Timeout` - When authentication times out
    /// - `StreamError` - When communication with the server fails
    pub async fn authenticate<R, W>(
        &self,
        reader: R,
        writer: W,
    ) -> Result<AuthenticatedSession<R, W>>
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
                    session_id: None, // Primary connection, no existing session
                },
                self.auth_timeout,
            )
            .await?;

        let auth_response = auth_stream.recv_message_timeout(self.auth_timeout).await?;

        // Retrieve the stream parts back to be reused
        let (reader, writer) = auth_stream.into_inner();

        match auth_response {
            AuthMessage::Authenticated {
                client_address,
                client_address_v6,
                server_address,
                server_address_v6,
                session_id,
            } => Ok(AuthenticatedSession {
                client_address,
                client_address_v6,
                server_address,
                server_address_v6,
                session_id,
                reader,
                writer,
            }),
            AuthMessage::Failed => Err(AuthError::InvalidCredentials)?,
            _ => Err(AuthError::InvalidPayload)?,
        }
    }
    /// Establishes a secondary connection that joins an existing session.
    pub async fn authenticate_secondary<R, W>(
        &self,
        reader: R,
        writer: W,
        session_id: [u8; 8],
    ) -> Result<(R, W)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut auth_stream = AuthStream::new(reader, writer);

        // For secondary connections, we send the Session ID directly
        // The payload is still needed for signature verification
        let authentication_payload = self.authenticator.generate_payload().await?;
        
        auth_stream
            .send_message_timeout(
                AuthMessage::Authenticate {
                    payload: authentication_payload,
                    session_id: Some(session_id),
                },
                self.auth_timeout,
            )
            .await?;

        let auth_response = auth_stream.recv_message_timeout(self.auth_timeout).await?;

        // Retrieve the stream parts back
        let (reader, writer) = auth_stream.into_inner();

        match auth_response {
            AuthMessage::Authenticated { .. } => Ok((reader, writer)),
            AuthMessage::Failed => Err(AuthError::InvalidCredentials)?,
            _ => Err(AuthError::InvalidPayload)?,
        }
    }
}
