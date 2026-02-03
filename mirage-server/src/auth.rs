//! Server-side authentication handling for the Mirage VPN.
//!
//! This module provides the AuthServer which handles the authentication
//! handshake with clients over TLS streams.

use ipnet::IpNet;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

use mirage::{
    auth::{
        stream::{AuthMessage, AuthStream},
        ServerAuthenticator,
    },
    error::AuthError,
    Result,
};

/// Represents an authentication server handling initial authentication and session management.
pub struct AuthServer {
    authenticator: Box<dyn ServerAuthenticator>,
    server_address: IpNet,
    server_address_v6: Option<IpNet>,
    auth_timeout: Duration,
}

impl AuthServer {
    /// Creates a new `AuthServer` with a provided authenticator.
    pub fn new(
        authenticator: Box<dyn ServerAuthenticator>,
        server_address: IpNet,
        server_address_v6: Option<IpNet>,
        auth_timeout: Duration,
    ) -> Self {
        Self {
            authenticator,
            server_address,
            server_address_v6,
            auth_timeout,
        }
    }

    /// Handles authentication for a client over a TLS stream.
    ///
    /// # Arguments
    /// * `reader` - The read half of the TLS stream
    /// * `writer` - The write half of the TLS stream
    ///
    /// # Returns
    /// A tuple containing the authenticated username and assigned client IP address
    ///
    /// # Errors
    /// Returns `AuthError` variants for authentication failures
    pub async fn handle_authentication<R, W>(
        &self,
        reader: R,
        writer: W,
    ) -> Result<(String, IpNet, Option<IpNet>, R, W)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut auth_stream = AuthStream::new(reader, writer);

        let message = auth_stream.recv_message_timeout(self.auth_timeout).await?;

        let (username, client_address, client_address_v6) = match message {
            AuthMessage::Authenticate { payload } => {
                let (username, client_address_v4, client_address_v6) =
                    self.authenticator.authenticate_user(payload).await?;

                auth_stream
                    .send_message_timeout(
                        AuthMessage::Authenticated {
                            client_address: client_address_v4,
                            client_address_v6,
                            server_address: self.server_address,
                            server_address_v6: self.server_address_v6,
                        },
                        self.auth_timeout,
                    )
                    .await?;

                (username, client_address_v4, client_address_v6)
            }
            _ => {
                // Send failure message to client if authentication format is invalid
                let _ = auth_stream.send_message(AuthMessage::Failed).await;
                return Err(AuthError::InvalidPayload.into());
            }
        };

        let (reader, writer) = auth_stream.into_inner();
        Ok((username, client_address, client_address_v6, reader, writer))
    }
}
