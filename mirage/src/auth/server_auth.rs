//! Server-side authentication handling for the Mirage VPN.
//!
//! This module provides the AuthServer which handles the authentication
//! handshake with clients over TLS streams.

use ipnet::IpNet;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
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
    /// A tuple containing the authenticated username, assigned client IP addresses, session_id, and streams
    ///
    /// # Errors
    /// Returns `AuthError` variants for authentication failures
    pub async fn handle_authentication<R, W>(
        &self,
        reader: R,
        writer: W,
    ) -> Result<(String, IpNet, Option<IpNet>, [u8; 8], R, W)>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut auth_stream = AuthStream::new(reader, writer);

        let message = auth_stream.recv_message_timeout(self.auth_timeout).await?;

        let (username, client_address, client_address_v6, session_id) = match message {
            AuthMessage::Authenticate {
                payload,
                session_id: existing_session,
            } => {
                let skip_ip_allocation = existing_session.is_some();
                let (username, client_address_v4, client_address_v6) = self
                    .authenticator
                    .authenticate_user(payload, skip_ip_allocation)
                    .await?;

                // Use existing session ID if parallel connection, else generate new one
                let session_id = if let Some(id) = existing_session {
                    id
                } else {
                    let mut id = [0u8; 8];
                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
                    id
                };

                auth_stream
                    .send_message_timeout(
                        AuthMessage::Authenticated {
                            client_address: client_address_v4,
                            client_address_v6,
                            server_address: self.server_address,
                            server_address_v6: self.server_address_v6,
                            session_id,
                        },
                        self.auth_timeout,
                    )
                    .await?;

                (username, client_address_v4, client_address_v6, session_id)
            }
            _ => {
                // Send failure message to client if authentication format is invalid
                let _ = auth_stream.send_message(AuthMessage::Failed).await;
                return Err(AuthError::InvalidPayload.into());
            }
        };

        let (reader, writer) = auth_stream.into_inner();
        Ok((
            username,
            client_address,
            client_address_v6,
            session_id,
            reader,
            writer,
        ))
    }
}
