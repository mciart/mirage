//! Authentication stream handling for the Mirage VPN system.
//!
//! This module provides authentication message exchange over any async
//! read/write stream (TCP/TLS).

use std::time::Duration;

use bytes::BytesMut;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::{
    constants::AUTH_MESSAGE_BUFFER_SIZE,
    error::{AuthError, Result},
};

/// Represents an authentication message sent between the client and the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthMessage {
    /// Authentication request containing user credentials
    Authenticate { payload: Value },
    /// Successful authentication response with network configuration
    Authenticated {
        client_address: IpNet,
        server_address: IpNet,
    },
    /// Authentication failure response
    Failed,
}

/// Handles authentication communication over TCP/TLS streams
pub struct AuthStream<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> AuthStream<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Creates a new authentication stream from reader and writer halves
    ///
    /// # Arguments
    /// * `reader` - The read half of the stream
    /// * `writer` - The write half of the stream
    pub fn new(reader: R, writer: W) -> Self {
        AuthStream { reader, writer }
    }

    /// Sends an authentication message to the other side of the connection.
    ///
    /// Uses a simple length-prefixed protocol:
    /// - 4 bytes: message length (big-endian u32)
    /// - N bytes: JSON message
    ///
    /// # Arguments
    /// * `message` - The authentication message to send
    ///
    /// # Errors
    /// Returns `AuthError::InvalidPayload` if message serialization fails
    /// Returns `AuthError::StreamError` if network transmission fails
    pub async fn send_message(&mut self, message: AuthMessage) -> Result<()> {
        let serialized = serde_json::to_vec(&message).map_err(|_| AuthError::InvalidPayload)?;

        // Write length prefix
        let len = serialized.len() as u32;
        self.writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|_| AuthError::StreamError)?;

        // Write message
        self.writer
            .write_all(&serialized)
            .await
            .map_err(|_| AuthError::StreamError)?;

        self.writer
            .flush()
            .await
            .map_err(|_| AuthError::StreamError)?;

        Ok(())
    }

    /// Receives an authentication message from the other side of the connection.
    ///
    /// # Errors
    /// Returns `AuthError::StreamError` if network reception fails
    /// Returns `AuthError::InvalidPayload` if message deserialization fails
    pub async fn recv_message(&mut self) -> Result<AuthMessage> {
        // Read length prefix
        let mut len_buf = [0u8; 4];
        self.reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|_| AuthError::StreamError)?;

        let len = u32::from_be_bytes(len_buf) as usize;

        if len > AUTH_MESSAGE_BUFFER_SIZE {
            return Err(AuthError::InvalidPayload.into());
        }

        // Read message
        let mut buf = BytesMut::with_capacity(len);
        buf.resize(len, 0);
        self.reader
            .read_exact(&mut buf)
            .await
            .map_err(|_| AuthError::StreamError)?;

        serde_json::from_slice(&buf).map_err(|_| AuthError::InvalidPayload.into())
    }

    /// Receives an authentication message with a timeout.
    ///
    /// # Arguments
    /// * `connection_timeout` - Maximum time to wait for the message
    ///
    /// # Errors
    /// Returns `AuthError::Timeout` if the operation times out
    pub async fn recv_message_timeout(
        &mut self,
        connection_timeout: Duration,
    ) -> Result<AuthMessage> {
        match timeout(connection_timeout, self.recv_message()).await {
            Ok(result) => result,
            Err(_) => Err(AuthError::Timeout.into()),
        }
    }

    /// Sends an authentication message with a timeout.
    ///
    /// # Arguments
    /// * `message` - The authentication message to send
    /// * `connection_timeout` - Maximum time to wait for sending
    ///
    /// # Errors
    /// Returns `AuthError::Timeout` if the operation times out
    pub async fn send_message_timeout(
        &mut self,
        message: AuthMessage,
        connection_timeout: Duration,
    ) -> Result<()> {
        match timeout(connection_timeout, self.send_message(message)).await {
            Ok(result) => result,
            Err(_) => Err(AuthError::Timeout.into()),
        }
    }
}

/// Helper to create an AuthStream from a split TLS stream
pub fn create_auth_stream<S>(
    stream: S,
) -> AuthStream<tokio::io::ReadHalf<S>, tokio::io::WriteHalf<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (reader, writer) = tokio::io::split(stream);
    AuthStream::new(reader, writer)
}
