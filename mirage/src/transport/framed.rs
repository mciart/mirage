//! Framed stream implementation for length-prefixed packet transport.
//!
//! This module provides a `FramedStream` that wraps any AsyncRead/AsyncWrite
//! stream and provides packet-level read/write operations using length-prefixed
//! framing. This replaces QUIC datagrams for our TCP/TLS transport.

use crate::constants::{FRAME_HEADER_SIZE, MAX_FRAME_SIZE};
use crate::error::{NetworkError, Result};
use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A framed stream that provides packet-level operations over a byte stream.
///
/// Uses a simple length-prefixed protocol:
/// - 4 bytes: packet length (big-endian u32)
/// - N bytes: packet data
pub struct FramedStream<S> {
    stream: S,
    read_buffer: BytesMut,
}

impl<S> FramedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new FramedStream wrapping the provided stream.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buffer: BytesMut::with_capacity(MAX_FRAME_SIZE),
        }
    }

    /// Sends a packet over the stream.
    ///
    /// The packet is prefixed with its length as a big-endian u32.
    ///
    /// # Errors
    /// Returns `NetworkError::PacketError` if the packet is too large.
    /// Returns I/O errors on write failure.
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!(
                    "Packet too large: {} bytes (max: {})",
                    packet.len(),
                    MAX_FRAME_SIZE
                ),
            }
            .into());
        }

        let len = packet.len() as u32;
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header.copy_from_slice(&len.to_be_bytes());

        self.stream.write_all(&header).await?;
        self.stream.write_all(packet).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Receives a packet from the stream.
    ///
    /// Reads the length prefix, then the packet data.
    ///
    /// # Returns
    /// The packet data as a `BytesMut`.
    ///
    /// # Errors
    /// Returns `NetworkError::PacketError` if the frame is too large.
    /// Returns I/O errors on read failure.
    pub async fn recv_packet(&mut self) -> Result<BytesMut> {
        // Read length prefix
        let mut header = [0u8; FRAME_HEADER_SIZE];
        self.stream.read_exact(&mut header).await?;

        let len = u32::from_be_bytes(header) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!(
                    "Frame too large: {} bytes (max: {})",
                    len, MAX_FRAME_SIZE
                ),
            }
            .into());
        }

        // Read packet data
        self.read_buffer.clear();
        self.read_buffer.resize(len, 0);
        self.stream.read_exact(&mut self.read_buffer).await?;

        Ok(self.read_buffer.split())
    }

    /// Gets a reference to the underlying stream.
    pub fn inner(&self) -> &S {
        &self.stream
    }

    /// Gets a mutable reference to the underlying stream.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Consumes self and returns the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

/// Splits a FramedStream into read and write halves.
///
/// This is useful when you need to read and write concurrently from different tasks.
#[allow(dead_code)]
pub fn split_framed<S>(
    stream: FramedStream<S>,
) -> (FramedReader<tokio::io::ReadHalf<S>>, FramedWriter<tokio::io::WriteHalf<S>>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, write_half) = tokio::io::split(stream.stream);
    (
        FramedReader::new(read_half),
        FramedWriter::new(write_half),
    )
}

/// Read half of a split FramedStream.
#[allow(dead_code)]
pub struct FramedReader<R> {
    reader: R,
    read_buffer: BytesMut,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    /// Creates a new FramedReader.
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            read_buffer: BytesMut::with_capacity(MAX_FRAME_SIZE),
        }
    }

    /// Receives a packet from the stream.
    pub async fn recv_packet(&mut self) -> Result<BytesMut> {
        // Read length prefix
        let mut header = [0u8; FRAME_HEADER_SIZE];
        self.reader.read_exact(&mut header).await?;

        let len = u32::from_be_bytes(header) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!("Frame too large: {} bytes", len),
            }
            .into());
        }

        // Read packet data
        self.read_buffer.clear();
        self.read_buffer.resize(len, 0);
        self.reader.read_exact(&mut self.read_buffer).await?;

        Ok(self.read_buffer.split())
    }
}

/// Write half of a split FramedStream.
#[allow(dead_code)]
pub struct FramedWriter<W> {
    writer: W,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    /// Creates a new FramedWriter.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Sends a packet over the stream.
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!("Packet too large: {} bytes", packet.len()),
            }
            .into());
        }

        let len = packet.len() as u32;
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header.copy_from_slice(&len.to_be_bytes());

        self.writer.write_all(&header).await?;
        self.writer.write_all(packet).await?;
        self.writer.flush().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn test_send_recv_packet() {
        let (client, server) = duplex(4096);
        let mut client_framed = FramedStream::new(client);
        let mut server_framed = FramedStream::new(server);

        let test_data = b"Hello, Mirage!";

        // Client sends
        tokio::spawn(async move {
            client_framed.send_packet(test_data).await.unwrap();
        });

        // Server receives
        let received = server_framed.recv_packet().await.unwrap();
        assert_eq!(&received[..], test_data);
    }
}
