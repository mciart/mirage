//! Framed stream implementation for length-prefixed packet transport.
//!
//! This module provides a `FramedStream` that wraps any AsyncRead/AsyncWrite
//! stream and provides packet-level read/write operations using length-prefixed
//! framing. This replaces QUIC datagrams for our TCP/TLS transport.

use crate::constants::{FRAME_HEADER_SIZE, MAX_FRAME_SIZE};
use crate::error::{NetworkError, Result};
use bytes::BytesMut;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FRAME_TYPE_DATA: u8 = 0x00;
const FRAME_TYPE_PADDING: u8 = 0x01;
// const FRAME_TYPE_KEEPALIVE: u8 = 0xFF; // Reserved for future

/// A framed stream that provides packet-level operations over a byte stream.
///
/// Uses a length-prefixed protocol V2:
/// - 4 bytes: packet length (big-endian u32)
/// - 1 byte:  packet type (0x00 = Data, 0x01 = Padding)
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

    /// Sends a data packet over the stream.
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
        // Length (4 bytes)
        header[0..4].copy_from_slice(&len.to_be_bytes());
        // Type (1 byte)
        header[4] = FRAME_TYPE_DATA;

        self.stream.write_all(&header).await?;
        self.stream.write_all(packet).await?;
        self.stream.flush().await?;

        Ok(())
    }

    /// Sends a padding packet of the specified length with random content.
    pub async fn send_padding(&mut self, len: usize) -> Result<()> {
        if len > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!("Padding too large: {} bytes", len),
            }
            .into());
        }

        let len_u32 = len as u32;
        let mut header = [0u8; FRAME_HEADER_SIZE];
        // Length
        header[0..4].copy_from_slice(&len_u32.to_be_bytes());
        // Type
        header[4] = FRAME_TYPE_PADDING;

        self.stream.write_all(&header).await?;

        // Generate and send random padding
        let mut padding = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut padding);
        self.stream.write_all(&padding).await?;

        self.stream.flush().await?;

        Ok(())
    }

    /// Receives a packet from the stream, transparently handling padding.
    pub async fn recv_packet(&mut self) -> Result<BytesMut> {
        loop {
            // Read header
            let mut header = [0u8; FRAME_HEADER_SIZE];
            self.stream.read_exact(&mut header).await?;

            let len = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
            let type_byte = header[4];

            if len > MAX_FRAME_SIZE {
                return Err(NetworkError::PacketError {
                    reason: format!("Frame too large: {} bytes (max: {})", len, MAX_FRAME_SIZE),
                }
                .into());
            }

            // Read payload
            self.read_buffer.clear();
            self.read_buffer.resize(len, 0);
            self.stream.read_exact(&mut self.read_buffer).await?;

            match type_byte {
                FRAME_TYPE_DATA => {
                    return Ok(self.read_buffer.split());
                }
                FRAME_TYPE_PADDING => {
                    // Ignore padding and continue loop
                    continue;
                }
                _ => {
                    // Unknown type, ignore (forward compatibility)
                    continue;
                }
            }
        }
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
) -> (
    FramedReader<tokio::io::ReadHalf<S>>,
    FramedWriter<tokio::io::WriteHalf<S>>,
)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, write_half) = tokio::io::split(stream.stream);
    (FramedReader::new(read_half), FramedWriter::new(write_half))
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

    /// Receives a packet from the stream, transparently handling padding.
    #[allow(dead_code)]
    pub async fn recv_packet(&mut self) -> Result<BytesMut> {
        loop {
            // Read header
            let mut header = [0u8; FRAME_HEADER_SIZE];
            self.reader.read_exact(&mut header).await?;

            let len = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
            let type_byte = header[4];

            if len > MAX_FRAME_SIZE {
                return Err(NetworkError::PacketError {
                    reason: format!("Frame too large: {} bytes", len),
                }
                .into());
            }

            // Read packet data
            self.read_buffer.clear();
            self.read_buffer.reserve(len);

            // Use take adapter to read exactly len bytes without over-reading
            // and use read_buf to avoid initializing memory
            use tokio::io::AsyncReadExt;
            let mut taker = (&mut self.reader).take(len as u64);
            while self.read_buffer.len() < len {
                let n = taker.read_buf(&mut self.read_buffer).await?;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
                }
            }

            match type_byte {
                FRAME_TYPE_DATA => {
                    return Ok(self.read_buffer.split());
                }
                FRAME_TYPE_PADDING => {
                    continue;
                }
                _ => {
                    continue;
                }
            }
        }
    }
}

/// Write half of a split FramedStream.
#[allow(dead_code)]
pub struct FramedWriter<W> {
    writer: W,
    padding_buffer: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    /// Creates a new FramedWriter.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            padding_buffer: Vec::with_capacity(1024),
        }
    }

    /// Sends a data packet over the stream.
    #[allow(dead_code)]
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!("Packet too large: {} bytes", packet.len()),
            }
            .into());
        }

        let len = packet.len() as u32;
        let mut header = [0u8; FRAME_HEADER_SIZE];
        // Length
        header[0..4].copy_from_slice(&len.to_be_bytes());
        // Type
        header[4] = FRAME_TYPE_DATA;

        self.writer.write_all(&header).await?;
        self.writer.write_all(packet).await?;
        self.writer.flush().await?;

        Ok(())
    }

    /// Sends a data packet but does NOT flush the stream.
    /// Useful for batching multiple packets. Caller MUST flush manually.
    pub async fn send_packet_no_flush(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!("Packet too large: {} bytes", packet.len()),
            }
            .into());
        }

        let len = packet.len() as u32;
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0..4].copy_from_slice(&len.to_be_bytes());
        header[4] = FRAME_TYPE_DATA;

        self.writer.write_all(&header).await?;
        self.writer.write_all(packet).await?;

        Ok(())
    }

    /// Sends a padding packet.
    #[allow(dead_code)]
    pub async fn send_padding(&mut self, len: usize) -> Result<()> {
        if len > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!("Padding too large: {} bytes", len),
            }
            .into());
        }

        let len_u32 = len as u32;
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0..4].copy_from_slice(&len_u32.to_be_bytes());
        header[4] = FRAME_TYPE_PADDING;

        self.writer.write_all(&header).await?;

        // Random padding (reuse buffer)
        self.padding_buffer.clear();
        // Resize zeroes, but since we overwrite with random soon, it's fine.
        // Zeroing is cheap compared to allocation.
        self.padding_buffer.resize(len, 0);
        rand::thread_rng().fill_bytes(&mut self.padding_buffer);

        self.writer.write_all(&self.padding_buffer).await?;

        self.writer.flush().await?;

        Ok(())
    }

    /// Flushes the underlying stream.
    pub async fn flush(&mut self) -> Result<()> {
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
