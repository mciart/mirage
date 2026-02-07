//! Framed stream implementation for length-prefixed packet transport.
//!
//! This module provides a `FramedStream` that wraps any AsyncRead/AsyncWrite
//! stream and provides packet-level read/write operations using length-prefixed
//! framing. This replaces QUIC datagrams for our TCP/TLS transport.

use crate::constants::{FRAME_HEADER_SIZE, MAX_FRAME_SIZE};
use crate::error::{NetworkError, Result};
use bytes::{BufMut, BytesMut};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const FRAME_TYPE_DATA: u8 = 0x00;
const FRAME_TYPE_PADDING: u8 = 0x01;

/// Reads and parses a single frame from an async reader.
///
/// This function handles the common frame parsing logic:
/// - Reads the 5-byte header (4-byte length + 1-byte type)
/// - Validates frame size against MAX_FRAME_SIZE
/// - Reads the frame payload into the provided buffer
/// - Returns the frame type byte for caller to handle
///
/// # Arguments
/// * `reader` - Any type implementing AsyncRead + Unpin
/// * `buffer` - BytesMut buffer to read the frame payload into
///
/// # Returns
/// The frame type byte on success
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, buffer: &mut BytesMut) -> Result<u8> {
    let mut header = [0u8; FRAME_HEADER_SIZE];
    reader.read_exact(&mut header).await?;

    let len = u32::from_be_bytes(header[0..4].try_into().unwrap()) as usize;
    let type_byte = header[4];

    if len > MAX_FRAME_SIZE {
        return Err(NetworkError::PacketError {
            reason: format!("Frame too large: {} bytes (max: {})", len, MAX_FRAME_SIZE),
        }
        .into());
    }

    buffer.clear();
    buffer.reserve(len);

    // Use take() to limit reads to exactly `len` bytes
    let mut taker = reader.take(len as u64);
    while buffer.len() < len {
        let n = taker.read_buf(buffer).await?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
    }

    Ok(type_byte)
}

/// A framed stream that provides packet-level operations over a byte stream.
pub struct FramedStream<S> {
    stream: S,
    read_buffer: BytesMut,
}

impl<S> FramedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
        header[0..4].copy_from_slice(&len.to_be_bytes());
        header[4] = FRAME_TYPE_DATA;

        // Simple implementation for duplex stream (mostly used in tests)
        self.stream.write_all(&header).await?;
        self.stream.write_all(packet).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn send_padding(&mut self, len: usize) -> Result<()> {
        let len_u32 = len as u32;
        let mut header = [0u8; FRAME_HEADER_SIZE];
        header[0..4].copy_from_slice(&len_u32.to_be_bytes());
        header[4] = FRAME_TYPE_PADDING;

        self.stream.write_all(&header).await?;
        let mut padding = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut padding);
        self.stream.write_all(&padding).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receives a data packet from the stream, skipping padding frames.
    pub async fn recv_packet(&mut self) -> Result<BytesMut> {
        loop {
            let type_byte = read_frame(&mut self.stream, &mut self.read_buffer).await?;
            match type_byte {
                FRAME_TYPE_DATA => return Ok(self.read_buffer.split()),
                FRAME_TYPE_PADDING => continue,
                _ => continue,
            }
        }
    }

    pub fn inner(&self) -> &S {
        &self.stream
    }
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.stream
    }
    pub fn into_inner(self) -> S {
        self.stream
    }
}

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

pub struct FramedReader<R> {
    reader: R,
    read_buffer: BytesMut,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            read_buffer: BytesMut::with_capacity(MAX_FRAME_SIZE),
        }
    }

    /// Receives a data packet from the reader, skipping padding frames.
    pub async fn recv_packet(&mut self) -> Result<BytesMut> {
        loop {
            let type_byte = read_frame(&mut self.reader, &mut self.read_buffer).await?;
            match type_byte {
                FRAME_TYPE_DATA => return Ok(self.read_buffer.split()),
                FRAME_TYPE_PADDING => continue,
                _ => continue,
            }
        }
    }
}

/// Write half of a split FramedStream.
pub struct FramedWriter<W> {
    writer: W,
    padding_buffer: Vec<u8>,
    // Accumulation buffer for Write Coalescing
    write_buffer: BytesMut,
}

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            padding_buffer: Vec::with_capacity(1024),
            // Pre-allocate a larger buffer (e.g. 32KB) to hold multiple packets
            write_buffer: BytesMut::with_capacity(32 * 1024),
        }
    }

    /// Sends a data packet immediately (buffers then flushes).
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.send_packet_no_flush(packet).await?;
        self.flush().await?;
        Ok(())
    }

    /// Buffers a data packet into memory.
    /// DOES NOT perform any system calls or encryption until flush() is called.
    /// This achieves True Write Coalescing.
    pub async fn send_packet_no_flush(&mut self, packet: &[u8]) -> Result<()> {
        if packet.len() > MAX_FRAME_SIZE {
            return Err(NetworkError::PacketError {
                reason: format!("Packet too large: {} bytes", packet.len()),
            }
            .into());
        }

        // Safety check: If buffer is getting too full (>64KB), force a flush to prevent OOM
        // or exceeding typical TLS record limits excessively.
        if self.write_buffer.len() > 64 * 1024 {
            self.flush_internal(false).await?;
        }

        let len = packet.len() as u32;

        // 1. Write Header to Buffer (Memory Op)
        self.write_buffer.put_u32(len);
        self.write_buffer.put_u8(FRAME_TYPE_DATA);

        // 2. Write Payload to Buffer (Memory Op)
        self.write_buffer.put_slice(packet);

        Ok(())
    }

    /// Sends a padding packet.
    pub async fn send_padding(&mut self, len: usize) -> Result<()> {
        // If we have pending data, flush it first to keep padding logic simple and synchronized
        if !self.write_buffer.is_empty() {
            self.flush_internal(false).await?;
        }

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

        self.padding_buffer.clear();
        self.padding_buffer.resize(len, 0);
        rand::thread_rng().fill_bytes(&mut self.padding_buffer);

        self.writer.write_all(&self.padding_buffer).await?;
        self.writer.flush().await?;

        Ok(())
    }

    /// Flushes the write buffer to the underlying stream and then flushes the stream.
    pub async fn flush(&mut self) -> Result<()> {
        self.flush_internal(true).await
    }

    // Helper to flush buffer to stream, optionally flushing the stream itself
    async fn flush_internal(&mut self, flush_stream: bool) -> Result<()> {
        if !self.write_buffer.is_empty() {
            // This Single Write Call will be encrypted as one (or few) large TLS records
            self.writer.write_all(&self.write_buffer).await?;
            self.write_buffer.clear();
        }

        if flush_stream {
            self.writer.flush().await?;
        }
        Ok(())
    }
}
