//! Framed stream implementation for length-prefixed packet transport.
//!
//! This module provides a `FramedStream` that wraps any AsyncRead/AsyncWrite
//! stream and provides packet-level read/write operations using length-prefixed
//! framing. This replaces QUIC datagrams for our TCP/TLS transport.
//!
//! ## Frame Format
//!
//! Fixed 3-byte header: `[type: 1 byte] [length: 2 bytes big-endian]`
//!
//! Maximum payload: 65535 bytes (u16::MAX).

use crate::constants::MAX_FRAME_SIZE;
use crate::error::{NetworkError, Result};
use bytes::{BufMut, BytesMut};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Frame type: Data packet
const FRAME_TYPE_DATA: u8 = 0x00;
/// Frame type: Padding (for traffic shaping)
const FRAME_TYPE_PADDING: u8 = 0x01;
/// Frame type: Heartbeat (keep-alive)
const FRAME_TYPE_HEARTBEAT: u8 = 0x02;

/// Encodes a compact frame header.
/// Format: [1 byte type] [2 bytes length BE]
/// Total: 3 bytes (down from 5 bytes in old format)
#[inline]
fn encode_compact_header(len: usize, frame_type: u8) -> ([u8; 3], usize) {
    let len_bytes = (len as u16).to_be_bytes();
    ([frame_type, len_bytes[0], len_bytes[1]], 3)
}

/// Reads and decodes a compact frame header from an async reader.
/// Returns (frame_type, payload_length).
async fn read_compact_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u8, usize)> {
    let mut header = [0u8; 3];
    reader.read_exact(&mut header).await?;

    let frame_type = header[0];
    let len = u16::from_be_bytes([header[1], header[2]]) as usize;

    Ok((frame_type, len))
}

/// Reads a complete frame from an async reader using compact header format.
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, buffer: &mut BytesMut) -> Result<u8> {
    let (frame_type, len) = read_compact_header(reader).await?;

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

    Ok(frame_type)
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
            // VPN packets are typically ≤ MTU (1500). Allocate 2KB initially;
            // BytesMut will grow if a larger frame arrives (rare).
            read_buffer: BytesMut::with_capacity(2048),
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

        let (header, header_len) = encode_compact_header(packet.len(), FRAME_TYPE_DATA);

        // Simple implementation for duplex stream (mostly used in tests)
        self.stream.write_all(&header[..header_len]).await?;
        self.stream.write_all(packet).await?;
        self.stream.flush().await?;

        Ok(())
    }

    pub async fn send_padding(&mut self, len: usize) -> Result<()> {
        let (header, header_len) = encode_compact_header(len, FRAME_TYPE_PADDING);

        self.stream.write_all(&header[..header_len]).await?;
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
            read_buffer: BytesMut::with_capacity(2048),
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
            padding_buffer: Vec::with_capacity(256),
            // Pre-allocate buffer for batch coalescing. 8KB holds ~5 MTU packets.
            // BytesMut will grow on demand if needed.
            write_buffer: BytesMut::with_capacity(8 * 1024),
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

        // Use compact header for minimal overhead
        let (header, header_len) = encode_compact_header(packet.len(), FRAME_TYPE_DATA);

        // 1. Write Header to Buffer (Memory Op)
        self.write_buffer.put_slice(&header[..header_len]);

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

        let (header, header_len) = encode_compact_header(len, FRAME_TYPE_PADDING);

        self.writer.write_all(&header[..header_len]).await?;

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

    /// Sends a heartbeat (zero-payload keep-alive frame).
    /// Used to prevent middleboxes from closing idle TCP/TLS connections.
    pub async fn send_heartbeat(&mut self) -> Result<()> {
        let (header, header_len) = encode_compact_header(0, FRAME_TYPE_HEARTBEAT);
        self.writer.write_all(&header[..header_len]).await?;
        self.writer.flush().await?;
        Ok(())
    }
}
