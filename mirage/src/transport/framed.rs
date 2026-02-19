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
use crate::transport::crypto::{FrameCipher, TAG_SIZE};
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

pub struct FramedReader<R> {
    reader: R,
    read_buffer: BytesMut,
    cipher: Option<FrameCipher>,
}

impl<R: AsyncRead + Unpin> FramedReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            read_buffer: BytesMut::with_capacity(2048),
            cipher: None,
        }
    }

    /// Sets the decryption cipher for this reader.
    pub fn set_cipher(&mut self, cipher: FrameCipher) {
        self.cipher = Some(cipher);
    }

    /// Receives a data packet from the reader, skipping padding frames.
    /// If a cipher is set, DATA payloads are decrypted automatically.
    pub async fn recv_packet(&mut self) -> Result<BytesMut> {
        loop {
            let type_byte = read_frame(&mut self.reader, &mut self.read_buffer).await?;
            match type_byte {
                FRAME_TYPE_DATA => {
                    if let Some(cipher) = &mut self.cipher {
                        // Build AAD from the original frame header (type + encrypted length)
                        let encrypted_len = self.read_buffer.len();
                        let (aad, _) = encode_compact_header(encrypted_len, FRAME_TYPE_DATA);

                        let plaintext = cipher.decrypt(&aad, &self.read_buffer).map_err(|e| {
                            NetworkError::PacketError {
                                reason: format!("Decryption failed: {}", e),
                            }
                        })?;

                        self.read_buffer.clear();
                        self.read_buffer.extend_from_slice(&plaintext);
                    }
                    return Ok(self.read_buffer.split());
                }
                FRAME_TYPE_PADDING => continue,
                _ => continue,
            }
        }
    }

    /// Zero-allocation packet processing: reads a data frame into the internal
    /// buffer and calls `write_fn` with a reference to the packet data.
    ///
    /// Unlike `recv_packet()`, this does NOT call `split()` on the buffer,
    /// so the buffer retains its capacity across calls — zero heap allocations
    /// per packet after the first.
    #[inline]
    pub async fn recv_and_write<F>(&mut self, write_fn: F) -> Result<()>
    where
        F: FnOnce(&[u8]),
    {
        loop {
            let type_byte = read_frame(&mut self.reader, &mut self.read_buffer).await?;
            match type_byte {
                FRAME_TYPE_DATA => {
                    if let Some(cipher) = &mut self.cipher {
                        let encrypted_len = self.read_buffer.len();
                        let (aad, _) = encode_compact_header(encrypted_len, FRAME_TYPE_DATA);

                        let plaintext = cipher.decrypt(&aad, &self.read_buffer).map_err(|e| {
                            NetworkError::PacketError {
                                reason: format!("Decryption failed: {}", e),
                            }
                        })?;

                        write_fn(&plaintext);
                    } else {
                        write_fn(&self.read_buffer);
                    }
                    return Ok(());
                }
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
    /// Whether to pad write buffers to TLS record boundaries (16KB)
    tls_record_padding: bool,
    /// Optional encryption cipher for DATA payloads
    cipher: Option<FrameCipher>,
}

/// TLS record payload size (16KB). Real browsers fill entire records during data transfer.
const TLS_RECORD_SIZE: usize = 16384;
/// Minimum buffer size before considering TLS record padding (avoids padding tiny writes)
const TLS_PAD_THRESHOLD: usize = 4096;

impl<W: AsyncWrite + Unpin> FramedWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            padding_buffer: Vec::with_capacity(256),
            // Pre-allocate buffer for batch coalescing. 8KB holds ~5 MTU packets.
            // BytesMut will grow on demand if needed.
            write_buffer: BytesMut::with_capacity(8 * 1024),
            tls_record_padding: false,
            cipher: None,
        }
    }

    /// Enables TLS record boundary padding on this writer.
    pub fn set_tls_record_padding(&mut self, enabled: bool) {
        self.tls_record_padding = enabled;
    }

    /// Sets the encryption cipher for this writer.
    pub fn set_cipher(&mut self, cipher: FrameCipher) {
        self.cipher = Some(cipher);
    }

    /// Sends a data packet immediately (buffers then flushes).
    pub async fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.send_packet_no_flush(packet).await?;
        self.flush().await?;
        Ok(())
    }

    /// Buffers a data packet into memory.
    /// If a cipher is set, the payload is encrypted before buffering.
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

        if let Some(cipher) = &mut self.cipher {
            // Encrypted path: encrypt payload, then write header with encrypted length
            let encrypted_len = packet.len() + TAG_SIZE;
            let (header, header_len) = encode_compact_header(encrypted_len, FRAME_TYPE_DATA);

            // Encrypt with AAD = frame header (type + length)
            let ciphertext = cipher.encrypt(&header[..header_len], packet).map_err(|e| {
                NetworkError::PacketError {
                    reason: format!("Encryption failed: {}", e),
                }
            })?;

            self.write_buffer.put_slice(&header[..header_len]);
            self.write_buffer.put_slice(&ciphertext);
        } else {
            // Plaintext path: use compact header for minimal overhead
            let (header, header_len) = encode_compact_header(packet.len(), FRAME_TYPE_DATA);
            self.write_buffer.put_slice(&header[..header_len]);
            self.write_buffer.put_slice(packet);
        }

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
            // TLS Record Padding: when enabled, pad buffers between 4KB-16KB to fill
            // an entire TLS record. This makes all records a uniform 16KB, matching
            // real HTTPS browser behavior (browsers always fill records during data transfer).
            if self.tls_record_padding
                && self.write_buffer.len() >= TLS_PAD_THRESHOLD
                && self.write_buffer.len() < TLS_RECORD_SIZE
            {
                let gap = TLS_RECORD_SIZE - self.write_buffer.len();
                // Account for the padding frame header (3 bytes)
                if gap > 3 {
                    let pad_payload_len = gap - 3;
                    let (header, header_len) =
                        encode_compact_header(pad_payload_len, FRAME_TYPE_PADDING);
                    self.write_buffer.put_slice(&header[..header_len]);
                    // Fill with random bytes
                    let start = self.write_buffer.len();
                    self.write_buffer.resize(start + pad_payload_len, 0);
                    rand::thread_rng().fill_bytes(&mut self.write_buffer[start..]);
                }
            }

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
