//! Connection pool for parallel TCP/TLS connections.
//!
//! This module manages multiple parallel connections to improve throughput
//! by aggregating bandwidth across multiple TCP streams.

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use mirage::transport::framed::{FramedReader, FramedWriter};

/// A pooled connection with its reader and writer components.
pub struct PooledConnection {
    pub reader: FramedReader<ReadHalf<SslStream<TcpStream>>>,
    pub writer: FramedWriter<WriteHalf<SslStream<TcpStream>>>,
}

/// Manages multiple parallel TCP/TLS connections for improved throughput.
pub struct ConnectionPool {
    /// Session ID shared across all connections in this pool
    pub session_id: [u8; 8],
    /// Writers for outbound traffic (one per connection)
    writers: Vec<FramedWriter<WriteHalf<SslStream<TcpStream>>>>,
    /// Readers for inbound traffic (one per connection)  
    readers: Vec<FramedReader<ReadHalf<SslStream<TcpStream>>>>,
    /// Round-robin index for load balancing
    round_robin_idx: AtomicUsize,
}

impl ConnectionPool {
    /// Creates a new connection pool from authenticated connections.
    pub fn new(
        session_id: [u8; 8],
        connections: Vec<(
            ReadHalf<SslStream<TcpStream>>,
            WriteHalf<SslStream<TcpStream>>,
        )>,
    ) -> Self {
        let mut readers = Vec::with_capacity(connections.len());
        let mut writers = Vec::with_capacity(connections.len());

        for (read_half, write_half) in connections {
            readers.push(FramedReader::new(read_half));
            writers.push(FramedWriter::new(write_half));
        }

        Self {
            session_id,
            writers,
            readers,
            round_robin_idx: AtomicUsize::new(0),
        }
    }

    /// Returns the number of connections in the pool.
    pub fn len(&self) -> usize {
        self.writers.len()
    }

    /// Returns true if the pool has no connections.
    pub fn is_empty(&self) -> bool {
        self.writers.is_empty()
    }

    /// Takes ownership of all writers for distribution to outbound tasks.
    pub fn take_writers(
        self,
    ) -> (
        Vec<FramedWriter<WriteHalf<SslStream<TcpStream>>>>,
        Vec<FramedReader<ReadHalf<SslStream<TcpStream>>>>,
    ) {
        (self.writers, self.readers)
    }
}

/// Arc-wrapped connection pool for shared access.
pub type SharedConnectionPool = Arc<ConnectionPool>;
