//! Connection pool for parallel TCP/TLS connections.
//!
//! This module manages multiple parallel connections to improve throughput
//! by aggregating bandwidth across multiple TCP streams.

#![allow(dead_code)]

use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use crate::transport::framed::{FramedReader, FramedWriter};
use tokio::io::{ReadHalf, WriteHalf};

use super::TransportStream;

/// A pooled connection with its reader and writer components.
pub struct PooledConnection {
    pub reader: FramedReader<ReadHalf<TransportStream>>,
    pub writer: FramedWriter<WriteHalf<TransportStream>>,
}

/// Manages multiple parallel TCP/TLS connections for improved throughput.
pub struct ConnectionPool {
    /// Session ID shared across all connections in this pool
    pub session_id: [u8; 8],
    /// Writers for outbound traffic (one per connection)
    writers: Vec<FramedWriter<WriteHalf<TransportStream>>>,
    /// Readers for inbound traffic (one per connection)  
    readers: Vec<FramedReader<ReadHalf<TransportStream>>>,
    /// Round-robin index for load balancing
    round_robin_idx: AtomicUsize,
}

impl ConnectionPool {
    /// Creates a new connection pool from authenticated connections.
    #[allow(clippy::type_complexity)]
    pub fn new(
        session_id: [u8; 8],
        connections: Vec<(ReadHalf<TransportStream>, WriteHalf<TransportStream>)>,
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
    #[allow(clippy::type_complexity)]
    pub fn take_writers(
        self,
    ) -> (
        Vec<FramedWriter<WriteHalf<TransportStream>>>,
        Vec<FramedReader<ReadHalf<TransportStream>>>,
    ) {
        (self.writers, self.readers)
    }
}

/// Arc-wrapped connection pool for shared access.
pub type SharedConnectionPool = Arc<ConnectionPool>;
