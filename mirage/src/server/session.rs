use bytes::Bytes;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::debug;

/// Manages a user session with multiple connections, performing
/// load-balancing for downlink (server -> client) traffic.
pub struct SessionDispatcher {
    /// Channel receiving packets from TUN interface (intended for this user)
    ingress_rx: Receiver<Bytes>,
    /// Channel for registering new connections to this session
    register_rx: Receiver<Sender<Bytes>>,
    /// Active connections (senders to their write queues)
    connections: Vec<Sender<Bytes>>,
}

impl SessionDispatcher {
    pub fn new(ingress_rx: Receiver<Bytes>, register_rx: Receiver<Sender<Bytes>>) -> Self {
        Self {
            ingress_rx,
            register_rx,
            connections: Vec::new(),
        }
    }

    pub async fn run(mut self) {
        debug!("SessionDispatcher started");

        let mut robin_idx: usize = 0;

        loop {
            tokio::select! {
                // Handle new packet from TUN
                Some(packet) = self.ingress_rx.recv() => {
                    if self.connections.is_empty() {
                        // No active connections, drop packet
                        continue;
                    }

                    // Round-Robin distribution using try_send (non-blocking).
                    // CRITICAL: We must NOT use send().await here because if one
                    // connection's channel is full (slow/dying QUIC stream), it would
                    // block the entire dispatcher and freeze ALL connections.
                    let num_conns = self.connections.len();
                    let mut sent = false;
                    let mut has_closed = false;

                    for attempt in 0..num_conns {
                        let idx = (robin_idx + attempt) % num_conns;

                        if self.connections[idx].is_closed() {
                            has_closed = true;
                            continue;
                        }

                        match self.connections[idx].try_send(packet.clone()) {
                            Ok(_) => {
                                robin_idx = (idx + 1) % num_conns;
                                sent = true;
                                break;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                // Channel full — skip this connection, try next
                                debug!("SessionDispatcher: connection {} channel full, skipping", idx);
                                continue;
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                has_closed = true;
                                continue;
                            }
                        }
                    }

                    if !sent {
                        debug!("SessionDispatcher: no available connections for packet, dropped");
                    }

                    // Clean up closed connections
                    if has_closed {
                        let old_len = self.connections.len();
                        self.connections.retain(|tx| !tx.is_closed());
                        if self.connections.len() < old_len {
                            debug!("Cleaned up {} closed connections in session", old_len - self.connections.len());
                        }
                        if self.connections.is_empty() {
                            robin_idx = 0;
                        } else {
                            robin_idx %= self.connections.len();
                        }
                    }
                }

                // Handle new connection registration
                Some(conn_tx) = self.register_rx.recv() => {
                    debug!("SessionDispatcher: Registering new connection sender (total: {})",
                        self.connections.len() + 1);
                    self.connections.push(conn_tx);
                }

                else => {
                    debug!("SessionDispatcher shutting down");
                    break;
                }
            }
        }
    }
}

/// Context stored in the SessionMap to allow new connections to join
#[derive(Clone)]
pub struct SessionContext {
    /// The main packet sender (put this into ConnectionMap)
    pub packet_tx: Sender<Bytes>,
    /// Channel to register a new connection's sender
    pub register_tx: Sender<Sender<Bytes>>,
    /// Number of active connections in this session.
    /// Only the last connection to exit performs cleanup.
    pub connection_count: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
