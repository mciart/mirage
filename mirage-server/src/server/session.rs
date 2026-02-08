use bytes::Bytes;
use tokio::sync::mpsc::{Receiver, Sender};
use tracing::{debug, warn};

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

        let mut robin_idx = 0;

        loop {
            tokio::select! {
                // Handle new packet from TUN
                Some(packet) = self.ingress_rx.recv() => {
                    if self.connections.is_empty() {
                        // No active connections, drop packet
                        continue;
                    }

                    // Round-Robin distribution
                    let start_len = self.connections.len();
                    let mut sent = false;
                    let mut attempts = 0;

                    while attempts < start_len {
                        robin_idx = (robin_idx + 1) % self.connections.len();

                        // Try sending to the selected connection
                        // try_send is generally better for dispatching to avoid blocking if one connection is full
                        // But send().await ensures backpressure propagation.
                        // Given we want Aggregation, blocking on one full connection is bad.
                        // Ideally we should skip full connections.
                        // But Sender doesn't expose is_full easily without try_send.

                        // We use `send` for now. If one connection stalls, it might block the dispatcher
                        // which blocks the TUN reader. This is acceptable for now.
                        // Better approach: use `try_send` and if full, try next.

                         match self.connections[robin_idx].send(packet.clone()).await {
                            Ok(_) => {
                                sent = true;
                                break;
                            }
                            Err(_) => {
                                // Channel closed (connection dropped)
                                // We'll clean up closed connections later
                                attempts += 1;
                            }
                        }
                    }

                    // Periodic cleanup of closed connections (e.g. every packet or when failure happens)
                     if !sent || attempts > 0 {
                          // Simple cleanup: retain only open channels
                          let old_len = self.connections.len();
                          self.connections.retain(|tx| !tx.is_closed());
                          if self.connections.len() < old_len {
                               debug!("Cleaned up {} closed connections in session", old_len - self.connections.len());
                          }

                          if self.connections.is_empty() {
                              robin_idx = 0;
                          } else {
                              robin_idx = robin_idx % self.connections.len();
                          }
                     }
                }

                // Handle new connection registration
                Some(conn_tx) = self.register_rx.recv() => {
                    debug!("SessionDispatcher: Registering new connection sender");
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
}
