use crate::config::ObfuscationConfig;
use crate::network::packet::Packet;
use crate::transport::framed::FramedWriter;
use rand::Rng;
use std::collections::VecDeque;
use std::marker::Unpin;
use std::time::Duration;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;
use tracing::{error, warn};

/// Spawns a background task that handles packet sending with jitter.
/// Does NOT block the input channel.
pub fn spawn_jitter_sender<W>(
    mut rx: Receiver<Packet>,
    mut writer: FramedWriter<W>,
    config: ObfuscationConfig,
) -> tokio::task::JoinHandle<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        // Fast Path: If obfuscation is disabled or effectively zero, bypass queue overhead
        let jitter_disabled =
            !config.enabled || (config.jitter_max_ms == 0 && config.padding_probability <= 0.0);

        if jitter_disabled {
            while let Some(packet) = rx.recv().await {
                // Revert Adaptive Batching:
                // Send immediately and flush. This ensures minimum latency for TCP ACKs.
                // Stability > Peak Throughput for TCP Tunnel.
                if let Err(e) = writer.send_packet(&packet).await {
                    error!("Failed to send packet (fast path): {}", e);
                    break;
                }
            }
            return;
        }

        // Slow Path: Jitter Queue
        // Queue to hold packets waiting for their send time
        // Item: (Packet, TargetSendTime)
        let mut queue: VecDeque<(Packet, Instant)> = VecDeque::new();

        // Track the previous packet's target time to ensure monotonic order
        let mut last_target_time = Instant::now();

        // Initialize heartbeat timer with random 10-30 second interval.
        // Only triggers when no real data packets have been sent for this duration.
        let mut next_heartbeat =
            Instant::now() + Duration::from_secs(rand::thread_rng().gen_range(10..=30));

        loop {
            // Determine the deadline for the next packet
            let sleep_future = if let Some((_, target_time)) = queue.front() {
                // If target_time is in past, sleep_until returns immediately
                Some(tokio::time::sleep_until(*target_time))
            } else {
                None
            };

            // Heartbeat future
            let heartbeat_future = tokio::time::sleep_until(next_heartbeat);

            tokio::select! {
                // 1. Receive new packets
                res = rx.recv() => {
                    match res {
                        Some(packet) => {
                            // Activity detection: received real data, reset heartbeat timer.
                            // Avoids inserting unnecessary heartbeats during high-speed transfers.
                            next_heartbeat = Instant::now() + Duration::from_secs(rand::thread_rng().gen_range(10..=30));

                            // Calculate Jitter
                            let jitter_ms = if config.enabled {
                                let range = config.jitter_max_ms - config.jitter_min_ms;
                                if range > 0 {
                                    rand::thread_rng().gen_range(config.jitter_min_ms..=config.jitter_max_ms)
                                } else {
                                    config.jitter_min_ms
                                }
                            } else {
                                0
                            };

                            let now = Instant::now();
                            let jitter = Duration::from_millis(jitter_ms as u64);

                            // Target Time = max(Now + Jitter, LastTargetTime)
                            // This ensures:
                            // 1. At least 'Jitter' delay from now.
                            // 2. Strict ordering (never sent before previous packet).
                            let mut target = now + jitter;
                            if target < last_target_time {
                                target = last_target_time;
                            }
                            last_target_time = target;

                            queue.push_back((packet, target));
                        }
                        None => {
                            // Channel closed
                            // Flush remaining queue?
                            // Yes, best effort.
                            while let Some((pkt, _)) = queue.pop_front() {
                                if let Err(e) = writer.send_packet(&pkt).await {
                                     warn!("Failed to flush packet: {}", e);
                                     break;
                                }
                            }
                            break;
                        }
                    }
                }

                // 2. Send packets when deadline reached
                _ = async {
                    if let Some(s) = sleep_future { s.await } else { std::future::pending().await }
                }, if !queue.is_empty() => {
                    // Timeout reached for the front packet
                    if let Some((packet, _)) = queue.pop_front() {
                        if let Err(e) = writer.send_packet(&packet).await {
                             error!("Failed to send packet: {}", e);
                             break;
                        }

                        // Traffic shaping using weighted distribution instead of uniform random,
                        // simulating real HTTPS traffic characteristics.
                        if config.enabled && config.padding_probability > 0.0 && rand::thread_rng().gen_bool(config.padding_probability) {
                             // Generate random 0-99 to determine packet size type
                             let profile = rand::thread_rng().gen_range(0..100);

                             let raw_len = if profile < 60 {
                                 // 60% probability: simulate "control frames/ACK" (40-100 bytes)
                                 // Like TLS Alerts, HTTP/2 WindowUpdates
                                 rand::thread_rng().gen_range(40..=100)
                             } else if profile < 90 {
                                 // 30% probability: simulate "headers/metadata" (250-600 bytes)
                                 // Like HTTP Headers, TLS Handshake fragments
                                 rand::thread_rng().gen_range(250..=600)
                             } else {
                                 // 10% probability: simulate "data chunks" (800-1200 bytes)
                                 // Like image loading data blocks
                                 rand::thread_rng().gen_range(800..=1200)
                             };

                             // Still respect config max value to prevent MTU overflow,
                             // but allow smaller than config.padding_min (small packets look more like real ACKs)
                             let final_len = raw_len.min(config.padding_max).max(1);

                             if let Err(e) = writer.send_padding(final_len).await {
                                 warn!("Failed to send padding: {}", e);
                             }
                        }
                    }
                }

                // 3. Idle Heartbeat
                // Triggers when there's no data exchange for a long time, simulating long connection keep-alive
                _ = heartbeat_future => {
                    // Send a small 40-80 byte packet, disguised as TCP ACK or Keep-Alive
                    let pad_len = rand::thread_rng().gen_range(40..80);

                    if let Err(e) = writer.send_padding(pad_len).await {
                        warn!("Failed to send heartbeat padding: {}", e);
                    }

                    // Schedule next heartbeat
                    next_heartbeat = Instant::now() + Duration::from_secs(rand::thread_rng().gen_range(10..=30));
                }
            }
        }
    })
}
