use crate::config::ObfuscationConfig;
use crate::transport::framed::FramedWriter;
use crate::network::packet::Packet;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::io::AsyncWrite;
use std::marker::Unpin;
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
        // Queue to hold packets waiting for their send time
        // Item: (Packet, TargetSendTime)
        let mut queue: VecDeque<(Packet, Instant)> = VecDeque::new();
        
        // Track the previous packet's target time to ensure monotonic order
        let mut last_target_time = Instant::now();
        
        loop {
            // Determine the deadline for the next packet
            let sleep_future = if let Some((_, target_time)) = queue.front() {
                // If target_time is in past, sleep_until returns immediately
                Some(tokio::time::sleep_until(*target_time))
            } else {
                None
            };

            tokio::select! {
                // 1. Receive new packets
                res = rx.recv() => {
                    match res {
                        Some(packet) => {
                            // Calculate Jitter
                            let jitter_ms = if config.enabled {
                                use rand::Rng;
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
                        
                        // Also handle Padding Opportunity here?
                        // Or handle in the main loop?
                        // If we move logic here, we need random padding logic.
                        if config.enabled && config.padding_probability > 0.0 {
                             use rand::Rng;
                             if rand::thread_rng().gen_bool(config.padding_probability) {
                                 let pad_len = rand::thread_rng().gen_range(config.padding_min..=config.padding_max);
                                 if let Err(e) = writer.send_padding(pad_len).await {
                                     warn!("Failed to send padding: {}", e);
                                 }
                             }
                        }
                    }
                }
            }
        }
    })
}
