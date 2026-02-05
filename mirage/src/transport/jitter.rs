use crate::config::ObfuscationConfig;
use crate::network::packet::Packet;
use crate::transport::framed::FramedWriter;
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

                        // [核心修改] 流量整形 (Traffic Shaping)
                        // 使用加权分布替代均匀随机，模拟真实 HTTPS 特征
                        if config.enabled && config.padding_probability > 0.0 {
                             use rand::Rng;

                             if rand::thread_rng().gen_bool(config.padding_probability) {
                                 // 生成 0-99 的随机数来决定包的大小类型
                                 let profile = rand::thread_rng().gen_range(0..100);

                                 let raw_len = if profile < 60 {
                                     // 60% 概率：模拟 "控制帧/ACK" (40-100 Bytes)
                                     // 像 TLS Alerts, HTTP/2 WindowUpdates
                                     rand::thread_rng().gen_range(40..=100)
                                 } else if profile < 90 {
                                     // 30% 概率：模拟 "Headers/元数据" (250-600 Bytes)
                                     // 像 HTTP Headers, TLS Handshake fragments
                                     rand::thread_rng().gen_range(250..=600)
                                 } else {
                                     // 10% 概率：模拟 "数据切片" (800-1200 Bytes)
                                     // 像图片加载的数据块
                                     rand::thread_rng().gen_range(800..=1200)
                                 };

                                 // 仍然遵守配置的最大值限制以防 MTU 溢出，
                                 // 但我们允许它小于 config.padding_min (因为小包才更像真实的 ACK)
                                 let final_len = raw_len.min(config.padding_max).max(1);

                                 if let Err(e) = writer.send_padding(final_len).await {
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
