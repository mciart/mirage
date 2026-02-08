# Mirage VPN Security Analysis & Xray Comparison

## 深度对比评估 (Deep Dive Comparison)

Mirage VPN 目前在**直连隐匿性**（Stealth）上，已经达到了与 Xray (VLESS/VMess + Reality) 相同甚至超越的顶尖水平。

### 1. 握手隐匿性 (Handshake) —— **打平**
*   **Xray (Reality)**: 模拟真实的 TLS 握手，盗取目标网站的证书特征。
*   **Mirage (Reality)**: 采用了完全相同的原理。通过 `SslStream` 和伪装 SNI，Mirage 呈现的也是标准的 HTTPS 流量。
*   **结论**: **平手**。GFW 看到的都只是在访问一个正常的海外网站。

### 2. 流量特征隐匿性 (Traffic Fingerprint) —— **Mirage 略优**
*   **Xray**: 虽然有 Vision 流控，但对包长度的随机化处理主要依赖于具体配置和协议。
*   **Mirage**:
    *   **Padding (Weighted Traffic Mimicry)**: 采用高级的**加权拟态轮廓**，模拟真实 HTTPS 流量的三态分布。
    *   **Jitter**: Mirage 的随机时序抖动专门针对"关联分析"。
    *   **Heartbeat**: 空闲时自动保活，防止因"长连接零吞吐"被识别。
*   **结论**: **Mirage 在抗深度分析上更进一步**。

### 3. 生存能力 (Resurrect/CDN) —— **Mirage 进化**
*   **Xray**: 支持 WebSocket / gRPC，可以套 Cloudflare CDN。
*   **Mirage**:
    *   **Port Hopping (QUIC)**: 独有的端口跳跃技术，每隔 N 秒（如 30s）自动轮换 UDP 端口，利用 QUIC 连接迁移特性保持会话不断。这有效规避了针对长连接 UDP 的 QoS 和阻断。
    *   **CDN**: 目前尚未支持 WebSocket (Planned)，仍需 TCP 直连。
*   **结论**: **Mirage 在直连抗封锁上通过 Port Hopping 扳回一局，但 CDN 支持仍缺席**。

### 4. 协议层级与体验 (Layer & UX) —— **Mirage 胜出**
*   **Xray**: 本质上是 **L4 代理** (SOCKS/HTTP)。
*   **Mirage**: 是真正的 **L3 VPN (HTTPS/QUIC VPN)**，支持原生 ICMP，支持 **双栈聚合 (IPv4+IPv6)**。
*   **结论**: **Mirage 提供更底层、更完整的网络体验**。

### 5. 性能优化 (Performance) —— **Mirage 胜出**
*   **Xray**: 默认配置，依赖 Go 运行时。
*   **Mirage**:
    *   **多 TCP 连接池**: 1-4 个并行连接，Active-Standby 策略避免乱序
    *   **QUIC 0-RTT**: 极速重连与连接复用
    *   **Dual Stack Aggregation**: 同时榨干 IPv4 和 IPv6 带宽
    *   **TCP BBR / 4MB Buffer**: 工业级内核调优
*   **结论**: **Mirage 性能优化达到工业级水准**。

### 总结

Mirage 具备对抗 GFW 所有主流检测手段的能力：
1.  **SNI 阻断/检测** -> Reality
2.  **TLS 指纹识别** -> BoringSSL + Reality
3.  **包长度分析** -> Padding
4.  **时序关联分析** -> Jitter
5.  **静默连接检测** -> Heartbeat
6.  **带宽限制/连接中断** -> 连接池 + Dual Stack
7.  **UDP QoS/长连接阻断** -> QUIC Port Hopping

**技术细节**：
- **Protocol V2**: `[Length: 2B][Type: 1B][Payload]` (紧凑帧头，仅 3 字节)
- **Padding**: 三态加权分布，模拟真实协议特征
- **Jitter**: 随机睡眠 0-20ms
- **Port Hopping**: QUIC 连接每 30s 轮换端口
- **Dual Stack**: 同时并发使用 IPv4/IPv6
