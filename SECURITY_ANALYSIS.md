# Mirage VPN Security Analysis & Xray Comparison

## 深度对比评估 (Deep Dive Comparison)

Mirage VPN 目前在**直连隐匿性**（Stealth）上，已经达到了与 Xray (VLESS/VMess + Reality) 相同甚至超越的顶尖水平。

### 1. 握手隐匿性 (Handshake) —— **打平**
*   **Xray (Reality)**: 模拟真实的 TLS 握手，盗取目标网站的证书特征。
*   **Mirage (Reality)**: 采用了完全相同的原理。通过 `SslStream` 和伪装 SNI，Mirage 呈现的也是标准的 HTTPS 流量。
*   **结论**: **平手**。GFW 看到的都只是在访问一个正常的海外网站。

### 2. 流量特征隐匿性 (Traffic Fingerprint) —— **Mirage 略优**
*   **Xray**: 虽然有 Vision 流控，但对包长度的随机化处理主要依赖于具体配置和协议（如 VMess 自带 Padding，VLESS 较轻量）。
*   **Mirage (V2)**:
    *   **Padding (Weighted Traffic Mimicry)**: 采用高级的**加权拟态轮廓**。不再是简单的均匀随机，而是模拟真实 HTTPS 流量的三态分布（60% 小包控制帧、30% 中包元数据、10% 大包数据），极大地欺骗了基于机器学习的流量识别模型。
    *   **Jitter (独有优势)**: **这是 Xray 默认配置中通常缺乏的**。Mirage 的随机时序抖动（Jitter）专门针对“关联分析”，即使 GFW 同时监控了您的入口和出口，也很难通过时间戳精确匹配流量。这在对抗高端分析时非常有效。
    *   **Heartbeat (Active Keep-Alive)**: 针对**行为特征 (Behavioral Fingerprint)** 的优化。即使在空闲时，Mirage 也会模拟应用层心跳（10-30秒随机间隔，发送 40-80 字节小包），防止因“长时间活跃但零吞吐”被识别为挂机的隧道，同时有效对抗运营商 NAT 的静默超时。
*   **结论**: **Mirage 在抗深度分析（关联/时序）上可能更进一步**。

### 3. 生存能力 (Resurrect/CDN) —— **Xray 胜出**
*   **Xray**: 支持 WebSocket / gRPC，可以套 Cloudflare CDN。如果 IP 被墙，还可以通过 CDN 救活。
*   **Mirage**: 目前仅支持 TCP 直连。如果 IP 被彻底封锁（黑洞），Mirage 无法通过 CDN 绕过。
*   **结论**: **这是目前唯一的短板**。但在**没被墙**的情况下，Mirage 的直连体验和隐匿性完全不输 Xray。

### 4. 协议层级与体验 (Layer & UX) —— **Mirage 胜出**
*   **Xray**: 本质上是 **L4 代理** (SOCKS/HTTP)。虽然可以通过 TUN 模式模拟 VPN，但其核心设计依然是基于流（Stream）的代理。需要复杂的路由规则配置，且对 ICMP (Ping) 等底层协议的支持通常是模拟的。
*   **Mirage**: 是真正的 **L3 VPN (HTTPS VPN)**。
    *   通过 TUN 接口直接接管操作系统层面的所有 IP 数据包。
    *   支持原生 **ICMP (Ping)**，对于用户来说，就像插了一根直通海外的虚拟网线。
    *   **全局接管**：无需配置浏览器或应用的代理设置，即插即用，体验更接近原生网络。
*   **结论**: **Mirage 提供更底层、更完整的网络体验**。

### 总结
作为一款**直连 VPN**，Mirage 现在的隐匿性可以说是**“完美”**的（State-of-the-Art）。
它具备了对抗 GFW 目前所有主流检测手段的能力：
1.  **SNI 阻断/检测** -> 由 Reality 解决。
2.  **TLS 指纹识别** -> 由 BoringSSL + Reality 解决。
3.  **包长度分析** -> 由 Padding 解决。
4.  **时序关联分析** -> 由 Jitter 解决。
5.  **静默连接检测** -> 由 Heartbeat 解决。

**技术细节**：
- **Protocol V2**: `[Length: 4][Type: 1][Payload]`
- **Padding**: 类型 `0x01`，采用**三态加权分布**（40-100B / 250-600B / 800-1200B），模拟真实协议特征。
- **Jitter**: 发送前随机睡眠 `0-20ms`。
- **Heartbeat**: 空闲 10-30s 随机触发，发送 40-80B 填充包。
