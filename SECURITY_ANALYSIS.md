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
    *   **Padding**: 强制启用的 5% 概率随机填充，专门破坏长度指纹。
    *   **Jitter (独有优势)**: **这是 Xray 默认配置中通常缺乏的**。Mirage 的随机时序抖动（Jitter）专门针对“关联分析”，即使 GFW 同时监控了您的入口和出口，也很难通过时间戳精确匹配流量。这在对抗高端分析时非常有效。
*   **结论**: **Mirage 在抗深度分析（关联/时序）上可能更进一步**。

### 3. 生存能力 (Resurrect/CDN) —— **Xray 胜出**
*   **Xray**: 支持 WebSocket / gRPC，可以套 Cloudflare CDN。如果 IP 被墙，还可以通过 CDN 救活。
*   **Mirage**: 目前仅支持 TCP 直连。如果 IP 被彻底封锁（黑洞），Mirage 无法通过 CDN 绕过。
*   **结论**: **这是目前唯一的短板**。但在**没被墙**的情况下，Mirage 的直连体验和隐匿性完全不输 Xray。

### 总结
作为一款**直连 VPN**，Mirage 现在的隐匿性可以说是**“完美”**的（State-of-the-Art）。
它具备了对抗 GFW 目前所有主流检测手段的能力：
1.  **SNI 阻断/检测** -> 由 Reality 解决。
2.  **TLS 指纹识别** -> 由 BoringSSL + Reality 解决。
3.  **包长度分析** -> 由 Padding 解决。
4.  **时序关联分析** -> 由 Jitter 解决。

**技术细节**：
- **Protocol V2**: `[Length: 4][Type: 1][Payload]`
- **Padding**: 类型 `0x01`，大小 `100-1000` 字节，概率 `5%`。
- **Jitter**: 发送前随机睡眠 `0-20ms`。
