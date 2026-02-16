# Mirage VPN — 安全与隐匿性分析

## 检测手段与对策矩阵

| 检测手段 | 对策 | 状态 |
|---------|------|------|
| **SNI 阻断** | Mirage 伪装 (TCP) / JLS (QUIC) | ✅ |
| **TLS 指纹识别** | BoringSSL (Chrome 同源指纹) | ✅ |
| **主动探测 (Active Probing)** | ShortID 验证 (TCP) + JLS 上游转发 (QUIC) | ✅ |
| **包长度分析** | 加权拟态轮廓 (Weighted Traffic Mimicry) | ✅ |
| **时序关联分析** | 智能时序抖动 (Jitter) | ✅ |
| **静默连接检测** | 应用层心跳 (Heartbeat) | ✅ |
| **长连接指纹** | 连接轮换 (max_lifetime + jitter) | ✅ |
| **UDP 长连接阻断** | QUIC Port Hopping | ✅ |
| **单栈封锁** | IPv4/IPv6 双栈聚合 | ✅ |
| **CDN 封锁** | WebSocket/gRPC | ⏳ 计划中 |

---

## 伪装能力分析

### TCP 层: Mirage 伪装 ✅

TCP+TLS 连接具备完整的抗检测能力：

1. **BoringSSL 原生指纹**: Chrome 同源库，指纹无法与真实浏览器区分
2. **SNI 伪装**: ClientHello 中呈现目标网站的 SNI (如 `www.microsoft.com`)
3. **ALPN ShortID 认证**: 通过 ALPN 扩展携带认证令牌，验证失败则反向代理到真实网站
4. **抗主动探测**: 探测者无论怎样尝试都只能看到真实网站的响应

### QUIC 层: JLS 伪装 ✅

QUIC 连接集成 **JLS (rustls-jls + quinn-jls)**，实现 QUIC 层完整伪装：

- JLS 认证：通过 `jls_password` + `jls_iv` 进行客户端/服务端双向验证
- 抗主动探测：未通过 JLS 认证的连接自动转发到上游真实网站 (如 `www.microsoft.com:443`)
- h3 ALPN 伪装 + 端口跳跃 (Port Hopping) + 0-RTT 快速重连

| 特性 | TCP (Mirage 伪装) | QUIC (JLS 伪装) |
|------|-------------------|-----------------|
| SNI 伪装 | ✅ | ✅ |
| 无需证书 | ✅ | ✅ |
| 抗主动探测 | ✅ 反向代理 | ✅ 上游转发 |
| TLS 指纹 | ✅ Chrome (BoringSSL) | ✅ JLS |
| 延迟 | 1-RTT | **0-RTT** |

**两种协议都具备完整的抗检测能力**，QUIC 还额外拥有 0-RTT 超低延迟优势。

---

## 与 Xray 深度对比

### 1. 握手隐匿性 — 打平
- **Xray (Reality)**: 模拟真实 TLS 握手，盗取目标网站证书特征
- **Mirage**: 完全相同的原理 + BoringSSL 原生 Chrome 指纹

### 2. 流量特征 — Mirage 略优
- **Xray**: Vision 流控，配置依赖性强
- **Mirage**: 加权拟态轮廓 (3 态分布) + Jitter + Heartbeat，开箱即用

### 3. 生存能力 — 各有侧重
- **Xray**: WebSocket / gRPC + CDN 支持
- **Mirage**: Port Hopping + Dual Stack + 连接轮换，直连抗封锁更强

### 4. 协议层级 — Mirage 胜出
- **Xray**: L4 代理 (SOCKS/HTTP)
- **Mirage**: **L3 VPN** — 原生 ICMP/TCP/UDP，双栈聚合

### 5. QUIC 伪装 — Mirage 全面领先
- **Xray**: QUIC 无 Reality 伪装
- **Mirage**: JLS QUIC 层完整伪装 + 0-RTT + Port Hopping

---

## 协议技术细节

- **帧格式**: `[Length: 2B][Type: 1B][Payload]` — 紧凑仅 3 字节开销
- **Padding**: 三态加权分布 (60% 小包 / 30% 中包 / 10% 大包)
- **Jitter**: 随机化 0-20ms 发包间隔
- **Port Hopping**: QUIC 每 N 秒轮换 UDP 端口 (默认 0 = 禁用)
- **连接轮换**: max_lifetime_s (默认 300s) + lifetime_jitter_s (±60s)
