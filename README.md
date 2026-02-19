# Mirage（开发测试中）

[![Crates.io](https://img.shields.io/crates/v/mirage.svg)](https://crates.io/crates/mirage)
[![Documentation](https://docs.rs/mirage/badge.svg)](https://docs.rs/mirage/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENCE)

> **Mirage** 是一款基于 Rust 开发的下一代隐匿 L3 VPN，集成 **BoringSSL** (Chrome 同源)、**Mirage 伪装协议** (TCP SNI 伪装 + 抗主动探测)、**JLS** (QUIC 层伪装 + 0-RTT)，以及智能流量混淆。

<img src="docs/gui.png" alt="GUI" width="800">

---

## 核心特性

### 🛡️ 完美的 TLS 指纹伪装
集成 Google Chrome 同源的 **BoringSSL**，原生支持 X25519Kyber768 (后量子)、GREASE、TLS 扩展随机排列。
任何检测者看到的都是标准 Chrome HTTPS 流量。

### 🎭 Mirage 伪装协议
TCP 和 QUIC 双协议均具备完整伪装能力，探测者只能看到合法流量：
- **TCP 层**: BoringSSL (Chrome 指纹) + SNI 伪装 + ShortID 认证，验证失败反向代理到真实网站
- **QUIC 层**: JLS 伪装 (rustls-jls) + 0-RTT 超低延迟，未认证连接自动转发到上游真实网站
- 无需目标网站证书即可伪装任意域名，抗主动探测

### 🚀 高性能双协议传输
- **TCP 模式**: Length-Prefixed 帧协议 + BBR 拥塞控制 + TCP_QUICKACK + Smart Batching
- **QUIC 模式**: JLS 伪装 + 0-RTT 快速握手 + 端口跳跃 (Port Hopping)
- **协议优先级回退**: `protocols = ["udp", "tcp"]`，先尝试 QUIC，失败自动回退 TCP

### 🌊 流量混淆
- **加权拟态轮廓 (Weighted Traffic Mimicry)**: 模拟真实 HTTPS 的三态分布
- **智能时序抖动 (Jitter)**: 随机化发包间隔，对抗时序关联分析
- **应用层心跳 (Heartbeat)**: 空闲时自动保活，防止"长连接零吞吐"特征

### 🌐 全双工双栈聚合
- IPv4/IPv6 并发聚合带宽
- 多连接池 (1-4 并行连接)
- 连接轮换 (max_lifetime) 对抗长连接指纹

---

## 架构对比

| 特性 | Mirage | Xray (Reality) | OpenVPN |
|------|--------|----------------|---------|
| **传输层** | TCP/TLS + QUIC + 优先级回退 | TCP/TLS, QUIC, WS, gRPC | TCP/UDP (自定义协议) |
| **TLS 库** | **BoringSSL** (Chrome 同源) | uTLS (Go) | OpenSSL |
| **TCP 伪装** | **类 Reality** (SNI + 抗主动探测) | Reality | 无 (特征明显) |
| **QUIC 伪装** | **JLS** (无需证书 + 抗主动探测 + 0-RTT) | 无 | 无 |
| **VPN 层级** | **L3 VPN** (原生 ICMP/TCP/UDP) | L4 代理 (SOCKS/HTTP) | L3 VPN (TUN/TAP) |
| **流量混淆** | Padding + Jitter + Heartbeat | Vision 流控 | 无 (需插件) |
| **抗封锁** | Port Hopping + Dual Stack + 连接轮换 | CDN (WS/gRPC) | 弱 (协议指纹易识别) |

| 维度 | Xray REALITY | Mirage |
|---|---|---|
| CCS 阈值攻击 | ❌ **致命** (Go 16 vs 源网站 32) | ✅ **免疫** (BoringSSL 32 全链路) |
| 回落对比攻击 | ❌ 两种 TLS 栈行为差异 150% | ✅ 同系 TLS 栈，无差异 |
| "Caddy 困境" | ❌ 修复后反而更分裂 | ⚠️ 仅当 target_sni 指向 Go 服务器时有风险 |
| 被动识别 (域名/IP 不匹配) | ⚠️ 通用风险 | ⚠️ 同等风险 |
| 被动识别 (多源单聚) | ⚠️ 通用风险 | ⚠️ 同等风险 |

---

## 快速开始

### 支持平台

| 平台 | 架构 | 方式 |
|------|------|------|
| Windows | x86_64 | CLI (Wintun) |
| Linux | x86_64, aarch64 | CLI |
| macOS | aarch64, x86_64 | **原生 SwiftUI GUI** + CLI |
| iOS / iPadOS | aarch64 | **原生 SwiftUI GUI** (Network Extension) |
| FreeBSD | x86_64, aarch64 | CLI |

### 编译安装

**CLI (命令行)**:

```bash
cargo build --release
cargo install --path mirage
```

**macOS / iOS GUI**:

```bash
# 一键编译所有 Apple 平台 Rust FFI 库
zsh scripts/build-apple.sh

# 用 Xcode 打开并构建
open apple/Mirage/Mirage.xcodeproj
# ⌘⇧K (Clean Build Folder) → ⌘R (Run)
```

### 使用

```bash
mirage client --config client.toml   # 运行客户端
mirage server --config server.toml   # 运行服务端
mirage users --add users             # 管理用户
```

### Docker

```bash
docker run --rm \
  --cap-add=NET_ADMIN --device=/dev/net/tun \
  -p 443:443 -v $(pwd)/config:/etc/mirage \
  m0dex/mirage:latest \
  mirage server --config /etc/mirage/server.toml
```

---

## 配置指南

> [!TIP]
> **全局路由**: 建议使用 `0.0.0.0/1` + `128.0.0.0/1` 拆分路由，利用最长前缀匹配原则稳定接管流量。

示例请参考 [`examples/`](examples/) 目录。

---

## 网络配置 (服务端)

### 自动 NAT 配置

```toml
[nat]
ipv4_interface = "eth0"
ipv6_interface = "eth0"
```

> 启用需 `root` 权限，停止时自动清理。留空则不修改 iptables。

### 手动配置

```bash
# 开启转发
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1

# NAT
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
ip6tables -t nat -A POSTROUTING -s fd00::/64 -o eth0 -j MASQUERADE

# 放行 FORWARD
iptables -I FORWARD -o tun+ -j ACCEPT && iptables -I FORWARD -i tun+ -j ACCEPT
ip6tables -I FORWARD -o tun+ -j ACCEPT && ip6tables -I FORWARD -i tun+ -j ACCEPT
```

---

## 用户管理

使用 `Argon2` 加密存储密码：

```bash
mirage users --add /path/to/users      # 添加用户（users 为用户文件路径，默认 ./users）
mirage users --delete /path/to/users   # 删除用户
```

---

## 路线图

- [x] **Phase 1**: TCP/TLS 隧道
- [x] **Phase 2**: Mirage 伪装协议 (TCP 层 SNI 伪装 + 抗主动探测)
- [x] **Phase 3**: 流量混淆 (Padding, Jitter, Heartbeat)
- [x] **Phase 4**: QUIC 传输 (h3 伪装, 0-RTT, Port Hopping)
- [x] **Phase 5**: 双栈聚合 + 连接轮换
- [x] **Phase 6**: **JLS 集成** — QUIC 层 Mirage 伪装 (无需证书, 0-RTT, 抗主动探测)
- [x] **Phase 7**: **Apple 原生 GUI** — SwiftUI (macOS + iOS/iPadOS) + Network Extension
- [ ] **Phase 8**: CDN 支持 (WebSocket, gRPC)

---

## 许可证

Mirage 使用 AGPL-3.0 许可证。
