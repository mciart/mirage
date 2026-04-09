# Mirage（开发测试中）

[![Crates.io](https://img.shields.io/crates/v/mirage.svg)](https://crates.io/crates/mirage)
[![Documentation](https://docs.rs/mirage/badge.svg)](https://docs.rs/mirage/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENCE)

> **Mirage** 是一款基于 Rust 开发的下一代隐匿 L3 VPN，集成 **BoringSSL** (Chrome 同源)、**Mirage 伪装协议** (TCP SNI 伪装 + 抗主动探测)、**JLS** (QUIC 层伪装 + 0-RTT)，以及智能流量混淆。

<img src="resources/docs/gui.png" alt="GUI" width="800">

---

## 核心特性

### 🛡️ BoringSSL — 原生 Chrome TLS 指纹
集成 Google Chrome 同源的 **BoringSSL**，原生支持 GREASE、TLS 扩展随机排列。
不是"模拟"Chrome 指纹 (uTLS 的做法)，**就是 Chrome 的 TLS 栈本身**。
针对论文 *Killing the Parrot* 揭示的 CCS 阈值攻击、注入式探测、ECH GREASE 泄露等问题**完全免疫**。

### 🎭 Mirage 伪装协议
TCP 和 QUIC 双协议均具备完整伪装能力，探测者只能看到合法流量：
- **TCP 层**: BoringSSL (Chrome 指纹) + SNI 伪装 + 认证，验证失败反向代理到真实网站
- **QUIC 层**: JLS 伪装 (rustls-jls) + 0-RTT 超低延迟，未认证连接自动转发到上游真实网站
- 无需目标网站证书即可伪装任意域名，抗主动探测

### 🚀 高性能双协议传输
- **TCP 模式**: Length-Prefixed 帧协议 + BBR 拥塞控制 + TCP_QUICKACK + Smart Batching
- **QUIC 模式**: JLS 伪装 + 0-RTT 快速握手 + 端口跳跃 (Port Hopping)
- **协议优先级回退**: `protocols = ["udp", "tcp"]`，先尝试 QUIC，失败自动回退 TCP

### 🌊 流量混淆与纵深加密
- **应用层加密 (Inner Encryption)**: ChaCha20-Poly1305 AEAD 独立加密 DATA 帧，即使外层 TLS 被 CDN 剥离，内层数据仍为密文
- **TLS 记录填充**: 将写入填充到 16KB TLS Record 边界，对抗记录大小指纹
- **加权拟态轮廓**: 模拟真实 HTTPS 的三态分布 (控制帧 / 头部 / 数据块)
- **双向填充对称**: 检测非对称传输并自动增强填充
- **智能时序抖动 (Jitter)**: 自适应随机化发包间隔，空闲放大、高流量缩小
- **应用层心跳 (Heartbeat)**: 空闲时自动保活，防止"长连接零吞吐"特征

### 🌐 全双工双栈聚合
- IPv4/IPv6 并发聚合带宽
- 多连接池 (1-4 并行连接)
- 连接轮换 (max_lifetime) 对抗长连接指纹

---

## 架构对比

| 特性 | Mirage | Xray (Reality) | NaiveProxy | AnyTLS | OpenVPN |
|------|--------|----------------|------------|--------|---------|
| **传输层** | TCP/TLS + QUIC + 优先级回退 | TCP/TLS, QUIC, WS, gRPC | Chromium HTTP/2 | 自定义 TLS | TCP/UDP (自定义) |
| **TLS 库** | **BoringSSL** (Chrome 同源) | uTLS (Go 模拟) | Chromium (原生) | OpenSSL | OpenSSL |
| **TCP 伪装** | SNI + 抗主动探测 | Reality | Chromium 原生 | 自定义握手 | 无 (特征明显) |
| **QUIC 伪装** | **JLS** (无需证书 + 0-RTT) | 无 | 无 | 无 | 无 |
| **VPN 层级** | **L3 VPN** (原生 ICMP/TCP/UDP) | L4 代理 (SOCKS/HTTP) | L4 代理 | L4 代理 | L3 VPN |
| **流量混淆** | Padding + Jitter + Heartbeat + **Inner Encryption** | Vision 流控 | 无 | 无 | 无 (需插件) |
| **CDN 支持** | ⏳ 计划中 | ✅ (WS/gRPC) | ✅ (需要证书) | ✅ | 无 |

---

## 安全分析

> [!NOTE]
> 完整的安全分析、已知问题、改进计划和检测对策矩阵请参阅 **[SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md)**。

**核心安全能力：**

| 论文攻击方式 | Reality (Go/uTLS) | **Mirage** |
|---|---|---|
| JA3/JA4 指纹 | ⚠️ uTLS 模拟 | ✅ BoringSSL 原生 |
| CCS 计数器阈值 | ❌ 致命 (16 vs 32) | ✅ 免疫 (32 全链路) |
| Warning Alert 计数器 | ❌ 暴露 | ✅ 原生行为 |
| 注入式攻击 (4.5) | ❌ Go 行为不同 | ✅ BoringSSL 行为正确 |
| ECH GREASE 泄露 | ❌ uTLS 漏洞 | ✅ BoringSSL 原生 |
| 重放攻击 (4.4) | ❌ Go TLS ≠ 真实服务器 | ⚠️ 代理回落缓解 |

**已知待改进：**

| 问题 | 风险 | 优先级 |
|---|---|---|
| 认证令牌传输通道可被被动检测 | 高 | 🔴 P0 |
| FrameCipher 密钥 Drop 时未完全清零 | 中 | 🟡 P1 |
| 代理回落存在时序差异 | 中 | 🟡 P1 |

> 详细的改进计划和待办事项请参阅 [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) 第二节。

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
zsh resources/scripts/build-apple.sh

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

使用 `post_up` / `post_down` 生命周期脚本配置网络，与 WireGuard 的 PostUp/PostDown 用法一致。
`%i` 会自动替换为 TUN 接口名（如 `mirage0` 或 `interface_name` 指定的名称）。

### iptables (Debian 12 及以前 / Ubuntu 20.04)

```toml
# 指定 TUN 接口名（可选）
interface_name = "mirage0"

post_up = [
    "sysctl -w net.ipv4.ip_forward=1",
    "sysctl -w net.ipv6.conf.all.forwarding=1",
    "iptables -A FORWARD -i %i -j ACCEPT",
    "iptables -A FORWARD -o %i -j ACCEPT",
    "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE",
    "ip6tables -A FORWARD -i %i -j ACCEPT",
    "ip6tables -A FORWARD -o %i -j ACCEPT",
    "ip6tables -t nat -A POSTROUTING -s fd00::/64 -o eth0 -j MASQUERADE",
]
post_down = [
    "iptables -D FORWARD -i %i -j ACCEPT",
    "iptables -D FORWARD -o %i -j ACCEPT",
    "iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE",
    "ip6tables -D FORWARD -i %i -j ACCEPT",
    "ip6tables -D FORWARD -o %i -j ACCEPT",
    "ip6tables -t nat -D POSTROUTING -s fd00::/64 -o eth0 -j MASQUERADE",
]
```

### nftables (Debian 13+ / Ubuntu 22.04+ / RHEL 9+)

```toml
interface_name = "mirage0"

post_up = [
    "sysctl -w net.ipv4.ip_forward=1",
    "sysctl -w net.ipv6.conf.all.forwarding=1",
    "nft add table inet mirage",
    "nft add chain inet mirage forward { type filter hook forward priority 0 \\; policy accept \\; }",
    "nft add rule inet mirage forward iifname %i accept",
    "nft add rule inet mirage forward oifname %i accept",
    "nft add chain inet mirage postrouting { type nat hook postrouting priority 100 \\; }",
    "nft add rule inet mirage postrouting ip saddr 10.0.0.0/24 oifname eth0 masquerade",
    "nft add rule inet mirage postrouting ip6 saddr fd00::/64 oifname eth0 masquerade",
]
post_down = [
    "nft delete table inet mirage",
]
```

> [!TIP]
> 不配置 `post_up` / `post_down` 则不进行任何自动网络配置。
> nftables 的 `post_down` 只需一条命令即可清理所有规则，比 iptables 更简洁。

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
- [x] **Phase 7.5**: **纵深加密** — 应用层 ChaCha20-Poly1305 AEAD + TLS 记录填充 + 双向填充对称
- [ ] **Phase 8**: CDN 支持 (WebSocket, gRPC)

---

## 许可证

Mirage 使用 AGPL-3.0 许可证。
