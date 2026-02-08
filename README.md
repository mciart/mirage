# Mirage (原本的 Quincy)

[![Crates.io](https://img.shields.io/crates/v/mirage.svg)](https://crates.io/crates/mirage)
[![Documentation](https://docs.rs/mirage/badge.svg)](https://docs.rs/mirage/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENCE)

> **Mirage** 是一款基于 Rust 开发的下一代 VPN 客户端和服务端，旨在提供极致的隐蔽性和性能。
> 它从原本的 QUIC 架构迁移到了 **TCP/TLS**，集成 **BoringSSL** 以完美模拟 Chrome 指纹，并采用 **Reality** 协议思想进行主动伪装。

<img src="docs/gui.png" alt="GUI" width="800">

---

## 核心特性 (Features)

基于最新的[理论分析](./docs/mirage_feasibility_analysis.md)，Mirage 具备以下独有优势：

### 1. 完美的 TLS 指纹伪装 🎭
Mirage 放弃了传统的 OpenSSL/Rustls 模拟方案，直接集成 Google Chrome 同源的 **BoringSSL** 库。
- **原生 Chrome 指纹**：支持 X25519Kyber768 (后量子加密)、GREASE 扩展、TLS 扩展随机排列。
- **抗主动探测**：服务端无法通过 TLS 握手特征识别，完美伪装成正常的 HTTPS 流量。

### 2. Reality 协议集成 🌐
服务端不再仅仅是一个 VPN 端点，而是一个智能的 SNI 反向代理：
- **验证通过**：进入 VPN 隧道模式，高速传输数据。
- **验证失败**：无缝转发到真实的目标网站（如 `www.microsoft.com`），探测者只能看到合法的网站内容。

### 3. 高性能传输架构 🚀
- **TCP 模式**:
  - Length-Prefixed 帧协议，解决 TCP 粘包问题。
  - **TCP 优化 (Linux)**: BBR 拥塞控制、TCP_QUICKACK、Smart Batching。
  - **多 TCP 连接池**: 1-4 个并行连接，Active-Standby 策略。
- **QUIC 模式 (New)**:
  - 基于 **h3 (HTTP/3)** 伪装，完美模拟标准 QUIC 流量。
  - **0-RTT**: 连接复用与快速握手。
  - **端口跳跃 (Port Hopping)**: 指定时间间隔自动轮换 UDP 端口，对抗 ISP 针对长连接的 QoS 或阻断。

### 4. 流量混淆与隐匿 🕵️
- **加权拟态轮廓**: 模拟真实 HTTPS 流量的三态分布（小包/中包/大包）。
- **智能时序抖动 (Jitter)**: 随机化发包间隔，对抗时序关联分析。
- **应用层心跳 (Heartbeat)**: 空闲时自动保活。

### 5. 多模共存 (Multi-Mode) 🌗
服务端单端口 (443) 同时支持 **标准 TLS**、**Reality** 和 **QUIC** 等多种协议，客户端拥有极高的连接灵活性：
- **自定义优先级**: 客户端可通过配置文件定义 `enabled_protocols` 列表（例如 `["quic", "reality", "tcp-tls"]`）。
- **智能回退**: 如果首选协议连接失败，自动尝试下一个协议。

### 6. 全双工双栈聚合 (Full-Duplex Dual Stack Aggregation) 🌐
- **双向带宽聚合**: 客户端和服务端均实现了多路径分发 (Session Dispatcher)。
- **IPv4/IPv6 并发**: 同时利用 v4 和 v6 链路进行传输，互为备份且聚合带宽。
- **协议级多路复用**: 自适应 TCP 和 QUIC 的连接特性，同时利用 TCP 的稳定性和 QUIC 的低延迟。
- **SNI 伪装**: 支持自定义 SNI，配合 Reality 实现连接 IP 与 伪装域名的分离 (Domain Fronting 思想)。

---

## 架构对比 (Mirage vs Quincy vs Xray)

| 特性 | Quincy (旧版) | Mirage (新版) | Xray (Reality) |
|------|---------------|---------------|----------------|
| **传输层** | QUIC (UDP) | TCP/TLS + QUIC | TCP/TLS, QUIC, WS, gRPC |
| **TLS 库** | Rustls | **BoringSSL** (Chrome 同源) | uTLS (Go) |
| **伪装能力** | 弱 | **极致** (Reality + Chrome 指纹 + QUIC h3) | 强 (Reality) |
| **抗探测** | 易受限 | **端口跳跃** + Jitter + Padding | Vision 流控 |
| **多路复用** | 弱 | **强** (QUIC Stream Mux + TCP Pool) | Mux.Cool |
| **网络栈** | IPv4 | **Dual Stack (v4+v6 聚合)** | Dual Stack |

---

## 快速开始 (Quick Start)

### 支持平台
- [x] Windows (x86_64) - 使用 Wintun
- [x] Linux (x86_64, aarch64)
- [x] macOS (aarch64)
- [x] FreeBSD (x86_64, aarch64)

### 编译安装

Mirage 依赖 Rust 工具链和 C 编译器（用于构建 BoringSSL）。

```bash
# 编译所有组件
cargo build --release

# 安装二进制文件
cargo install --path mirage-client
cargo install --path mirage-server
cargo install --path mirage-gui
```

### 使用 Docker 运行（未测试）

```bash
# 服务端运行示例
docker run --rm \
  --cap-add=NET_ADMIN \
  --device=/dev/net/tun \
  -p 443:443 \
  -v $(pwd)/config:/etc/mirage \
  m0dex/mirage:latest \
  mirage-server --config-path /etc/mirage/server.toml
```

---

## 配置指南 (Configuration)

### 客户端 (`client.toml`)

```toml
# Mirage 服务器的连接地址和端口 (支持直接 IP)
connection_string = "1.2.3.4:443"

[connection]
# 自定义 SNI (可选)
# 连接 IP 时伪装成域名，实现类似域前置的效果
sni = "www.microsoft.com"

# 并发连接数
parallel_connections = 2       # TCP 并发数
quic_parallel_connections = 2  # QUIC 并发数
dual_stack_enabled = true      # 开启 IPv4/IPv6 双栈聚合

# 开启的协议优先顺序 (支持: "reality", "tcp-tls", "quic")
enabled_protocols = ["reality", "tcp-tls", "quic"]

[reality]
# 伪装的目标域名，必须与服务端一致
target_sni = "www.microsoft.com"
# 客户端认证 ShortId (列表)
short_ids = ["abcd1234deadbeef"]

[authentication]
username = "myuser"
password = "mypassword"
```

> [!TIP]
> **关于全局路由 (Global Mode)**:
> 在 `client.toml` 配置路由时，**强烈建议**保留 **拆分路由** (`0.0.0.0/1` + `128.0.0.0/1`) 的配置。
> 虽然 Mirage 客户端已经内置了智能的防环路机制（自动检测网关并添加排除路由），但拆分路由利用 "最长前缀匹配" 原则，能更稳定地接管系统流量，避免与 macOS 系统的默认路由发生冲突。

### 服务端 (`server.toml`)

```toml
bind_address = "0.0.0.0"
# IPv6: bind_address = "::0"
bind_port = 443
tunnel_network = "10.0.0.1/24"
# IPv6 (可选，开启双栈):
# tunnel_network_v6 = "fd00::1/64"

[reality]
# 伪装目标，非 VPN 流量将被转发到此地址
target_sni = "www.microsoft.com"
# 客户端客户端 ShortId 列表 (需要与客户端匹配)
short_ids = ["abcd1234deadbeef"]

[connection]
reuse_socket = true
```

更多示例请参考 [`examples/`](examples/) 目录。


---

## 网络配置与 NAT (Networking)

为了让客户端能够通过 VPN 访问互联网，您**必须**在服务端进行网络配置 (Enable Forwarding & NAT)。

### 4. 自动化 NAT 配置 (可选)

Mirage 服务端可以自动配置系统的 NAT (Masquerade) 和转发规则，省去手动配置 `iptables` 的麻烦。

在 `server.toml` 中添加 `[nat]` 部分：

```toml
[nat]
# IPv4 出站网口 (例如 eth0)
# 如果配置了此项，Mirage 启动时会自动执行:
# sysctl -w net.ipv4.ip_forward=1
# iptables -t nat -A POSTROUTING -s 10.11.12.0/24 -o eth0 -j MASQUERADE
ipv4_interface = "eth0"

# IPv6 出站网口 (例如 eth0)
# 如果配置了此项，会自动配置 ip6tables 转发和 MASQUERADE
ipv6_interface = "eth0"
```

> **注意**: 
> 1. 启用此功能需要服务端以 `root` 权限运行。
> 2. **如果留空或不配置**：Mirage 不会修改任何 iptables 规则。您需要手动参照下文进行配置。
> 3. 服务端停止时，这些规则会自动清理 (Best Effort)。

### 5. 手动网络配置 (Linux)

如果您不想使用自动配置，或者环境比较复杂，可以手动配置。

#### 开启 IP 转发 (必须)
```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
```

#### 配置 NAT (Masquerade)
如果您的服务端在 NAT 后面 (例如 AWS EC2)，或者您希望客户端通过服务器 IP 上网：

```bash
# IPv4 (假设网卡是 eth0)
iptables -t nat -A POSTROUTING -s 10.11.12.0/24 -o eth0 -j MASQUERADE

# IPv6 (假设网卡是 eth0)
ip6tables -t nat -A POSTROUTING -s fd00::/64 -o eth0 -j MASQUERADE
```

**关键：放行转发流量 (FORWARD Chain)**:
如果系统的默认策略是 DROP，您必须显式放行 VPN 流量，否则包会被内核丢弃！
```bash
# IPv4
iptables -I FORWARD -o tun+ -j ACCEPT
iptables -I FORWARD -i tun+ -j ACCEPT

# IPv6 (不要忘记这个！)
ip6tables -I FORWARD -o tun+ -j ACCEPT
ip6tables -I FORWARD -i tun+ -j ACCEPT
```

---

## 用户管理 (User Management)

Mirage 使用 `Argon2` 算法存储加密的用户密码。服务端提供了配套的 `mirage-users` 命令行工具来管理用户文件。

### 1. 安装工具
`mirage-users` 包含在 `mirage-server` 包中：
```bash
cargo install --path mirage-server
# 现在可以使用 mirage-users 命令
```

### 2. 使用方法
```bash
# 添加新用户 (交互式输入密码)
mirage-users --add users

# 删除用户
mirage-users --delete users
```

### 3. 服务端配置
生成好用户文件后，在 `server.toml` 中配置路径：
```toml
[authentication]
type = "file"
users_file = "users"
```
---

## 附录：Feasibility Analysis (可行性分析)

详情请参阅项目中的 [理论分析](./docs/mirage_feasibility_analysis.md) 文档，其中详细阐述了从 QUIC 迁移到 TCP/TLS 的技术决策过程和路线图。

### 开发路线图 (Roadmap)
- [x] **Phase 1**: 基础 TCP/TLS 隧道开发 (已完成)
- [x] **Phase 2**: 功能增强与伪装 (Reality 已完成)
- [x] **Phase 3**: 流量混淆与隐匿 (Padding, Jitter & Heartbeat 已完成)
- [x] **Phase 3.5**: 性能优化 (连接池, TCP BBR, Smart Batching 已完成)
- [x] **Phase 4**: QUIC 传输层回归 (h3 伪装, 0-RTT)
- [x] **Phase 5**: 进阶抗封锁 (Port Hopping 端口跳跃, Dual Stack 双栈聚合)
- [ ] **Phase 6**: CDN 支持 (WebSocket, gRPC 等)

---

## 许可证

Mirage 使用 AGPL-3.0 许可证。
