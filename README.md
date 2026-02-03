# Mirage (原本的 Quincy)

[![Crates.io](https://img.shields.io/crates/v/mirage.svg)](https://crates.io/crates/mirage)
[![Documentation](https://docs.rs/mirage/badge.svg)](https://docs.rs/mirage/)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENCE)

> [!WARNING]
> **🚧 项目开发中 (Work in Progress) 🚧**
>
> Mirage 目前处于 **Phase 2 (Reality 服务端)** 开发阶段。虽然代码可以通过编译 (`cargo build --release`)，但可能仍不稳定。
> 详情请查阅 [Mirage 可行性分析](./mirage_feasibility_analysis.md)。

> **Mirage** 是一款基于 Rust 开发的下一代 VPN 客户端和服务端，旨在提供极致的隐蔽性和性能。
> 它从原本的 QUIC 架构迁移到了 **TCP/TLS**，集成 **BoringSSL** 以完美模拟 Chrome 指纹，并采用 **Reality** 协议思想进行主动伪装。

<img src="docs/gui.png" alt="GUI" width="800">

---

## 核心特性 (Features)

基于最新的[理论分析](./mirage_feasibility_analysis.md)，Mirage 具备以下独有优势：

### 1. 完美的 TLS 指纹伪装 🎭
Mirage 放弃了传统的 OpenSSL/Rustls 模拟方案，直接集成 Google Chrome 同源的 **BoringSSL** 库。
- **原生 Chrome 指纹**：支持 X25519Kyber768 (后量子加密)、GREASE 扩展、TLS 扩展随机排列。
- **抗主动探测**：服务端无法通过 TLS 握手特征识别，完美伪装成正常的 HTTPS 流量。

### 2. Reality 协议集成 🌐
服务端不再仅仅是一个 VPN 端点，而是一个智能的 SNI 反向代理：
- **验证通过**：进入 VPN 隧道模式，高速传输数据。
- **验证失败**：无缝转发到真实的目标网站（如 `www.microsoft.com`），探测者只能看到合法的网站内容。

### 3. 高性能 TCP 传输 🚀
- 采用 Length-Prefixed 帧协议，解决 TCP 粘包问题。
- 设计为未来支持 **XTLS-Vision** 流控，旨在消除 TLS-in-TLS 双重加密开销，实现原生 HTTPS 级别的性能。

### 4. 多模共存 (Multi-Mode) 🌗
服务端单端口 (443) 同时支持 **标准 TLS** 和 **Reality** 等多种协议，客户端拥有极高的连接灵活性：
- **自定义优先级**：客户端可通过配置文件定义 `enabled_protocols` 列表（例如 `["reality", "tcp-tls"]`），决定连接尝试的顺序。
- **按需开启**：您可以为不同的客户端单独配置开启哪些协议。例如，为不方便安装证书的设备仅开启 Reality，或为特定环境仅开启标准 TLS。
- **智能回退**：如果首选协议连接失败（被阻断或超时），客户端会自动尝试列表中的下一个协议，确保连接的高可用性。

### 5. 全面双栈支持 (Full Dual Stack) 🌐
- **IPv4/IPv6 并行**：隧道内部同时分配 V4 和 V6 地址，完美支持双栈流量。
- **自动防环路**：客户端智能检测网关，自动添加防环路路由，彻底告别配置烦恼。

### 6. CDN 友好架构 (Planned) ☁️
- 得益于 **TCP/TLS** 架构，未来将支持 **WebSocket** 传输层。
- **救活被墙 IP**：可配合 Cloudflare 等 CDN 复活被屏蔽的服务器 IP。

---

## 架构对比 (Mirage vs Quincy)

| 特性 | Quincy (旧版) | Mirage (新版) |
|------|---------------|---------------|
| **传输层** | QUIC (UDP) | TCP/TLS (1.3) |
| **扩展性** | 难 (CDN 不支持 UDP) | 强 (原生支持 WebSocket/CDN) |
| **网络层** | IPv4 Only (通常) | Full Dual Stack (IPv4 + IPv6) |
| **TLS 库** | Rustls | BoringSSL (Chrome 同源) |
| **伪装能力** | 弱 (仅标准 TLS) | 强 (Reality + Chrome 指纹) |
| **抗探测** | 易受 UDP QoS 限制 | 伪装为 HTTPS，通用性更强 |

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
# Mirage 服务器的连接地址和端口
connection_string = "your-server.com:443"

# 开启的协议优先顺序 (支持: "reality", "tcp-tls")
enabled_protocols = ["reality", "tcp-tls"]

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
> 在 `client.toml` 配置路由时，建议使用 **拆分路由** (`0.0.0.0/1` + `128.0.0.0/1`) 而非直接使用 `0.0.0.0/0`。
> 这是因为在 macOS 等系统中，直接覆盖默认路由 (`default`) 可能会失败或被系统忽略。拆分路由利用了 "最长前缀匹配" 原则，可以确保流量稳定地被 VPN 接管。

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

详情请参阅项目中的 [mirage_feasibility_analysis.md](./mirage_feasibility_analysis.md) 文档，其中详细阐述了从 QUIC 迁移到 TCP/TLS 的技术决策过程和路线图。

### 开发路线图 (Roadmap)
- [x] **Phase 1**: 基础 TCP/TLS 隧道开发 (已完成)
- [x] **Phase 2**: 功能增强与伪装 (Reality 已完成)
  - [x] Dual Stack (IPv4/IPv6)
  - [x] Reality 协议 (ALPN Auth, SNI Dispatcher)
  - [x] 双模共存与回退 (Protocol Fallback)
- [ ] **Phase 3**: XTLS-Vision 流控优化
- [ ] **Phase 4**: CDN 支持 (WebSocket, gRPC 等)

---

## 许可证

Mirage 使用 AGPL-3.0 许可证。
