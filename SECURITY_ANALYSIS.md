# Mirage VPN — 安全与隐匿性分析

> 本文档基于论文 *[Killing the Parrot: How to Fingerprint & Detect REALITY]* 的攻击模型，结合代码审计，对 Mirage 的安全性进行深度分析。

---

## 一、核心优势

### 1. BoringSSL 全链路 — CCS 阈值攻击免疫 ✅

Mirage 使用 `boring = "4"` (BoringSSL Rust 绑定)，服务端全链路均为 BoringSSL。

| 探测方式 | Mirage (BoringSSL) | Reality (Go) |
|---|---|---|
| Warning Alert 计数器 | **4** (原生) | 16 (暴露) |
| TLS 1.3 明文 CCS | **Bad Record MAC** | 计入计数器 (暴露) |
| Fatal UserCanceled | **按 Warning 计入** | 按 Warning 计入 |
| **CCS 阈值攻击** | **✅ 免疫** (阈值 32) | ❌ 致命 (阈值 16 vs 32) |

### 2. TLS 指纹原生真实 ✅

BoringSSL 是 Chrome 的底层 TLS 库。Mirage 不是"模拟" Chrome 指纹 (uTLS 的做法)，**就是 Chrome 的 TLS 栈本身**。
任何 JA3/JA4 指纹检测、ECH GREASE 检测、注入式攻击 (论文 4.5) 都无法区分 Mirage 与真实 Chrome。

### 3. ALPN ShortID 认证 — 常量时间比较 ✅

`dispatcher.rs` 使用 `subtle::ConstantTimeEq` 进行认证令牌验证，防止时序侧信道攻击。

### 4. 应用层加密 (Inner Encryption) ✅

`crypto.rs` 使用 ChaCha20-Poly1305 AEAD + HKDF-SHA256 密钥派生 + 方向性密钥分离。
即使外层 TLS 被 CDN 剥离，内层 DATA 帧仍为密文。密码学设计规范。

### 5. 双向填充对称 ✅

`jitter.rs` 通过 `receive_activity` 标志检测单向传输，自动增强反方向的填充频率和大小。

### 6. 连接轮换 + minRTT 调度 ✅

XMUX 多连接池 + 随机化 lifetime + EWMA 延迟追踪，对抗长连接指纹。

---

## 二、已知问题与改进计划

### 🔴 P0 — ALPN ShortID 被动指纹 (高风险)

**问题**: ShortID 作为额外的 ALPN 协议名追加到 ALPN 列表。

```
正常 Chrome ALPN: ["h2", "http/1.1"]
Mirage 客户端:    ["h2", "http/1.1", "abcd1234"]
                                      ^^^^^^^^^^^
                                      非标准 ALPN — 被动可检测
```

任何 DPI 设备都可以被动检测 ClientHello 中包含非标准 ALPN 协议名。Chrome 从不发送 `h2`, `http/1.1` 以外的 ALPN（除了 `h3` 用于 QUIC）。

**改进方案**: 迁移到更隐蔽的认证通道，候选方案：

| 通道 | 可行性 | 隐蔽性 |
|---|---|---|
| ClientHello Random 后 8 字节 HMAC | ✅ 最佳 | 极高 — Random 本就是随机数据，DPI 无法区分 |
| TLS Extensions Padding 长度编码 | ⚠️ 中 | 高 — 但 padding 长度可能有规律 |
| TLS PSK Identity | ❌ 低 | 高 — BoringSSL PSK API 受限 |
| Session Ticket 特定字段 | ❌ 低 | 高 — 需要先有 ticket |

推荐：利用 ClientHello Random 的后 8 字节携带 `HMAC-SHA256(PSK, random_prefix)[:8]`。

- [ ] 调查 BoringSSL `SslConnectorBuilder` 是否支持自定义 ClientHello Random
- [ ] 如不支持，调查 BoringSSL FFI 层面 `SSL_CTX_set_client_hello_cb` 或 `SSL_set_tlsext_*` 的可行性
- [ ] 实现 ClientHello Random HMAC 认证方案
- [ ] 从 ALPN 列表移除 ShortID
- [ ] 更新服务端 dispatcher 解析逻辑

---

### 🟡 P1 — FrameCipher 密钥未清零 (中风险)

**问题**: `crypto.rs` 的 `FrameCipher` Drop 实现只清零了 `counter`，未清零 `cipher` 内部的密钥材料。

```rust
impl Drop for FrameCipher {
    fn drop(&mut self) {
        self.counter = 0;  // ← 只清零了 counter
        // cipher (ChaCha20Poly1305) 的密钥材料未被擦除
    }
}
```

`Cargo.toml` 已引入 `zeroize`，但未在 `FrameCipher` 上使用。

- [ ] 验证 `chacha20poly1305` crate 的 `ChaCha20Poly1305` 是否在 Drop 时自动 zeroize
- [ ] 若不自动清零，在 `FrameCipher` 中保存 `Zeroizing<[u8; 32]>` 密钥副本
- [ ] 确保 `counter` 也通过 `zeroize` trait 清零

---

### 🟡 P1 — 重放攻击时序差异 (中风险)

**问题**: 论文 4.4 的重放式探测 — 审查者将 ClientHello 重放到真实目标服务器对比 ServerHello 响应。

Mirage 的 Proxy 回落在 ClientHello 解析阶段就会介入（无有效 ShortID → TCP pipe to 真实服务器），探测者拿到的是真实服务器的 ServerHello。**但代理增加了一跳**：

| 子问题 | 说明 |
|---|---|
| TCP TTL 差异 | 代理增加一跳，TTL 值不同 |
| TLS 握手时序 | 代理 DNS 解析 + TCP 连接增加延迟 |
| 服务端 TLS 配置差异 | `SslAcceptor::mozilla_intermediate_v5` 预设的密码套件/扩展可能与目标服务器不同 |

- [ ] 预建连接池到 `target_sni:443`，消除代理时的 DNS + TCP 连接延迟
- [ ] 考虑 `setsockopt(IP_TTL)` 匹配目标服务器响应的 TTL
- [ ] 评估是否需要替换 `mozilla_intermediate_v5` 为手动配置的 TLS 参数

---

### 🟢 P2 — Proxy 回落 DNS 解析泄露 (低风险)

**问题**: `dispatcher.rs` 的 `proxy_connection` 在每次探测触发时执行 DNS 解析。

```rust
let target_addr = format!("{}:443", target_host);
let mut target = TcpStream::connect(&target_addr).await
```

如果服务器本地 DNS 有缓存/超时差异，或连接时序与直连有微妙差异，理论上可被检测。

- [ ] 启动时解析并缓存 `target_sni` 的 IP 地址
- [ ] 定期刷新 DNS 缓存（如每 5 分钟）
- [ ] 或复用 P1 的预建连接池方案一并解决

---

### 🟢 P2 — TLS 记录小包填充 (低-中风险)

**问题**: `framed.rs` 的 TLS 记录填充仅在 buffer > 4KB 时生效。

```rust
if self.tls_record_padding
    && self.write_buffer.len() >= TLS_PAD_THRESHOLD  // 4096
    && self.write_buffer.len() < TLS_RECORD_SIZE      // 16384
{
    // 填充到 16KB
}
```

小于 4KB 的 TLS 记录（控制流量、DNS 查询等）不会被填充，可能被统计分析区分于真实 HTTPS。

**注意**: 全部填充到 16KB 也非最优 — 真实 HTTPS 中小包本就不会被填充，全 16KB 反而是异常指纹。

- [ ] 实现多级填充策略（128B / 512B / 2KB / 4KB / 16KB 边界）
- [ ] 根据原始大小选择最近的标准化边界
- [ ] 使填充后的包大小分布更接近真实 HTTPS

---

### 🟢 P2 — impersonate.rs 缺少 Kyber 后量子支持 (低-中风险)

**问题**: `impersonate.rs` 的 `set_curves_list` 仅设置了 `X25519:P-256:P-384`。

真实 Chrome 130+ 的 `supported_groups` 包含 `X25519Kyber768Draft00`。缺少此扩展是一个被动指纹 — 审查者可能注意到 ClientHello 的 groups 中没有 Kyber。

注释中已提到此问题但未实现：
```rust
// Note: "X25519Kyber768" is the post-quantum draft used by Chrome, but standard BoringSSL
// crate might not expose it easily via string yet unless compiled with specific flags.
```

- [ ] 调查 `boring = "4"` 是否支持 `X25519Kyber768Draft00` 曲线
- [ ] 如支持，添加到 `set_curves_list`
- [ ] 如不支持，调查 BoringSSL 编译选项或上游 PR

---

### 🟢 P3 — Padding 分布硬编码 (低风险)

**问题**: `jitter.rs` 的三态分布是硬编码的（60% 小包 / 30% 中包 / 10% 大包）。真实 HTTPS 的包大小分布是动态的，固定分布理论上可被 ML 模型学习。

**缓解因素**: 当前风险较低，原因：
1. padding 叠加在真实数据包之上，真实流量会混淆 padding 分布
2. 独立 padding 机制进一步打乱了分布
3. 审查者需要大量流量样本

- [ ] 可选：实现 per-connection 随机化 profile（Browsing / Streaming / API 等）
- [ ] 可选：允许通过配置文件自定义分布参数

---

### 🟢 P3 — QUIC 层使用 rustls-jls 而非 BoringSSL (低风险)

**问题**: TCP 层用 BoringSSL，QUIC 层用 `rustls-jls`（rustls 的 JLS 分支）。

```toml
rustls = { package = "rustls-jls", version = "=0.23.36-1.3.1" }
```

QUIC 连接的 TLS 行为是 rustls 的，不是 BoringSSL 的。如果审查者对 QUIC Initial 进行深度行为探测，rustls 的行为指纹可能与真实 Chrome（BoringSSL → QUIC）不同。

**缓解因素**: QUIC 全加密特性让中间盒注入探测包更困难，风险比 TCP 低。

这是一个已知的架构权衡 — 目前没有 BoringSSL 的 QUIC 实现可直接用于 Rust 生态。

- [ ] 长期：评估 `s2n-quic`（AWS 基于 BoringSSL 的 QUIC）的适配可行性
- [ ] 长期：关注 BoringSSL 原生 QUIC API 的 Rust 绑定成熟度

---

### 🟢 P3 — inner_key 无密码拉伸 (低风险)

**问题**: `crypto.rs` 的 `derive_key_pair` 将用户提供的 `inner_key` 字符串直接传给 HKDF。HKDF 不提供密码拉伸（与 Argon2/scrypt 不同），弱密码的熵不会被放大。

**缓解因素**: `inner_key` 的用途是加密 DATA 帧而非用户认证（认证已有 Argon2）。

- [ ] 在文档中强调 `inner_key` 应使用高熵随机密钥（如 `openssl rand -hex 32`）
- [ ] 可选：提供自动生成 `inner_key` 的 CLI 命令

---

## 三、论文攻击方式对照

| 论文攻击方式 | Reality (Go/uTLS) | **Mirage** |
|---|---|---|
| JA3/JA4 指纹 | ⚠️ uTLS 模拟 | ✅ BoringSSL 原生 |
| CCS 计数器阈值 | ❌ 16 vs 32 | ✅ 32 (原生) |
| Warning Alert 计数器 | ❌ 16 vs 4-32 | ✅ 4 (原生) |
| 握手后 CCS 注入 | ❌ 行为不一致 | ✅ 行为匹配 |
| ECH GREASE 泄露 | ❌ uTLS 漏洞 | ✅ BoringSSL 原生 |
| 注入式攻击 (4.5) | ❌ Go 行为不同 | ✅ BoringSSL 行为正确 |
| 重放攻击 (4.4) | ❌ Go TLS ≠ 真实服务器 | ⚠️ 代理回落缓解，但有时序差异 |
| **ALPN 被动指纹** | ✅ 正常 ALPN | ⚠️ ShortID 多出非标准 ALPN |

---

## 四、检测手段与对策矩阵

| 检测手段 | 对策 | 状态 |
|---------|------|------|
| **SNI 阻断** | Mirage 伪装 (TCP) / JLS (QUIC) | ✅ |
| **TLS 指纹识别** | BoringSSL (Chrome 同源指纹) | ✅ |
| **CCS 阈值攻击** | BoringSSL (阈值 32，全链路一致) | ✅ |
| **注入式探测** | BoringSSL 原生行为 | ✅ |
| **主动探测 (Active Probing)** | ShortID 验证 + 回落到真实服务器 | ✅ |
| **包长度分析** | 加权拟态轮廓 + TLS 记录填充 | ✅ |
| **时序关联分析** | 智能时序抖动 + 自适应 Jitter | ✅ |
| **静默连接检测** | 应用层心跳 | ✅ |
| **长连接指纹** | 连接轮换 (max_lifetime + jitter) | ✅ |
| **UDP 长连接阻断** | QUIC Port Hopping | ✅ |
| **单栈封锁** | IPv4/IPv6 双栈聚合 | ✅ |
| **ALPN 被动检测** | ⚠️ 需迁移认证通道 | 🔴 待修复 |
| **CDN 封锁** | WebSocket/gRPC | ⏳ 计划中 |

---

## 五、协议技术细节

- **帧格式**: `[Type: 1B][Length: 2B BE][Payload]` — 紧凑 3 字节开销
- **应用层加密**: ChaCha20-Poly1305 AEAD, HKDF-SHA256 密钥派生, 方向性密钥分离 (c2s / s2c)
- **Nonce**: 96-bit 计数器 nonce, 方向性密钥保证 (key, nonce) 唯一性
- **Padding**: 三态加权分布 (60% 控制帧 40-100B / 30% 头部 250-600B / 10% 数据块 800-1200B)
- **Jitter**: 自适应抖动（空闲放大 3x / 高流量最小化 / 正常使用配置范围）
- **双向填充**: 检测反方向活跃 + 本方向空闲，自动增强填充（间隔 0.5-2s，更大 padding）
- **Port Hopping**: QUIC 每 N 秒轮换 UDP 端口 (默认 0 = 禁用)
- **连接轮换**: max_lifetime_s (默认 300s) + lifetime_jitter_s (±60s)
