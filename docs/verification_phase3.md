# Phase 3 验证指引：流量混淆测试

本文档指导您如何验证 Mirage VPN 的 Phase 3 功能（协议混淆、填充、时序抖动）。

## 准备工作
1. **服务端**: 启动 `mirage-server`。
   ```bash
   cargo run --bin mirage-server -- -c examples/server.toml
   ```
2. **客户端**: 启动 `mirage-client`。
   ```bash
   cargo run --bin mirage-client -- -c examples/client.toml
   ```
3. **抓包工具**: 安装 `tcpdump` 或 `Wireshark`。

---

## 测试 1: 验证协议 V2 与填充 (Padding)

**目标**: 确认传输层不再是单纯的数据包，而是包含了随机填充的“垃圾数据”。

**步骤**:
1. 在客户端或服务端机器上抓包（假设网卡为 `eth0`，端口 `443`）：
   ```bash
   sudo tcpdump -i eth0 port 443 -X -n
   ```
2. 在客户端保持静默（不访问网页），或仅发送少量 `ping`。
3. **观察**:
   - 如果您只发送了一个 `ping` 包（通常几十字节），您是否看到了比预期**更多**的数据包？
   - 或者某些数据包的大小明显**大**于 ICMP 包的大小？
   - **预期结果**: 由于 `padding_probability = 0.05`，您可能会偶尔看到一些额外的流量。为了更容易观察，您可以临时将 `padding_probability` 改为 `0.5` 或 `1.0`。
   
**深度验证**:
- 查看包内容（十六进制），寻找 `00 00 00` 开头的数据（Type 0: Data）和 `01` 开头的数据（Type 1: Padding）。由于 TLS 加密，您在 `tcpdump` 中看到的都是乱码，无法直接区分 Type。
- **最简单的验证方法**: 看流量统计。发送 1MB 文件，接收端收到的实际 TCP 流量是否大于 1MB？（Padding 会增加流量消耗）。

---

## 测试 2: 验证时序抖动 (Jitter)

**目标**: 确认发包时存在随机延迟。

**步骤**:
1. 修改配置文件 `examples/client.toml`，将 Jitter 调大以便观察：
   ```toml
   [connection.obfuscation]
   jitter_min_ms = 100  # 最小延迟 100ms
   jitter_max_ms = 500  # 最大延迟 500ms
   ```
2. 重启客户端。
3. 运行 `ping` 测试：
   ```bash
   ping 10.11.12.1
   ```
4. **观察**:
   - Ping 的延迟是否变得**不稳定**且**显著增加**？
   - 正常本地 Ping 可能只需 <10ms，现在应该在 100ms-500ms 之间波动。
   - **预期结果**: 如果 Ping 值确实在设定范围内随机跳动，说明 Jitter 生效了。

---

## 测试 3: 验证零拷贝与稳定性

**目标**: 确认优化后的代码没有引入 Bug。

**步骤**:
1. 跑满带宽（例如用 `iperf3` 或下载大文件）。
2. 观察内存使用率（`top` / `Activity Monitor`）。
3. 确认长时间运行不崩溃，不亦断开连接。

---

## 恢复配置
测试完成后，记得将配置改回默认值，以免影响正常体验：
- `jitter_min_ms = 0`
- `jitter_max_ms = 20`
