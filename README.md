# NetP2P

基于 `github.com/libp2p/go-libp2p` 的去中心化、可管理 overlay 网络。项目借鉴 NetBird 的
group/policy/route/network map 管理模型，但协议从头设计，**不使用 WireGuard**，也不兼容
NetBird Management API。

## 核心能力

- **完全去中心化 manager**：4 节点 BFT committee（HotStuff-lite，`n=4, f=1`），
  proposal → Ed25519 vote → `2f+1` QC → commit，client 验证 certified snapshot。
- **libp2p 数据面**：身份、multiaddr、swarm、QUIC、NAT 穿透、relay 均由 libp2p 提供；
  加密由 libp2p secure channel 承担。
- **智能选路（规划中）**：按 RTT/丢包/抖动/带宽/成本为 flow 评分，而非简单 relay 兜底。
- **流量配额（规划中）**：committee 维护权威 quota，peer/relay 上报聚合用量。

## 当前状态

可运行的最小闭环：4 manager 完成 genesis，client 用 setup key 注册并获得 overlay IP 与
certified snapshot，由 certified state 驱动的 policy 允许/拒绝 overlay ICMP 转发。数据面通过
用户态 UDP packet endpoint 接入，**不依赖 TUN**。

- 架构：`docs/architecture.md`
- NetBird 调研：`docs/netbird-research.md`
- 路线图：`docs/roadmap.md`
- 测试与运行：`docs/testing.md`

## 快速开始

```bash
go test ./...        # 单元 + 进程内 E2E
scripts/e2e.sh       # Docker E2E（4 manager + 2 client，无 TUN）
```
