# NetP2P 架构设计

## 设计边界

NetP2P 是一个可管理的去中心化 overlay 网络。项目使用 `github.com/libp2p/go-libp2p` 作为唯一网络栈：

- 身份使用 libp2p `PeerID`；
- 地址与拨号使用 multiaddr 和 swarm；
- 传输默认使用 QUIC，也可按平台能力回退到 TCP/WebSocket；
- 加密、stream 复用、NAT traversal、relay、DHT 和 gossipsub 均由 libp2p 提供；
- 不使用 WireGuard 作为传输层或加密层；
- TUN 只作为可选的操作系统 VPN 接入层，不是底层传输协议。

项目不兼容 NetBird Management API。NetBird 只作为管理模型参考。

## 协议

| 协议 | 用途 |
| --- | --- |
| `/netp2p/control/login/1.0.0` | 提交身份、OIDC JWT/setup key 与设备信息 |
| `/netp2p/control/sync/1.0.0` | 请求 certified snapshot 或建立增量同步流 |
| `/netp2p/control/state-update/1.0.0` | 分发 signed state 和 state proof |
| `/netp2p/link/probe/1.0.0` | 采集 RTT、丢包、抖动、带宽估计与路径能力 |
| `/netp2p/data/frame/1.0.0` | 传输 overlay frame 或服务流量 |
| `/netp2p/data/quota/1.0.0` | 上报聚合用量，不逐包上报 |

所有协议消息都应携带 source PeerID、destination/network id、protocol version、nonce 和签名。高版本协议通过 libp2p multistream negotiation 与 capability exchange 兼容。

## 控制面

普通 client 不参与共识。Manager 是一个 BFT committee，建议初始容错为 `n = 3f + 1`：

1. client、admin API 或 IdP 同步产生 proposal；
2. proposal 进入 committee decision log；
3. committee 对 state transition 达成 BFT 共识；
4. 共识结果生成 monotonically increasing `epoch` 和 certified snapshot；
5. snapshot 由 committee threshold signature 或 aggregator signature 签名后分发；
6. client 验证 signer/quorum proof 后替换本地 network map。

Policy、group、peer、route、quota、committee membership 的变更都是 state transition。Cold start 使用 bootstrap manager 或静态 committee 配置发布第一个 network genesis state。

Client 保留最近 certified snapshot。Manager 短暂不可用时继续使用已有策略；manager 恢复后通过 epoch 与 decision log 追平状态。

### v0 实现

当前代码实现固定 `n = 4, f = 1` 的 HotStuff-lite committee：

- 每轮由 `leader = committee[(height + round) % n]` 发起 proposal；proposal 携带完整 `NetworkState`；
- committee 成员对 `state_hash` 投 Ed25519 签名票，`2f + 1 = 3` 票组成 `QuorumCertificate`；
- commit 生成 `SignedSnapshot{epoch, height, stateHash, state, committee, qc}`；
- client 用 `ValidateSnapshot` 校验 state hash、QC 门槛、signer 去重与每个签名；
- committee 成员之间通过 `/netp2p/control/state-update/1.0.0` 交换 proposal、vote、QC 和 snapshot；
- 冷启动由静态 seed 描述 committee，height-1 leader 提交 genesis。

去中心化的下一个迭代仍是 epoch 追平（decision log 增量）、完整 view change（Pacemaker 超时）与 threshold signature；v0 使用 round-robin 轮换作为简化 view change。

### Catch-up 与 View Change

- `Engine.CatchUp(snapshot)` 允许重启/落后的 manager 从任意 peer 的 certified snapshot 直接 commit，无需本地 proposal。
- `CommitteeMesh.CatchUp(ctx)` 在 manager 启动后主动向所有 peer 发送 `sync_request`，等待第一个有效 `sync_response` 并 CatchUp。
- `Submit` 在 round 超时（2s）后轮换到下一个 round 的 leader，最多轮换 `n` 次。一个 leader 宕机时最多浪费一轮，committee 不停摆。
- `Engine.Snapshot(height)` 和 `Engine.LatestSnapshot()` 提供 decision log 查询接口。

### Admin 管理面

libp2p 协议 `/netp2p/control/admin/1.0.0` 接受带静态 token 的 `StateTransition`（upsert/remove group、policy、route、budget、setup key）。Manager 验证 token 后经 BFT Submit 认证，返回 certified snapshot。CLI 通过 `netp2pd --role admin` 提交。

## Group、Policy 与 Network Map

Group 是稳定授权标签，可包含 user、device peer、route peer 和 service。SSO claims 不直接写入 policy，而是映射为 managed groups。

Policy 表达 source 与 destination 之间的关系：

```text
Policy {
  id
  source_groups
  destination_groups
  services { protocol, start_port, end_port }
  effect: allow | deny
  direction: unidirectional | bidirectional
  posture_requirements
  link_constraints
}
```

Deny 优先于 allow。Peer membership 或 user group membership 变化后，manager 重新编译 policy，并为每个 peer 生成最小 NetworkMap。

## 路由与链路选择

Manager 下发候选与约束，peer 根据本地探测结果选择路径：

- direct path：libp2p hole punching 后的直连；
- relay path：libp2p circuit relay；
- multi-hop path：受信 overlay relay/gateway 组合；
- exit path：提供受限外网访问的 gateway。

路径不是简单“P2P 优先、relay 兜底”。每个候选路径维护 `LinkProfile`：

```text
LinkProfile {
  path_id
  path_type
  next_peer
  rtt
  loss
  jitter
  bandwidth_estimate
  stability
  congestion
  relay_cost
  public_relay
}
```

路径评分按 flow class 计算：

- 延迟敏感：RTT、抖动、拥塞权重高；
- 吞吐敏感：带宽、丢包恢复能力权重高；
- 成本敏感：relay 成本、公网 relay、配额消耗权重高；
- 高可靠：要求热备路径与快速切换。

Manager 可通过 link constraints 禁止付费 relay、限制最大路径长度、指定 gateway 或要求热备。最终 path decision 留在 peer，减少探测上报和切换延迟。

## TrafficBudget

TrafficBudget 是 committee 维护的权威状态：

```text
TrafficBudget {
  subject: peer | user | group | route | service
  daily_bytes
  monthly_bytes
  peak_bps
  burst_bytes
  relay_cost_limit
  on_exhausted: block | throttle | degrade | switch_path
}
```

Peer/relay/gateway 聚合用量后通过 quota protocol 上报。本地执行器在运行时扣减 token/byte bucket；committee 周期性合并用量并发布新的 certified quota state。

## SSO 同步

支持 OIDC authorization code + PKCE 和 device authorization flow：

1. client 向 IdP 认证并获得 JWT；
2. client 通过 libp2p login stream 提交 JWT 和设备公钥绑定；
3. manager 验证 issuer、audience、signature、expiry、nonce 和 device binding；
4. manager 从 groups/roles claims 映射到 managed groups；
5. membership 变化触发 policy 编译和 NetworkMap 重新发布；
6. certified signed state 通过 control stream 或 gossipsub 下发。

Setup key 是无人工交互设备的引导凭证，必须有 scope、expiry、使用次数和撤销状态。

## 数据面

overlay frame 建立在 libp2p secure stream 上。数据面通过一个统一的 `PacketSink` 接口接入操作系统：

- **UDPPacketSink（v0 默认）**：在本地 `127.0.0.1:51820` 监听 UDP，收发 length-prefixed IPv4 packet。它不依赖 TUN 或 `NET_ADMIN`，可在 WSL、CI 和容器内运行，用于验证数据面。
- **TUN（规划中）**：Linux 环境下插入同一 `PacketSink` 接口，读取/写回真实 IP packet。TUN 只是操作系统接入层，加密与传输仍由 libp2p 承担。

当前 v0 数据流：

1. 本地 endpoint 收到 IPv4 packet，按目标 overlay IP 查找 `PeerRecord`；
2. 用 certified state 对 source→destination 方向执行 policy，允许则经 `/netp2p/data/frame/1.0.0` 发给对端；
3. 接收端校验 `RemotePeer()`、source overlay IP、目标为本机 overlay IP，再按 source→self 方向执行 policy；
4. 若收到 ICMP echo request，接收端生成 echo reply 并经 frame stream 发回请求方；请求方把 reply 写入本地 endpoint。

v0 简化：ICMP echo reply 视为已授权请求的响应，通过上述 source 校验后直接投递给本地 endpoint，不再做第二次 policy 检查。否则 `deny B->A` 会连带阻断 `A->B` 的回包。

Frame payload 是原始 IPv4 packet，外层使用 `Envelope{protocol, payload}` JSON 封装；加密与完整性由 libp2p secure channel 保证。后续迭代会引入显式 frame header（network id、source/destination PeerID、flow id、path id、epoch）与逐 flow 的路径选择。
