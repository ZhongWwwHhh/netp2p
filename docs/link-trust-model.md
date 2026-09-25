# EigenSpeed 链路观测与不可信客户端模型

## 结论

取消独立的 relay 身份。网络中只保留两类节点身份：

```text
client   纯数据面接入节点，不可信。
manager  client 能力的超集，同时具备：
         1. BFT 决策成员；
         2. 路由/路径 planner；
         3. 数据转发节点；
         4. 管理 UI / API 节点；
         5. 链路观测节点。
```

因此不存在语义模糊的 relay。一条多跳路径由 manager 组成：

```text
client A -> manager M1 -> manager M2 -> client B
```

极端情况下也可以是：

```text
client A -> manager M1 -> manager M2 -> manager M3 -> client B
```

manager committee 负责生成、认证和下发这条路径；client 不再自行在 direct 与 relay 之间做全网级决策。

## 角色语义

### Manager 是 client 超集

Manager 保留完整 client runtime：

- 可以拥有 overlay identity；
- 可以连接其他 manager/client；
- 可以使用相同数据帧协议；
- 可以为自身所在网络转发流量；
- 可以暴露 Web 控制台和管理 API。

Manager 额外承担：

- 参与 BFT committee；
- 维护 certified state；
- 接收 client login/sync；
- 观测和探测链路；
- 计算和认证路径；
- 在数据面转发帧。

### 不再使用 relay 身份

旧概念映射：

```text
旧 relay 节点       -> manager 的 forwarding capability
relay path         -> via-manager path
multi-hop relay    -> multi-manager path
relay cost         -> manager forwarding cost
relay load         -> manager forwarding load
```

libp2p 的 circuit relay 只能作为过渡期的 NAT 穿透辅助机制。目标协议应使用显式的 manager forwarding path，而不是把“libp2p relay transport”暴露成一种网络身份。

## 信任模型

| 主体 | 信任级别 | 能贡献的数据 | 能影响的状态 |
| --- | --- | --- | --- |
| Manager committee | 半可信 | manager-manager 链路观测、manager-client 接入链路观测、路径候选 | certified network settings、certified route assignment |
| Client | 不信任 | 只能提供本端观测和路径准入结果 | 只影响自己的直接路径准入与本地偏好 |

Manager 也不能被完全信任，因此：

1. manager observation 必须签名；
2. 同一 segment 需要多观测者交叉验证；
3. EigenSpeed / trimmed median 过滤离群观测；
4. path assignment 需要 committee quorum 认证；
5. 单个 manager 不能私自决定影响全网的路径。

## 不直接采用“客户端上报全网状态”

不允许 client 提交如下数据并参与全网聚合：

```text
link(A, M1) = ...
link(M1, M2) = ...
link(M2, B) = ...
```

原因：

1. client A 无法真正测量 manager 之间的内部链路；
2. client 可以直接伪造全网矩阵；
3. 一条假报告会污染其他诚实 client 的路径；
4. 全网状态必须由多个 manager 按相同协议主动测量后聚合。

## EigenSpeed 的位置

EigenSpeed 只用于 manager 观测网，不用于 client 上报。

算法骨架：

1. 每个观测者 `i` 对若干 manager `j` 有本地测量；
2. 构造观测矩阵 `T[i][j]`；
3. 对矩阵做幂迭代，得到收敛的全局带宽/质量向量；
4. 对显著偏离主特征方向的报告做离群检测并降权；
5. 输出 manager mesh 的 `LinkView`。

矩阵范围：

```text
权威观测矩阵 = manager -> manager
辅助观测     = manager -> client
不可信观测   = client -> anything
```

`manager -> client` 可以帮助评估接入链路，但不应与 manager mesh 主矩阵混合；它更适合作为 access segment estimate。

## 三层状态

### 1. Observed link state

由测量行为本身产生。

```text
Observation {
  observer_peer_id
  subject_peer_id
  scope: manager_mesh | access | peer_direct
  direction: outbound | inbound | roundtrip
  rtt_ms
  loss_pct
  jitter_ms
  bandwidth_mbps
  samples
  measured_at
  seq
  observer_signature
}
```

规则：

- `manager_mesh` observation 只能由 manager 产生，进入 EigenSpeed 矩阵；
- `access` observation 由 manager 主动测量 client 得到，不进入 manager mesh 主矩阵；
- `peer_direct` observation 由两端 client 产生，只用于 direct path 准入；
- 所有 observation 带签名、序列号和 TTL；
- client observation 永远不能提升为全网状态。

### 2. Consensus link state

由 manager observation 聚合得到。

```text
LinkSegment {
  from
  to
  rtt_ms
  loss_pct
  bandwidth_mbps
  forwarding_cost
  forwarding_load
  confidence
  sample_count
  observers
  updated_at
}
```

生成方式：

1. 同一条 manager segment 收集多个签名观测值；
2. 用 trimmed median 去掉离群值；
3. 对 manager observation matrix 执行 EigenSpeed 式幂迭代；
4. 融合 EigenSpeed 主结构和 trimmed median；
5. 各 manager 计算确定性 `LinkView`；
6. `LinkView` 定期 gossip，不进入 BFT。

### 3. Certified route assignment

这是本轮的关键变化：路径规划从 client-local decision 移到 manager committee。

```text
RouteAssignment {
  assignment_id
  network_id
  source_peer_id
  destination_peer_id
  epoch
  primary_path: PathSpec
  fallback_paths: [PathSpec]
  admission_policy
  expires_at
}

PathSpec {
  path_id
  kind: direct | via_manager
  hops: [manager_peer_id]
  estimated_rtt_ms
  estimated_loss_pct
  estimated_bandwidth_mbps
  confidence
}
```

Manager committee 输入：

- policy 允许 A 与 B 通信；
- certified manager 列表和 forwarding capability；
- EigenSpeed `LinkView`；
- manager 负载和配额；
- client bilateral direct admission result。

输出：

1. primary path；
2. ordered fallback paths；
3. expires/revalidate time；
4. admission constraint。

该 assignment 进入 BFT certified state，client 验证 quorum 后才能使用。这样满足“manager 去中心化地决定路径”，而不是由单个 manager 私自下发。

### 4. Client-local admission state

Client 不再产生全网路径，但必须保留最后一层准入：

```text
AdmissionResult {
  assignment_id
  path_id
  local_end_to_end_ok
  measured_rtt_ms
  measured_loss_pct
  measured_bandwidth_mbps
  decided_at
}
```

规则：

- assignment 只是允许使用的候选；
- client 发送数据前必须 probe 该 assignment；
- probe 失败时只能切换到同一 certified assignment 中的 fallback；
- 所有 fallback 都失败时保持断开并请求 manager 重新规划；
- client 不能私自发明新的 multi-manager path。

## 路径选择流程

### 1. Manager mesh 观测

每个 manager 主动探测：

```text
manager -> manager
manager -> connected client
```

manager-manager 结果进入 EigenSpeed。

### 2. Candidate generation

manager committee 基于 `LinkView` 生成：

```text
direct A-B
A -> M1 -> B
A -> M1 -> M2 -> B
...
```

约束来自 certified settings：

```text
multi_hop_enabled
max_manager_hops
min_bandwidth_mbps
max_rtt_ms
max_loss_pct
max_forwarding_cost
```

候选路径按统一 B-score 排序，但最终顺序由 committee 认证。

### 3. Direct admission

direct path 只能由两端 client 共同准入：

1. manager 下发 probe token 和 assignment；
2. A 与 B 在允许时间窗口内互相探测；
3. 双端交换 signed admission result；
4. 两个结果都通过时 direct 才可被选中；
5. 结果不一致或样本不足时 manager 不应把 direct 设为 primary。

这样恶意 client 伪造“direct 很好”不能伤害 B，因为 B 的准入失败。

### 4. Via-manager admission

via-manager path 的段质量由 manager 观测，不需要信任 client 描述。

client 端仍执行端到端 probe：

```text
A -> M1 -> M2 -> B
```

端到端失败时，client 只能在 assignment 内切换 fallback。这个设计避免了 manager 因 stale link view 而把流量锁死在坏路径上。

### 5. Final decision

分两层：

```text
路径规划决策 = manager committee
运行时准入   = source/destination client
```

manager committee 不能强迫 client 使用实测失败路径；client 也不能绕过 committee 选择未经认证的多跳路径。

## EigenSpeed 计算位置

### v1

每个 manager 独立计算：

1. 本地收集 manager-manager signed observation；
2. manager 之间 gossip observation；
3. 各自执行确定性 trimmed median + EigenSpeed；
4. 输出相同 `LinkView` hash；
5. leader 或当前 proposal manager 基于该视图构造 route assignment；
6. committee 用 BFT 认证 assignment。

这样没有单个 link-view 计算者，但路径变更仍然有全局一致性。

### 后续优化

如果 assignment 更新频率过高：

- path epoch 与普通 state transition 分桶；
- 只对 assignment delta 出块；
- 使用 committee threshold attestation 签名短期 path lease；
- 视图稳定时降低 assignment refresh 频率。

## 抗攻击设计

| 攻击 | 缓解 |
| --- | --- |
| client 伪造 RTT/loss/bandwidth | client 报告不进入 EigenSpeed；只用于本端 direct admission |
| client A 伪造 direct 很好 | B 的 signed admission result 也必须通过 |
| client 合谋抬高某条路径 | manager mesh 使用主动测量，client 报告没有全网投票权 |
| manager 谎报链路 | 多 manager 观测交叉验证、trimmed median、EigenSpeed 离群检测 |
|单个 manager 私发坏路径 | RouteAssignment 必须通过 BFT quorum |
| observation 重放 | signature + seq + measured_at + TTL + probe token |
| 探测放大攻击 | token、频率上限、并发流上限、bandwidth budget |
| 虚假 manager 宣传 | manager identity 和 forwarding capability 来自 certified snapshot |
| path flapping | current path penalty、min dwell time、双阈值切换 |
| 恶意 client 频繁请求 replan | per-peer assignment rate limit |

## 权威状态与非权威状态

进入 BFT certified snapshot：

```text
NetworkSettings {
  link_min_bandwidth_mbps
  relay_latency_advantage_ms
  relay_loss_advantage_pct
  link_probe_interval_seconds
  link_probe_timeout_ms
  via_manager_enabled
  max_manager_hops
  direct_path_enabled
  trust_client_global_observations: false
}

RouteAssignment
```

不进入 BFT：

- raw link observation；
- EigenSpeed `LinkView`；
- manager forwarding load 的高频瞬时值；
- client admission result；
- client-local fallback 状态。

`RouteAssignment` 是低频决策状态；`LinkView` 是高频观测缓存。二者分离可以避免探测流量撑爆 BFT decision log。

## 实施计划

### Phase A：身份与模型重构

- 引入 `NodeRole: client | manager`；
- 在模型中移除独立 relay identity；
- manager capability 明确为 `forwarding_enabled`；
- 旧 `PathRelay` 过渡性映射为 `PathViaManager`；
- seed 中只允许 manager 出现在转发候选池。

### Phase B：观测协议（已实现）

新增 `internal/link`：

- `Observation`、`SegmentView`、`LinkView`、`AdmissionResult`；
- RTT/loss/jitter probe；
- 低开销 bandwidth probe；
- observer signature；
- TTL、seq、probe token 和频控。

实现 `/netp2p/link/probe/1.0.0`：`ProbeRequest{kind, nonce, bytes}` + `ProbeReply{nonce, receivedBytes}`，length-prefixed JSON header，bandwidth probe 后紧跟 `bytes` 原始字节。manager 与 client 都注册 `ProbeResponder`。

### Phase C：Manager mesh 观测网（已实现）

- manager 互相测量；
- manager 主动测量 client access link；
- manager 之间 gossip signed observation；
- 每 10–30 秒生成确定性 `LinkView`。

`internal/link.Prober` 每个周期测量全部 committee peer（`manager_mesh`）和 certified state 中的 client（`access`）；总带宽突发受 `NetworkSettings.ProbeBandwidthBudgetKB` 限制，目标轮换以保证公平。观测经 `/netp2p/link/gossip/1.0.0` 交换，`Publish` 只替换本机观测并保留远端观测。

### Phase D：EigenSpeed 聚合（已实现）

实现确定性算法：

1. 构造 manager observation matrix；
2. 缺失值不参与矩阵；
3. 对满足最小样本数的节点做幂迭代；
4. 输出主特征向量；
5. 计算观测与主结构的偏差；
6. trimmed median + EigenSpeed 结果融合。

测试必须覆盖：

- 相同观测集在所有 manager 得到相同 `LinkView` hash；
- 恶意 client 输入不影响矩阵；
- 恶意 manager 少数派观测被降权；
- 观测缺失时 confidence 下降。

### Phase E：BFT RouteAssignment

新增 transition：

```text
update_route_assignment
expire_route_assignment
```

状态模型包含 assignment、epoch、primary/fallback paths。Manager 基于 LinkView 和 policy 生成 assignment，committee quorum 认证后随 sync 下发。

### Phase F：Client runtime

- 验证 RouteAssignment QC；
- 只使用 certified paths；
- 对 primary path 做端到端 admission；
- 失败时只切换 assignment 内 fallback；
- 上报 admission failure 触发 replan，但不提交路径质量评分。

### Phase G：数据面 forwarding

Manager 增加帧转发器：

- per-path forwarding table；
- per-peer queue 和 backpressure；
- loop prevention；
- TTL；
- forwarding metrics；
- assignment 失效时停止转发。

### Phase H：Web/CLI

Settings 增加：

- via-manager 开关；
- 最大 manager hops；
- probe interval；
- probe bandwidth 预算；
- direct path 开关；
- trust client global observations 开关，固定默认关闭。

UI 需要展示：

- current assignment；
- primary/fallback path；
- manager hop 链；
- LinkView confidence；
- admission result；
- forwarding load。

所有 client-reported 数据只能标记为 `reported by client`，不参与全网评分。

## 验收标准

1. 网络模型中没有 relay identity；只有 `client` 和 `manager`。
2. `A -> M1 -> M2 -> B` 是一类普通 via-manager path，不需要新增第三方身份。
3. 恶意 client 提交任意假全网报告后，所有 manager 的 EigenSpeed `LinkView` hash 不变。
4. 相同 manager/observation 集在每个 manager 上计算出相同 `LinkView` hash。
5. path assignment 变更必须通过 BFT quorum；单个 manager 无法私自改路。
6. client 只能在 certified assignment 的 fallback 集合内切换，不能发明新多跳路径。
7. direct path 必须双端 admission 成功，单端伪造不能让另一端被迫使用坏路径。
8. probe 频率、带宽、状态表大小和 assignment 更新频率都有硬上限。
