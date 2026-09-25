# EigenSpeed 链路观测与不可信客户端模型

## 目标

路径选择不能只比较 `client-relay-client`。后续需要评估：

```text
client A -> relay R1 -> relay R2 -> client B
```

因此系统需要全网链路状态视图。但所有 client 都必须视为不可信：

- client 可以伪造自己的 RTT、丢包率、带宽、路径偏好；
- 多个恶意 client 可以合谋抬升或压低某条链路评分；
- 恶意报告最多影响该 client 自己的路径决策，不能影响其他诚实 client 或全网共识视图。

## 信任分层

| 主体 | 信任级别 | 能贡献的数据 | 能影响的状态 |
| --- | --- | --- | --- |
| Manager committee | 高信任 | 本地观测、路由候选、权威约束 | certified network settings |
| Relay / gateway | 中等信任 | 本地出/入口链路观测 | 全网链路视图、relay 候选排序 |
| Client | 不信任 | 只能提交本端 flow 观测 | 只作用于本端选择结果的偏好修正 |

Manager/Relay 不是完全可信。它们的数据也要带签名、时间戳、序列号、TTL 和异常检测，只是比 client 有更高先验权重。

## 不直接采用“客户端上报全网状态”

不允许 client 提交如下数据并参与全网聚合：

```text
link(A, R1) = ...
link(R1, R2) = ...
link(R2, B) = ...
```

原因：

1. client A 无法真正测量 `R1 -> R2` 内部链路；
2. client 可以直接伪造全网矩阵；
3. 一条假报告会污染其他诚实 client 的路径；
4. 全网状态不应该由 client 主观描述，而应由多个观测者按相同协议测量后聚合。

## EigenSpeed 的可用部分

EigenSpeed 的核心不是相信某个节点，而是：

1. 每个观测者 `i` 对若干节点 `j` 有本地测量；
2. 构造观测矩阵 `T[i][j]`；
3. 对矩阵做幂迭代，得到收敛的全局带宽/质量向量；
4. 对显著偏离主特征方向的报告做离群检测并降权/丢弃。

在 NetP2P 中采用它的三点：

- **多观测者聚合**：manager 和 relay 的测量进入矩阵；
- **异常降权**：偏离矩阵主结构的观测被过滤；
- **收敛视图**：manager 侧形成全网 relay/segment 质量估计。

不采用的部分：

- client 的主观上报不直接进入 EigenSpeed 矩阵；
- EigenSpeed 输出不覆盖本端实测的 direct path 质量；
- 恶意 client 无法通过报告修改其他 peer 的矩阵。

## 三层状态

### 1. Observed link state

由测量行为本身产生。

```text
Observation {
  observer_peer_id
  subject_peer_id
  direction: inbound | outbound | roundtrip
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

- manager/relay 是首选 observer；
- client 只能观测与自己直接相连的 peer/relay；
- client 的 observation 单独存表，永远不会和 manager/relay observation 混入同一矩阵；
- observation 必须带 observer signature，供 committee 审计。

### 2. Consensus link state

由 manager/relay observation 聚合得到。

```text
LinkSegment {
  from
  to
  rtt_ms
  loss_pct
  bandwidth_mbps
  confidence
  sample_count
  observers
  updated_at
}
```

生成方式：

1. 同一条 segment 收集多个观测值；
2. 用 trimmed median 去掉离群值；
3. 对 manager/relay 观测矩阵执行 EigenSpeed 式幂迭代；
4. 输出全网 segment 视图和 confidence；
5. 视图定期 gossip，不进入 BFT。

### 3. Client-local path view

每个 client 自己维护：

```text
PathCandidate {
  path_type: direct | relay | multi-hop
  measured_quality
  estimated_quality
  confidence
  source: local | consensus
}
```

direct 候选只信任 `source = local`。relay/multi-hop 候选使用：

```text
quality =
  0.60 * local_probe
  + 0.40 * consensus_estimate
```

如果本地样本不足，权重改为：

```text
quality =
  0.30 * local_probe
  + 0.70 * consensus_estimate
```

这个候选只保存在该 client 本地，影响它自己，不影响别人。

## 路径选择边界

### direct path

只使用本端实测：

- RTT、loss、jitter、带宽；
- 本端连接稳定性和队列丢弃率；
- 不允许被 manager 或 relay 的全网视图覆盖。

### relay path

如果 client 对 relay 有直接连接：

1. 本端测量 `client -> relay` 和端到端 relay stream；
2. manager 下发全网 segment estimate 作为参考；
3. 两边融合后交给现有 `path.Score()`。

### multi-hop path

client 不构造全网链路声明。流程为：

1. manager/relay 链路视图给出候选路径；
2. relay 沿路径逐段测量；
3. client 只对完整候选路径做端到端 probe；
4. 本地端到端结果决定最终选择。

因此多跳路径遵循：

```text
candidate generation = consensus view
path admission = local end-to-end probe
final selection = local B-score
```

## EigenSpeed 计算位置

不建议放在单个 manager。

### v1

每个 manager 独立计算：

1. 本地收集 manager/relay observation；
2. gossip 交换原始 signed observation；
3. 各自做确定性 trimmed median + EigenSpeed 计算；
4. 比较输出 link view hash。

优点：无单点；可用性不受单 manager 故障影响。

后续如果视图分裂频繁，再考虑：

- committee epoch 聚合；
- leader 构建 draft view，`2f+1` manager 签名；
- client 验证 view attestation。

本轮不把 link view 放入 BFT state，避免高频探测造成决策日志无限增长。

## 抗攻击设计

| 攻击 | 缓解 |
| --- | --- |
| client 伪造 RTT/loss/bandwidth | client 报告不进入全网矩阵 |
| client 合谋抬高某 relay | 只影响各自本地候选；manager/relay 矩阵使用独立观测 |
| relay 谎报链路 | 多 observer 交叉验证、trimmed median、异常降权 |
|观测重放 | observer signature + seq + measured_at + TTL |
|探测放大攻击 | probe token、频率上限、并发流上限 |
|虚假 relay 宣传 | relay 地址/能力必须来自 certified snapshot |
| score flapping | 当前路径惩罚、最小驻留时间、双侧分数差阈值 |

## 权威状态与非权威状态

进入 BFT certified snapshot 的只有低频控制面配置：

```text
NetworkSettings {
  link_min_bandwidth_mbps
  relay_latency_advantage_ms
  relay_loss_advantage_pct
  link_probe_interval_seconds
  link_probe_timeout_ms
  multi_hop_enabled
  max_multi_hop_segments
  trust_client_observations: false
}
```

不进入 BFT 的有：

- raw link observation；
- EigenSpeed link view；
- relay 负载；
- client-local path decision。

## 实施计划

### Phase A：观测与协议

新增 `internal/link`：

- `Observation`、`SegmentView`、`CandidateView`；
- RTT/loss/jitter probe；
- 低开销 bandwidth probe；
- observer signature；
- observation TTL、序列号和频控。

启用并实现 `/netp2p/link/probe/1.0.0`。

### Phase B：Manager/Relay 观测网

- manager 与所有已知 relay/client 测量直接链路；
- relay 测量与其他 relay/相邻 peer 的链路；
- manager 之间 gossip signed observation；
- 每 10–30 秒生成一次 `LinkView`。

### Phase C：EigenSpeed 聚合

实现确定性算法：

1. 构造 manager/relay observation matrix；
2. 缺失值先不填充；
3. 对最小支持样本数的节点做幂迭代；
4. 输出主特征向量；
5. 计算每条观测与主结构的偏差；
6. trimmed median + EigenSpeed 结果融合为 segment estimate。

包含属性测试：

- 正常观测收敛；
- 少量离群值被降权；
- 恶意 client 输入不影响矩阵；
- manager/relay 观测缺失时 confidence 下降。

### Phase D：路径融合

扩展候选生成：

- direct：仅本地；
- relay：本地 + consensus；
- multi-hop：consensus 生成，端到端本地验证；
- 每个 path candidate 保留 `source` 和 `confidence`。

`path.Score()` 增加信任校正：

```text
effective_metric = observed_metric
quality_confidence = [0, 1]
```

低 confidence 的 relay/multi-hop 候选增加惩罚，但仍然可以参与排序。

### Phase E：Web/CLI 观测

Settings 增加：

- multi-hop 开关；
- 最大跳数；
- probe interval；
- probe bandwidth 预算；
- trust client observations 开关，默认关闭。

Peers 页面 Link 数据必须区分：

- `local measured`；
- `consensus estimated`；
- `reported by client`。

`reported by client` 默认只在调试详情中展示，不参与评分。

## 验收标准

1. 恶意 client 提交任意假链路报告后，其他 client 的 EigenSpeed `LinkView` hash 不变。
2. 同一 manager/relay 观测集在任何 manager 上计算出相同 `LinkView` hash。
3. direct 路径永远不被全网估计覆盖。
4. `A -> R1 -> R2 -> B` 候选只有在端到端本地 probe 通过后才可被选中。
5. 恶意 client 修改自己的上报只能改变自己的候选排序。
6. probe 频率、带宽和状态表大小有硬上限。
