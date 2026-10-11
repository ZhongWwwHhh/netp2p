# 实施路线图

## Phase 0：设计与契约

- [x] 确定 libp2p-only 数据面。
- [x] 确定不使用 WireGuard 传输/加密。
- [x] 定义 protocol IDs、policy/route/quota/network map 核心对象。
- [x] 定义 BFT certified state 与 client 验证模型。
- [x] 输出 protobuf schema（`proto/netp2p/v1`，deterministic 编码替代 canonical JSON）与 mermaid state transition 图（见 `docs/architecture.md`）。

## Phase 1：libp2p MVP

- [x] libp2p host 构造、PeerID、multiaddr 展示与配置持久化。
- [x] protocol ID 与安全 stream 收发骨架。
- [x] group 展开、policy 编译、NetworkMap 生成。
- [x] LinkProfile 路径评分和主/备路径选择。
- [x] TrafficBudget 聚合用量模型。
- [x] 固定 4 节点 HotStuff-lite BFT committee、canonical state hash、QC 验证。
- [x] 静态 seed、setup key 注册、overlay IP 分配、login/sync 骨架。
- [x] 无 TUN userspace UDP packet endpoint、IPv4/ICMP codec 和用户态 probe。
- [x] 两节点端到端数据面验收：policy 允许的 ICMP echo 收到 reply，deny 方向超时（Go 进程内 E2E + Docker E2E）。
- [x] TUN 接入（Linux），复用同一 `PacketSink` 接口：`/dev/net/tun` + 路由 reconcile + MTU 1280，缺失时回退 userspace。
- [x] 持久化二进制帧通道（`4 字节长度 + IPv4 payload`）替换「每包一条 stream + JSON/base64」。
- [x] TCP/UDP 端口解析接入 policy，flow 表让请求/回复方向各自独立判定。

## Phase 2：中心式过渡 Manager

- [x] admin CLI + libp2p admin 协议（token 鉴权 → BFT transition → 认证 snapshot）。
- [x] group/policy/route/budget/setup key 动态 upsert/remove。

- [x] Network/user/device/group/policy/route CRUD（Web 控制台 + admin CLI，同一权限矩阵）。
- [x] OIDC device flow（peer）与 PKCE（浏览器，经 manager 反向代理）登录。
- [x] JWT groups 到 managed groups 的映射，user 记录进入 certified state，peer 绑定 user。
- [x] 完整角色模型（owner/admin/network_admin/auditor/usage_viewer/user）× 模块 × 操作矩阵。
- [x] 登录过期（`LoginExpirationDays`）与客户端自动重新认证。
- [x] 本地 DNS 解析器：certified zone、peer 名自动注册、MatchDomains 转发、resolv.conf 接管/恢复（重启后从备份恢复真实上游）。
- [x] setup key 的 scope/expiry/使用次数与撤销（token hash 存储、one-off/reusable、Web UI 创建/撤销）。
- [x] sync 流下发 certified snapshot，client 长轮询并重连（`handleSync` + `SyncLoop`）。
- [x] incremental update 与 decision log 追平（`Engine.Activity` + `/api/v1/activity`）。
- [x] 控制面 Web 控制台：NetBird 式多页布局、深链接、浅色主题。
- [x] peer 认证元数据（hostname/OS/version）与观测在线状态（presence gossip）。
- [x] DNS 控制面对象（nameserver / zone / settings）与 BFT transition。

## Phase 3：链路探测

- [x] direct 与 circuit relay 候选发现（libp2p hole punching + static relay）。
- [x] B-score 链路评分：加权 RTT/loss/bandwidth/cost，归一化区间由 Web Settings 中的 relay advantage 阈值参数化。
- [x] RTT/loss/jitter/bandwidth probe（`/netp2p/link/probe/1.0.0`）：manager 主动测量 mesh 与 client access 链路，有界突发受 `ProbeBandwidthBudgetKB` 约束。
- [x] EigenSpeed 式 manager mesh 链路观测网与 client 不可信隔离：trimmed median + 幂迭代主特征向量 + 离群降权，access 段独立于 mesh 矩阵。
- [x] 评分收敛到 `internal/path.Score`（删除 `link.directScore`），未知带宽不再被硬排除；scheduler 对指标抖动做容差抑制，并在单次扫描内收敛所有发生变化的 peer pair（避免每个 assignment 各占一个 30s 冷却窗口导致多 peer 网络收敛过慢）。
- [x] flow class 用户可选（`Route`/`Policy.FlowClass` + `NetworkSettings.DefaultFlowClass` 接入 `path.Score` 权重）。
- [x] 路径持久化 hot-standby（重启后恢复 last-known-good path 与准入状态，TTL 24h）。
- [x] 取消 relay 身份，manager 成为 client/决策/转发/UI 超集。
- [x] BFT certified RouteAssignment：manager committee 规划 primary/fallback path。
- [x] via-manager forwarding data plane 与 client end-to-end admission（客户端严格按 certified primary→fallback 选路，manager 按上一跳身份转发并计数）。
- [x] Docker E2E `--with-tun` 闭环：等待 TUN 健康/overlay DNS 后验证内核 ICMP、policy TCP 与外部 DNS 转发。

## Phase 4：去中心化 Manager

- [x] 4 节点 BFT committee、proposal → vote → QC → commit、signed snapshot。
- [x] 单 manager 故障后仍能形成 quorum 并认证新状态。
- [x] decision log（committed map 查询）、落后/重启 manager catch-up。
- [x] view change：Submit 轮换 round，leader 宕机后仍能出块。
- [x] 决策日志认证：transition hash 纳入投票签名，snapshot 携带 transition 与 leader。
- [x] threshold signature（BLS12-381 分片聚合 QC）。
- [x] committee reconfiguration（在线替换成员、密钥轮换、epoch 校验）。

## Phase 5：多跳与配额

- [x] multi-hop planner（简单路径枚举、无 loop、`MaxHops`、每跳成本与 `Cost` tie-break）。
- [x] token bucket、峰值速率、burst 与成本限制（双端执行 + 有界 throttle）。
- [x] committee 权威配额状态和聚合用量结算（`update_budget_usage`，结算频率硬上限 60s，日/月确定性归零）。

## Phase 6：生产化

- [x] committee reconfiguration、key rotation、灾难恢复（`docs/upgrade.md`）。
- [x] threshold signature（BLS12-381，替代 2f+1 独立 Ed25519 签名）。
- [x] metrics、审计、混沌测试（`internal/metrics`、`/api/v1/events`、`internal/chaos`）。
- [x] 审计 actor 归属：服务端写入 `StateTransition.Actor`，纳入 transition hash 与 QC。
- [x] 告警本地规则与 webhook 导出（`internal/alerts`、`quorum_degraded`/`forward_drops`/`quota_exceeded`/`probe_failed`，状态跳变投递 + 有限重试）。
- [x] tracing（OTLP 可选导出）。
- [x] Docker compose `multihop` / `quota` / `chaos` profile 与 `scripts/e2e.sh --with-multihop/--with-quota/--with-chaos` 断言（4 个 profile 均已本地 Docker 实测通过）。
- [x] 安装器（nfpm DEB/RPM + systemd unit + `netp2pd --role doctor`）、协议版本协商（`/2.0.0`）与升级文档。
- [x] Windows/macOS TUN 实现（`RouteConfigurator` 抽象 + `wireguard-go/tun` 后端；本机仅编译验证）与第三方安全审计（仍待外部完成）。
- [x] threshold DKG（Pedersen DKG，`--dkg`，替代种子确定性派生）。
- [x] billing（`/api/v1/quota/history`，见 Phase 11）。

## Phase 7：TUN 数据面验收闭环

- [x] `scripts/e2e.sh --with-tun`：等待 TUN 健康检查与 overlay DNS 后，验证内核 ICMP、policy TCP 与外部 DNS 转发。
- [x] tun profile 增加 `healthcheck`（TUN 接口存在且分配了 overlay IP）。

## Phase 8：Exit Node 与 Subnet Route（Linux/TUN）

- [x] 模型：`Route.Masquerade`、`PeerRecord.IsExitNode`、`NetworkSettings.ExitNodeEnabled`（JSON + proto + wire 双向映射）。
- [x] BFT 校验：`upsert_route` 要求 routing group 至少一个 exit-node peer；`register_peer` 一律落 `IsExitNode=false`；`update_peer` 是唯一的开关入口且支持部分更新（不再清空 hostname/OS/version）。
- [x] 客户端 CIDR 路由：`applySnapshot` 为可见 certified Route 安装 `ip route replace <cidr> dev netp2p0`，并 pin underlay 目的地址以保住 0.0.0.0/0 场景；网关选择确定性（Metric→ID，RoutingGroup 内最低 PeerID）。
- [x] 客户端出向：非 overlay 目的命中 certified Route 时经 `sendToPeer` 发给 gateway（复用 quota / assignment / direct fallback）。
- [x] Exit gateway 服务端（`internal/exitnode`，Linux）：`ip_forward`（保存/恢复原值）+ iptables `MASQUERADE`/FORWARD 幂等 reconcile；TUN 注入内核完成转发与 SNAT，conntrack 回程。
- [x] 回程安全：masquerade 的 foreign 源地址仅在「来源是覆盖该地址的 certified gateway + 命中本地出向 flow」时交付内核，否则按伪造丢弃；非 exit peer 不得转发 off-overlay 包。
- [x] 非 Linux / 非 TUN：`ErrUnsupported`，显式告警并禁用本机 exit 能力，不影响普通 client。
- [x] admin CLI 新增 `update-peer` 动作，operator 无需 Web 也可标记 exit node。
- [x] Web 控制台：Routes 页 masquerade toggle 与 exit-node 提示；Peers 页 exit-node 列/抽屉开关（`peers:update`）；Settings 页 `exitNodeEnabled`。
- [x] Docker E2E `--with-exit`：foreign 子网 target + TUN exit gateway，验证内核 ICMP 经 gateway 抵达、MASQUERADE 生效。

## Phase 9：Route 约束执行 + Posture Check

- [x] `PeerRecord.Posture []string`（json `posture`）随 `register_peer` 上报、`update_peer` 覆盖（nil 保留旧值），BFT 校验去重、拒空、上限 32；proto/`internal/wire`/`NormalizeState` 同步。
- [x] `upsert_route` 校验 `AllowedPathTypes ⊆ {direct, via_manager, multi-hop}`、`FlowClass ∈ {"", latency, throughput, reliability, cost}`、`MaxHops`/`Metric` 非负。
- [x] planner 按 certified `Route` 派生约束：destination CIDR 匹配（`netip.ParsePrefix`）、source 隶属 `DistributionGroup`（空=全体）、多命中按 `Metric`→`Route.ID` 取唯一；`AllowedPathTypes`/`MaxHops`/`FlowClass` 覆盖网络默认，`Metric` 作为 score→centrality 后的 tie-break。
- [x] Budget 约束：候选路径累计 `PathSpec.Cost` 超过关联 `TrafficBudget.ForwardingCostLimit`（limit>0）时 score=0 硬排除。
- [x] `policy.Authorize` 新增 `sourcePosture`；`Policy.Posture` 非空且 `required ⊄ sourcePosture` 时该策略按 deny 计；client 出向传自身 posture、入向传源 peer posture。
- [x] Web：Routes 页新增 flowClass 选择；Peers 抽屉展示并按 `peers:update` 编辑 posture 标签。

## Phase 10：Threshold DKG + 安全加固

- [x] 安全加固：setup key 查表改用 `hmac.Equal` 常量时间比较；告警 webhook 强制 `https`（`--allow-insecure-webhook` 才能用 http）；`doctor` 在 seed 含 `keySeed` 时输出 WARN 建议启用 DKG。
- [x] `internal/crypto/bls` Pedersen DKG 原语：成员多项式承诺（G2 compressed）、share 验证（`g^share == Π C_k^{x^k}`）、群公钥与全体成员 share 公钥派生、`NewKeySetFromShares` 兼容已有签名/聚合路径。
- [x] `internal/dkg` + `/netp2p/control/dkg/2.0.0`：两轮 commit→share 加一轮结果广播与就绪屏障；仅 committee 成员参与，按 peer 身份鉴权。
- [x] share 持久化：`<dataDir>/dkg-share-<epoch>.json`（原子写）；`SetDKGLoader` 让 manager 重启后继续用本地 share 签名。
- [x] BFT 接线：`rotate_committee_keys` 可携带经校验的 DKG `GroupPublicKey`，engine 在 commit/catch-up 时采用本地 DKG share；缺省仍走确定性 seed 派生。
- [x] CLI：`--dkg`（默认 off，全体 manager 需同开）跑一轮 ceremony 后由 leader 提交轮换；`--rotate-committee-keys` 单独提交确定性轮换。

## Phase 11：可观测性收尾 + CI + billing

- [x] OTLP tracing：`internal/tracing` + `--otel-endpoint`（默认空=零开销，`tracing.Enabled()` 守卫）；BFT submit、forward accept、sync handler、DNS resolve 四处埋点。
- [x] Docker profiles：`multihop`（认证 `directPathEnabled=false`/`maxManagerHops=2`，断言出现 `via_manager` assignment 且 manager 转发计数 > 0）、`quota`（每 peer block 预算，断言超限后后续 probe 被丢弃且用量结算进 decision log）、`chaos`（`manager-4` 重启后恢复出块）；`scripts/e2e.sh` 新增 `--with-multihop/--with-quota/--with-chaos`。
- [x] admin CLI 新增 `update-settings` 动作（提交 `NetworkSettings`）与只读 `show-snapshot` 查询（认证 AdminProtocol 返回最新 certified snapshot JSON）；e2e 的设置/用量断言走该查询，因为 `--web-listen` 端口只暴露 `/api/bootstrap`。
- [x] GitHub Actions CI：`lint`（go vet + gofmt）、`test`（`go test ./internal/...`）、`e2e`（userspace）、`ui`（build + vitest）、`build-other`（GOOS=darwin/windows）。
- [x] billing：`GET /api/v1/quota/history?period=daily|monthly` 从 decision log 的 `update_budget_usage` 按 budget + 时间桶重算（`budgets` 读权限）。

## Phase 12：多平台 TUN

- [x] `internal/tun` 抽出 `RouteConfigurator`（`SetUp`/`AddAddress`/`SetMTU`/`AddRoute`/`DelRoute`/`AddHostRoute`/`DelHostRoute`/`DefaultGateway`）；Device 不再直接调用 `ip`。
- [x] Linux 保持 iproute2 实现与既有命令序列（单测不变）；darwin 用 `ifconfig`/`route`，windows 用 `netsh`/`route`。
- [x] darwin/windows 通过 `golang.zx2c4.com/wireguard/tun`（新增依赖）创建 utun/Wintun 设备；其他平台返回 `ErrUnsupported`。
- [x] `netp2pd --role doctor` 报告平台 TUN 可用性与所需权限；`docs/upgrade.md` 补齐各平台特权要求。
- [x] 验收：`GOOS=darwin`/`GOOS=windows` `go build ./...` 通过；Linux `internal/tun` 测试全绿（真机运行验证不在本轮范围）。
