# 实施路线图

## Phase 0：设计与契约

- [x] 确定 libp2p-only 数据面。
- [x] 确定不使用 WireGuard 传输/加密。
- [x] 定义 protocol IDs、policy/route/quota/network map 核心对象。
- [x] 定义 BFT certified state 与 client 验证模型。
- [ ] 输出 protobuf/CDDL schema 与 state transition 图（当前用 canonical JSON）。

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

- [ ] Network/user/device/group/policy/route CRUD。
- [x] OIDC device flow（peer）与 PKCE（浏览器，经 manager 反向代理）登录。
- [x] JWT groups 到 managed groups 的映射，user 记录进入 certified state，peer 绑定 user。
- [x] 完整角色模型（owner/admin/network_admin/auditor/usage_viewer/user）× 模块 × 操作矩阵。
- [x] 登录过期（`LoginExpirationDays`）与客户端自动重新认证。
- [x] 本地 DNS 解析器：certified zone、peer 名自动注册、MatchDomains 转发、resolv.conf 接管/恢复（重启后从备份恢复真实上游）。
- [ ] setup key 的 scope/expiry/使用次数与撤销。
- [x] sync 流下发 certified snapshot，client 长轮询并重连（`handleSync` + `SyncLoop`）。
- [x] incremental update 与 decision log 追平（`Engine.Activity` + `/api/v1/activity`）。
- [x] 控制面 Web 控制台：NetBird 式多页布局、深链接、浅色主题。
- [x] peer 认证元数据（hostname/OS/version）与观测在线状态（presence gossip）。
- [x] DNS 控制面对象（nameserver / zone / settings）与 BFT transition。

## Phase 3：链路探测

- [ ] direct 与 circuit relay 候选发现。
- [ ] RTT/loss/jitter/bandwidth/stability probe（`/netp2p/link/probe/1.0.0`）。
- [ ] flow class 约束、路径切换迟滞与热备。

## Phase 4：去中心化 Manager

- [x] 4 节点 BFT committee、proposal → vote → QC → commit、signed snapshot。
- [x] 单 manager 故障后仍能形成 quorum 并认证新状态。
- [x] decision log（committed map 查询）、落后/重启 manager catch-up。
- [x] view change：Submit 轮换 round，leader 宕机后仍能出块。
- [x] 决策日志认证：transition hash 纳入投票签名，snapshot 携带 transition 与 leader。
- [ ] threshold signature、committee reconfiguration。

## Phase 5：多跳与配额

- [ ] multi-hop planner 与 relay/gateway 候选池。
- [ ] token bucket、峰值速率、burst 与成本限制。
- [ ] committee 权威配额状态和聚合用量结算。

## Phase 6：生产化

- [ ] committee reconfiguration、key rotation、灾难恢复。
- [ ] threshold signature（当前为 2f+1 个独立 Ed25519 签名）。
- [ ] metrics、tracing、审计、告警与混沌测试。
- [ ] 多平台客户端、安装器、协议版本升级与安全审计。
