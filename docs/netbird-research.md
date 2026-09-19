# NetBird 调研与映射

## 1. Group / Policy 设计

NetBird 把 group 作为主要授权抽象。Peer、user、route 和 policy 都通过 group 关联，而不是互相直连引用。这带来三个优点：

- 语义稳定：成员变化只影响 group，不需要重写 policy；
- 管理可扩展：设备可以由 SSO group 或 setup key 自动进入 group；
- 编译简单：policy 编译器展开 group membership，生成 peer 级 ACL。

NetBird policy 的核心是 source group 与 destination group，可限制 protocol 和 port，并区分 bidirectional/unidirectional。这个模型足够表达大多数服务访问关系。

NetP2P 保留该模型，并扩展 posture requirement、link constraints、deny 优先级和 TrafficBudget。授权与链路选择解耦：policy 决定“是否可达”，path planner 决定“走哪条路径”。

## 2. Manager 路由管理

NetBird Management 通过 Login / Sync / NetworkMap 模式下发配置：

- Login 完成身份、account 和初始注册；
- Sync 保持长期变更流或定期同步；
- NetworkMap 包含 allowed peers、DNS、routes、firewall 和 manager 配置。

Route 主要字段包括目标 CIDR/DNS、routing peer/group、distribution group、metric 和 masquerade。Routing peer 负责转发目标网段流量，distribution group 决定谁能看到 route。

NetP2P 将该模型改为约束驱动：

```text
Route {
  id
  destination
  routing_group
  distribution_groups
  metric
  path_constraints
  allowed_path_types
  max_hops
  budget_ids
}
```

Manager 下发 route candidate 和 policy constraint，peer 使用本地探测结果选择 direct、relay、multi-hop 或 gateway。这样 manager 拥有治理权，client 拥有实时链路决策权。

## 3. SSO 登录与 Group 同步

NetBird 的 SSO 流程是 client 获取 IdP JWT 后交给 Management；Management 校验 JWT 并从 groups/roles claims 建立 user/group membership。之后 group membership 会影响 AutoGroups、policy 与 network map。

NetP2P 采用相同同步语义，但信任根不同：

- OIDC discovery/JWKS 仍然是用户身份信任根；
- overlay state 的信任根是 manager committee threshold signature；
- client 验证的是 JWT 认证结果产生的 certified state，而不是信任单个 manager；
- group membership 变化会生成 decision log 事件，并触发新 epoch。

## 4. 差异结论

| 领域 | NetBird | NetP2P |
| --- | --- | --- |
| 传输 | WireGuard/用户态 WireGuard | go-libp2p QUIC/stream |
| Manager | 中心服务 | BFT committee |
| 授权 | Group + policy | Group + policy + posture + link constraints |
| 链路 | P2P 优先，relay 回退 | 多候选路径按 flow 约束评分 |
| 配额 | 弱/外置 | TrafficBudget 是一等状态 |
| 状态信任 | Management API | signed certified snapshot + epoch |
