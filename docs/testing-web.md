# Web 控制面验证

控制台是一个 NetBird 风格的多页应用，每个 manager 都在自己的二进制里内嵌同一份
静态资源，因此任意一个 manager 都可以作为浏览器入口。

## 页面

侧边栏按 NetBird 的分区组织：

| 分区 | 页面 | 数据来源 |
| --- | --- | --- |
| Control Center | Peers | 认证元数据 + 观测在线状态 |
| Access Control | Policies / Groups / Setup Keys | certified state |
| Network Routing | Routes / Traffic Budgets | certified state |
| DNS | Nameservers / Zones / DNS Settings | certified state |
| BFT | Committee / Activity | committee 与认证决策日志 |
| Settings | Settings | bootstrap 与会话信息 |

## 信任模型

控制台把两类数据严格区分开，UI 上也用不同措辞标注：

- **认证数据**：来自 committee 的 signed snapshot，写入前必须经过 BFT 共识。页面上的
  Policies、Groups、Routes、DNS 等都属于这一类。
- **观测数据**：peer 在线状态由每个 manager 本地观测（libp2p 连接事件 + 长轮询活跃度），
  通过 `/netp2p/presence/1.0.0` 在 committee 间 gossip，按 last-write-wins 合并。
  Peers / Committee 页用 “Observed · observed by …” 明确标注，绝不与认证字段混为一谈。

Activity 页展示的是认证决策日志：每条记录的 transition 都被写进签名摘要，因此无法被
单个 manager 篡改。展开 Raw 可以看到原始 transition 与 QC。

## 运行

```bash
make ui                 # 安装依赖、类型检查、构建 ui/dist
docker build -t netp2p-test:latest .
sudo docker compose --env-file deploy/compose.env -f docker-compose.test.yml up -d
```

compose 把四个 manager 的 web 端口分别映射到 8080–8083，便于对照多 manager 的
认证状态是否一致。

## 验证步骤

1. 打开 `http://127.0.0.1:8080/peers`，确认深链接直接返回 SPA。
2. 输入 admin token（seed 中默认 `netp2p-admin-v0`）后点击 Connect，页面应显示
   certified height、peers、groups、policies 等面板，且没有 error 横幅。
3. 在 Groups / Routes / Budgets / Nameservers / Zones / Setup Keys 页各创建一条记录，
   确认 toast 提示 committed、表格出现新行、顶栏 height 递增。
4. 打开 Activity，确认出现对应的 `upsert_*` 条目，包含 leader、signers 与 transition hash。
5. 逐个打开 8080–8083，确认四个 manager 显示同一个 height 与同一份状态。
6. 停掉当前 leader（Activity 中 height+1 对应的 `leader`），再执行一次写操作，
   确认 round 轮换后仍然 commit，且 Activity 中新条目的 `round` 大于 0。
7. 重新启动被停掉的 manager，确认其 height 追平多数派。

## 已知限制

- DNS 只做控制面：nameserver / zone / settings 会随 certified snapshot 下发，
  但客户端不修改系统 DNS，需要等 TUN / split-DNS 层。
- 静态 admin token 是 v0 方案，尚无 OIDC 与细粒度 RBAC。
- 浏览器通过 libp2p WebRTC-direct 直连 manager，跨 NAT 场景需要 manager 具备
  公网可达地址，TURN / circuit relay 尚未接入。
- 投票与快照的线格式已包含 transition hash，因此 4 个 manager 必须同版本运行。
