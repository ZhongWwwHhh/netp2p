# Web 控制面验证

控制台是一个 NetBird 风格的多页应用，每个 manager 都在自己的二进制里内嵌同一份
静态资源，因此任意一个 manager 都可以作为浏览器入口。

## 页面

侧边栏按 NetBird 的分区组织：

| 分区 | 页面 | 数据来源 |
| --- | --- | --- |
| Control Center | Peers | 认证元数据 + 观测在线状态 |
| Access Control | Policies / Groups / Setup Keys / Users | certified state |
| Network Routing | Routes / Traffic Budgets / Paths | certified state（Paths 另含本地 admission 观测） |
| DNS | Nameservers / Zones / DNS Settings | certified state |
| BFT | Committee / Activity | committee 与认证决策日志 |
| Operations | Diagnostics | metrics / 转发 / 配额 / 观测健康快照 |
| Settings | Settings | bootstrap 与会话信息 |

## 信任模型

控制台把两类数据严格区分开，UI 上也用不同措辞标注：

- **认证数据**：来自 committee 的 signed snapshot，写入前必须经过 BFT 共识。页面上的
  Policies、Groups、Routes、DNS 等都属于这一类。
- **观测数据**：peer 在线状态由每个 manager 本地观测（libp2p 连接事件 + 长轮询活跃度），
  通过 `/netp2p/presence/3.0.0` 在 committee 间 gossip，按 last-write-wins 合并。
  Peers / Committee 页用 “Observed · observed by …” 明确标注，绝不与认证字段混为一谈。

Activity 页展示的是认证决策日志：每条记录的 transition 都被写进签名摘要，因此无法被
单个 manager 篡改。展开 Raw 可以看到原始 transition 与 QC。

Paths 页把两类数据并排展示并分别标注：**certified assignment**（committee 通过 BFT
认证的 primary / fallback 路径及评分估计）与 **local admission**（本 manager 最近听到的
客户端端到端准入观测，非认证）。Diagnostics 页汇聚 metrics、转发计数、配额用量、
presence 与问题清单；配额用量同时展示在 Traffic Budgets 页（进度条 + 日/月重置）。

## 运行

```bash
make ui                 # 安装依赖、类型检查、构建 internal/web/dist（已入库，需一并提交）
docker build -t netp2p-test:latest .
sudo docker compose --env-file deploy/compose.env -f docker-compose.test.yml up -d
```

compose 把三个 manager 的 web 端口分别映射到 8080–8082，便于对照多 manager 的
认证状态是否一致。

## 验证步骤

1. 打开 `http://127.0.0.1:8080/peers`，确认深链接直接返回 SPA。
2. 使用测试 fixture 提供的 owner 凭据或 break-glass admin token 登录，页面应显示
   certified height、peers、groups、policies 等面板，且没有 error 横幅。
3. 在 Groups / Routes / Budgets / Nameservers / Zones / Setup Keys 页各创建一条记录，
   确认 toast 提示 committed、表格出现新行、顶栏 height 递增。
4. 打开 Activity，确认出现对应的 `upsert_*` 条目，包含 leader、signer bitmap/epoch 与 transition hash。
5. 逐个打开 8080–8082，确认三个 manager 显示同一个 height 与同一份状态。
6. 停掉任意一个 manager，再执行一次写操作，确认 3-of-3 committee 进入 degraded
   状态且写操作被明确拒绝，而不是静默丢失。
7. 重新启动被停掉的 manager，确认 committee 恢复 ready，落后节点 height 追平，
   随后的写操作可以 commit。
8. 在 Settings 页修改 `viaManagerEnabled` / `maxManagerHops` / 配额与探测参数并保存，
   确认 height 递增且 `user` 角色下这些控件被禁用、服务端返回 403。
9. 打开 `/paths` 与 `/diagnostics`，确认无 console error，certified 与观测字段分别标注。

## SSO 登录与权限

manager 的 bootstrap 监听额外提供三个仅用于登录的端点（不修改任何状态）：

- `GET /auth/login`：生成 PKCE verifier/challenge 并跳转到 IdP；
- `GET /auth/idp/*`：到 issuer 的反向代理，让只在内网可解析的 IdP 也能被浏览器使用；
- `GET /auth/callback`：用 code 换 ID token，再 302 到 `/#id_token=…`。

验证步骤：

1. 启动 mock IdP：`docker compose --env-file deploy/compose.env -f docker-compose.test.yml --profile sso up -d mock-idp`。
2. 打开 `http://127.0.0.1:8080/`，点击 “Sign in with SSO”，应自动完成 PKCE 并进入控制台。
3. `/settings` 的 Session 卡片显示用户与角色；`/users` 列出该用户和 device-flow 用户。
4. 用非 `netp2p-admins` 组登录时角色为 `user`：写操作按钮隐藏，直接调用写接口返回 403。

## 已知限制

- DNS 只做控制面：nameserver / zone / settings 会随 certified snapshot 下发，
  客户端本地解析器已生效，但系统 DNS 接管仅在 TUN 模式且允许时进行。
- 静态 admin token 仍是 break-glass 凭证（映射为 owner）；SSO 用户按角色矩阵授权。
- 浏览器通过 libp2p WebRTC-direct 直连 manager，跨 NAT 场景需要 manager 具备
  公网可达地址，TURN / circuit relay 尚未接入。
- 投票与快照的线格式已包含 transition hash，因此 3 个 manager 必须同版本运行。
