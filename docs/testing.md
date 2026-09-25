# 测试与本地运行

## Go 测试

```bash
go test ./...                # 单元测试 + 进程内 E2E
go test -race ./internal/... # 并发敏感包
```

进程内 E2E（`internal/e2e`）在单进程内启动 4 个 manager + 2 个 client，走完整的
genesis → login → sync → frame 数据面，覆盖：

- policy 允许的 `A -> B` ICMP probe 收到 echo reply；
- `deny B -> A` 方向超时；
- 停掉 1 个 manager 后剩余 3 个仍能认证新 peer（quorum）；
- 篡改 state 或删减 QC 签名的 snapshot 被拒绝。
- SSO device flow：mock IdP 签发 ID token → `register_user` → `upsert_group`（JWT 组）→ peer 绑定 user 且 groups 含 `jwt-eng`。
- BLS 阈值 QC：3 个分片可聚合验证、2 个失败、篡改 `stateHash`/`transitionHash` 或错群公钥失败。
- committee 在线替换成员 / 轮换密钥后新 epoch 继续出块；旧 epoch 投票与快照被拒绝。
- 配额：token bucket 边界、优先级匹配、throttle 有界、`update_budget_usage` 结算与日/月归零。
- 多跳：planner 产生 1..N 跳候选、`Cost` tie-break、超 hop 拒绝、重复 hop（loop）拒绝。
- via-manager 数据面：certified assignment 驱动 `A -> M -> B` 转发成功且 `dropped == 0`。

`internal/oidc`、`internal/web` 另有单元测试覆盖 device flow + 真实 verifier、PKCE 反向代理全链路（login → authorize → callback → verifier 验证）与权限矩阵。

## 混沌测试（`internal/chaos`）

`internal/chaos.Controller` 在 libp2p 发送路径上注入确定性故障（`p2p.Node.SetSendHook`），可在单进程内复现真实网络故障而无需真机抖动：

- `Partition(peerID)` 丢弃发往该 peer 的消息；`Isolate(peerID)` 双向切断（同时丢弃该 peer 的出站）。
- `Fault{Protocol, Loss, Duplicate, Delay}` 按协议过滤做丢包 / 重放 / 延迟。
- `Stats()` 暴露 dropped / duplicated / delayed 计数，供断言。

`internal/e2e/chaos_test.go` 覆盖：隔离 1 个 manager 后剩余 3 个仍认证新高度且被隔离者落后；恢复后经单步 `sync_request` catch-up 追平且 state hash 一致；重放全部 committee 消息不破坏共识；隔离下一高度 leader 后 committee 轮换到存活 leader 继续出块。

```bash
go test ./internal/chaos/...
go test ./internal/e2e -run TestChaos -v
```

## Docker E2E

前置：`sudo -n docker` 可用、`python3` 可用。**不需要 TUN，也不需要 `NET_ADMIN`。**

```bash
scripts/e2e.sh
```

脚本会：

1. `netp2pd --role seedgen` 生成确定性的 `deploy/state.json` 与 manager PeerID；
2. 构建 `netp2p-test:latest` 镜像；
3. 启动 4 个 manager + `client-a`/`client-b`，从 `deploy/run/*.json` 读取 overlay IP；
4. 验证 `client-a -> client-b` 的 ICMP 收到 reply，反向被 deny；
5. 停止 `manager-4` 后启动 `client-c`，验证 height ≥ 4 的新 certified state；
6. 断言 `client-a` 的 status 文件包含 certified `assignments`（`kind` ∈ `direct`/`via_manager`）与递增 `height`；
7. 从宿主抓取 `manager-1` 的 `http://127.0.0.1:9100/metrics`，断言存在 `netp2p_bft_height` 与 `netp2p_forward_*` 指标。

`NETP2P_E2E_KEEP=1 scripts/e2e.sh` 保留容器便于排查；默认退出时 `down -v` 清理。

## Docker：TUN、SSO 与控制台

```bash
# TUN 客户端（需要 --device /dev/net/tun 与 --cap-add NET_ADMIN）
sudo -n docker compose --env-file deploy/compose.env -f docker-compose.test.yml --profile tun up -d client-a-tun client-b-tun
sudo -n docker exec netp2p-client-a-tun-1 ping -c 3 100.64.0.2   # overlay 地址按 deploy/run/*.json 为准

# DNS：容器内 resolv.conf 被接管到 127.0.0.1，外部域名与 overlay 名都要能解析
sudo -n docker exec netp2p-client-a-tun-1 cat /etc/resolv.conf        # nameserver 127.0.0.1
sudo -n docker exec netp2p-client-a-tun-1 getent hosts example.com    # 转发到备份里的真实上游
sudo -n docker exec netp2p-client-a-tun-1 getent hosts manager-1
sudo -n docker exec netp2p-client-a-tun-1 getent hosts "$(sudo -n docker exec netp2p-client-b-tun-1 hostname).netp2p.internal"
# 重启后仍要能解析：上游从 /etc/resolv.conf.netp2p.bak 恢复，而不是转给自己
sudo -n docker restart netp2p-client-a-tun-1 && sleep 15
sudo -n docker exec netp2p-client-a-tun-1 getent hosts example.com

# SSO：mock IdP + device flow 客户端
sudo -n docker compose --env-file deploy/compose.env -f docker-compose.test.yml --profile sso up -d mock-idp client-sso
sudo -n docker logs netp2p-client-sso-1        # 会打印 verification URI 与 user code（mock 自动批准）

# 浏览器控制台
#   http://127.0.0.1:8080  → “Sign in with SSO” 走 PKCE（经 manager 的 /auth 代理）
#   或输入 admin token netp2p-admin-v0
```

控制台验证要点：

- `/users` 列出 SSO 用户、角色与 auto groups；`/settings` 的 Session 卡片显示角色与 IdP issuer。
- 首个登录用户为 `owner`；后续非 `netp2p-admins` 组的用户为 `user`，写操作按钮被隐藏且服务端返回 403。
- 停掉 1 个 manager 后仍可写入；`GET /api/v1/activity` 的每条记录都能用 snapshot 内 committee 公钥验证。

生成 Docker 栈需要重新构建镜像（前端已嵌进 manager binary）：

```bash
cd ui && npm run build && cd ..
sudo -n docker build -t netp2p-test:latest .
```

迭代调试时不必整镜像重建：`CGO_ENABLED=0 go build -o /tmp/netp2pd ./cmd/netp2pd`，
再 `docker cp /tmp/netp2pd <container>:/usr/local/bin/netp2pd && docker restart <container>`。

## 手动运行

```bash
# 1. 生成 seed（确定性 PeerID）
go run ./cmd/netp2pd --role seedgen --config deploy/state.json

# 2. 启动 manager（每个进程一个 ID）
NETP2P_MANAGER_ID=manager-1 go run ./cmd/netp2pd --role manager \
  --config deploy/state.json --listen /ip4/0.0.0.0/udp/4001/quic-v1

# 3. 启动 client（manager 地址需带 /p2p/<peerID>）
go run ./cmd/netp2pd --role client \
  --manager /dns4/manager-1/udp/4001/quic-v1/p2p/<peerID> \
  --setup-key setup-key-a --packet-listen 127.0.0.1:51820 --status-file /tmp/client-a.json

# 4. 用户态 ICMP probe（替代需要 root 的系统 ping）
go run ./cmd/netp2p-probe --packet-listen 127.0.0.1:51820 \
  --source 100.64.0.1 --target 100.64.0.2
```

## 已知无害告警

- `failed to sufficiently increase receive buffer size ...`：WSL/容器 UDP buffer 限制，
  来自 quic-go，不影响测试。
- Docker 构建时 `The legacy builder is deprecated`：可安装 buildx 消除。
