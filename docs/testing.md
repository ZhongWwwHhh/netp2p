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

前置：`sudo -n docker` 可用、`python3` 可用。默认（userspace）模式**不需要 TUN，也不需要 `NET_ADMIN`**；
`--with-tun` 模式需要 `/dev/net/tun` 与 `NET_ADMIN`。

```bash
scripts/e2e.sh
```

或加 `--with-tun` 验证真实内核流量经过 TUN 设备：

```bash
scripts/e2e.sh --with-tun
```

脚本会（默认断言 + TUN 断言）：

1. `netp2pd --role seedgen` 生成确定性的 `deploy/state.json` 与 manager PeerID；
2. 构建 `netp2p-test:latest` 镜像；
3. 启动 4 个 manager + `client-a`/`client-b`，从 `deploy/run/*.json` 读取 overlay IP；
4. 验证 `client-a -> client-b` 的 ICMP 收到 reply，反向被 deny；
5. 停止 `manager-4` 后启动 `client-c`，验证 height ≥ 4 的新 certified state；
6. 断言 `client-a` 的 status 文件包含 certified `assignments`（`kind` ∈ `direct`/`via_manager`）与递增 `height`；
7. 从宿主抓取 `manager-1` 的 `http://127.0.0.1:9100/metrics`，断言存在 `netp2p_bft_height` 与 `netp2p_forward_*` 指标。
8. `--with-tun` 时先等待 overlay DNS 解析 peer 名，再验证内核 ICMP `client-a-tun -> client-b-tun` 收到 reply、TCP 按 certified policy 通、外部域名继续由备份上游转发。
9. `--with-exit` 时（隐含 `--with-tun`）用 admin CLI 把 `client-exit-tun` 提升为 exit node 并认证一条 `198.18.0.0/24` 的 route，然后验证 `client-a-tun` 安装该内核路由、`ping 198.18.0.10` 经 gateway 抵达、gateway 上存在 MASQUERADE 规则。
10. `--with-multihop` 时（隐含 `--with-tun`）通过 admin CLI 认证 `directPathEnabled=false` / `viaManagerEnabled=true` / `maxManagerHops=2` 的 settings，等到 `client-a-tun` 收到 `via_manager`/`multi_hop` assignment，再验证内核流量仍经 manager 转发（转发计数 > 0）。
11. `--with-quota` 时认证一条针对 `client-b` 的 2 KiB block 预算并开启 enforcement，持续发流量直到超限，然后断言后续 probe 被丢弃、且认证用量已结算进 decision log。
12. `--with-chaos` 时重启先前停掉的 `manager-4`，再提交一次 settings 变更，验证 4 manager 恢复出块。

`NETP2P_E2E_KEEP=1 scripts/e2e.sh` 保留容器便于排查；默认退出时 `down -v` 清理。

> admin CLI 的只读动作 `--action show-snapshot` 走已认证的 AdminProtocol 返回最新 certified snapshot（JSON）。浏览器的 `--web-listen` 端口只暴露 `/api/bootstrap`，控制台其余 API 经 js-libp2p WebRTC 隧道访问，因此脚本断言一律走 admin CLI 而非 HTTP。

## Docker：TUN、SSO 与控制台

```bash
# 完整 TUN 验收（推荐直接跑上面带 --with-tun 的 e2e 脚本）；
# 下面是手动操作步骤。需要 --device /dev/net/tun 与 --cap-add NET_ADMIN。
sudo -n docker compose --env-file deploy/compose.env -f docker-compose.test.yml --profile tun up -d client-a-tun client-b-tun

# 读 overlay IP（由 status file 持续刷新）
A_TUN_IP="$(python3 -c 'import json; print(json.load(open("deploy/run/client-a-tun.json"))["overlayIP"])')"
B_TUN_IP="$(python3 -c 'import json; print(json.load(open("deploy/run/client-b-tun.json"))["overlayIP"])')"
B_TUN_PEER="$(python3 -c 'import json; print(json.load(open("deploy/run/client-b-tun.json"))["peerID"])')"

# TUN 设备存在且分配了 overlay /32
sudo -n docker exec netp2p-client-a-tun-1 ip addr show netp2p0 | grep "inet $A_TUN_IP"

# ICMP：内核层 echo request -> overlay -> echo reply
sudo -n docker exec netp2p-client-a-tun-1 ping -c 3 "$B_TUN_IP"

# TCP：client-b-tun 上监听，client-a-tun 通过 kernel 路由连接
sudo -n docker exec -d netp2p-client-b-tun-1 nc -l -s "$B_TUN_IP" -p 9999
echo hello | sudo -n docker exec -i netp2p-client-a-tun-1 nc -w 3 "$B_TUN_IP" 9999

# DNS：overlay peer 名 + 外部域名（resolv.conf 已接管到 127.0.0.1）
sudo -n docker exec netp2p-client-a-tun-1 cat /etc/resolv.conf
sudo -n docker exec netp2p-client-a-tun-1 getent hosts client-b-tun.netp2p.internal
sudo -n docker exec netp2p-client-a-tun-1 getent hosts example.com
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
