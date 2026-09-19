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
5. 停止 `manager-4` 后启动 `client-c`，验证 height ≥ 4 的新 certified state。

`NETP2P_E2E_KEEP=1 scripts/e2e.sh` 保留容器便于排查；默认退出时 `down -v` 清理。

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
