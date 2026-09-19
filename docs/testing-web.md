# Web 控制面验证

1. `make ui && make build`
2. 生成 seed：`go run ./cmd/netp2pd --role seedgen --config deploy/state.json`
3. 启动任意 manager 后访问 `http://127.0.0.1:8080/`。
4. 页面会请求 `/api/bootstrap`，返回 PeerID、WebRTC multiaddr、API protocol 与 committee。
5. 管理 API 通过 libp2p HTTP protocol `/netp2p/web-api/1.0.0` 调用；普通 HTTP 只允许静态资源、
   `/api/bootstrap` 和 `/healthz`。
6. 写操作使用 `POST /api/v1/transitions`，请求仍由 BFT committee 认证并返回 certified snapshot。
