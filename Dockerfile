FROM node:24-bookworm AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm install --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM golang:1.25.7-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/web/dist ./internal/web/dist
RUN CGO_ENABLED=0 go build -o /out/netp2pd ./cmd/netp2pd && \
    CGO_ENABLED=0 go build -o /out/netp2p-probe ./cmd/netp2p-probe && \
    CGO_ENABLED=0 go build -o /out/netp2p-mockidp ./cmd/netp2p-mockidp

FROM debian:bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping netcat-openbsd iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/netp2pd /usr/local/bin/netp2pd
COPY --from=build /out/netp2p-probe /usr/local/bin/netp2p-probe
COPY --from=build /out/netp2p-mockidp /usr/local/bin/netp2p-mockidp

# Production image: runs unprivileged. UDP-only deployments need no extra
# capabilities; TUN/DNS deployments must add CAP_NET_ADMIN and make
# /dev/net/tun available (see docs/upgrade.md). Build with --target runtime.
FROM base AS runtime
RUN groupadd --system netp2p \
    && useradd --system --gid netp2p --home-dir /var/lib/netp2p --create-home netp2p \
    && mkdir -p /var/lib/netp2p \
    && chown -R netp2p:netp2p /var/lib/netp2p
USER netp2p
WORKDIR /var/lib/netp2p
ENTRYPOINT ["/usr/local/bin/netp2pd"]
CMD ["--role", "doctor"]

# Test image (the default target): stays root so the TUN profile can create
# /dev/net/tun interfaces. This is what docker-compose.test.yml builds.
FROM base AS test
ENTRYPOINT ["/usr/local/bin/netp2pd"]
