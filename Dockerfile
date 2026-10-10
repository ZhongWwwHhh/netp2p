FROM --platform=$BUILDPLATFORM node:24-bookworm AS ui
ARG VERSION=0.0.0-dev
WORKDIR /src/ui
 COPY ui/package.json ui/package-lock.json ui/.npmrc ./
 RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN VITE_NETP2P_VERSION=${VERSION} npm run build

FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm AS build
ARG VERSION=0.0.0-dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/web/dist ./internal/web/dist
ARG LDFLAGS="-s -w -X github.com/netp2p/netp2p/internal/version.Version=${VERSION}"
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "${LDFLAGS}" -o /out/netp2pd ./cmd/netp2pd && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "${LDFLAGS}" -o /out/netp2p ./cmd/netp2p && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "${LDFLAGS}" -o /out/netp2p-probe ./cmd/netp2p-probe && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "${LDFLAGS}" -o /out/netp2p-mockidp ./cmd/netp2p-mockidp

FROM debian:bookworm-slim AS base
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="NetP2P" \
      org.opencontainers.image.description="Decentralized overlay VPN with a BFT committee control plane" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/ZhongWwwHhh/netp2p" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping netcat-openbsd iptables \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/netp2pd /usr/local/bin/netp2pd
COPY --from=build /out/netp2p /usr/local/bin/netp2p
COPY --from=build /out/netp2p-probe /usr/local/bin/netp2p-probe
COPY --from=build /out/netp2p-mockidp /usr/local/bin/netp2p-mockidp

FROM base AS runtime
RUN groupadd --system netp2p \
    && useradd --system --gid netp2p --home-dir /var/lib/netp2p --create-home netp2p \
    && mkdir -p /var/lib/netp2p /run/netp2p \
    && chown -R netp2p:netp2p /var/lib/netp2p /run/netp2p
USER netp2p
WORKDIR /var/lib/netp2p
ENTRYPOINT ["/usr/local/bin/netp2pd"]
CMD ["--role", "doctor"]

FROM base AS test
ENTRYPOINT ["/usr/local/bin/netp2pd"]
