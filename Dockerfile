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

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/netp2pd /usr/local/bin/netp2pd
COPY --from=build /out/netp2p-probe /usr/local/bin/netp2p-probe
COPY --from=build /out/netp2p-mockidp /usr/local/bin/netp2p-mockidp
ENTRYPOINT ["/usr/local/bin/netp2pd"]
