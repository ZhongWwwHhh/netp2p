FROM golang:1.25.7-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/netp2pd ./cmd/netp2pd && \
    CGO_ENABLED=0 go build -o /out/netp2p-probe ./cmd/netp2p-probe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/netp2pd /usr/local/bin/netp2pd
COPY --from=build /out/netp2p-probe /usr/local/bin/netp2p-probe
ENTRYPOINT ["/usr/local/bin/netp2pd"]
