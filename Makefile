.PHONY: ui build test e2e proto race package

GOBIN := $(shell go env GOPATH)/bin
PROTOC_GEN_GO_VERSION := v1.36.11
NFPM_VERSION := v2.47.0
VERSION ?= 0.0.0-dev

proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	PATH="$(PATH):$(GOBIN)" protoc --proto_path=proto \
		--go_out=. --go_opt=module=github.com/netp2p/netp2p \
		proto/netp2p/v1/netp2p.proto

ui:
	cd ui && npm install --no-audit --no-fund
	cd ui && npm run build

build: ui
	CGO_ENABLED=0 go build -o bin/netp2pd ./cmd/netp2pd
	CGO_ENABLED=0 go build -o bin/netp2p-probe ./cmd/netp2p-probe

test: ui
	cd ui && npm test
	go test ./...
	go test -race ./internal/...
	go vet ./...

race:
	go test -race ./internal/...

e2e:
	scripts/e2e.sh

package: build
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)
	VERSION=$(VERSION) "$(GOBIN)/nfpm" package -f packaging/nfpm.yaml -p deb -p rpm --target dist
