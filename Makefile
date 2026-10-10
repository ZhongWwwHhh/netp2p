.PHONY: ui build build-linux test race e2e package-linux package-tarball package-windows checksums sbom release clean

GOBIN := $(shell go env GOPATH)/bin
PROTOC_GEN_GO_VERSION := v1.36.11
NFPM_VERSION := v2.47.0
VERSION ?= 0.0.0-dev
LDFLAGS := -s -w -X github.com/netp2p/netp2p/internal/version.Version=$(VERSION)

proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	PATH="$(PATH):$(GOBIN)" protoc --proto_path=proto \
		--go_out=. --go_opt=module=github.com/netp2p/netp2p \
		proto/netp2p/v1/netp2p.proto

ui:
	cd ui && VITE_NETP2P_VERSION=$(VERSION) npm ci --no-audit --no-fund
	cd ui && VITE_NETP2P_VERSION=$(VERSION) npm run build

build: $(if $(SKIP_UI),,ui)
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2pd ./cmd/netp2pd
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2p ./cmd/netp2p
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2p-probe ./cmd/netp2p-probe
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2p-mockidp ./cmd/netp2p-mockidp

build-linux: $(if $(SKIP_UI),,ui)
	mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2pd ./cmd/netp2pd
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2p ./cmd/netp2p
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2p-probe ./cmd/netp2p-probe
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/netp2p-mockidp ./cmd/netp2p-mockidp

test: ui
	cd ui && VITE_NETP2P_VERSION=$(VERSION) npm test
	go test ./cmd/... ./internal/...
	go test -race ./internal/...
	go vet ./...

race:
	go test -race ./internal/...

e2e:
	scripts/e2e.sh

package-linux: build-linux
	go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)
	mkdir -p dist
	VERSION=$(VERSION) "$(GOBIN)/nfpm" package -f packaging/nfpm.yaml -p deb --target dist
	VERSION=$(VERSION) "$(GOBIN)/nfpm" package -f packaging/nfpm.yaml -p rpm --target dist

package-tarball: build-linux
	mkdir -p dist
	sh packaging/tarball.sh $(VERSION) dist/netp2p-$(VERSION)-linux-amd64.tar.gz .

package-windows: $(if $(SKIP_UI),,ui)
	powershell -NoProfile -ExecutionPolicy Bypass -File packaging/windows/build.ps1 -Version $(VERSION) -BinDir dist/windows -OutDir dist

checksums:
	sh packaging/checksums.sh dist/netp2p-$(VERSION)-SHA256SUMS dist/netp2p-$(VERSION)-linux-amd64.tar.gz dist/*.deb dist/*.rpm dist/*.msi

sbom:
	sh packaging/sbom.sh dist/netp2p-$(VERSION)-sbom.cdx.json dir:.

release: package-linux package-tarball package-windows sbom checksums

clean:
	rm -rf bin dist
