.PHONY: ui build test e2e

ui:
	cd ui && npm install --no-audit --no-fund
	cd ui && npm run build

build: ui
	CGO_ENABLED=0 go build -o bin/netp2pd ./cmd/netp2pd
	CGO_ENABLED=0 go build -o bin/netp2p-probe ./cmd/netp2p-probe

test: ui
	cd ui && npm test
	go test ./...

e2e:
	scripts/e2e.sh
