VERSION ?= v0.1.0-dev
COMMIT  := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/openvapt/openvapt/internal/version.Version=$(VERSION) -X github.com/openvapt/openvapt/internal/version.Commit=$(COMMIT)

.PHONY: build check test site release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o openvapt ./cmd/openvapt

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

test:
	go test ./...

# Builds the self-hosted assets and the site, then verifies the output:
# every local link resolves, the SEO and security artefacts exist, and no
# page carries a long dash or a banned phrase.
site:
	cd site && npm ci --ignore-scripts && npm run build
	go run ./cmd/sitegen -out dist/site
	go run ./cmd/sitecheck dist/site

release:
	mkdir -p dist/release
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/release/openvapt_linux_$$arch ./cmd/openvapt; \
	done
	cd dist/release && sha256sum openvapt_linux_* > SHA256SUMS

clean:
	rm -rf openvapt dist
