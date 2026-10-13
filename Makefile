VERSION ?= v0.1.0-dev
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
# Reproducible: no build paths (-trimpath), no VCS stamp (-buildvcs=false, the
# commit is passed explicitly), no cgo, fixed ldflags and no timestamps. The
# release workflow builds twice on separate runners and refuses to publish if
# the two builds differ byte for byte; `make release VERSION=<tag> COMMIT=<sha>`
# reproduces a published binary.
LDFLAGS   := -s -w -X github.com/openvapt/openvapt/internal/version.Version=$(VERSION) -X github.com/openvapt/openvapt/internal/version.Commit=$(COMMIT)
GOBUILD   := CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

.PHONY: build check test site release clean

build:
	$(GOBUILD) -o openvapt ./cmd/openvapt

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

test:
	go test ./...

site:
	cd site && npm ci --ignore-scripts && npm run build
	go run ./cmd/sitegen -out dist/site

release:
	mkdir -p dist/release
	for arch in amd64 arm64; do \
	  GOOS=linux GOARCH=$$arch $(GOBUILD) -o dist/release/openvapt_linux_$$arch ./cmd/openvapt; \
	done
	cd dist/release && sha256sum openvapt_linux_* > SHA256SUMS

clean:
	rm -rf openvapt dist
