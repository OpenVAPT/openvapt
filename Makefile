VERSION ?= v0.1.0-dev
COMMIT  := $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X github.com/openvapt/openvapt/internal/version.Version=$(VERSION) -X github.com/openvapt/openvapt/internal/version.Commit=$(COMMIT)

.PHONY: build check test site release vulndb clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o openvapt ./cmd/openvapt

check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test -race ./...

test:
	go test ./...

site:
	cd site && npm ci --ignore-scripts && npm run build
	go run ./cmd/sitegen -out dist/site

# Generate the offline vulnerability snapshot from the public OSV ecosystem
# exports and the CISA KEV feed into the embed path, so a source build
# matches real advisories instead of the test fixture. Network access is
# needed for this target only; scans never go online.
ECOSYSTEMS ?= Debian:11,Debian:12,Debian:13,Ubuntu:20.04:LTS,Ubuntu:22.04:LTS,Ubuntu:24.04:LTS,AlmaLinux:8,AlmaLinux:9,Rocky Linux:8,Rocky Linux:9,Packagist,npm,WordPress:Core
vulndb:
	go run ./cmd/vulndbgen -out internal/vulndb/data/snapshot.json.gz -ecosystems "$(ECOSYSTEMS)" -packages docs/vulndb-packages.txt

release:
	mkdir -p dist/release
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/release/openvapt_linux_$$arch ./cmd/openvapt; \
	done
	cd dist/release && sha256sum openvapt_linux_* > SHA256SUMS

clean:
	rm -rf openvapt dist
