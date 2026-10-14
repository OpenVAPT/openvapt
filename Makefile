VERSION ?= v0.1.0-dev
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)
# Reproducible: no build paths (-trimpath), no VCS stamp (-buildvcs=false, the
# commit is passed explicitly), no cgo, fixed ldflags and no timestamps. The
# release workflow builds twice on separate runners and refuses to publish if
# the two builds differ byte for byte; `make release VERSION=<tag> COMMIT=<sha>`
# reproduces a published binary.
LDFLAGS   := -s -w -X github.com/openvapt/openvapt/internal/version.Version=$(VERSION) -X github.com/openvapt/openvapt/internal/version.Commit=$(COMMIT)
GOBUILD   := CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)"

.PHONY: build check test site release vulndb clean man

build:
	$(GOBUILD) -o openvapt ./cmd/openvapt

# The manual page is generated from the same command and flag definitions
# the CLI uses, so it never drifts: openvapt man > openvapt.1
man:
	go run ./cmd/openvapt man > openvapt.1

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

# Generate the offline vulnerability snapshot from the public OSV ecosystem
# exports and the CISA KEV feed into the embed path, so a source build
# matches real advisories instead of the test fixture. Network access is
# needed for this target only; scans never go online.
ECOSYSTEMS ?= Debian:11,Debian:12,Debian:13,Ubuntu:20.04:LTS,Ubuntu:22.04:LTS,Ubuntu:24.04:LTS,AlmaLinux:8,AlmaLinux:9,Rocky Linux:8,Rocky Linux:9,Packagist,npm
vulndb:
	go run ./cmd/vulndbgen -out internal/vulndb/data/snapshot.json.gz -ecosystems "$(ECOSYSTEMS)" -packages docs/vulndb-packages.txt

release:
	mkdir -p dist/release
	for arch in amd64 arm64; do \
	  GOOS=linux GOARCH=$$arch $(GOBUILD) -o dist/release/openvapt_linux_$$arch ./cmd/openvapt; \
	done
	cd dist/release && sha256sum openvapt_linux_* > SHA256SUMS

clean:
	rm -rf openvapt openvapt.1 dist
