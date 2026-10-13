// Package version holds build information, set at release time with
//
//	go build -ldflags "-X github.com/openvapt/openvapt/internal/version.Version=v1.0.0 -X ...Commit=<sha>"
package version

var (
	Version = "v0.1.0-dev"
	Commit  = "unknown"
)
