// Package version holds build information, set at release time with
//
//	go build -ldflags "-X github.com/openvapt/openvapt/internal/version.Version=v1.0.0 -X ...Commit=<sha>"
package version

import "github.com/openvapt/openvapt/internal/channels"

var (
	Version = "v0.1.0-dev"
	Commit  = "unknown"
)

// Channel is the release channel this build belongs to, derived from its
// version: alpha, beta, rc, stable, or dev for a local build.
func Channel() channels.Channel { return channels.Of(Version) }

// ChannelName is the channel's display name, e.g. "Release Candidate".
func ChannelName() string { return channels.InfoFor(Channel()).Name }

// PreRelease reports whether this build is anything other than Stable.
func PreRelease() bool { return Channel() != channels.Stable }
