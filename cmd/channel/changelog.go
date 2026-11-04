package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	unreleasedHeading = "## [Unreleased]"
	// unreleasedEmpty is what a fresh [Unreleased] section holds. Release notes
	// treat it as "nothing to report".
	unreleasedEmpty = "_No changes recorded yet._"
)

var changelogHeading = regexp.MustCompile(`(?m)^## `)

// unreleasedSection returns the body of the [Unreleased] section (the text up
// to the next "## " heading), trimmed, and reports whether the heading exists.
func unreleasedSection(changelog string) (body string, ok bool) {
	i := strings.Index(changelog, unreleasedHeading+"\n")
	if i < 0 {
		if strings.HasSuffix(changelog, unreleasedHeading) {
			return "", true
		}
		return "", false
	}
	rest := changelog[i+len(unreleasedHeading)+1:]
	if m := changelogHeading.FindStringIndex(rest); m != nil {
		rest = rest[:m[0]]
	}
	return strings.TrimSpace(rest), true
}

// releaseNotes returns the changelog text that describes one release: the
// [Unreleased] body at release time, or a plain sentence when it is empty.
func releaseNotes(changelog string) string {
	body, ok := unreleasedSection(changelog)
	if !ok || body == "" || body == unreleasedEmpty {
		return "No changelog entries for this build."
	}
	return body
}

// updateChangelog turns the [Unreleased] section into the section for version
// (keep-a-changelog style, "## [vX.Y.Z-channel.N] - YYYY-MM-DD") and opens a
// fresh [Unreleased] section above it. When [Unreleased] is empty, which is the
// case when a build already released in one channel moves up to the next, the
// new section records note instead, so every published version has a section
// and release notes never show "Unreleased".
func updateChangelog(path, version, date, note string) error {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed repository file chosen by the operator
	if err != nil {
		return err
	}
	s := string(b)
	body, ok := unreleasedSection(s)
	if !ok {
		return fmt.Errorf("%s has no %q heading to update", path, unreleasedHeading)
	}
	i := strings.Index(s, unreleasedHeading)
	j := i + len(unreleasedHeading)
	if m := changelogHeading.FindStringIndex(s[j:]); m != nil {
		j += m[0]
	} else {
		j = len(s)
	}
	section := body
	if section == "" || section == unreleasedEmpty {
		section = "- " + strings.TrimSpace(note)
	}
	out := s[:i] + unreleasedHeading + "\n\n" + unreleasedEmpty + "\n\n" +
		"## [" + version + "] - " + date + "\n\n" + section + "\n\n" + s[j:]
	return os.WriteFile(path, []byte(strings.TrimRight(out, "\n")+"\n"), 0o644) // #nosec G306 -- public changelog
}
