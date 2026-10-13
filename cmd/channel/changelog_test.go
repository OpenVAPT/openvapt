package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const changelogFixture = "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n### Stream: pipeline\n- Fixed a thing.\n\n## [v0.1.0-alpha.2] - 2026-10-13\n\n- Older.\n"

func TestReleaseNotesUseOnlyTheUnreleasedSection(t *testing.T) {
	got := releaseNotes(changelogFixture)
	if !strings.Contains(got, "Fixed a thing.") || strings.Contains(got, "Older.") || strings.Contains(got, "Unreleased") {
		t.Fatalf("notes must hold only the [Unreleased] body, got:\n%s", got)
	}
	for _, empty := range []string{"## [Unreleased]\n\n## [v1] - 2026-01-01\n- x\n", "## [Unreleased]\n\n" + unreleasedEmpty + "\n", "# Changelog\n", "## [Unreleased]"} {
		if got := releaseNotes(empty); got != "No changelog entries for this build." {
			t.Errorf("empty section %q gave %q", empty, got)
		}
	}
}

func TestUpdateChangelogRenamesUnreleased(t *testing.T) {
	p := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(p, []byte(changelogFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := updateChangelog(p, "v0.1.0-alpha.3", "2026-10-15", "unused"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	s := string(b)
	want := "## [Unreleased]\n\n" + unreleasedEmpty + "\n\n## [v0.1.0-alpha.3] - 2026-10-15\n\n### Stream: pipeline\n- Fixed a thing.\n\n## [v0.1.0-alpha.2] - 2026-10-13\n\n- Older.\n"
	if !strings.HasSuffix(s, want) || !strings.HasPrefix(s, "# Changelog\n\nIntro.\n\n") || strings.Count(s, "[Unreleased]") != 1 {
		t.Fatalf("got:\n%s", s)
	}
	if releaseNotes(s) != "No changelog entries for this build." {
		t.Fatal("the fresh [Unreleased] section must read as empty")
	}

	// A second promotion of the same build (alpha to beta) records the note.
	if err := updateChangelog(p, "v0.1.0-beta.1", "2026-10-22", "Same build as v0.1.0-alpha.3, promoted to Beta."); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(p)
	if !strings.Contains(string(b), "## [v0.1.0-beta.1] - 2026-10-22\n\n- Same build as v0.1.0-alpha.3, promoted to Beta.\n\n## [v0.1.0-alpha.3]") {
		t.Fatalf("got:\n%s", b)
	}
	if err := updateChangelog(filepath.Join(t.TempDir(), "x.md"), "v1", "d", "n"); err == nil {
		t.Fatal("missing file must fail")
	}
	q := filepath.Join(t.TempDir(), "CHANGELOG.md")
	_ = os.WriteFile(q, []byte("# Changelog\n"), 0o600)
	if err := updateChangelog(q, "v1", "d", "n"); err == nil {
		t.Fatal("a changelog without [Unreleased] must fail")
	}
}
