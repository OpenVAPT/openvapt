package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildHeadIgnoresRecordCommits reproduces F-PIPE-05: the record job
// commits release/ and CITATION.cff after alpha.N, and that commit must not
// become the head that plan compares against the current alpha commit.
func TestBuildHeadIgnoresRecordCommits(t *testing.T) {
	const (
		record = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		code   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	log := "\x00" + record + "\n\nrelease/channels.json\nrelease/channels.txt\nCITATION.cff\nCHANGELOG.md\n\n" +
		"\x00" + code + "\n\ninternal/checks/host/ssh.go\nCITATION.cff\n\n"
	if got := buildHead(log); got != code {
		t.Fatalf("head = %s, want the code commit %s (the record commit must not count as a new build)", got, code)
	}
	// The pre-fix rule (exclude release/ only) would have picked the record
	// commit because it also changed CITATION.cff.
	if isRecordPath("CITATION.cff") != true || isRecordPath("release/channels.json") != true || isRecordPath("release") != true {
		t.Fatal("record paths must include CITATION.cff and everything under release/")
	}
	for _, p := range []string{"internal/x.go", "releases/x", "release.go", "docs/CHANGELOG.md", "cmd/channel/main.go"} {
		if isRecordPath(p) {
			t.Errorf("%s must count as a build file", p)
		}
	}
	if got := buildHead("\x00" + record + "\n\nrelease/channels.json\n"); got != "" {
		t.Fatalf("a history with only record commits must have no head, got %s", got)
	}
}

// TestGitHeadOnRealRepository builds a repository in which the newest commit
// is a record-only commit and checks that git reports the code commit as the
// head, including when the code arrived through a merge.
func TestGitHeadOnRealRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@localhost", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@localhost", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q", "-b", "main")
	write("main.go", "package main\n")
	write("CITATION.cff", "version: \"0.0.0\"\n")
	run("add", ".")
	run("commit", "-q", "-m", "code")
	code := run("rev-parse", "HEAD")

	// The record commit: release/ plus CITATION.cff, as promote.yml's record job writes.
	write("release/channels.json", "{}\n")
	write("CITATION.cff", "version: \"0.1.0-alpha.1\"\n")
	write("CHANGELOG.md", "## [Unreleased]\n")
	run("add", ".")
	run("commit", "-q", "-m", "release: promote v0.1.0-alpha.1 to alpha")
	if got, err := gitHead(dir); err != nil || got != code {
		t.Fatalf("head after a record commit = %q, %v; want the code commit %s", got, err, code)
	}

	// Code merged from a branch: the merge commit on main is the head, not a
	// commit inside the branch and not the record commit above it.
	run("checkout", "-q", "-b", "feature")
	write("internal/x.go", "package internal\n")
	run("add", ".")
	run("commit", "-q", "-m", "feat")
	run("checkout", "-q", "main")
	run("merge", "-q", "--no-ff", "-m", "merge feature", "feature")
	merge := run("rev-parse", "HEAD")
	write("release/channels.json", "{\"n\":2}\n")
	run("add", ".")
	run("commit", "-q", "-m", "release: promote v0.1.0-alpha.2 to alpha")
	if got, err := gitHead(dir); err != nil || got != merge {
		t.Fatalf("head after a merge and a record commit = %q, %v; want the merge commit %s", got, err, merge)
	}
}
