package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
	"strings"
)

// recordPaths are the files the promote record job writes when it records a
// promotion. A commit that touches only these files is a record of a release,
// not a new build, so it must never become the next alpha candidate. Before
// this list existed, plan excluded release/ only; the record commit for
// alpha.N also rewrote CITATION.cff, so the next day it was promoted as
// alpha.N+1 with identical code, and every promotion reset the soak clock.
var recordPaths = []string{"release/", "CITATION.cff", "CHANGELOG.md"}

// isRecordPath reports whether a repository path is written by the record job.
func isRecordPath(p string) bool {
	p = path.Clean(strings.TrimPrefix(strings.ReplaceAll(p, "\\", "/"), "./"))
	for _, r := range recordPaths {
		if strings.HasSuffix(r, "/") {
			if p == strings.TrimSuffix(r, "/") || strings.HasPrefix(p, r) {
				return true
			}
		} else if p == r {
			return true
		}
	}
	return false
}

// buildHead returns the newest commit that changed at least one file outside
// recordPaths, given the output of
//
//	git log --format=%x00%H --name-only
//
// (see gitHead) in which every commit starts with a NUL-prefixed hash line followed by the
// paths it changed. It returns "" when no commit changed a build file.
func buildHead(gitLog string) string {
	commit := ""
	for _, line := range strings.Split(gitLog, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "\x00") {
			commit = strings.TrimSpace(line[1:])
			continue
		}
		if line == "" || commit == "" {
			continue
		}
		if !isRecordPath(line) {
			return commit
		}
	}
	return ""
}

// gitHead runs git in dir and returns the build head (see buildHead). History
// is walked along the first parent, and a merge commit lists everything it
// brought in (its diff against the first parent), so the head is always a
// commit on main itself, never one inside a merged branch.
func gitHead(dir string) (string, error) {
	cmd := exec.Command("git", "log", "--first-parent", "--diff-merges=first-parent", // #nosec G204 -- fixed arguments
		"--format=%x00%H", "--name-only", "--", ".")
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git log: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	h := buildHead(out.String())
	if h == "" {
		return "", fmt.Errorf("no commit changes a file outside %s", strings.Join(recordPaths, ", "))
	}
	return h, nil
}
