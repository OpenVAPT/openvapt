package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// reportsFolder is the folder, under the home folder of the user running
// the scan, that holds one dated sub-folder per scan when --out is not given.
const reportsFolder = "openvapt-reports"

// xdgOpen is the only program OpenVAPT may start outside the read-only
// allow-list in internal/sys, and only for --open. It is a fixed absolute
// path (never looked up in PATH, never run through a shell) and it is only
// ever given the report.html file this run has just written.
const xdgOpen = "/usr/bin/xdg-open"

// scanReportsDir creates a new private folder home/openvapt-reports/<UTC
// timestamp> for one scan. It never reuses or overwrites a folder: when
// the name is taken (two scans in the same second) it adds -2, -3 and so on.
func scanReportsDir(home string, now time.Time) (string, error) {
	if home == "" || !filepath.IsAbs(home) {
		return "", errors.New("no home folder is known, so there is no default report folder; choose one with --out DIR")
	}
	base := filepath.Join(home, reportsFolder)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	if lst, err := os.Lstat(base); err != nil {
		return "", err
	} else if lst.Mode()&os.ModeSymlink != 0 || !lst.IsDir() {
		return "", fmt.Errorf("%s must be a real folder, not a link; choose another with --out DIR", base)
	}
	stamp := now.UTC().Format("20060102T150405Z")
	for i := 1; i <= 100; i++ {
		name := stamp
		if i > 1 {
			name += "-" + strconv.Itoa(i)
		}
		dir := filepath.Join(base, name)
		err := os.Mkdir(dir, 0o700)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		// Mkdir is subject to the umask; make sure it is owner-only.
		err = os.Chmod(dir, 0o700) // #nosec G302 -- directory, not a file
		if err != nil {
			return "", err
		}
		return dir, nil
	}
	return "", fmt.Errorf("too many report folders named %s in %s; choose one with --out DIR", stamp, base)
}

// desktopSession reports whether a graphical session is available, which
// is the only case in which --open starts a browser.
func desktopSession(getenv func(string) string) bool {
	return getenv("DISPLAY") != "" || getenv("WAYLAND_DISPLAY") != ""
}

// htmlReport returns the report.html path among the written files, or "".
func htmlReport(files []string) string {
	for _, p := range files {
		if filepath.Base(p) == "report.html" {
			abs, err := filepath.Abs(p)
			if err != nil {
				return p
			}
			return abs
		}
	}
	return ""
}

// printReports prints the Reports block: every written file and one line
// on how to open the HTML report.
func printReports(w io.Writer, files []string) {
	fmt.Fprintln(w, "Reports (written only on this machine, readable only by this user):")
	for _, p := range files {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		fmt.Fprintln(w, "  "+abs)
	}
	if h := htmlReport(files); h != "" {
		fmt.Fprintf(w, "Open the HTML report in any web browser, for example: xdg-open %s\n", h)
	}
}

// openReport opens the report.html this run just wrote with xdg-open, only
// in a desktop session and never as root. It prints why when it does not.
func openReport(w io.Writer, files []string, getenv func(string) string, euid int) {
	h := htmlReport(files)
	switch {
	case h == "":
		fmt.Fprintln(w, "--open: no HTML report was written (add html to --format).")
		return
	case euid == 0:
		fmt.Fprintln(w, "--open: not starting a web browser as root. Open the report as your own user instead.")
		return
	case !desktopSession(getenv):
		fmt.Fprintln(w, "--open: no desktop session (DISPLAY or WAYLAND_DISPLAY is not set), so nothing was opened.")
		return
	}
	if st, err := os.Stat(xdgOpen); err != nil || st.IsDir() {
		fmt.Fprintf(w, "--open: %s is not installed, so nothing was opened.\n", xdgOpen)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// A fixed program and a single argument: the absolute path of the file
	// this run wrote. No shell is involved.
	cmd := exec.CommandContext(ctx, xdgOpen, h) // #nosec G204 -- fixed binary, path of our own report
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(w, "--open: xdg-open did not succeed (%v). Open %s yourself.\n", err, h)
		return
	}
	fmt.Fprintf(w, "Opened %s with xdg-open.\n", h)
}
