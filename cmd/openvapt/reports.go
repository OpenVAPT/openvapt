package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

// reportOwner is the user who receives the default report folder when a
// scan runs as root through sudo.
type reportOwner struct{ uid, gid int }

// lookupHome returns the home folder of a user id from the system's user
// database. It is a variable so tests can use a fake user database.
var lookupHome = func(uid string) (string, error) {
	u, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// sudoOwner returns the user who ran sudo, when the scan runs as root
// (euid 0) with SUDO_UID and SUDO_GID set and home is inside that user's
// own home folder as the user database records it. HOME alone is never
// trusted. In every other case it returns nil and the reports stay owned
// by the user running the scan (root under sudo with root's home).
func sudoOwner(euid int, getenv func(string) string, home string) *reportOwner {
	if euid != 0 || home == "" || !filepath.IsAbs(home) {
		return nil
	}
	uid, err1 := strconv.Atoi(getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid <= 0 || gid < 0 {
		return nil
	}
	uh, err := lookupHome(strconv.Itoa(uid))
	if err != nil || uh == "" || !filepath.IsAbs(uh) {
		return nil
	}
	uh, home = filepath.Clean(uh), filepath.Clean(home)
	if uh == "/" {
		return nil
	}
	if rel, err := filepath.Rel(uh, home); err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil
	}
	return &reportOwner{uid: uid, gid: gid}
}

// reportsDir is a new dated report folder inside home/openvapt-reports.
// base stays open as an os.Root, so handing the folder over to the sudo
// user later cannot be redirected by renaming or replacing a folder.
type reportsDir struct {
	Path        string
	name        string
	base        *os.Root
	owner       *reportOwner
	createdBase bool
}

// scanReportsDir creates a new private folder home/openvapt-reports/<UTC
// timestamp> for one scan. It never reuses or overwrites a folder: when
// the name is taken (two scans in the same second) it adds -2, -3 and so on.
// The base folder is created with Mkdir (never through a link) and checked
// with Lstat to be a real folder owned by the expected user before use.
func scanReportsDir(home string, now time.Time, owner *reportOwner) (*reportsDir, error) {
	if home == "" || !filepath.IsAbs(home) {
		return nil, errors.New("no home folder is known, so there is no default report folder; choose one with --out DIR")
	}
	base := filepath.Join(home, reportsFolder)
	created := false
	if err := os.Mkdir(base, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	lst, err := os.Lstat(base)
	if err != nil {
		return nil, err
	}
	if lst.Mode()&os.ModeSymlink != 0 || !lst.IsDir() {
		return nil, fmt.Errorf("%s must be a real folder, not a link; choose another with --out DIR", base)
	}
	euid := os.Geteuid()
	if uid, ok := fileUID(lst); ok {
		good := uid == euid || (!created && owner != nil && uid == owner.uid)
		if !good {
			return nil, fmt.Errorf("%s is owned by another user; choose another folder with --out DIR", base)
		}
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	// The folder opened must be the one just checked, not a replacement.
	if st, err := root.Stat("."); err != nil || !os.SameFile(st, lst) {
		_ = root.Close()
		return nil, fmt.Errorf("%s changed while it was being opened; try again or choose --out DIR", base)
	}
	if created {
		// Mkdir is subject to the umask; make sure it is owner-only.
		if err := root.Chmod(".", 0o700); err != nil {
			_ = root.Close()
			return nil, err
		}
	}
	stamp := now.UTC().Format("20060102T150405Z")
	for i := 1; i <= 100; i++ {
		name := stamp
		if i > 1 {
			name += "-" + strconv.Itoa(i)
		}
		err := root.Mkdir(name, 0o700)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err == nil {
			err = root.Chmod(name, 0o700)
		}
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		return &reportsDir{Path: filepath.Join(base, name), name: name, base: root, owner: owner, createdBase: created}, nil
	}
	_ = root.Close()
	return nil, fmt.Errorf("too many report folders named %s in %s; choose one with --out DIR", stamp, base)
}

// finish hands the folder and the files written into it to the sudo user,
// when there is one, and closes the base folder. Every change goes through
// the open base folder and never follows a link.
func (d *reportsDir) finish(files []string) error {
	defer d.base.Close()
	if d.owner == nil {
		return nil
	}
	uid, gid := d.owner.uid, d.owner.gid
	for _, f := range files {
		if err := d.base.Lchown(filepath.Join(d.name, filepath.Base(f)), uid, gid); err != nil {
			return err
		}
	}
	if err := d.base.Lchown(d.name, uid, gid); err != nil {
		return err
	}
	if d.createdBase {
		return d.base.Lchown(".", uid, gid)
	}
	return nil
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
