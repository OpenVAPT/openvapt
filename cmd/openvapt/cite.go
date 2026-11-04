package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/academy"
	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/cite"
	"github.com/openvapt/openvapt/internal/version"
)

// citeFlagSet is the flag set of openvapt cite.
func citeFlagSet(format, checkID, moduleID *string) *flag.FlagSet {
	fs := flag.NewFlagSet("cite", flag.ExitOnError)
	fs.StringVar(format, "format", "apa", "citation format: "+strings.Join(cite.Formats, ", "))
	fs.StringVar(checkID, "check", "", "cite one check page, for example HOST-SSH-001")
	fs.StringVar(moduleID, "module", "", "cite one Academy module page")
	return fs
}

func cmdCite(_ context.Context, args []string) error {
	return citeTo(os.Stdout, os.Stderr, args, time.Now())
}

// citeTo prints the citation for this exact build. Nothing is sent anywhere.
func citeTo(w, note io.Writer, args []string, now time.Time) error {
	var format, checkID, moduleID string
	fs := citeFlagSet(&format, &checkID, &moduleID)
	if err := fs.Parse(args); err != nil {
		return usageErr("cite: %v", err)
	}
	if fs.NArg() > 0 {
		return usageErr("cite takes no positional arguments")
	}
	if checkID != "" && moduleID != "" {
		return usageErr("cite: use --check or --module, not both")
	}
	work := cite.New(version.Version, now)
	var out string
	var err error
	switch {
	case checkID != "":
		c := check.Get(strings.ToUpper(checkID))
		if c == nil {
			return usageErr("cite: unknown check %q (see openvapt checks)", checkID)
		}
		out, err = work.PageFormat(cite.CheckPage(c.ID, c.Title), format)
	case moduleID != "":
		m := academy.Get(strings.ToUpper(moduleID))
		if m == nil {
			return usageErr("cite: unknown module %q (see openvapt learn)", moduleID)
		}
		out, err = work.PageFormat(cite.ModulePage(m.ID, m.Title), format)
	default:
		out, err = work.Format(format)
	}
	if err != nil {
		return usageErr("cite: %v", err)
	}
	fmt.Fprintln(w, out)
	if work.Version == cite.Unreleased {
		c := version.Commit
		if c == "" || c == "unknown" {
			c = "you built from (git rev-parse HEAD)"
		}
		fmt.Fprintf(note, "Note: this is an %s made from source, not a release; add the commit %s to your citation.\n", cite.Unreleased, c)
	}
	return nil
}
