package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseFormats(t *testing.T) {
	got, err := parseFormats(" JSON,html,json, md ,")
	if err != nil || !reflect.DeepEqual(got, []string{"json", "html", "md"}) {
		t.Fatalf("got %v %v", got, err)
	}
	for _, bad := range []string{"pdf", "json,xml", "", " , "} {
		_, err := parseFormats(bad)
		var ee *exitError
		if !errors.As(err, &ee) || ee.code != 2 {
			t.Errorf("%q: want usage error exit 2, got %v", bad, err)
		}
	}
}

func TestPrepareLoadsBaselineFirst(t *testing.T) {
	f := scanFlags{formats: "json", baseline: filepath.Join(t.TempDir(), "missing.json")}
	err := f.prepare()
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != 2 || !strings.Contains(err.Error(), "baseline") {
		t.Fatalf("missing baseline must be a usage error before scanning, got %v", err)
	}
}

func TestDefaultOutDirIsPrivateAndTimestamped(t *testing.T) {
	wd, _ := os.Getwd()
	d := t.TempDir()
	if err := os.Chdir(d); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)
	a, err := defaultOutDir("openvapt-demo-report-")
	if err != nil {
		t.Fatal(err)
	}
	b, err := defaultOutDir("openvapt-demo-report-")
	if err != nil || a == b {
		t.Fatalf("each run needs its own folder: %s %s %v", a, b, err)
	}
	st, _ := os.Stat(a)
	if st.Mode().Perm() != 0o700 || !strings.HasPrefix(filepath.Base(a), "openvapt-demo-report-20") {
		t.Fatalf("bad folder %s %v", a, st.Mode().Perm())
	}
}
