package collect

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/sys"
)

func TestRPMSource(t *testing.T) {
	for in, want := range map[string][2]string{
		"openssh-8.7p1-38.el9.src.rpm":         {"openssh", "8.7p1-38.el9"},
		"java-17-openjdk-17.0.9-1.el9.src.rpm": {"java-17-openjdk", "17.0.9-1.el9"},
		"(none)":                               {"", ""},
		"bad.src.rpm":                          {"", ""},
	} {
		if n, v := rpmSource(in); n != want[0] || v != want[1] {
			t.Errorf("%s: got %q %q", in, n, v)
		}
	}
}

func TestRPMSubpackagesUseSourceVersion(t *testing.T) {
	items := []Installed{
		{Package: "perl-interpreter", Version: "4:5.32.1-481.el9", Source: "perl", SourceVersion: "5.32.1-481.el9"},
		{Package: "perl-Carp", Version: "0:1.50-460.el9", Source: "perl", SourceVersion: "5.32.1-481.el9"},
		{Package: "orphan-sub", Version: "0:1.0-1.el9", Source: "orphan", SourceVersion: "9.9-1.el9"},
	}
	resolveRPMSources(items)
	if n := items[1].Names(); len(n) != 2 || n[1] != [2]string{"perl", "4:5.32.1-481.el9"} {
		t.Errorf("perl-Carp must compare at the source version: %v", n)
	}
	if n := items[2].Names(); len(n) != 1 {
		t.Errorf("no sibling means no source match: %v", n)
	}
}

func TestDpkgSourceParsing(t *testing.T) {
	s := &sys.Fake{Files: map[string]string{}}
	s.Files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"12\"\n"
	s.Files["/var/lib/dpkg/status"] = "Package: foo\nStatus: install ok installed\nSource: foo-src (1-2)\nVersion: 1-2+b1\n\n" +
		"Package: linux-image-amd64\nStatus: install ok installed\nSource: linux-signed-amd64 (6.1.76+1)\nVersion: 6.1.76-1\n\n" +
		"Package: sudo\nStatus: install ok installed\nVersion: 1.9\n\n"
	items, ok := HostInventory(context.Background(), s)
	if !ok || len(items) != 3 {
		t.Fatalf("%v %v", ok, items)
	}
	want := [][2]string{{"foo-src", "1-2"}, {"linux", "6.1.76-1"}, {"sudo", "1.9"}}
	for n, i := range items {
		if got := i.Names(); len(got) != 1 || got[0] != want[n] {
			t.Errorf("%s: got %v, want %v", i.Package, got, want[n])
		}
	}
}

func TestUnsignedKernel(t *testing.T) {
	for in, want := range map[string]string{"linux-signed": "linux", "linux-signed-amd64": "linux", "linux-signed-hwe-5.15": "linux-hwe-5.15", "linux-signed-aws": "linux-aws"} {
		if got, ok := unsignedKernel(in); !ok || got != want {
			t.Errorf("%s: got %q", in, got)
		}
	}
	if _, ok := unsignedKernel("openssh"); ok {
		t.Error("only signed kernels map")
	}
}

func TestApkAndAlpineEcosystem(t *testing.T) {
	if e := Ecosystem(map[string]string{"ID": "alpine", "VERSION_ID": "3.20.3"}); e != "Alpine:v3.20" {
		t.Errorf("%s", e)
	}
	got := parseApkInstalled("P:libcrypto3\nV:3.3.1-r0\no:openssl\n\nP:musl\nV:1.2.5-r0\n", "Alpine:v3.20", "x")
	if len(got) != 2 || got[0].Names()[0] != [2]string{"openssl", "3.3.1-r0"} || got[1].Names()[0] != [2]string{"musl", "1.2.5-r0"} {
		t.Errorf("%+v", got)
	}
}

func TestLockfilesOutsideDocRoots(t *testing.T) {
	s := &sys.Fake{Files: map[string]string{"/srv/app/requirements.txt": "flask==2.0.1\n"}, Infos: map[string]sys.FileInfo{
		"/srv":                      {Path: "/srv", IsDir: true},
		"/srv/app/requirements.txt": {Path: "/srv/app/requirements.txt", Mode: 0o644},
	}}
	got, ok := WebInventory(context.Background(), s)
	if !ok || len(got) != 1 || got[0].Package != "flask" {
		t.Fatalf("%v %+v", ok, got)
	}
}

func TestLayerInventory(t *testing.T) {
	base := "/var/lib/docker/overlay2/"
	s := &sys.Fake{Files: map[string]string{
		base + "aaaaaaaaaaaaaaaa/diff/etc/os-release":      "ID=debian\nVERSION_ID=\"12\"\n",
		base + "bbbbbbbbbbbbbbbb/diff/var/lib/dpkg/status": "Package: sudo\nStatus: install ok installed\nVersion: 1.9\n",
	}, Infos: map[string]sys.FileInfo{}}
	got, found, complete := LayerInventory(context.Background(), s)
	if !found || !complete || len(got) != 1 || got[0].Ecosystem != "Debian:12" || got[0].Layer != "bbbbbbbbbbbb" {
		t.Fatalf("%v %v %+v", found, complete, got)
	}
}

func TestPartialWalkKeepsItems(t *testing.T) {
	s := &sys.Fake{Files: map[string]string{"/opt/a/requirements.txt": "flask==2.0.1\n"}, IncompleteWalks: map[string]bool{"/opt": true}, Infos: map[string]sys.FileInfo{
		"/opt":                    {Path: "/opt", IsDir: true},
		"/opt/a/requirements.txt": {Path: "/opt/a/requirements.txt", Mode: 0o644},
	}}
	got, ok := WebInventory(context.Background(), s)
	if ok || len(got) != 1 {
		t.Fatalf("%v %+v", ok, got)
	}
}

func TestAlpineEdgeHasNoEcosystem(t *testing.T) {
	if e := Ecosystem(map[string]string{"ID": "alpine", "VERSION_ID": "3.23_alpha20250101"}); e != "" {
		t.Errorf("%s", e)
	}
}
