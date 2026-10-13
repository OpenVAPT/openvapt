package sources

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	_ "github.com/openvapt/openvapt/internal/checks/all"
)

var update = flag.Bool("update", false, "rewrite SOURCES.md")

const sourcesFile = "../../SOURCES.md"

func TestEveryHostHasPublisher(t *testing.T) {
	for _, c := range Collect() {
		if c.Title == "" {
			t.Errorf("%s: reference has no title (%v)", c.URL, c.UsedBy)
		}
		if h := Host(c.URL); PublisherFor(h) == nil {
			t.Errorf("%q (cited by %v) has no publisher entry in internal/sources; add one with its terms", h, c.UsedBy)
		}
	}
}

func TestHostsAreUnique(t *testing.T) {
	seen := map[string]string{}
	for _, p := range Publishers {
		for _, h := range p.Hosts {
			if prev, ok := seen[h]; ok {
				t.Errorf("host %s is in both %q and %q", h, prev, p.Name)
			}
			seen[h] = p.Name
		}
	}
}

func TestSourcesFileIsCurrent(t *testing.T) {
	want := Markdown(Collect())
	if *update {
		if err := os.WriteFile(sourcesFile, []byte(want), 0o600); err != nil { // #nosec G306 -- repository document, not secret
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(sourcesFile)
	if err != nil || string(got) != want {
		t.Fatal("SOURCES.md is missing or stale; run: go test ./internal/sources -update")
	}
}

// TestCitationVersionIsCurrent keeps CITATION.cff pointing at the most
// advanced published release, so academic citations name a real version.
func TestCitationVersionIsCurrent(t *testing.T) {
	b, err := os.ReadFile("../../release/channels.json")
	if err != nil {
		t.Fatal(err)
	}
	var ch struct {
		Current map[string]struct{ Version string } `json:"current"`
	}
	if err := json.Unmarshal(b, &ch); err != nil {
		t.Fatal(err)
	}
	want := ""
	for _, name := range []string{"stable", "rc", "beta", "alpha"} {
		if c, ok := ch.Current[name]; ok {
			want = strings.TrimPrefix(c.Version, "v")
			break
		}
	}
	if want == "" {
		t.Skip("no published release yet")
	}
	cff, err := os.ReadFile("../../CITATION.cff")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cff), "\nversion: \""+want+"\"\n") {
		t.Fatalf("CITATION.cff version must be %q (latest published release in release/channels.json)", want)
	}
}
