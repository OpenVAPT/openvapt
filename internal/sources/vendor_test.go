package sources

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const assets = "../../site/static/assets/"

// TestVendoredFilesAreCited keeps CREDITS.md section 3a true: every
// third-party file the website serves must be listed with its exact SHA-256,
// and every library must ship its licence text.
func TestVendoredFilesAreCited(t *testing.T) {
	credits, err := os.ReadFile("../../CREDITS.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(credits)
	var files []string
	for _, dir := range []string{"vendor", "fonts"} {
		es, err := os.ReadDir(assets + dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if !e.IsDir() && e.Name() != "VERSIONS.txt" {
				files = append(files, dir+"/"+e.Name())
			}
		}
	}
	// site.css is excluded: it is mostly OpenVAPT's own styles and changes
	// with every template edit; CREDITS.md cites it without a fixed hash.
	for _, f := range files {
		b, err := os.ReadFile(filepath.Clean(assets + f))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if !strings.Contains(text, hex.EncodeToString(sum[:])) {
			t.Errorf("assets/%s: SHA-256 %x is not in CREDITS.md section 3a; update the inventory after re-vendoring or rebuilding CSS", f, sum)
		}
	}
	for _, lic := range []string{"ag-grid-community", "echarts", "echarts-NOTICE", "zrender", "d3", "lucide", "ibm-plex", "tailwindcss"} {
		if _, err := os.Stat(assets + "vendor/LICENSES/" + lic + ".txt"); err != nil {
			t.Errorf("licence text %s.txt is missing from assets/vendor/LICENSES", lic)
		}
	}
	// Every version in VERSIONS.txt must be the one CREDITS.md names.
	v, err := os.ReadFile(assets + "vendor/VERSIONS.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(v)), "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		if !strings.Contains(text, parts[1]) {
			t.Errorf("%s %s from VERSIONS.txt is not named in CREDITS.md", parts[0], parts[1])
		}
	}
}
