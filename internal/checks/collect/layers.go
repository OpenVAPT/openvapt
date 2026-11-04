package collect

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

const (
	layerBase = "/var/lib/docker/overlay2"
	maxLayers = 300
)

// LayerInventory lists packages from the dpkg and apk databases inside Docker
// overlay2 image layers. Layer files come from images, so a final symbolic link
// is refused and they are used only as package lists. found is false when
// no layer holds a package database. complete is false when a layer could not
// be read or its distribution could not be told.
func LayerInventory(ctx context.Context, s sys.System) (items []Installed, found, complete bool) {
	dpkg, _ := s.Glob(layerBase + "/*/diff/var/lib/dpkg/status")
	apk, _ := s.Glob(layerBase + "/*/diff/lib/apk/db/installed")
	paths := append(dpkg, apk...)
	sort.Strings(paths)
	if len(paths) == 0 {
		return nil, false, true
	}
	complete = true
	if len(paths) > maxLayers {
		paths, complete = paths[:maxLayers], false
	}
	byLayer := layerEcosystems(ctx, s)
	only := ""
	for _, e := range byLayer {
		if only != "" && only != e {
			only = ""
			break
		}
		only = e
	}
	for _, p := range paths {
		id := layerID(p)
		eco := byLayer[id]
		if eco == "" {
			eco = only // upper layers rarely hold os-release
		}
		r, e := sys.ReadFileNoFollow(ctx, s, p)
		if eco == "" || e != nil || !r.Complete {
			complete = false
			continue
		}
		var got []Installed
		if strings.HasSuffix(p, "installed") {
			got = parseApkInstalled(string(r.Data), eco, "image layer")
		} else {
			got = parseDpkgStatus(string(r.Data), eco, "image layer")
		}
		for i := range got {
			got[i].Layer = id[:min(12, len(id))]
		}
		items = append(items, got...)
	}
	return items, true, complete
}

func layerID(path string) string {
	rest := strings.TrimPrefix(path, layerBase+"/")
	id, _, _ := strings.Cut(rest, "/")
	return id
}

func layerEcosystems(ctx context.Context, s sys.System) map[string]string {
	out := map[string]string{}
	for _, pat := range []string{"/*/diff/etc/os-release", "/*/diff/usr/lib/os-release"} {
		files, _ := s.Glob(filepath.Join(layerBase, pat))
		for _, f := range files {
			r, e := sys.ReadFileNoFollow(ctx, s, f)
			if e != nil {
				continue
			}
			m := map[string]string{}
			for _, line := range strings.Split(string(r.Data), "\n") {
				if k, v, ok := strings.Cut(line, "="); ok {
					m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
				}
			}
			if eco := Ecosystem(m); eco != "" {
				out[layerID(f)] = eco
			}
		}
	}
	return out
}
