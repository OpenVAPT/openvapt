// Command vulndbgen builds an offline release snapshot. It is never used by scans.
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/vulndb"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	out := flag.String("out", "internal/vulndb/data/snapshot.json.gz", "snapshot path")
	ecos := flag.String("ecosystems", "Debian:12,Ubuntu:24.04:LTS,AlmaLinux:9,Rocky Linux:9,Packagist,npm", "OSV ecosystems")
	packages := flag.String("packages", "docs/vulndb-packages.txt", "one package per line")
	flag.Parse()
	b, e := os.ReadFile(*packages)
	if e != nil {
		panic(e)
	}
	allow := map[string]bool{}
	for _, p := range strings.Split(string(b), "\n") {
		p = strings.TrimSpace(strings.SplitN(p, "#", 2)[0])
		if p != "" {
			allow[p] = true
		}
	}
	s, e := build(strings.Split(*ecos, ","), allow, fetch)
	if e != nil {
		panic(e)
	}
	f, e := os.Create(*out)
	if e != nil {
		panic(e)
	}
	defer f.Close()
	z := gzip.NewWriter(f)
	if e = json.NewEncoder(z).Encode(s); e != nil {
		panic(e)
	}
	if e = z.Close(); e != nil {
		panic(e)
	}
	fmt.Printf("Snapshot %s: %d advisories, %d affected entries\n", s.Header.Generated, s.Header.Counts.Advisories, s.Header.Counts.Affected)
}
func fetch(url string) ([]byte, error) {
	c := http.Client{Timeout: 2 * time.Minute}
	r, e := c.Get(url)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d", url, r.StatusCode)
	}
	return io.ReadAll(io.LimitReader(r.Body, 256<<20))
}
func build(ecos []string, allow map[string]bool, get func(string) ([]byte, error)) (vulndb.Snapshot, error) {
	s := vulndb.Snapshot{Header: vulndb.Header{Schema: 1, Generated: time.Now().UTC().Format("2006-01-02"), Sources: []vulndb.Source{{Name: "OSV ecosystem exports", URL: "https://osv-vulnerabilities.storage.googleapis.com/", Licence: "check source"}, {Name: "CISA KEV", URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", Licence: "check source"}}}}
	kevData, e := get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if e != nil {
		return s, e
	}
	var feed struct{ Vulnerabilities []struct{ CveID string } }
	if e = json.Unmarshal(kevData, &feed); e != nil {
		return s, e
	}
	kev := map[string]bool{}
	for _, v := range feed.Vulnerabilities {
		kev[v.CveID] = true
	}
	seen := map[string]*vulndb.Advisory{}
	exports := map[string][]byte{}
	for _, eco := range ecos {
		eco = strings.TrimSpace(eco)
		if eco == "" {
			continue
		}
		b, e := export(eco, get, exports)
		if e != nil {
			return s, e
		}
		zr, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if e != nil {
			return s, e
		}
		for _, file := range zr.File {
			if !strings.HasSuffix(file.Name, ".json") {
				continue
			}
			r, e := file.Open()
			if e != nil {
				return s, e
			}
			data, e := io.ReadAll(io.LimitReader(r, 4<<20))
			if ce := r.Close(); e == nil {
				e = ce
			}
			if e != nil {
				return s, e
			}
			var raw struct {
				ID         string
				Aliases    []string
				Summary    string
				Published  string
				Modified   string
				References []struct{ URL string }
				Severity   []struct{ Type, Score string }
				Affected   []struct {
					Package  struct{ Name, Ecosystem string }
					Ranges   []vulndb.Range
					Versions []string
				}
			}
			if json.Unmarshal(data, &raw) != nil {
				continue
			}
			isKEV := false
			for _, a := range raw.Aliases {
				isKEV = isKEV || kev[a]
			}
			sev := ""
			score := 0.0
			vector := ""
			for _, v := range raw.Severity {
				if strings.HasPrefix(v.Score, "CVSS:3") {
					score, _ = check.BaseScore(v.Score)
					vector = v.Score
					break
				} else if n, e := strconv.ParseFloat(v.Score, 64); e == nil {
					score = n
				}
			}
			if score >= 9 {
				sev = "critical"
			} else if score >= 7 {
				sev = "high"
			}
			if sev == "" && !isKEV {
				continue
			}
			var affected []vulndb.Affected
			for _, a := range raw.Affected {
				if allow[a.Package.Name] && a.Package.Ecosystem == eco {
					affected = append(affected, vulndb.Affected{Ecosystem: eco, Package: a.Package.Name, Ranges: a.Ranges, Versions: a.Versions})
				}
			}
			if len(affected) == 0 {
				continue
			}
			if old := seen[raw.ID]; old != nil {
				old.Affected = append(old.Affected, affected...)
				continue
			}
			a := vulndb.Advisory{ID: raw.ID, Aliases: raw.Aliases, Summary: raw.Summary, Severity: sev, CVSSScore: score, CVSSVector: vector, Published: raw.Published, Modified: raw.Modified, KEV: isKEV, Affected: affected}
			for _, r := range raw.References {
				a.References = append(a.References, r.URL)
			}
			seen[a.ID] = &a
		}
	}
	for _, a := range seen {
		s.Advisories = append(s.Advisories, *a)
		s.Header.Counts.Affected += len(a.Affected)
	}
	sort.Slice(s.Advisories, func(i, j int) bool { return s.Advisories[i].ID < s.Advisories[j].ID })
	s.Header.Counts.Advisories = len(s.Advisories)
	return s, nil
}

// export downloads the OSV export that holds an ecosystem's records. OSV
// publishes some release-specific ecosystems (Debian:12, Ubuntu:24.04:LTS)
// as their own export, and others (AlmaLinux:8, Rocky Linux:9) only inside
// the parent export (AlmaLinux, Rocky Linux), so a 404 falls back to the
// parent. Records are filtered by their own ecosystem afterwards, so the
// fallback never mixes releases. Each export is downloaded once.
func export(eco string, get func(string) ([]byte, error), cache map[string][]byte) ([]byte, error) {
	const bucket = "https://osv-vulnerabilities.storage.googleapis.com/"
	names := []string{eco}
	if parent, _, ok := strings.Cut(eco, ":"); ok {
		names = append(names, parent)
	}
	var lastErr error
	for _, n := range names {
		if b, ok := cache[n]; ok {
			return b, nil
		}
		b, e := get(bucket + url.PathEscape(n) + "/all.zip")
		if e == nil {
			cache[n] = b
			return b, nil
		}
		lastErr = e
		if !strings.Contains(e.Error(), "HTTP 404") {
			break
		}
	}
	return nil, lastErr
}
