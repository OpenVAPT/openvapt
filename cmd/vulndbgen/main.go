// Command vulndbgen builds an offline release snapshot. It is never used by scans.
package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/openvapt/openvapt/internal/vulndb"
	"io"
	"math"
	"net/http"
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
	for _, eco := range ecos {
		eco = strings.TrimSpace(eco)
		if eco == "" {
			continue
		}
		url := "https://osv-vulnerabilities.storage.googleapis.com/" + eco + "/all.zip"
		b, e := get(url)
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
					score = cvss3(v.Score)
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

// cvss3 computes the CVSS v3 base score from an OSV severity vector.
func cvss3(vector string) float64 {
	m := map[string]string{}
	for _, p := range strings.Split(vector, "/") {
		k, v, ok := strings.Cut(p, ":")
		if ok {
			m[k] = v
		}
	}
	av := map[string]float64{"N": .85, "A": .62, "L": .55, "P": .2}[m["AV"]]
	ac := map[string]float64{"L": .77, "H": .44}[m["AC"]]
	ui := map[string]float64{"N": .85, "R": .62}[m["UI"]]
	pr := map[string]float64{"N": .85, "L": .62, "H": .27}[m["PR"]]
	if m["S"] == "C" {
		pr = map[string]float64{"N": .85, "L": .68, "H": .5}[m["PR"]]
	}
	impactMetric := func(x string) float64 { return map[string]float64{"N": 0, "L": .22, "H": .56}[x] }
	isc := 1 - (1-impactMetric(m["C"]))*(1-impactMetric(m["I"]))*(1-impactMetric(m["A"]))
	impact := 6.42 * isc
	if m["S"] == "C" {
		impact = 7.52*(isc-.029) - 3.25*math.Pow(isc-.02, 15)
	}
	if impact <= 0 {
		return 0
	}
	exploit := 8.22 * av * ac * pr * ui
	score := math.Min(impact+exploit, 10)
	if m["S"] == "C" {
		score = math.Min(1.08*(impact+exploit), 10)
	}
	return math.Ceil(score*10) / 10
}
