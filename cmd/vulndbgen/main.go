// Command vulndbgen builds an offline release snapshot. It is never used by scans.
package main

import (
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/vulndb"
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

// Limits on what one release build will accept from the public feeds. They
// are far above today's sizes and exist so a hostile or broken mirror fails
// the build loudly instead of exhausting the runner or shrinking the data.
const (
	maxDownload      = 1 << 30   // bytes per downloaded file
	maxEntry         = 4 << 20   // uncompressed bytes per OSV record
	maxEntries       = 2_000_000 // OSV records per export
	maxUncompressed  = 8 << 30   // uncompressed bytes per export
	maxParseFailures = 0.01      // fraction of records that may fail to parse
)

var client = &http.Client{
	Timeout: 15 * time.Minute,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-https URL %s", req.URL.Redacted())
		}
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// fetch streams url into a new temporary file and returns its path. The
// caller removes it. It refuses anything that is not https, any answer other
// than 200, and any body larger than maxDownload, whether announced by
// Content-Length or discovered while copying.
func fetch(u string) (string, error) {
	if !strings.HasPrefix(u, "https://") {
		return "", fmt.Errorf("refusing non-https URL %s", u)
	}
	r, e := client.Get(u)
	if e != nil {
		return "", e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("%s: HTTP %d", u, r.StatusCode)
	}
	if r.ContentLength > maxDownload {
		return "", fmt.Errorf("%s: %d bytes exceeds the %d byte limit", u, r.ContentLength, maxDownload)
	}
	f, e := os.CreateTemp("", "vulndbgen-*")
	if e != nil {
		return "", e
	}
	n, e := io.Copy(f, io.LimitReader(r.Body, maxDownload+1))
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e == nil && n > maxDownload {
		e = fmt.Errorf("%s: body exceeds the %d byte limit", u, maxDownload)
	}
	if e != nil {
		os.Remove(f.Name())
		return "", e
	}
	return f.Name(), nil
}

type osvRecord struct {
	ID         string
	Aliases    []string
	Upstream   []string
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

// severity rates a record. A CVSS v3 vector wins; otherwise a CVSS v4
// vector is rated conservatively (see cvss4Severity); otherwise an Ubuntu
// priority word; otherwise a bare numeric score. Only CVSS v3 sets a score
// and vector, because the snapshot's score fields are CVSS v3.
func severity(r osvRecord) (sev string, score float64, vector string) {
	v4, word := "", ""
	for _, v := range r.Severity {
		switch {
		case strings.HasPrefix(v.Score, "CVSS:3"):
			if n, e := check.BaseScore(v.Score); e == nil {
				return bucket(n), n, v.Score
			}
		case strings.HasPrefix(v.Score, "CVSS:4"):
			v4 = v.Score
		case strings.EqualFold(v.Type, "Ubuntu"):
			word = strings.ToLower(strings.TrimSpace(v.Score))
		default:
			if n, e := strconv.ParseFloat(v.Score, 64); e == nil && n > score {
				score = n
			}
		}
	}
	if v4 != "" {
		return cvss4Severity(v4), 0, ""
	}
	switch word {
	case "critical", "high":
		return word, 0, ""
	case "medium", "low", "negligible":
		return "", 0, ""
	}
	return bucket(score), score, ""
}

func bucket(n float64) string {
	switch {
	case n >= 9:
		return "critical"
	case n >= 7:
		return "high"
	}
	return ""
}

// cvss4Severity rates a CVSS v4.0 base vector without the official
// macrovector lookup table, rounding up so nothing is under-rated: critical
// when the flaw is reachable over the network with no attack requirements,
// privileges or user interaction and has a High impact on the vulnerable
// system; high when any vulnerable or subsequent system impact is High;
// otherwise not included. An unparsable vector is rated high so it is kept
// for review rather than silently dropped.
func cvss4Severity(vector string) string {
	m := map[string]string{}
	parts := strings.Split(vector, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CVSS:4") {
		return "high"
	}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return "high"
		}
		m[k] = v
	}
	for _, k := range []string{"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"} {
		if m[k] == "" {
			return "high"
		}
	}
	vulnHigh := m["VC"] == "H" || m["VI"] == "H" || m["VA"] == "H"
	subHigh := m["SC"] == "H" || m["SI"] == "H" || m["SA"] == "H"
	if vulnHigh && m["AV"] == "N" && m["AC"] == "L" && m["AT"] == "N" && m["PR"] == "N" && m["UI"] == "N" {
		return "critical"
	}
	if vulnHigh || subHigh {
		return "high"
	}
	return ""
}

func isKEV(r osvRecord, kev map[string]bool) bool {
	if kev[r.ID] {
		return true
	}
	for _, list := range [][]string{r.Aliases, r.Upstream} {
		for _, a := range list {
			if kev[a] {
				return true
			}
		}
	}
	return false
}

func build(ecos []string, allow map[string]bool, get func(string) (string, error)) (vulndb.Snapshot, error) {
	s := vulndb.Snapshot{Header: vulndb.Header{Schema: 1, Generated: time.Now().UTC().Format("2006-01-02"), Sources: []vulndb.Source{{Name: "OSV ecosystem exports", URL: "https://osv-vulnerabilities.storage.googleapis.com/", Licence: "check source"}, {Name: "CISA KEV", URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", Licence: "check source"}}}}
	kevPath, e := get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if e != nil {
		return s, e
	}
	kevData, e := os.ReadFile(kevPath) // #nosec G304 -- temporary file created by fetch
	os.Remove(kevPath)
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
	// One ecosystem at a time: each export is streamed to a temporary file
	// and read from disk. Only the most recent export is kept, so releases
	// that share a parent export (Rocky Linux:9, Rocky Linux:8) reuse one
	// download when listed next to each other, and disk holds at most one.
	cur := &oneFile{}
	defer cur.drop()
	sorted := make([]string, 0, len(ecos))
	for _, eco := range ecos {
		if eco = strings.TrimSpace(eco); eco != "" {
			sorted = append(sorted, eco)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool { return parentOf(sorted[i]) < parentOf(sorted[j]) })
	for _, eco := range sorted {
		if e := buildEco(eco, allow, kev, seen, get, cur); e != nil {
			return s, e
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

// oneFile remembers the single export currently on disk.
type oneFile struct{ name, path string }

func (f *oneFile) drop() {
	if f.path != "" {
		os.Remove(f.path)
	}
	*f = oneFile{}
}

func parentOf(eco string) string {
	p, _, _ := strings.Cut(eco, ":")
	return p
}

func buildEco(eco string, allow, kev map[string]bool, seen map[string]*vulndb.Advisory, get func(string) (string, error), cur *oneFile) error {
	path, e := export(eco, get, cur)
	if e != nil {
		return e
	}
	zr, e := zip.OpenReader(path)
	if e != nil {
		return fmt.Errorf("%s: %w", eco, e)
	}
	defer zr.Close()
	var records, failed int
	var total int64
	for _, file := range zr.File {
		if !strings.HasSuffix(file.Name, ".json") {
			continue
		}
		records++
		if records > maxEntries {
			return fmt.Errorf("%s: more than %d records", eco, maxEntries)
		}
		if file.UncompressedSize64 > maxEntry {
			return fmt.Errorf("%s: %s is %d bytes, over the %d byte record limit", eco, file.Name, file.UncompressedSize64, maxEntry)
		}
		r, e := file.Open()
		if e != nil {
			return e
		}
		data, e := io.ReadAll(io.LimitReader(r, maxEntry+1))
		if ce := r.Close(); e == nil {
			e = ce
		}
		if e != nil {
			return fmt.Errorf("%s: %s: %w", eco, file.Name, e)
		}
		if len(data) > maxEntry {
			return fmt.Errorf("%s: %s is over the %d byte record limit", eco, file.Name, maxEntry)
		}
		if total += int64(len(data)); total > maxUncompressed {
			return fmt.Errorf("%s: more than %d uncompressed bytes", eco, int64(maxUncompressed))
		}
		var raw osvRecord
		if json.Unmarshal(data, &raw) != nil || raw.ID == "" {
			failed++
			continue
		}
		add(raw, eco, allow, kev, seen)
	}
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "vulndbgen: %s: %d of %d records failed to parse\n", eco, failed, records)
	}
	if records > 0 && float64(failed)/float64(records) > maxParseFailures {
		return fmt.Errorf("%s: %d of %d records failed to parse, over the %.0f%% limit", eco, failed, records, maxParseFailures*100)
	}
	return nil
}

func add(raw osvRecord, eco string, allow, kev map[string]bool, seen map[string]*vulndb.Advisory) {
	inKEV := isKEV(raw, kev)
	sev, score, vector := severity(raw)
	if sev == "" && !inKEV {
		return
	}
	var affected []vulndb.Affected
	for _, a := range raw.Affected {
		if allow[a.Package.Name] && a.Package.Ecosystem == eco {
			affected = append(affected, vulndb.Affected{Ecosystem: eco, Package: a.Package.Name, Ranges: a.Ranges, Versions: a.Versions})
		}
	}
	if len(affected) == 0 {
		return
	}
	if old := seen[raw.ID]; old != nil {
		old.Affected = append(old.Affected, affected...)
		return
	}
	a := vulndb.Advisory{ID: raw.ID, Aliases: raw.Aliases, Summary: raw.Summary, Severity: sev, CVSSScore: score, CVSSVector: vector, Published: raw.Published, Modified: raw.Modified, KEV: inKEV, Affected: affected}
	for _, r := range raw.References {
		a.References = append(a.References, r.URL)
	}
	seen[a.ID] = &a
}

// export downloads the OSV export that holds an ecosystem's records to a
// temporary file. OSV publishes some release-specific ecosystems (Debian:12,
// Ubuntu:24.04:LTS) as their own export, and others (AlmaLinux:8, Rocky
// Linux:9) only inside the parent export (AlmaLinux, Rocky Linux), so a 404
// falls back to the parent. Records are filtered by their own ecosystem
// afterwards, so the fallback never mixes releases. cur holds the one
// export kept on disk; a different export replaces it.
func export(eco string, get func(string) (string, error), cur *oneFile) (string, error) {
	const bucket = "https://osv-vulnerabilities.storage.googleapis.com/"
	names := []string{eco}
	if parent, _, ok := strings.Cut(eco, ":"); ok {
		names = append(names, parent)
	}
	var lastErr error
	for _, n := range names {
		if cur.path != "" && cur.name == n {
			return cur.path, nil
		}
		p, e := get(bucket + url.PathEscape(n) + "/all.zip")
		if e == nil {
			cur.drop()
			cur.name, cur.path = n, p
			return p, nil
		}
		lastErr = e
		if !strings.Contains(e.Error(), "HTTP 404") {
			break
		}
	}
	return "", lastErr
}
