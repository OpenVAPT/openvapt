package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// file writes b to a temporary file, as fetch would, and returns its path.
func file(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dl")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// getter serves the KEV feed and one Debian:12 export holding records.
func getter(t *testing.T, kev string, records ...map[string]any) func(string) (string, error) {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for i, r := range records {
		f, err := z.Create(fmt.Sprintf("r%d.json", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(f).Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	z.Close()
	return func(u string) (string, error) {
		switch u {
		case "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
			return file(t, []byte(kev)), nil
		case "https://osv-vulnerabilities.storage.googleapis.com/Debian:12/all.zip":
			return file(t, b.Bytes()), nil
		}
		return "", fmt.Errorf("%s: HTTP 404", u)
	}
}

func rec(id string, sev []map[string]string, extra map[string]any) map[string]any {
	r := map[string]any{"id": id, "severity": sev, "affected": []map[string]any{{"package": map[string]string{"name": "sudo", "ecosystem": "Debian:12"}}}}
	for k, v := range extra {
		r[k] = v
	}
	return r
}

const noKEV = `{"vulnerabilities":[]}`

// Debian records are DEBIAN-CVE-* and name the CVE only in "upstream".
func TestKEVMatchesUpstream(t *testing.T) {
	get := getter(t, `{"vulnerabilities":[{"cveID":"CVE-2021-3156"}]}`,
		rec("DEBIAN-CVE-2021-3156", nil, map[string]any{"upstream": []string{"CVE-2021-3156"}}))
	s, err := build([]string{"Debian:12"}, map[string]bool{"sudo": true}, get)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Advisories) != 1 || !s.Advisories[0].KEV {
		t.Fatalf("upstream CVE in KEV must mark the record KEV: %+v", s.Advisories)
	}
}

func TestSeverityV4AndUbuntu(t *testing.T) {
	cases := []struct {
		id   string
		sev  []map[string]string
		want string
	}{
		{"V4-CRIT", []map[string]string{{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}, "critical"},
		{"V4-HIGH", []map[string]string{{"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"}}, "high"},
		{"V4-LOW", []map[string]string{{"type": "CVSS_V4", "score": "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"}}, ""},
		{"V4-BROKEN", []map[string]string{{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}}, "high"},
		{"V3-WINS", []map[string]string{{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}}, "high"},
		{"UB-CRIT", []map[string]string{{"type": "Ubuntu", "score": "critical"}}, "critical"},
		{"UB-HIGH", []map[string]string{{"type": "Ubuntu", "score": "High"}}, "high"},
		{"UB-MED", []map[string]string{{"type": "Ubuntu", "score": "medium"}}, ""},
		{"UB-LOW", []map[string]string{{"type": "Ubuntu", "score": "low"}}, ""},
	}
	for _, c := range cases {
		var r osvRecord
		b, _ := json.Marshal(rec(c.id, c.sev, nil))
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := severity(r); got != c.want {
			t.Errorf("%s: got %q, want %q", c.id, got, c.want)
		}
	}
}

func TestOversizeEntryIsAnError(t *testing.T) {
	big := rec("BIG-1", nil, map[string]any{"summary": strings.Repeat("x", maxEntry)})
	if _, err := build([]string{"Debian:12"}, map[string]bool{"sudo": true}, getter(t, noKEV, big)); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected a record limit error, got %v", err)
	}
}

func TestParseFailureThreshold(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for i := 0; i < 10; i++ {
		f, _ := z.Create(fmt.Sprintf("r%d.json", i))
		body := `{"id":"OK-` + strconv.Itoa(i) + `"}`
		if i == 0 {
			body = "{not json"
		}
		_, _ = f.Write([]byte(body))
	}
	z.Close()
	get := func(u string) (string, error) {
		if strings.Contains(u, "cisa.gov") {
			return file(t, []byte(noKEV)), nil
		}
		return file(t, b.Bytes()), nil
	}
	if _, err := build([]string{"Debian:12"}, nil, get); err == nil || !strings.Contains(err.Error(), "failed to parse") {
		t.Fatalf("1 in 10 failing must exceed the limit, got %v", err)
	}
}

func TestFetchRefusesUnsafe(t *testing.T) {
	if _, err := fetch("http://example.invalid/x"); err == nil {
		t.Error("plain http accepted")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Length", strconv.FormatInt(maxDownload+1, 10))
			w.WriteHeader(200)
		case "/redirect":
			http.Redirect(w, r, "http://127.0.0.1:1/plain", http.StatusFound)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	old := client
	defer func() { client = old }()
	c := srv.Client()
	c.CheckRedirect = old.CheckRedirect
	client = c
	if _, err := fetch(srv.URL + "/big"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversized Content-Length accepted: %v", err)
	}
	if _, err := fetch(srv.URL + "/redirect"); err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Errorf("redirect to http accepted: %v", err)
	}
	p, err := fetch(srv.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(p)
	if b, _ := os.ReadFile(p); string(b) != "ok" {
		t.Errorf("got %q", b)
	}
}

func TestBuildLocalFeeds(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	f, e := z.Create("one.json")
	if e != nil {
		t.Fatal(e)
	}
	record := map[string]any{"id": "TEST-1", "aliases": []string{"CVE-2021-3156"}, "summary": "test", "severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}, "affected": []map[string]any{{"package": map[string]string{"name": "sudo", "ecosystem": "Debian:12"}, "ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "2.0"}}}}}}}
	if e = json.NewEncoder(f).Encode(record); e != nil {
		t.Fatal(e)
	}
	z.Close()
	get := func(url string) (string, error) {
		if url == "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" {
			return file(t, []byte("{\"vulnerabilities\":[{\"cveID\":\"CVE-2021-3156\"}]}")), nil
		}
		if url == "https://osv-vulnerabilities.storage.googleapis.com/Debian:12/all.zip" {
			return file(t, b.Bytes()), nil
		}
		return "", fmt.Errorf("unexpected URL %s", url)
	}
	s, e := build([]string{"Debian:12"}, map[string]bool{"sudo": true}, get)
	if e != nil {
		t.Fatal(e)
	}
	if s.Header.Fixture || s.Header.Counts.Advisories != 1 || !s.Advisories[0].KEV || s.Advisories[0].Severity != "critical" {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
}

// AlmaLinux:8 and Rocky Linux:9 records live in the parent export; the
// generator must fall back to it, escape the space, download it once and keep
// only the requested release's records.
func TestParentExportFallback(t *testing.T) {
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for i, eco := range []string{"Rocky Linux:9", "Rocky Linux:8"} {
		f, _ := z.Create(fmt.Sprintf("r%d.json", i))
		rec := map[string]any{"id": fmt.Sprintf("RLSA-%d", i), "severity": []map[string]string{{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
			"affected": []map[string]any{{"package": map[string]string{"name": "sudo", "ecosystem": eco}}}}
		_ = json.NewEncoder(f).Encode(rec)
	}
	z.Close()
	calls := map[string]int{}
	get := func(u string) (string, error) {
		calls[u]++
		switch u {
		case "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
			return file(t, []byte(`{"vulnerabilities":[]}`)), nil
		case "https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip":
			return file(t, b.Bytes()), nil
		}
		return "", fmt.Errorf("%s: HTTP 404", u)
	}
	s, e := build([]string{"Rocky Linux:9", "Rocky Linux:8"}, map[string]bool{"sudo": true}, get)
	if e != nil {
		t.Fatal(e)
	}
	if s.Header.Counts.Advisories != 2 || s.Header.Counts.Affected != 2 {
		t.Fatalf("each release must keep only its own record: %+v", s.Header.Counts)
	}
	if calls["https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip"] != 1 {
		t.Errorf("parent export downloaded %d times", calls["https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip"])
	}
}
