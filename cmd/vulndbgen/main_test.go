package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
)

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
	get := func(url string) ([]byte, error) {
		if url == "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" {
			return []byte("{\"vulnerabilities\":[{\"cveID\":\"CVE-2021-3156\"}]}"), nil
		}
		if url == "https://osv-vulnerabilities.storage.googleapis.com/Debian:12/all.zip" {
			return b.Bytes(), nil
		}
		return nil, fmt.Errorf("unexpected URL %s", url)
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
	get := func(u string) ([]byte, error) {
		calls[u]++
		switch u {
		case "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json":
			return []byte(`{"vulnerabilities":[]}`), nil
		case "https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/all.zip":
			return b.Bytes(), nil
		}
		return nil, fmt.Errorf("%s: HTTP 404", u)
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
