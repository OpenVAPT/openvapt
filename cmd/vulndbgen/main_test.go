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
