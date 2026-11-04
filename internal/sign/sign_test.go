package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/openvapt/openvapt/internal/report"
)

func TestSignVerifyAndTamper(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := &report.Report{Schema: report.SchemaVersion, Findings: []report.Finding{{ID: "X-1", Status: "fail", Severity: "high"}}}
	r.Summarise()
	if err := Sign(r, priv); err != nil {
		t.Fatal(err)
	}
	if err := Verify(r, ""); err != nil {
		t.Fatalf("fresh report should verify: %v", err)
	}
	if err := Verify(r, "0000000000000000"); err == nil {
		t.Fatal("wrong key id must fail")
	}
	r.Findings[0].Status = "pass" // tamper: hide a finding
	if err := Verify(r, ""); err == nil {
		t.Fatal("tampered report must fail verification")
	}
}
