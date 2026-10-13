package engine

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
	"github.com/openvapt/openvapt/internal/lab"
)

// Every check must fire on the vulnerable lab server...
func TestEveryCheckFiresOnVulnerableLab(t *testing.T) {
	r := Run(context.Background(), lab.Vulnerable(), Options{})
	for _, f := range r.Findings {
		if f.Severity == string(check.Info) {
			continue
		}
		if f.Status != string(check.Fail) {
			t.Errorf("%s (%s) should FAIL on the vulnerable lab, got %s: %+v", f.ID, f.Title, f.Status, f.Results)
		}
	}
}

// ...and none may fire once the fixes are applied (no false positives).
func TestNoCheckFiresOnHardenedLab(t *testing.T) {
	r := Run(context.Background(), lab.Hardened(), Options{})
	for _, f := range r.Findings {
		if f.Status == string(check.Fail) || f.Status == string(check.Error) {
			t.Errorf("%s (%s) should not fail on the hardened lab, got %s: %+v", f.ID, f.Title, f.Status, f.Results)
		}
	}
}

// These checks have hardened fixtures, so they must reach a real Pass rather
// than Skip on the hardened lab.
func TestHardenedLabPassesNotSkips(t *testing.T) {
	want := map[string]bool{"HOST-DKR-001": true, "NET-FW-002": true, "NET-SVC-003": true, "WEB-CMS-009": true}
	r := Run(context.Background(), lab.Hardened(), Options{})
	for _, f := range r.Findings {
		if want[f.ID] {
			delete(want, f.ID)
			if f.Status != string(check.Pass) {
				t.Errorf("%s should pass on the hardened lab, got %s: %+v", f.ID, f.Status, f.Results)
			}
		}
	}
	for id := range want {
		t.Errorf("%s was not run", id)
	}
}

func TestEveryCheckIsDocumented(t *testing.T) {
	for _, c := range check.All() {
		if c.Summary == "" || c.Detection == "" || c.Verify == "" || c.CVSS == "" || c.SourceFile == "" {
			t.Errorf("%s is missing documentation fields", c.ID)
		}
	}
	if n := len(check.All()); n < 50 {
		t.Errorf("expected at least 50 checks, have %d", n)
	}
}

func TestSecretsNeverReachTheReport(t *testing.T) {
	r := Run(context.Background(), lab.Vulnerable(), Options{})
	b, _ := r.JSON()
	for _, secret := range []string{"hunter2", "hashedvalue"} {
		if contains(string(b), secret) {
			t.Errorf("secret %q leaked into the report", secret)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
