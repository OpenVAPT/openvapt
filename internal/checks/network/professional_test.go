package network

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func TestNewConfigCheckTreatsPartialSecureInputAsIncomplete(t *testing.T) {
	c := check.Get("NET-DB-002")
	f := &sys.Fake{Files: map[string]string{"/etc/redis/redis.conf": "bind 127.0.0.1\nprotected-mode yes\nuser app on >redacted ~* +@all\n"}, IncompleteFiles: map[string]bool{"/etc/redis/redis.conf": true}}
	r := c.Run(context.Background(), f)
	if len(r) != 1 || r[0].Status != check.Incomplete {
		t.Fatalf("expected incomplete, got %+v", r)
	}
}

func TestNewChecksHaveProfessionalMetadata(t *testing.T) {
	newIDs := map[string]bool{"NET-DB-002": true, "NET-DB-003": true, "NET-DB-004": true, "NET-DB-005": true, "NET-DB-006": true, "NET-DB-007": true, "NET-DB-008": true, "NET-DB-009": true, "NET-DB-010": true, "NET-DB-011": true, "NET-DB-012": true, "NET-DB-013": true, "NET-SVC-002": true, "NET-SVC-004": true, "NET-APP-001": true, "NET-APP-002": true, "NET-FW-002": true, "NET-SVC-003": true, "NET-TLS-004": true, "NET-TLS-005": true, "NET-TLS-006": true}
	for _, c := range check.All() {
		if !newIDs[c.ID] {
			continue
		}
		if c.Category == "" || c.Effort == "" || len(c.Standards.CWE) == 0 || len(c.Refs) == 0 || c.Refs[0].URL == "" {
			t.Errorf("%s has incomplete metadata", c.ID)
		}
	}
}
