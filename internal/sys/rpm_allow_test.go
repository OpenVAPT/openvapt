package sys

import "testing"

func TestRPMExactAllowList(t *testing.T) {
	good := []string{"-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"}
	if !IsAllowed("rpm", good) {
		t.Fatal("expected exact rpm query")
	}
	for _, bad := range [][]string{{"-qa"}, {"-qa", "--qf", "%{NAME}"}, {"-qa", "--qf", good[2], ";id"}, {"-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n", "--scripts"}, {"-q", "--scripts", "sudo"}} {
		if IsAllowed("rpm", bad) {
			t.Fatalf("allowed variant %q", bad)
		}
	}
}
