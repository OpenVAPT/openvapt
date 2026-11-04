package network

import "testing"

func TestNFTInputPolicyMustBeDefaultDeny(t *testing.T) {
	bad := "chain input { type filter hook input priority 0; policy accept; } chain forward { drop }"
	if nftInputDefaultDeny(bad) {
		t.Fatal("unrelated drop rule was accepted")
	}
	if !nftInputDefaultDeny("chain input { type filter hook input priority 0; policy drop; }") {
		t.Fatal("input default drop was not accepted")
	}
}
