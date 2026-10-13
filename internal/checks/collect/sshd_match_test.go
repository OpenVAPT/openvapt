package collect

import (
	"context"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/sys"
)

const baseSSHD = "permitrootlogin no\npasswordauthentication no\nx11forwarding no\n"

func matchFake(conf string) *sys.Fake {
	f := &sys.Fake{
		Files: map[string]string{
			"/etc/ssh/sshd_config": conf,
			"/etc/group":           "root:x:0:\nadmins:x:1001:carol,dave\nempty:x:1002:\n",
		},
		Commands: map[string]string{},
	}
	for _, c := range []string{"user=root,host=localhost,addr=127.0.0.1", "user=nobody,host=localhost,addr=127.0.0.1", "user=root,host=localhost,addr=192.0.2.1", "user=nobody,host=localhost,addr=192.0.2.1"} {
		f.Commands["sshd -T -C "+c] = baseSSHD
	}
	return f
}

func TestMatchContextsValidation(t *testing.T) {
	conf := "PermitRootLogin no\n" +
		"Match User alice\n  X11Forwarding yes\n" +
		"Match Group admins Address 10.1.0.0/16\n  PasswordAuthentication yes\n" +
		"Match Group empty\n  PasswordAuthentication yes\n" +
		"Match User bob;id,$(id),*,!eve Address 1.2.3.4;rm\n  PasswordAuthentication yes\n" +
		"Match Address 2001:db8::/32\n  PasswordAuthentication yes\n" +
		"Match User root Address 127.0.0.1\n  PasswordAuthentication yes\n" +
		"Match Host evil.example\n  PasswordAuthentication yes\n"
	got := MatchContexts(context.Background(), matchFake(conf), []string{"user=root,host=localhost,addr=127.0.0.1"})
	want := []string{
		"user=alice,host=localhost,addr=192.0.2.1",
		"user=carol,host=localhost,addr=10.1.0.0",
		"user=nobody,host=localhost,addr=2001:db8::",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, c := range got {
		if !sys.ValidSSHDContext(c) {
			t.Errorf("invalid context %q", c)
		}
	}
}

func TestMatchContextsCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("Match User u" + string(rune('a'+i)) + "\n  X11Forwarding yes\n")
	}
	if got := MatchContexts(context.Background(), matchFake(b.String()), nil); len(got) != maxMatchContexts {
		t.Fatalf("got %d contexts, want %d", len(got), maxMatchContexts)
	}
}

func TestSSHDMergesMatchContextFinding(t *testing.T) {
	// The file shows a safe value under the Match line, but sshd's own
	// evaluation for that user (for example through an Include the parser
	// could not read) reports the risky value.
	f := matchFake("PermitRootLogin no\nMatch User alice\n  Banner none\n")
	f.Commands["sshd -T -C user=alice,host=localhost,addr=192.0.2.1"] = "permitrootlogin no\npasswordauthentication yes\nx11forwarding no\n"
	cfg, ok := SSHD(context.Background(), f)
	if !ok {
		t.Fatal("sshd config not found")
	}
	if cfg["passwordauthentication"] != "no" {
		t.Errorf("global value changed: %q", cfg["passwordauthentication"])
	}
	if cfg["match:passwordauthentication"] != "yes" || !strings.Contains(cfg["matchcond:passwordauthentication"], "user=alice") {
		t.Errorf("conditional finding missing: %v", cfg)
	}
}

func TestMatchKeepsNameCaseAndUsesPrimaryGroup(t *testing.T) {
	f := matchFake("Match User Alice\n  X11Forwarding yes\nMatch Group ops\n  PasswordAuthentication yes\n")
	f.Files["/etc/group"] += "ops:x:1500:\n"
	f.Files["/etc/passwd"] = "root:x:0:0::/root:/bin/bash\nerin:x:1501:1500::/home/erin:/bin/bash\n"
	got := MatchContexts(context.Background(), f, nil)
	// "Alice" has an uppercase letter, which sshd user contexts reject, so it
	// is skipped rather than silently lowercased into a different user.
	for _, c := range got {
		if strings.Contains(c, "user=alice") {
			t.Errorf("Match User Alice must not become alice: %v", got)
		}
	}
	found := false
	for _, c := range got {
		if strings.HasPrefix(c, "user=erin,") {
			found = true
		}
	}
	if !found {
		t.Errorf("primary-group member erin not used for Match Group ops: %v", got)
	}
}
