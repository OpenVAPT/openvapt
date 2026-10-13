package web

import (
	"context"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

func TestWPDefineIgnoresCommentsAndKeepsFirst(t *testing.T) {
	cfg := "<?php\n// define('WP_DEBUG', true);\n/* define('AUTOMATIC_UPDATER_DISABLED', true); */\n# define('X', 1);\ndefine('WP_HOME', 'http://example.test');\ndefine( 'WP_DEBUG', false );\ndefine('WP_DEBUG', true);\ndefine('Y', (bool) getenv('Y'));\n"
	if v, ok := wpDefine(cfg, "WP_DEBUG"); !ok || v != "false" {
		t.Errorf("WP_DEBUG = %q %v, want the first active value false", v, ok)
	}
	if _, ok := wpDefine(cfg, "AUTOMATIC_UPDATER_DISABLED"); ok {
		t.Error("a commented-out define must not count")
	}
	if v, _ := wpDefine(cfg, "WP_HOME"); v != "http://example.test" {
		t.Errorf("URLs must survive comment stripping, got %q", v)
	}
	if v, _ := wpDefine(cfg, "Y"); v != "(bool) getenv('y'" && v != "(bool) getenv('y')" {
		t.Errorf("expression value read as %q", v)
	}
}

func TestInspectPortIsNotTheInspector(t *testing.T) {
	if inspectFlag.MatchString("node --inspect-port=9230 app.js") {
		t.Error("--inspect-port does not start the inspector")
	}
	for _, s := range []string{"node --inspect app.js", "node --inspect=0.0.0.0:9229 app.js", "node --inspect-brk"} {
		if !inspectFlag.MatchString(s) {
			t.Errorf("%q starts the inspector", s)
		}
	}
}

func TestDjangoLastDebugAssignmentWins(t *testing.T) {
	run := func(settings string) string {
		f := &sys.Fake{Files: map[string]string{"/srv/app/app/settings.py": "INSTALLED_APPS = []\n" + settings}}
		for _, c := range check.All() {
			if c.ID == "WEB-PY-001" {
				return string(c.Run(context.Background(), f)[0].Status)
			}
		}
		return ""
	}
	if got := run("DEBUG = False\nDEBUG = True\n"); got != "fail" {
		t.Errorf("a later DEBUG = True is what Python uses, got %s", got)
	}
	if got := run("DEBUG = True\nDEBUG = os.environ.get('D') == '1'\n"); got != "pass" {
		t.Errorf("a final environment-driven DEBUG is safe, got %s", got)
	}
}
