package collect

import "testing"

func TestParseLockfile(t *testing.T) {
	cases := []struct {
		base, text string
		want       map[string]string
	}{
		{"poetry.lock", "[[package]]\nname = \"Django\"\nversion = \"4.2.1\"\n\n[package.dependencies]\nx = \"1\"\n\n[[package]]\nname = \"Jinja2\"\nversion = \"3.1.2\"\n", map[string]string{"django": "4.2.1", "jinja2": "3.1.2"}},
		{"Cargo.lock", "version = 3\n\n[[package]]\nname = \"hyper\"\nversion = \"0.14.10\"\n", map[string]string{"hyper": "0.14.10"}},
		{"Pipfile.lock", `{"default":{"Flask":{"version":"==2.0.0"}},"develop":{"pytest":{"version":"==7.0.0"}}}`, map[string]string{"flask": "2.0.0", "pytest": "7.0.0"}},
		{"requirements.txt", "# pinned\nrequests==2.25.0\nurllib3>=1.26\nPyYAML[libyaml] == 5.3 ; python_version > '3'\n-r other.txt\n", map[string]string{"requests": "2.25.0", "pyyaml": "5.3"}},
		{"Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n    nokogiri (1.13.0-x86_64-linux)\n      racc (~> 1.4)\n\nPLATFORMS\n  ruby\n", map[string]string{"rack": "2.2.3", "nokogiri": "1.13.0"}},
		{"go.mod", "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.17.0 // indirect\n\tgithub.com/gin-gonic/gin v1.9.1\n)\nrequire golang.org/x/crypto v0.14.0+incompatible\n", map[string]string{"golang.org/x/net": "0.17.0", "github.com/gin-gonic/gin": "1.9.1", "golang.org/x/crypto": "0.14.0"}},
	}
	for _, c := range cases {
		got, ok := ParseLockfile(c.base, "/srv/"+c.base, []byte(c.text))
		if !ok {
			t.Errorf("%s: not ok", c.base)
		}
		m := map[string]string{}
		for _, i := range got {
			m[i.Package] = i.Version
		}
		if len(m) != len(c.want) {
			t.Errorf("%s: got %v, want %v", c.base, m, c.want)
		}
		for k, v := range c.want {
			if m[k] != v {
				t.Errorf("%s: %s = %q, want %q", c.base, k, m[k], v)
			}
		}
	}
	if _, ok := ParseLockfile("Pipfile.lock", "x", []byte("not json")); ok {
		t.Error("broken Pipfile.lock must be reported as not ok")
	}
}
