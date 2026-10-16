package network

import "testing"

func TestJupyterAuthOff(t *testing.T) {
	cases := []struct {
		text string
		want int
	}{
		{"c.ServerApp.token = ''\n", 1},
		{"c.ServerApp.token = ''\nc.PasswordIdentityProvider.hashed_password = 'argon2:x'\n", 0},
		{"c.NotebookApp.token = \"\"  # open\n", 1},
		{"c.ServerApp.disable_check_xsrf = True\n", 1},
		{"c.ServerApp.disable_check_xsrf = False\nc.ServerApp.token = 'abc'\n", 0},
		{"# c.ServerApp.token = ''\n", 0},
		{"c.IdentityProvider.token = ''\nc.ServerApp.disable_check_xsrf = True\n", 2},
	}
	for _, c := range cases {
		if got := jupyterAuthOff(c.text); len(got) != c.want {
			t.Errorf("%q: got %v, want %d findings", c.text, got, c.want)
		}
	}
}
