package collect

import "testing"

func TestParseKV(t *testing.T) {
	m := ParseKV("# c\nbind 127.0.0.1 ::1\nprotected-mode yes\n[mysqld]\nlocal_infile = 0\nPASS_MAX_DAYS\t90\nkey: value # trailing\n")
	cases := map[string]string{"bind": "127.0.0.1 ::1", "protected-mode": "yes", "mysqld.local_infile": "0", "pass_max_days": "90", "key": "value"}
	for k, want := range cases {
		if got := m[k]; len(got) == 0 || got[0] != want {
			t.Errorf("%s = %v, want %q", k, got, want)
		}
	}
}
