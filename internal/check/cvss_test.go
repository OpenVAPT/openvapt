package check

import "testing"

// Reference scores from the FIRST CVSS v3.1 calculator.
func TestBaseScore(t *testing.T) {
	for v, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": 5.3,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H": 8.1,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,
		"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H": 7.2,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N": 4.2,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
		"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.6,
	} {
		got, err := BaseScore(v)
		if err != nil || got != want {
			t.Errorf("%s = %v %v, want %v", v, got, err, want)
		}
	}
	for _, bad := range []string{"", "CVSS:2.0/AV:N", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H", "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/AV:N/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, err := BaseScore(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
