package check_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/openvapt/openvapt/internal/check"
	_ "github.com/openvapt/openvapt/internal/checks/all"
)

// withdrawn80053 lists NIST SP 800-53 Rev. 5 controls and enhancements marked
// withdrawn in NIST's OSCAL catalogue (usnistgov/oscal-content,
// NIST_SP-800-53_rev5_catalog.json, read 2026-10-14). Base controls are
// complete; enhancements cover the families OpenVAPT maps to.
var withdrawn80053 = strings.Fields(`
AC-13 AC-15 AT-5 AU-15 CA-4 CP-5 IR-10 PE-7 PL-3 PL-5 PL-6 RA-4 SA-6 SA-7 SA-12
SA-13 SA-14 SA-18 SA-19 SC-9 SC-14 SC-19 SC-33 SI-9
AC-2(10) AC-3(1) AC-3(6) AC-4(16) AC-4(18) AC-7(1) AC-14(1) AC-17(5) AC-17(7)
AC-17(8) AC-18(2) AC-19(1) AC-19(2) AC-19(3) AU-2(1) AU-2(2) AU-2(3) AU-2(4)
AU-3(2) AU-6(2) AU-6(10) AU-7(2) AU-8(1) AU-8(2) AU-10(5) AU-14(2) CM-2(1)
CM-2(4) CM-2(5) CM-5(2) CM-5(3) CM-5(7) CM-6(3) CM-6(4) CM-8(5) CM-11(1)
IA-2(3) IA-2(4) IA-2(7) IA-2(9) IA-2(11) IA-3(2) IA-4(2) IA-4(3) IA-4(7) IA-5(3)
IA-5(4) IA-5(11) IA-8(3) IA-9(1) IA-9(2) RA-5(1) RA-5(7) RA-5(9) SC-4(1) SC-7(1)
SC-7(2) SC-7(6) SC-12(4) SC-12(5) SC-13(1) SC-13(2) SC-13(3) SC-13(4) SC-15(2)
SC-20(1) SC-21(1) SC-23(2) SC-23(4) SC-26(1) SC-30(1) SC-34(3) SC-42(3) SI-2(1)
SI-3(1) SI-3(2) SI-3(3) SI-3(5) SI-3(7) SI-3(9) SI-4(6) SI-4(8) SI-6(1) SI-7(4)
SI-7(11) SI-7(13) SI-7(14) SI-8(1) SI-13(2)`)

// discouragedCWE lists CWE ids whose Mapping_Notes Usage is "Discouraged" in
// MITRE CWE v4.20 and that OpenVAPT replaced with specific children (A2-07).
var discouragedCWE = []string{"CWE-20", "CWE-200", "CWE-269", "CWE-284", "CWE-287", "CWE-330", "CWE-345", "CWE-400", "CWE-657", "CWE-668", "CWE-693"}

var safeguardRe = regexp.MustCompile(`^\d{1,2}\.\d{1,2}$`)

func TestStandardsMetadataQuality(t *testing.T) {
	wd := map[string]bool{}
	for _, w := range withdrawn80053 {
		wd[w] = true
	}
	bad := map[string]bool{}
	for _, c := range discouragedCWE {
		bad[c] = true
	}
	for _, c := range check.All() {
		st := c.Standards
		if len(st.CWE) == 0 {
			t.Errorf("%s: no CWE", c.ID)
		}
		for _, w := range st.CWE {
			if bad[w] {
				t.Errorf("%s: %s is Discouraged for mapping by MITRE; use a specific child", c.ID, w)
			}
		}
		for _, n := range st.NIST {
			if wd[n] {
				t.Errorf("%s: NIST SP 800-53 %s is withdrawn in Rev. 5", c.ID, n)
			}
		}
		if len(st.CIS) == 0 {
			t.Errorf("%s: no CIS Controls v8 safeguard and no %q marker", c.ID, check.CISNone)
		}
		for _, s := range st.CIS {
			if s == check.CISNone {
				continue
			}
			if !safeguardRe.MatchString(s) || check.CISSafeguards[s] == "" {
				t.Errorf("%s: CIS reference %q is not a known v8 safeguard id", c.ID, s)
			}
		}
		if strings.Contains(st.CISTopic, "CIS Controls v8") && !regexp.MustCompile(`v8 \d{1,2}\.\d{1,2}`).MatchString(st.CISTopic) {
			t.Errorf("%s: CIS topic names CIS Controls v8 without a safeguard id: %q", c.ID, st.CISTopic)
		}
		if len(st.CSF) == 0 && !(len(st.CIS) == 1 && st.CIS[0] == check.CISNone) {
			t.Errorf("%s: no NIST CSF 2.0 subcategory", c.ID)
		}
		for _, f := range st.CSF {
			if check.CSFSubcategories[f] == "" {
				t.Errorf("%s: unknown CSF 2.0 subcategory %q", c.ID, f)
			}
		}
	}
}

func TestStandardsTestRejectsBadIDs(t *testing.T) {
	for _, w := range []string{"SA-12", "SI-9", "AC-2(10)"} {
		found := false
		for _, x := range withdrawn80053 {
			found = found || x == w
		}
		if !found {
			t.Errorf("withdrawn list is missing %s", w)
		}
	}
	if safeguardRe.MatchString("4") || !safeguardRe.MatchString("16.7") {
		t.Error("safeguard pattern must require a control.safeguard id")
	}
}
