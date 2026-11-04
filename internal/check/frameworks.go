package check

import (
	"regexp"
	"strings"
)

// Per-check framework mapping (audit A2-08).
//
// Every check carries a CIS Critical Security Controls v8 safeguard id in
// Standards.CIS and NIST CSF 2.0 subcategory ids in Standards.CSF, so a
// reader can trace a finding to one safeguard rather than to a whole control.
// A check may set them itself; otherwise Register derives them here, in this
// order: a "v8 N.M" safeguard named in CISTopic, a per-check override, then a
// rule based on the check's category and weakness. CSF subcategories follow
// from the safeguard. Safeguard and subcategory names below are short
// paraphrases written for OpenVAPT; no CIS or NIST text is reproduced.

// CISNone is the explicit marker for "no CIS Controls v8 safeguard fits".
const CISNone = "none"

// CISSafeguards names every safeguard OpenVAPT maps to, paraphrased.
var CISSafeguards = map[string]string{
	"2.2":  "Supported software only",
	"2.5":  "Allow-listed software sources",
	"3.3":  "Data access control lists",
	"3.10": "Encrypt data in transit",
	"4.1":  "Secure configuration process",
	"4.3":  "Session locking on idle",
	"4.4":  "Firewall on servers",
	"4.7":  "Manage default accounts",
	"4.8":  "Remove unneeded services",
	"5.2":  "Unique, strong passwords",
	"5.3":  "Disable dormant accounts",
	"5.4":  "Restrict administrator privileges",
	"7.3":  "Automated operating system patching",
	"7.4":  "Automated application patching",
	"8.2":  "Collect audit logs",
	"8.3":  "Adequate audit log storage",
	"8.4":  "Standardised time synchronisation",
	"8.5":  "Detailed audit logs",
	"8.9":  "Centralised audit logs",
	"16.2": "Accept and handle vulnerability reports",
	"16.7": "Hardened application infrastructure templates",
}

// CSFSubcategories names every NIST CSF 2.0 subcategory OpenVAPT maps to,
// paraphrased.
var CSFSubcategories = map[string]string{
	"ID.RA-01": "Vulnerabilities in assets are identified",
	"ID.RA-08": "Vulnerability disclosures are received and handled",
	"PR.AA-01": "Identities and credentials are managed",
	"PR.AA-03": "Users and services are authenticated",
	"PR.AA-05": "Access permissions follow least privilege",
	"PR.DS-01": "Data at rest is protected",
	"PR.DS-02": "Data in transit is protected",
	"PR.IR-01": "Networks are protected from unauthorised access",
	"PR.PS-01": "Configuration management practices are applied",
	"PR.PS-02": "Software is maintained, replaced and removed",
	"PR.PS-04": "Log records are generated",
	"PR.PS-05": "Unauthorised software is prevented",
	"DE.CM-09": "Computing hardware, software and data are monitored",
}

// csfFor maps each safeguard to the CSF 2.0 subcategories it supports.
var csfFor = map[string][]string{
	"2.2": {"ID.RA-01", "PR.PS-02"}, "2.5": {"PR.PS-05"}, "3.3": {"PR.AA-05", "PR.DS-01"}, "3.10": {"PR.DS-02"},
	"4.1": {"PR.PS-01"}, "4.3": {"PR.PS-01"}, "4.4": {"PR.IR-01"}, "4.7": {"PR.AA-01"}, "4.8": {"PR.PS-01", "PR.IR-01"},
	"5.2": {"PR.AA-01"}, "5.3": {"PR.AA-01"}, "5.4": {"PR.AA-05"},
	"7.3": {"ID.RA-01", "PR.PS-02"}, "7.4": {"ID.RA-01", "PR.PS-02"},
	"8.2": {"PR.PS-04"}, "8.3": {"PR.PS-04"}, "8.4": {"PR.PS-04"}, "8.5": {"PR.PS-04"}, "8.9": {"PR.PS-04", "DE.CM-09"},
	"16.2": {"ID.RA-08"}, "16.7": {"PR.PS-01"},
}

// asvsFill gives OWASP ASVS 4.0.3 requirement ids to web checks that do
// not name one themselves. Only clear matches are listed (14.2.1 components
// up to date, 14.3.2 debug modes off in production, 14.3.3 no version
// details in responses, 2.2.1 anti-automation); a check without a clear ASVS requirement stays unmapped.
var asvsFill = map[string][]string{
	"WEB-CVE-001": {"14.2.1"}, "WEB-NODE-001": {"14.2.1"}, "WEB-CMS-008": {"14.2.1"},
	"WEB-CMS-006": {"14.3.2"}, "WEB-CMS-009": {"14.3.2"}, "WEB-NODE-002": {"14.3.2"},
	"WEB-NODE-003": {"14.3.2"}, "WEB-PY-004": {"14.3.2"}, "WEB-PY-005": {"14.3.2"},
	"WEB-CMS-010": {"14.3.3"}, "WEB-CMS-011": {"14.3.3"},
	"WEB-CMS-002": {"2.2.1"},
}

// cisOverride pins checks the category rule would place less precisely.
var cisOverride = map[string]string{
	"WEB-SEC-001":   "16.2",
	"HOST-TIME-001": "8.4",
	"HOST-FS-012":   "8.3", "HOST-LOG-004": "8.3", "HOST-AUD-009": "8.3", "HOST-CTR-005": "8.3",
	"HOST-USR-001": "5.4", "HOST-USR-003": "5.4", "HOST-SSH-001": "5.4", "HOST-DKR-001": "5.4",
	"HOST-PAM-007": "5.3", "HOST-PAM-008": "4.1", "HOST-PAM-009": "4.3", "HOST-USR-005": "4.7",
}

var cisInTopic = regexp.MustCompile(`v8 (\d{1,2}\.\d{1,2})\b`)

// applyFrameworks fills Standards.CIS and Standards.CSF when a check does
// not set them itself.
func applyFrameworks(c *Check) {
	if len(c.Standards.ASVS) == 0 {
		if ids, ok := asvsFill[c.ID]; ok {
			c.Standards.ASVS = ids
		}
	}
	if len(c.Standards.CIS) == 0 {
		c.Standards.CIS = []string{deriveCIS(c)}
	}
	if len(c.Standards.CSF) == 0 {
		seen := map[string]bool{}
		for _, s := range c.Standards.CIS {
			for _, f := range csfFor[s] {
				if !seen[f] {
					seen[f] = true
					c.Standards.CSF = append(c.Standards.CSF, f)
				}
			}
		}
	}
}

func hasCWE(c *Check, ids ...string) bool {
	for _, have := range c.Standards.CWE {
		for _, want := range ids {
			if have == want {
				return true
			}
		}
	}
	return false
}

func deriveCIS(c *Check) string {
	if m := cisInTopic.FindStringSubmatch(c.Standards.CISTopic); m != nil {
		return m[1]
	}
	if s, ok := cisOverride[c.ID]; ok {
		return s
	}
	web := c.Domain == DomainWeb
	switch c.Category {
	case CatPatch:
		if strings.Contains(c.Title, "End of") {
			return "2.2"
		}
		if c.Domain == DomainHost {
			return "7.3"
		}
		return "7.4"
	case CatIdentity:
		if strings.HasPrefix(c.ID, "HOST-SSH-") {
			return "4.1"
		}
		return "5.2"
	case CatAccess:
		return "3.3"
	case CatCrypto:
		return "3.10"
	case CatLogging:
		if strings.HasPrefix(c.ID, "HOST-AUD-") {
			return "8.5"
		}
		return "8.2"
	case CatNetwork:
		if strings.HasPrefix(c.ID, "NET-FW-") {
			return "4.4"
		}
		return "4.8"
	case CatData:
		if hasCWE(c, "CWE-306", "CWE-732", "CWE-862") {
			return "3.3"
		}
		return "4.1"
	case CatExposure:
		if hasCWE(c, "CWE-538", "CWE-527", "CWE-260", "CWE-312", "CWE-530", "CWE-552", "CWE-532") {
			return "3.3"
		}
	}
	if web {
		return "16.7"
	}
	return "4.1"
}
