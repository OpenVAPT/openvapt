package check

// Category groups checks by security control area. Each category maps to the
// public control frameworks assessors report against, so every finding can be
// placed in a recognised structure:
//
//   - CIS Critical Security Controls v8 (control numbers only; no CIS text
//     is reproduced). https://www.cisecurity.org/controls/v8
//   - NIST Cybersecurity Framework 2.0 categories.
//     https://www.nist.gov/cyberframework
//
// This category mapping is broad orientation at control/category level.
// Each check's own safeguard and CSF subcategory live in Standards.CIS and
// Standards.CSF (see frameworks.go); coverage counts use those.
type Category string

const (
	CatIdentity Category = "identity" // accounts, authentication, privilege
	CatAccess   Category = "access"   // file and system access control
	CatPatch    Category = "patch"    // patching, lifecycle, vulnerable versions
	CatConfig   Category = "config"   // secure configuration and hardening
	CatCrypto   Category = "crypto"   // TLS, certificates, ciphers, keys
	CatLogging  Category = "logging"  // logging, auditing, time
	CatNetwork  Category = "network"  // listening services, firewall, protocols
	CatData     Category = "data"     // databases, caches, file shares, mail, DNS
	CatWebApp   Category = "webapp"   // web security controls (headers, cookies, CORS)
	CatExposure Category = "exposure" // information and secret exposure
)

// CategoryInfo describes a category and its framework mappings.
type CategoryInfo struct {
	ID      Category `json:"id"`
	Name    string   `json:"name"`
	About   string   `json:"about"`
	CIS     []string `json:"cis"`      // CIS Controls v8 control numbers
	NISTCSF []string `json:"nist_csf"` // NIST CSF 2.0 categories
}

// Categories lists every category in reporting order.
var Categories = []CategoryInfo{
	{CatIdentity, "Identity and Authentication", "Accounts, passwords, keys, privilege escalation paths and login controls.", []string{"5", "6"}, []string{"PR.AA"}},
	{CatAccess, "Access Control", "File, directory and system permissions that decide who can read or change what.", []string{"3", "6"}, []string{"PR.AA", "PR.DS"}},
	{CatPatch, "Patch and Vulnerability Management", "Supported releases, pending security updates and outdated components.", []string{"7", "2"}, []string{"ID.RA", "PR.PS"}},
	{CatConfig, "Secure Configuration", "Operating system and service hardening settings.", []string{"4"}, []string{"PR.PS"}},
	{CatCrypto, "Cryptography and TLS", "Protocol versions, ciphers, certificates and key protection.", []string{"3"}, []string{"PR.DS"}},
	{CatLogging, "Logging and Monitoring", "Log persistence, auditing, time synchronisation and monitoring readiness.", []string{"8"}, []string{"PR.PS", "DE.CM"}},
	{CatNetwork, "Network Exposure", "What the machine exposes to the network and how it is filtered.", []string{"4", "12", "13"}, []string{"PR.IR", "PR.PS"}},
	{CatData, "Data Services", "Databases, caches, file shares, mail and DNS services and their access controls.", []string{"3", "4", "12"}, []string{"PR.DS", "PR.PS"}},
	{CatWebApp, "Web Application Security", "Browser-enforced protections, cookies, cross-origin rules and transport security.", []string{"16"}, []string{"PR.PS", "PR.DS"}},
	{CatExposure, "Information Exposure", "Files, versions, errors and secrets that a website or server reveals.", []string{"3", "16"}, []string{"PR.DS"}},
}

// CategoryByID returns the category description, or a zero value.
func CategoryByID(id Category) CategoryInfo {
	for _, c := range Categories {
		if c.ID == id {
			return c
		}
	}
	return CategoryInfo{}
}

// Effort is a rough estimate of the work needed to remediate, used to order
// the remediation plan (quick wins first). It is guidance, not a promise.
type Effort string

const (
	EffortLow    Effort = "low"    // a configuration change and reload
	EffortMedium Effort = "medium" // several changes, testing or a maintenance window
	EffortHigh   Effort = "high"   // upgrade, migration or redesign
)

// legacy assigns categories and effort to checks written before these fields
// existed. New checks set Category and Effort directly.
var legacy = map[string]struct {
	cat Category
	eff Effort
}{
	"HOST-SSH-001": {CatIdentity, EffortLow}, "HOST-SSH-002": {CatIdentity, EffortLow}, "HOST-SSH-003": {CatIdentity, EffortLow},
	"HOST-SSH-004": {CatCrypto, EffortLow}, "HOST-SSH-005": {CatConfig, EffortLow}, "HOST-SSH-006": {CatIdentity, EffortLow},
	"HOST-SSH-007": {CatConfig, EffortLow}, "HOST-SSH-008": {CatIdentity, EffortLow},
	"HOST-USR-001": {CatIdentity, EffortMedium}, "HOST-USR-002": {CatIdentity, EffortLow}, "HOST-USR-003": {CatIdentity, EffortLow},
	"HOST-FS-001": {CatAccess, EffortLow}, "HOST-FS-002": {CatAccess, EffortLow}, "HOST-FS-003": {CatAccess, EffortMedium},
	"HOST-FS-004": {CatAccess, EffortMedium}, "HOST-FS-005": {CatAccess, EffortLow},
	"HOST-OS-001": {CatPatch, EffortHigh}, "HOST-PKG-001": {CatPatch, EffortMedium},
	"HOST-LOG-001": {CatLogging, EffortLow}, "HOST-LOG-002": {CatLogging, EffortMedium}, "HOST-TIME-001": {CatLogging, EffortLow},
	"NET-LSN-001": {CatNetwork, EffortLow}, "NET-DB-001": {CatData, EffortLow}, "NET-SVC-001": {CatNetwork, EffortMedium},
	"NET-FW-001": {CatNetwork, EffortMedium}, "NET-TLS-001": {CatCrypto, EffortLow}, "NET-TLS-002": {CatCrypto, EffortLow},
	"NET-TLS-003": {CatCrypto, EffortLow},
	"WEB-HDR-001": {CatWebApp, EffortLow}, "WEB-HDR-002": {CatWebApp, EffortMedium}, "WEB-HDR-003": {CatWebApp, EffortLow},
	"WEB-HDR-004": {CatWebApp, EffortLow}, "WEB-HDR-005": {CatWebApp, EffortLow}, "WEB-HDR-006": {CatWebApp, EffortLow},
	"WEB-HDR-007": {CatExposure, EffortLow}, "WEB-TLS-001": {CatCrypto, EffortLow}, "WEB-CK-001": {CatWebApp, EffortMedium},
	"WEB-EXP-001": {CatExposure, EffortLow}, "WEB-EXP-002": {CatExposure, EffortMedium}, "WEB-EXP-003": {CatExposure, EffortLow},
	"WEB-EXP-004": {CatExposure, EffortLow}, "WEB-EXP-005": {CatExposure, EffortLow}, "WEB-EXP-006": {CatExposure, EffortLow},
	"WEB-PHP-001": {CatConfig, EffortLow}, "WEB-PHP-002": {CatExposure, EffortLow}, "WEB-PHP-003": {CatConfig, EffortLow},
	"WEB-PHP-004": {CatPatch, EffortHigh}, "WEB-CMS-001": {CatExposure, EffortLow}, "WEB-CMS-002": {CatWebApp, EffortLow},
}

func applyLegacy(c *Check) {
	if c.Category != "" && c.Effort != "" {
		return
	}
	if l, ok := legacy[c.ID]; ok {
		if c.Category == "" {
			c.Category = l.cat
		}
		if c.Effort == "" {
			c.Effort = l.eff
		}
	}
	if len(c.ID) > 9 && c.ID[:9] == "HOST-KRN-" {
		if c.Category == "" {
			c.Category = CatConfig
		}
		if c.Effort == "" {
			c.Effort = EffortLow
		}
	}
}
