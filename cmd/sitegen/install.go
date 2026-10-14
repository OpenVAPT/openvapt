package main

import (
	"html/template"
	"strings"
)

// The installer commands shown on the download page. They are built here,
// once, so the page, the copy buttons and the tests use the same text as
// scripts/install.sh documents in its header.
const installURL = "https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh"

var (
	cmdDownloadOnly = "curl -fsSL " + installURL + " | sh"
	cmdDownloadScan = "curl -fsSL " + installURL + " | sh -s -- --run"
	cmdScanSudo     = "curl -fsSL " + installURL + " | sh -s -- --run --sudo"
	cmdScanLater    = "openvapt scan --dry-run      # preview: lists every file, command and request, scans nothing\nsudo openvapt scan          # scan this machine; reports go to a new dated folder"
)

// installBoxes returns the copyable command boxes for the download page.
// The manual download box links the release the installer would pick by
// default, read from the channel record, so no version is hard-coded.
func installBoxes(sc siteChannels) map[string]any {
	box := func(id, label, text, hint string) CiteBox {
		return CiteBox{ID: id, Label: label, Hint: hint, Text: template.HTML(template.HTMLEscapeString(text))} // #nosec G203 -- escaped above
	}
	m := map[string]any{
		"DownloadOnly": box("cmd-download-only", "Download Only", cmdDownloadOnly, ""),
		"DownloadScan": box("cmd-download-scan", "Download and Scan", cmdDownloadScan, ""),
		"ScanSudo":     box("cmd-download-scan-sudo", "Download and Scan With Full Coverage (sudo for the Scan Only)", cmdScanSudo, ""),
		"ScanLater":    box("cmd-scan-later", "Scan Later", cmdScanLater, ""),
	}
	if r := sc.Default; r != nil {
		base := repoURL + "/releases/download/" + r.Version + "/"
		var b strings.Builder
		b.WriteString("# " + sc.DefaultName + " " + r.Version + ", for amd64 (use arm64 on 64-bit ARM)\n")
		for _, f := range []string{"openvapt_linux_amd64", "SHA256SUMS", "openvapt_linux_amd64.sigstore.json"} {
			b.WriteString("curl -fsSLO " + base + f + "\n")
		}
		b.WriteString("sha256sum -c SHA256SUMS --ignore-missing      # must print: openvapt_linux_amd64: OK\n")
		b.WriteString("cosign verify-blob --certificate-identity-regexp '^https://github\\.com/OpenVAPT/openvapt/\\.github/workflows/release\\.yml@refs/heads/main$' \\\n")
		b.WriteString("  --certificate-oidc-issuer https://token.actions.githubusercontent.com \\\n")
		b.WriteString("  --bundle openvapt_linux_amd64.sigstore.json openvapt_linux_amd64\n")
		b.WriteString("install -m 0755 openvapt_linux_amd64 ~/.local/bin/openvapt\n")
		b.WriteString("openvapt version")
		m["Manual"] = box("cmd-manual", "Manual Download and Verification", b.String(), "")
		m["Assets"] = []map[string]string{
			{"Name": "openvapt_linux_amd64", "URL": base + "openvapt_linux_amd64", "Note": "Linux, 64-bit Intel or AMD"},
			{"Name": "openvapt_linux_arm64", "URL": base + "openvapt_linux_arm64", "Note": "Linux, 64-bit ARM"},
			{"Name": "SHA256SUMS", "URL": base + "SHA256SUMS", "Note": "SHA-256 checksums of every file"},
			{"Name": "openvapt_linux_amd64.sigstore.json", "URL": base + "openvapt_linux_amd64.sigstore.json", "Note": "Sigstore signature bundle, amd64"},
			{"Name": "openvapt_linux_arm64.sigstore.json", "URL": base + "openvapt_linux_arm64.sigstore.json", "Note": "Sigstore signature bundle, arm64"},
		}
		m["Release"] = r
		m["ReleaseName"] = sc.DefaultName
		m["ReleasePage"] = repoURL + "/releases/tag/" + r.Version
	}
	return m
}
