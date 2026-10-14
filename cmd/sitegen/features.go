package main

import (
	"regexp"
	"strconv"
)

// featuresSince is the first release that contains openvapt cite, scan
// --open and the default report folder ~/openvapt-reports/<UTC time>.
// Release v0.1.0-alpha.3 and older write ./openvapt-report-<time> in the
// current folder and have neither cite nor --open. Until the release the
// installer picks by default is at least this version, every page that
// mentions these features says they arrive in the next release and shows
// what the current release does instead. The notes disappear by themselves
// once release/channels.json records such a release. Change this constant
// only if the features ship in a different version.
const featuresSince = "v0.1.0-alpha.4"

// Features is what the website says about features newer than the release
// people download today.
type Features struct {
	Released bool   // the default release has them
	Since    string // featuresSince
	Current  string // the default release, or "" when none exists
}

var semverRE = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$`)

// versionKey turns vX.Y.Z or vX.Y.Z-(alpha|beta|rc).N into a comparable
// key. A final release sorts after its pre-releases.
func versionKey(v string) ([5]int, bool) {
	m := semverRE.FindStringSubmatch(v)
	if m == nil {
		return [5]int{}, false
	}
	var k [5]int
	for i, s := range []string{m[1], m[2], m[3]} {
		k[i], _ = strconv.Atoi(s)
	}
	k[3] = map[string]int{"alpha": 0, "beta": 1, "rc": 2, "": 3}[m[4]]
	k[4], _ = strconv.Atoi(m[5])
	return k, true
}

// versionAtLeast reports whether v is the same as or newer than min.
func versionAtLeast(v, min string) bool {
	a, ok1 := versionKey(v)
	b, ok2 := versionKey(min)
	if !ok1 || !ok2 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// featuresFor decides from the release record. It looks at the release the
// installer picks without --channel (the most stable channel with a
// release), because that is the build a new user gets.
func featuresFor(sc siteChannels) Features {
	f := Features{Since: featuresSince}
	if sc.Default != nil {
		f.Current = sc.Default.Version
		f.Released = versionAtLeast(sc.Default.Version, featuresSince)
	}
	return f
}

// siteFeatures is set once in main from the release record.
var siteFeatures Features

// citeNotReleased is the FAQ and llms.txt wording for citing while the
// default release has no openvapt cite command.
const citeNotReleased = "Press Cite at the top or bottom of any page of openvapt.com for APA, IEEE, Harvard, MLA, Chicago and BibTeX with Copy buttons and .bib, .ris, CITATION.cff and CSL-JSON downloads, or copy a reference from https://openvapt.com/cite.html or the CITATION.cff file in the repository; run openvapt version to see the version you used. The openvapt cite command, which prints the citation for your exact version, and a How to Cite block at the end of every report arrive in the next release. The author is the group author OpenVAPT, with no personal names, and OpenVAPT has no DOI yet. Citing is requested whenever OpenVAPT helped your work, and credit is required by section 5.4 of the licence when you copy or share its material."

// applyFeatures rewrites the FAQ answers that name unreleased features.
func applyFeatures(f Features, list []FAQ) {
	if f.Released {
		return
	}
	for i := range list {
		if list[i].Q == "How Do I Cite OpenVAPT?" {
			list[i].A = citeNotReleased
		}
	}
}

// citeCLILine is the command line pointer at the end of the llms.txt How to
// Cite section.
func citeCLILine(f Features) string {
	if f.Released {
		return "Command line: `openvapt cite --format bibtex`."
	}
	return "Files: " + siteURL + "/CITATION.cff and " + siteURL + "/openvapt.bib. The `openvapt cite` command arrives in the next release."
}
