package main

import (
	"fmt"
	"os"

	"github.com/openvapt/openvapt/internal/channels"
)

// The website is one site for every channel. It shows where each channel
// stands and stays hidden from search engines until a Stable release exists
// and the AI legal reviewer has signed off public release (AGENTS.md
// section 5). Nobody switches that by hand: it follows the release record.

var (
	statePath = "release/channels.json"
	legalPath = "release/legal-review.json"
)

// ChannelView is one channel as the Release Channels page shows it.
type ChannelView struct {
	channels.Info
	Release *channels.Release
	Gates   []string
	Install string
}

// gateText describes each channel's gate in plain words; internal/channels
// enforces exactly these conditions.
var gateText = map[channels.Channel][]string{
	channels.Alpha:  {"CI green: format, vet, race tests, static analysis, security and vulnerability scans", "Lab proof: every check fails on the vulnerable lab and passes on the hardened lab", "A new build since the last Alpha"},
	channels.Beta:   {"Everything required for Alpha, re-run on the exact Alpha commit", "At least 7 days in Alpha", "AI legal review recorded for the exact Alpha build, with no open High legal risk"},
	channels.RC:     {"Everything required for Beta, re-run on the exact Beta commit", "At least 7 days in Beta", "Installer test: a verified build installs and a tampered one is refused", "The Beta release carries Sigstore signatures, build provenance and an SBOM"},
	channels.Stable: {"Everything required for Release Candidate, re-run on the exact Release Candidate commit", "At least 14 days in Release Candidate", "The AI legal reviewer's sign-off for public release"},
}

type siteChannels struct {
	State   *channels.State
	Legal   channels.LegalReview
	Views   []ChannelView
	History []channels.Release
	Highest string // display name of the most mature released channel
	Public  bool   // a Stable release exists and public release is signed off
}

func loadChannels() siteChannels {
	s, err := channels.Load(statePath)
	must(err)
	lr, lerr := channels.LoadLegal(legalPath)
	sc := siteChannels{State: s, Legal: lr, Highest: "Pre-Release"}
	if h := s.Highest(); h != "" {
		sc.Highest = channels.InfoFor(h).Name
	}
	_, hasStable := s.Current[channels.Stable]
	sc.Public = hasStable && lerr == nil && lr.PublicLaunchApproved
	for i := len(channels.Order) - 1; i >= 0; i-- {
		c := channels.Order[i]
		v := ChannelView{Info: channels.InfoFor(c), Gates: gateText[c], Install: "--channel " + string(c)}
		if c == channels.Stable {
			v.Install = ""
		}
		if r, ok := s.Current[c]; ok {
			r := r
			v.Release = &r
		}
		sc.Views = append(sc.Views, v)
	}
	for i := len(s.History) - 1; i >= 0; i-- {
		sc.History = append(sc.History, s.History[i])
	}
	if !sc.Public && !*noindex {
		fmt.Fprintln(os.Stderr, "sitegen: no signed-off Stable release yet, so every page is built noindex")
		*noindex = true
	}
	return sc
}
