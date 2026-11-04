package report

import (
	"time"

	"github.com/openvapt/openvapt/internal/cite"
)

// Citation is the How to Cite block every report carries: the APA and
// BibTeX citation of the exact tool version, the report's own reference
// line and the credit line the licence (section 5.4) requires when the
// report is shared. The text comes from internal/cite, the single source
// the website, the CLI and the README also use.
type Citation struct {
	APA       string `json:"apa"`
	BibTeX    string `json:"bibtex"`
	Reference string `json:"reference"`
	Credit    string `json:"credit"`
}

// NewCitation builds the block for tool version v and a scan at t.
func NewCitation(v string, t time.Time) *Citation {
	w := cite.New(v, t)
	return &Citation{APA: w.APA(), BibTeX: w.BibTeX(), Reference: cite.ReportLine(v, t), Credit: cite.Credit}
}

// HowToCite returns the report's citation block, or builds one from the
// tool version and scan time for a report written before the block existed.
func (r *Report) HowToCite() *Citation {
	if r.Citation != nil {
		return r.Citation
	}
	return NewCitation(r.Tool.Version, r.Scan.Started)
}
