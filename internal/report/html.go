package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
)

//go:embed report.html.tmpl
var htmlTmpl string

// HTML renders a single self-contained page: inline CSS, no JavaScript
// libraries, no fonts, images or requests to any other site. It works
// offline and prints cleanly to PDF from any browser.
func (r *Report) HTML() ([]byte, error) {
	t, err := template.New("r").Funcs(template.FuncMap{
		"upper":  strings.ToUpper,
		"failed": func(f Finding) bool { return f.Status == string(check.Fail) },
		"coverage": func(f Finding) bool {
			return f.Status == string(check.Incomplete) || f.Status == string(check.Error) || f.Status == string(check.Skip)
		},
		"fails": func(rs []check.Result) []check.Result {
			var out []check.Result
			for _, x := range rs {
				if x.Status == check.Fail {
					out = append(out, x)
				}
			}
			return out
		},
		"join":  strings.Join,
		"short": short,
		"catName": func(c check.Category) string {
			if n := check.CategoryByID(c).Name; n != "" {
				return n
			}
			return string(c)
		},
		"title": func(v any) string {
			s := fmt.Sprint(v)
			if s == "" {
				return s
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
	}).Parse(htmlTmpl)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	err = t.Execute(&b, r)
	return b.Bytes(), err
}
