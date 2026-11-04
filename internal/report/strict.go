package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxReportSize caps how much of a report file is read.
const MaxReportSize = 64 << 20

// CanonicalJSON returns the exact bytes a signature covers: the indented
// JSON of the report with the integrity block absent. report.json is this
// form plus the integrity block, so it stays human readable.
func (r *Report) CanonicalJSON() ([]byte, error) {
	cp := *r
	cp.Integrity = nil
	return cp.JSON()
}

// ParseStrict decodes a report without migration and refuses anything a
// lenient decoder would silently accept: unknown fields, duplicate keys and
// keys that differ only in letter case. It is the decoder for verification,
// where every byte of the file must be accounted for.
func ParseStrict(b []byte) (*Report, error) {
	if err := checkKeys(b); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var r Report
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("not a well-formed OpenVAPT report: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("not a well-formed OpenVAPT report: trailing data after the report")
	}
	return &r, nil
}

// checkKeys walks every JSON object and rejects a key that appears twice,
// exactly or in another letter case.
func checkKeys(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 64 {
			return errors.New("report nesting is too deep")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]string{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				fold := strings.ToLower(k)
				if prev, dup := seen[fold]; dup {
					if prev == k {
						return fmt.Errorf("duplicate key %q in report", k)
					}
					return fmt.Errorf("keys %q and %q differ only in letter case", prev, k)
				}
				seen[fold] = k
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token() // closing }
			return err
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = dec.Token() // closing ]
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return fmt.Errorf("not a well-formed OpenVAPT report: %w", err)
	}
	return nil
}
