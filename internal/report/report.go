// Package report assigns alert statuses to certificate results and renders
// them as a human-readable table or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thejedi433/certprobe/internal/cert"
)

// Status is the alert level for one probed certificate.
type Status string

// Alert levels, ordered by severity: ok < warn < crit.
const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusCrit Status = "crit"
)

// Assign returns the status for one result given warning and critical
// day thresholds.
//
// Rules:
//   - no certificate data at all (dial/handshake failure) -> crit
//   - expired -> crit
//   - handshake succeeded but the chain did not verify -> crit when strict,
//     otherwise warn (a valid but untrusted cert is still useful to see)
//   - daysLeft <= critDays -> crit
//   - daysLeft <= warnDays -> warn
//   - otherwise -> ok
func Assign(r cert.Result, warnDays, critDays int, strict bool) Status {
	if r.NotAfter.IsZero() {
		return StatusCrit
	}
	if r.Expired {
		return StatusCrit
	}
	if !r.Verified && r.Host != "" && r.Port != 0 {
		if strict {
			return StatusCrit
		}
		return StatusWarn
	}
	if r.DaysLeft <= critDays {
		return StatusCrit
	}
	if r.DaysLeft <= warnDays {
		return StatusWarn
	}
	return StatusOK
}

// Line pairs a result with its assigned status for output.
type Line struct {
	cert.Result
	Status Status
}

// MarshalJSON embeds the certificate result and adds the status field.
func (l Line) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(l.Result)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(base, &m); err != nil {
		return nil, err
	}
	st, err := json.Marshal(string(l.Status))
	if err != nil {
		return nil, err
	}
	m["status"] = st
	return json.Marshal(m)
}

// Lines computes statuses for all results.
func Lines(results []cert.Result, warnDays, critDays int, strict bool) []Line {
	out := make([]Line, len(results))
	for i, r := range results {
		out[i] = Line{Result: r, Status: Assign(r, warnDays, critDays, strict)}
	}
	return out
}

// ExitCode maps statuses to the process exit code: 0 all ok, 1 any warn,
// 2 any crit.
func ExitCode(lines []Line) int {
	code := 0
	for _, l := range lines {
		switch l.Status {
		case StatusCrit:
			return 2
		case StatusWarn:
			code = 1
		}
	}
	return code
}

// WriteJSON renders lines as a JSON array, or one object per line when
// lines mode is requested.
func WriteJSON(w io.Writer, lines []Line, perLine bool) error {
	if !perLine {
		enc := json.NewEncoder(w)
		return enc.Encode(lines)
	}
	for _, l := range lines {
		if err := json.NewEncoder(w).Encode(l); err != nil {
			return err
		}
	}
	return nil
}

// Table renders a padded plain-text table. Widths adapt to content; the
// issuer is truncated to keep the line terminal-friendly.
func Table(w io.Writer, lines []Line) error {
	head := []string{"HOST:PORT", "STATUS", "DAYS", "EXPIRES", "VER", "ISSUER", "NOTE"}
	rows := make([][]string, 0, len(lines))
	for _, l := range lines {
		addr := l.Host
		if l.Port != 0 {
			addr = fmt.Sprintf("%s:%d", l.Host, l.Port)
		}
		exp := "-"
		if !l.NotAfter.IsZero() {
			exp = l.NotAfter.Format(time.RFC3339)
		}
		ver := "yes"
		if !l.Verified {
			ver = "no"
		}
		note := l.Error
		if l.Expired && note == "" {
			note = "EXPIRED"
		}
		rows = append(rows, []string{addr, string(l.Status), fmt.Sprint(l.DaysLeft), exp, ver, truncate(l.Issuer, 48), note})
	}
	widths := make([]int, len(head))
	for i, h := range head {
		widths[i] = utf8.RuneCountInString(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if n := utf8.RuneCountInString(c); n > widths[i] {
				widths[i] = n
			}
		}
	}
	writeRow := func(cols []string) error {
		parts := make([]string, len(cols))
		for i, c := range cols {
			pad := widths[i] - utf8.RuneCountInString(c)
			if pad < 0 {
				pad = 0
			}
			parts[i] = c + strings.Repeat(" ", pad)
		}
		_, err := fmt.Fprintln(w, strings.Join(parts, "  "))
		return err
	}
	if err := writeRow(head); err != nil {
		return err
	}
	for _, r := range rows {
		if err := writeRow(r); err != nil {
			return err
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
