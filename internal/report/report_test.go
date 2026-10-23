package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/thejedi433/certprobe/internal/cert"
)

func res(daysLeft int, verified, expired bool) cert.Result {
	r := cert.Result{
		Host:     "example.com",
		Port:     443,
		Verified: verified,
		Expired:  expired,
		NotAfter: time.Now().Add(time.Duration(daysLeft) * 24 * time.Hour),
		DaysLeft: daysLeft,
	}
	return r
}

func TestAssignStatuses(t *testing.T) {
	cases := []struct {
		name     string
		r        cert.Result
		warnDays int
		critDays int
		strict   bool
		want     Status
	}{
		{"ok", res(90, true, false), 21, 7, false, StatusOK},
		{"warn band", res(15, true, false), 21, 7, false, StatusWarn},
		{"crit band", res(5, true, false), 21, 7, false, StatusCrit},
		{"boundary warn", res(21, true, false), 21, 7, false, StatusWarn},
		{"boundary crit", res(7, true, false), 21, 7, false, StatusCrit},
		{"expired", res(0, false, true), 21, 7, false, StatusCrit},
		{"unverified lenient", res(90, false, false), 21, 7, false, StatusWarn},
		{"unverified strict", res(90, false, false), 21, 7, true, StatusCrit},
		{"no cert data", cert.Result{Host: "x"}, 21, 7, false, StatusCrit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Assign(c.r, c.warnDays, c.critDays, c.strict); got != c.want {
				t.Errorf("Assign = %v, want %v", got, c.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	lines := Lines([]cert.Result{res(90, true, false)}, 21, 7, false)
	if ExitCode(lines) != 0 {
		t.Error("all ok should be 0")
	}
	lines = Lines([]cert.Result{res(90, true, false), res(15, true, false)}, 21, 7, false)
	if ExitCode(lines) != 1 {
		t.Error("warn should be 1")
	}
	lines = Lines([]cert.Result{res(90, true, false), res(2, true, false)}, 21, 7, false)
	if ExitCode(lines) != 2 {
		t.Error("crit should be 2 and win over warn")
	}
}

func TestTableOutput(t *testing.T) {
	lines := Lines([]cert.Result{
		res(90, true, false),
		res(3, true, false),
	}, 21, 7, false)
	var buf bytes.Buffer
	if err := Table(&buf, lines); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"HOST:PORT", "example.com:443", "ok", "crit", "STATUS"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

func TestTableIssuerTruncation(t *testing.T) {
	r := res(90, true, false)
	r.Issuer = strings.Repeat("X", 200)
	var buf bytes.Buffer
	if err := Table(&buf, Lines([]cert.Result{r}, 21, 7, false)); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, strings.Repeat("X", 60)) {
			t.Error("issuer not truncated")
		}
	}
}

func TestJSONShape(t *testing.T) {
	r := res(30, true, false)
	r.SANs = []string{"a.example", "b.example"}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, Lines([]cert.Result{r}, 21, 7, false), false); err != nil {
		t.Fatal(err)
	}
	var got []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("invalid json %q: %v", buf.String(), err)
	}
	if got[0]["status"] != "ok" {
		t.Errorf("status = %v", got[0]["status"])
	}
	if got[0]["host"] != "example.com" {
		t.Errorf("host = %v", got[0]["host"])
	}
	if got[0]["days_left"] != float64(30) {
		t.Errorf("days_left = %v", got[0]["days_left"])
	}
}

func TestWriteJSONPerLine(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, Lines([]cert.Result{res(90, true, false), res(1, true, false)}, 21, 7, false), true)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 JSONL lines, got %d: %q", len(lines), buf.String())
	}
	for _, l := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("bad line %q: %v", l, err)
		}
	}
}

// failWriter errors on first write after N successful bytes.
type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	f.n--
	if f.n < 0 {
		return 0, errors.New("disk on fire")
	}
	return len(p), nil
}

func TestTableWriteError(t *testing.T) {
	lines := Lines([]cert.Result{res(90, true, false)}, 21, 7, false)
	if err := Table(&failWriter{n: 1}, lines); err == nil {
		t.Error("want write error from table")
	}
}

func TestWriteJSONErrors(t *testing.T) {
	lines := Lines([]cert.Result{res(90, true, false), res(5, true, false)}, 21, 7, false)
	// array mode encodes with a single Write -> fail the very first one
	if err := WriteJSON(&failWriter{n: 0}, lines, false); err == nil {
		t.Error("want write error from json array")
	}
	// per-line mode writes one Write per line -> first ok, second fails
	if err := WriteJSON(&failWriter{n: 1}, lines, true); err == nil {
		t.Error("want write error from jsonl")
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("short passthrough got %q", got)
	}
	if got := truncate("héllo wörld", 5); len([]rune(got)) != 5 || !strings.HasSuffix(got, "…") {
		t.Errorf("got %q", got)
	}
}
