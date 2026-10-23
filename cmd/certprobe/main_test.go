package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLooksLikeFile(t *testing.T) {
	cases := map[string]bool{
		"/etc/ssl/ca.pem":  true,
		"./x.crt":          true,
		"../y.der":         true,
		"C:\\certs\\a.pem": true,
		"example.com":      false,
		"example.com:8443": false,
		"[::1]:443":        false,
	}
	for in, want := range cases {
		if got := looksLikeFile(in); got != want {
			t.Errorf("looksLikeFile(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestRunNoTargets(t *testing.T) {
	var buf bytes.Buffer
	_, err := run([]string{}, &buf)
	if err == nil || !strings.Contains(err.Error(), "no targets") {
		t.Fatalf("want no-targets error, got %v", err)
	}
}

func TestRunThresholdValidation(t *testing.T) {
	var buf bytes.Buffer
	_, err := run([]string{"-warn-days", "5", "-crit-days", "10", "example.com"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "must be greater") {
		t.Fatalf("want threshold error, got %v", err)
	}
	_, err = run([]string{"-parallel", "0", "example.com"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "1-64") {
		t.Fatalf("want parallel error, got %v", err)
	}
}

func TestRunFileModeValidAndExpired(t *testing.T) {
	dir := t.TempDir()
	valid := makeCertFile(t, dir, "valid", 40)
	expired := makeCertFile(t, dir, "expired", -2)

	var buf bytes.Buffer
	code, err := run([]string{"-file", valid}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Errorf("valid 40-day cert: exit=%d, want 0; out=%s", code, buf.String())
	}

	buf.Reset()
	code, err = run([]string{"-file", expired}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 {
		t.Errorf("expired cert: exit=%d, want 2; out=%s", code, buf.String())
	}

	buf.Reset()
	code, err = run([]string{"-json", "-file", valid, expired}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 {
		t.Errorf("mixed files: exit=%d, want 2", code)
	}
	var lines []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &lines); err != nil {
		t.Fatalf("bad json %q: %v", buf.String(), err)
	}
	if len(lines) != 2 {
		t.Fatalf("want 2 entries, got %d", len(lines))
	}
	if lines[1]["status"] != "crit" {
		t.Errorf("expired status = %v", lines[1]["status"])
	}
}

func TestRunFileWarnBand(t *testing.T) {
	dir := t.TempDir()
	soon := makeCertFile(t, dir, "soon", 10) // within default warn 21
	var buf bytes.Buffer
	code, err := run([]string{"-file", soon}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Errorf("10-day cert: exit=%d, want 1 (warn)", code)
	}
}

func TestRunProbeUnreachable(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	var buf bytes.Buffer
	code, err := run([]string{"-timeout", "1s", addr}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 {
		t.Errorf("unreachable: exit=%d, want 2; out=%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "dial") {
		t.Errorf("want dial note in table, got %q", buf.String())
	}
}

func TestRunTargetListFile(t *testing.T) {
	dir := t.TempDir()
	lst := filepath.Join(dir, "targets.txt")
	body := "# comment\n\nexample.com\n"
	if err := os.WriteFile(lst, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// use file mode so no network needed; but the list path goes through
	// parseTargets — feed a bogus port list instead and expect dial crit.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	if err := os.WriteFile(lst, []byte("#c\n"+addr+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	code, err := run([]string{"-timeout", "1s", "@" + lst}, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if code != 2 {
		t.Errorf("exit=%d want 2", code)
	}
}

func TestRunBadTargetArg(t *testing.T) {
	var buf bytes.Buffer
	_, err := run([]string{"example.com:abc"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("want port error, got %v", err)
	}
}

func TestRunMissingCAFile(t *testing.T) {
	var buf bytes.Buffer
	_, err := run([]string{"-ca", "/nonexistent/roots.pem", "example.com"}, &buf)
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("want file error, got %v", err)
	}
}

func TestParseTargetsStdinAndFileErrors(t *testing.T) {
	if _, err := parseTargets([]string{"@/definitely/missing.txt"}); err == nil {
		t.Error("want open error")
	}
	// bad host inside list file
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.txt")
	os.WriteFile(p, []byte("host:99999\n"), 0o600)
	if _, err := parseTargets([]string{"@" + p}); err == nil || !strings.Contains(err.Error(), "bad.txt") {
		t.Errorf("want source-prefixed parse error, got %v", err)
	}
}

func TestRunFileModeMissingFile(t *testing.T) {
	var buf bytes.Buffer
	_, err := run([]string{"-file", "/nope/nothere.pem"}, &buf)
	if err == nil {
		t.Fatal("want missing file error")
	}
}

func TestRunJSONLStyleNotUsedButShapeOK(t *testing.T) {
	dir := t.TempDir()
	valid := makeCertFile(t, dir, "ok", 300)
	var buf bytes.Buffer
	code, err := run([]string{"-json", "-file", valid}, &buf)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.HasPrefix(strings.TrimSpace(buf.String()), "[") {
		t.Errorf("want json array, got %q", buf.String())
	}
}

func TestParseTargetsPlainAndComments(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "list.txt")
	os.WriteFile(p, []byte("# comment\n\nexample.com\n"), 0o600)
	tg, err := parseTargets([]string{"@" + p})
	if err != nil {
		t.Fatal(err)
	}
	if len(tg) != 1 || tg[0].Host != "example.com" {
		t.Errorf("targets = %+v", tg)
	}
}

// makeCertFile writes a self-signed cert expiring in daysFromNow and returns
// its path.
func makeCertFile(t *testing.T, dir, name string, daysFromNow int) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(daysFromNow) * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{name + ".example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name+".pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
