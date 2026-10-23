package cert

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// errConn wraps a net.Conn and can fail SetDeadline.
type errConn struct {
	net.Conn
	failDeadline bool
}

func (c *errConn) SetDeadline(t time.Time) error {
	if c.failDeadline {
		return errors.New("set deadline: no dice")
	}
	return c.Conn.SetDeadline(t)
}

// flakyDial returns prepared results in order.
type flakyDial struct {
	conns []net.Conn
	errs  []error
	i     int
}

func (f *flakyDial) dial(addr string) (net.Conn, error) {
	idx := f.i
	f.i++
	if idx < len(f.errs) && f.errs[idx] != nil {
		return nil, f.errs[idx]
	}
	return f.conns[idx], nil
}

func rawListener(t *testing.T) (addr string, accept func() net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	conns := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns <- c
		}
	}()
	return ln.Addr().String(), func() net.Conn { return <-conns }
}

func TestProbeDeadlineError(t *testing.T) {
	addr, accept := rawListener(t)
	_ = accept // not used
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	d := func(string) (net.Conn, error) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return &errConn{Conn: c, failDeadline: true}, nil
	}
	res, _ := probe(Target{Host: "127.0.0.1", Port: port}, time.Second, nil, d)
	if !strings.Contains(res.Error, "deadline") {
		t.Fatalf("want deadline error, got %q", res.Error)
	}
}

func TestProbeNonTLSServer(t *testing.T) {
	addr, accept := rawListener(t)
	go func() {
		c := accept()
		c.Write([]byte("not tls\r\n\r\n"))
		time.Sleep(50 * time.Millisecond)
		c.Close()
	}()
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	res, _ := probe(Target{Host: "127.0.0.1", Port: port}, 2*time.Second, nil, tcpDial(time.Second))
	if res.Error == "" {
		t.Fatal("want handshake error")
	}
	if strings.Contains(res.Error, "verify:") {
		t.Errorf("plain server should not take the verify path: %q", res.Error)
	}
}

func TestProbeRetryDialFails(t *testing.T) {
	// First: a real TLS server with a cert the client's pool rejects
	// (verify error), second: dial fails.
	ca := newTestCA(t)
	other := newTestCA(t)
	leaf := ca.leaf(t, "localhost", 10)
	addr := serve(t, leaf, "localhost")
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	var n int
	d := func(a string) (net.Conn, error) {
		n++
		if n == 1 {
			return net.Dial("tcp", a)
		}
		return nil, errors.New("second dial boom")
	}
	res, _ := probe(Target{Host: "localhost", Port: port}, 2*time.Second, other.pool, d)
	if res.Verified {
		t.Error("should not be verified")
	}
	if !strings.Contains(res.Error, "verify:") {
		t.Errorf("want verify error preserved, got %q", res.Error)
	}
	if n != 2 {
		t.Errorf("want 2 dials, got %d", n)
	}
}

func TestProbeRetryHandshakeFails(t *testing.T) {
	// first conn yields a verify error; second conn is a broken pipe
	addr, accept := rawListener(t)
	go func() {
		c := accept() // first: speak minimal TLS that fails verify? too complex;
		c.Close()     // just close -> handshake error not verify
		_ = c
	}()
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// craft first conn to produce verify error via a test CA chain, then a
	// plain broken conn for the retry
	ca := newTestCA(t)
	other := newTestCA(t)
	leaf := ca.leaf(t, "localhost", 10)
	saddr := serve(t, leaf, "localhost")
	var n int
	d := func(a string) (net.Conn, error) {
		n++
		target := saddr
		if n == 2 {
			target = addr
		}
		return net.Dial("tcp", target)
	}
	res, _ := probe(Target{Host: "localhost", Port: port}, 2*time.Second, other.pool, d)
	if res.Verified {
		t.Error("should not verify")
	}
	if n != 2 {
		t.Errorf("want 2 dials, got %d", n)
	}
}

func TestIsVerifyError(t *testing.T) {
	if !isVerifyError(errors.New("x509: certificate has expired")) {
		t.Error("string match should count")
	}
	if isVerifyError(errors.New("connection refused")) {
		t.Error("plain error should not count")
	}
	verr := &tls.CertificateVerificationError{Err: errors.New("unknown authority")}
	if !isVerifyError(verr) {
		t.Error("typed verification error should count")
	}
}

func TestDnStringVariants(t *testing.T) {
	if got := dnString(pkix.Name{CommonName: "cn"}); got != "cn" {
		t.Errorf("got %q", got)
	}
	got := dnString(pkix.Name{CommonName: "cn", Organization: []string{"o1", "o2"}})
	if got != "cn, o1/o2" {
		t.Errorf("got %q", got)
	}
	if got := dnString(pkix.Name{Organization: []string{"org"}}); got != "org" {
		t.Errorf("org-only got %q", got)
	}
}

func TestDaysBetween(t *testing.T) {
	now := time.Now()
	if d := daysBetween(now, now.Add(26*time.Hour)); d != 1 {
		t.Errorf("d = %d", d)
	}
	if d := daysBetween(now, now.Add(-time.Hour)); d != 0 {
		t.Errorf("negative clamp = %d", d)
	}
}

func TestTLSVersionNames(t *testing.T) {
	for v, want := range map[uint16]string{
		tls.VersionTLS10: "1.0",
		tls.VersionTLS11: "1.1",
	} {
		if got := tlsVersionName(v); got != want {
			t.Errorf("%d = %q want %q", v, got, want)
		}
	}
}

func TestParseTargetMore(t *testing.T) {
	if _, err := ParseTarget("[::1"); err == nil {
		t.Error("want unclosed bracket error")
	}
	if _, err := ParseTarget("[]:443"); err == nil {
		t.Error("want empty IPv6 error")
	}
	if _, err := ParseTarget("[::1]:abc"); err == nil {
		t.Error("want bad IPv6 port error")
	}
	if _, err := ParseTarget(":8443"); err == nil {
		t.Error("want empty host error")
	}
	// https with trailing slash and port
	tg, err := ParseTarget("https://example.com:8443/")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Port != 8443 {
		t.Errorf("port = %d", tg.Port)
	}
}

func TestAddr(t *testing.T) {
	if got := (Target{Host: "127.0.0.1", Port: 9}).Addr(); got != "127.0.0.1:9" {
		t.Errorf("Addr = %q", got)
	}
}

func TestLoadPEMRootsNonCertBlock(t *testing.T) {
	dir := t.TempDir()
	p := writeTestFile(t, dir, "mixed.pem", "-----BEGIN RSA PRIVATE KEY-----\nQUJD\n-----END RSA PRIVATE KEY-----\n")
	if _, err := LoadPEMRoots(p, false); err == nil {
		t.Error("want no CERTIFICATE error")
	}
	// garbage DER inside a CERTIFICATE block
	p2 := writeTestFile(t, dir, "garbage.pem", "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n")
	if _, err := LoadPEMRoots(p2, true); err == nil {
		t.Error("want parse error with system pool")
	}
}

func TestParseFileCertNilSerial(t *testing.T) {
	// certificates parsed from our own PEM always have a serial; ensure
	// serialString handles nil
	if got := serialString(nil); got != "" {
		t.Errorf("got %q", got)
	}
	_ = x509.Certificate{}
}

func writeTestFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := dir + "/" + name
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
