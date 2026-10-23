package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testCA mints self-signed certificates for tests.
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	pool    *x509.CertPool
	tlsC    tls.Certificate
	certPEM []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "certprobe-test-ca", Organization: []string{"Test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &testCA{cert: c, key: key, pool: pool, tlsC: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf mints a server certificate for host signed by the CA, expiring in
// daysFromNow (negative for already expired).
func (ca *testCA) leaf(t *testing.T, host string, daysFromNow int) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(daysFromNow) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serve starts a TLS server on a random port presenting cert for SNI host.
func serve(t *testing.T, cert tls.Certificate, host string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
			// complete handshake so client gets certs, then close
			_ = tc.Handshake()
			tc.Close()
		}
	}()
	return ln.Addr().String()
}

func TestProbeValidCert(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, "localhost", 30)
	addr := serve(t, leaf, "localhost")
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	res, err := Probe(Target{Host: "localhost", Port: port}, 5*time.Second, ca.pool)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatalf("want verified, got error: %s", res.Error)
	}
	if !res.ValidNow {
		t.Errorf("want ValidNow")
	}
	if res.Expired {
		t.Errorf("want not expired")
	}
	if res.DaysLeft < 28 || res.DaysLeft > 30 {
		t.Errorf("DaysLeft = %d, want ~30", res.DaysLeft)
	}
	if res.TLSVersion != "1.3" && res.TLSVersion != "1.2" {
		t.Errorf("TLSVersion = %q", res.TLSVersion)
	}
	if res.Serial == "" {
		t.Error("empty serial")
	}
	if len(res.SANs) != 1 || res.SANs[0] != "localhost" {
		t.Errorf("SANs = %v", res.SANs)
	}
}

func TestProbeExpiredCert(t *testing.T) {
	ca := newTestCA(t)
	leaf := ca.leaf(t, "localhost", -5) // expired 5 days ago
	addr := serve(t, leaf, "localhost")
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	res, err := Probe(Target{Host: "localhost", Port: port}, 5*time.Second, ca.pool)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified {
		t.Error("expired cert must not verify")
	}
	if !res.Expired {
		t.Error("Expired must be true")
	}
	if res.ValidNow {
		t.Error("ValidNow must be false")
	}
	// cert details still readable via the insecure retry
	if res.NotAfter.IsZero() {
		t.Error("NotAfter should be populated even when unverified")
	}
	if res.Subject != "localhost" {
		t.Errorf("Subject = %q", res.Subject)
	}
}

func TestProbeWrongCA(t *testing.T) {
	ca := newTestCA(t)
	other := newTestCA(t)
	leaf := ca.leaf(t, "localhost", 10)
	addr := serve(t, leaf, "localhost")
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	// verify against *other* pool -> must fail verification but still parse
	res, _ := Probe(Target{Host: "localhost", Port: port}, 5*time.Second, other.pool)
	if res.Verified {
		t.Fatal("cert from foreign CA should not verify against this pool")
	}
	if !res.ValidNow {
		t.Error("cert itself is time-valid; ValidNow should still be true")
	}
}

func TestProbeDialError(t *testing.T) {
	// port 1 on loopback is reliably refused (no listener)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // now closed -> connection refused
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	res, _ := Probe(Target{Host: "127.0.0.1", Port: port}, time.Second, nil)
	if res.Error == "" {
		t.Fatal("want dial error")
	}
	if res.NotAfter.IsZero() {
		// fine — handshake never completed
	} else {
		t.Error("unexpected cert data on dial failure")
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		port  int
		isErr bool
	}{
		{"example.com", "example.com", 443, false},
		{"example.com:8443", "example.com", 8443, false},
		{"https://example.com/path", "example.com", 443, false},
		{"http://example.com:8080/x", "example.com", 8080, false},
		{"example.com.", "example.com", 443, false},
		{"[::1]", "::1", 443, false},
		{"[::1]:8443", "::1", 8443, false},
		{"127.0.0.1:9", "127.0.0.1", 9, false},
		{"", "", 0, true},
		{"example.com:0", "", 0, true},
		{"example.com:99999", "", 0, true},
		{"example.com:abc", "", 0, true},
	}
	for _, c := range cases {
		tgt, err := ParseTarget(c.in)
		if c.isErr {
			if err == nil {
				t.Errorf("ParseTarget(%q): want error, got %+v", c.in, tgt)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q): unexpected err %v", c.in, err)
			continue
		}
		if tgt.Host != c.host || tgt.Port != c.port {
			t.Errorf("ParseTarget(%q) = %s:%d, want %s:%d", c.in, tgt.Host, tgt.Port, c.host, c.port)
		}
	}
}

func TestParseFileCertPEM(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ParseFileCert(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject != "certprobe-test-ca, Test" {
		t.Errorf("Subject = %q", res.Subject)
	}
	if res.Expired || !res.ValidNow {
		t.Error("CA cert should be valid now")
	}
}

func TestParseFileCertDER(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.der")
	if err := os.WriteFile(p, ca.cert.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ParseFileCert(p)
	if err != nil {
		t.Fatal(err)
	}
	if res.Serial != "1" {
		t.Errorf("Serial = %q", res.Serial)
	}
}

func TestParseFileCertGarbage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(p, []byte("not a cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFileCert(p); err == nil {
		t.Fatal("want parse error")
	}
	if _, err := ParseFileCert(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("want file error")
	}
}

func TestLoadPEMRoots(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	p := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(p, ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := LoadPEMRoots(p, false)
	if err != nil {
		t.Fatal(err)
	}
	// probe the CA-signed server trusting only this pool
	leaf := ca.leaf(t, "localhost", 12)
	addr := serve(t, leaf, "localhost")
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	res, _ := Probe(Target{Host: "localhost", Port: port}, 5*time.Second, pool)
	if !res.Verified {
		t.Errorf("custom root pool should verify chain: %s", res.Error)
	}

	// garbage bundle
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("hello"), 0o600)
	if _, err := LoadPEMRoots(bad, false); err == nil {
		t.Error("want error for no CERTIFICATE blocks")
	}
	if _, err := LoadPEMRoots(filepath.Join(dir, "nope.pem"), true); err == nil {
		t.Error("want error for missing file")
	}
}

func TestSerialNilSafe(t *testing.T) {
	if got := serialString(nil); got != "" {
		t.Errorf("serialString(nil) = %q", got)
	}
}

func TestTLSVersionName(t *testing.T) {
	if tlsVersionName(tls.VersionTLS13) != "1.3" {
		t.Error("want 1.3")
	}
	if tlsVersionName(0x0500) != "0x0500" {
		t.Error("want hex fallback")
	}
}

func TestProbeEmptyHost(t *testing.T) {
	if _, err := Probe(Target{}, time.Second, nil); err == nil {
		t.Fatal("want error for empty host")
	}
}
