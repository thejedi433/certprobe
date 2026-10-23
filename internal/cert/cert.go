// Package cert probes TLS endpoints and inspects the presented certificate
// chain: expiry, issuer, subject, SAN hosts, signature algorithm, and the
// verification outcome. Pure stdlib.
package cert

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Result is the outcome of probing one endpoint.
type Result struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	SNI        string    `json:"sni,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	Subject    string    `json:"subject,omitempty"`
	Serial     string    `json:"serial,omitempty"`
	SANs       []string  `json:"sans,omitempty"`
	NotBefore  time.Time `json:"not_before,omitzero"`
	NotAfter   time.Time `json:"not_after,omitzero"`
	ValidNow   bool      `json:"valid_now"`
	DaysLeft   int       `json:"days_left"`
	Expired    bool      `json:"expired"`
	SigAlgo    string    `json:"sig_algorithm,omitempty"`
	ChainLen   int       `json:"chain_len"`
	Verified   bool      `json:"verified"`
	TLSVersion string    `json:"tls_version,omitempty"`
	Error      string    `json:"error,omitempty"`
	ProbeAt    time.Time `json:"probe_at,omitzero"`
}

// Target is one host to probe.
type Target struct {
	Host string
	Port int
	SNI  string // empty means Host
}

// Addr returns the TCP address for the target.
func (t Target) Addr() string { return net.JoinHostPort(t.Host, fmt.Sprint(t.Port)) }

// ParseTarget turns "host", "host:port", or "https://host/path" into a
// Target. Default port is 443.
func ParseTarget(s string) (Target, error) {
	orig := s
	s = strings.TrimSpace(s)
	if s == "" {
		return Target{}, errors.New("empty target")
	}
	// scheme://host[/...]
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
		if j := strings.IndexByte(s, '/'); j >= 0 {
			s = s[:j]
		}
	}
	// strip trailing FQDN dot
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return Target{}, fmt.Errorf("invalid target %q", orig)
	}
	if strings.HasPrefix(s, "[") {
		// IPv6 literal [::1] or [::1]:8443
		close := strings.IndexByte(s, ']')
		if close < 0 {
			return Target{}, fmt.Errorf("invalid IPv6 target %q", orig)
		}
		host := s[1:close] // store bare; net.JoinHostPort re-adds brackets
		port := 443
		if len(s) > close+1 {
			rest := strings.TrimPrefix(s[close+1:], ":")
			var p int
			if _, err := fmt.Sscanf(rest, "%d", &p); err != nil || p <= 0 || p > 65535 || fmt.Sprint(p) != rest {
				return Target{}, fmt.Errorf("invalid port in IPv6 target %q", orig)
			}
			port = p
		}
		if host == "" {
			return Target{}, fmt.Errorf("empty host in target %q", orig)
		}
		return Target{Host: host, Port: port}, nil
	}
	host := s
	port := 443
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		host = s[:i]
		rest := s[i+1:]
		var p int
		if _, err := fmt.Sscanf(rest, "%d", &p); err != nil || p <= 0 || p > 65535 || fmt.Sprint(p) != rest {
			return Target{}, fmt.Errorf("invalid port in target %q", orig)
		}
		port = p
	}
	if host == "" {
		return Target{}, fmt.Errorf("empty host in target %q", orig)
	}
	return Target{Host: host, Port: port}, nil
}

// Dial opens the TCP connection; replaceable in tests.
type Dial func(addr string) (net.Conn, error)

// tcpDial returns a plain TCP dialer with the given timeout.
func tcpDial(timeout time.Duration) Dial {
	return func(addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: timeout}
		return d.Dial("tcp", addr)
	}
}

// Probe connects to the target, performs a TLS handshake, and inspects the
// leaf certificate. Verification failures still yield a full Result with
// Verified=false plus the reason in Error, because an expired or untrusted
// cert is exactly what this tool must report.
func Probe(t Target, timeout time.Duration, rootCAs *x509.CertPool) (Result, error) {
	return probe(t, timeout, rootCAs, tcpDial(timeout))
}

func probe(t Target, timeout time.Duration, rootCAs *x509.CertPool, dial Dial) (Result, error) {
	if t.Host == "" {
		return Result{}, errors.New("empty host")
	}
	sni := t.SNI
	if sni == "" {
		sni = t.Host
	}
	addr := t.Addr()
	res := Result{Host: t.Host, Port: t.Port, SNI: sni, ProbeAt: time.Now().UTC()}

	// Step 1: verified handshake against the (system or custom) pool.
	conn, err := dial(addr)
	if err != nil {
		res.Error = fmt.Sprintf("dial: %v", err)
		return res, nil
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		res.Error = fmt.Sprintf("deadline: %v", err)
		return res, nil
	}
	cfg := &tls.Config{ServerName: sni, RootCAs: rootCAs, MinVersion: tls.VersionTLS12}
	tconn := tls.Client(conn, cfg)
	hsErr := tconn.Handshake()
	if hsErr == nil {
		res.Verified = true
		defer tconn.Close()
		if err := fillFromState(&res, tconn); err != nil {
			return res, nil
		}
		return res, nil
	}
	conn.Close()

	// Step 2: if the failure was certificate verification (expired,
	// untrusted, hostname mismatch), retry insecure to still read the cert.
	if !isVerifyError(hsErr) {
		res.Error = fmt.Sprintf("handshake: %v", hsErr)
		return res, nil
	}
	res.Verified = false
	res.Error = fmt.Sprintf("verify: %v", hsErr)
	conn2, err := dial(addr)
	if err != nil {
		return res, nil
	}
	if err := conn2.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn2.Close()
		return res, nil
	}
	cfg2 := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	tconn = tls.Client(conn2, cfg2)
	if hsErr := tconn.Handshake(); hsErr != nil {
		conn2.Close()
		res.Error = fmt.Sprintf("handshake: %v", hsErr)
		return res, nil
	}
	defer tconn.Close()
	if err := fillFromState(&res, tconn); err != nil {
		return res, nil
	}
	return res, nil
}

// fillFromState extracts certificate details from a completed handshake.
func fillFromState(res *Result, tconn *tls.Conn) error {
	state := tconn.ConnectionState()
	// ConnectionState before handshake completion returns zero certs; the
	// caller handshakes first, so we are safe here.
	res.TLSVersion = tlsVersionName(state.Version)
	if len(state.PeerCertificates) == 0 {
		res.Error = "no peer certificate"
		return errors.New("no peer certificate")
	}
	leaf := state.PeerCertificates[0]
	res.ChainLen = len(state.PeerCertificates)
	res.Subject = dnString(leaf.Subject)
	res.Issuer = dnString(leaf.Issuer)
	res.Serial = leaf.SerialNumber.String()
	res.NotBefore = leaf.NotBefore.UTC()
	res.NotAfter = leaf.NotAfter.UTC()
	res.SigAlgo = leaf.SignatureAlgorithm.String()
	sans := append([]string{}, leaf.DNSNames...)
	sort.Strings(sans)
	res.SANs = sans
	res.ValidNow = res.ProbeAt.Before(res.NotAfter) && !res.ProbeAt.Before(res.NotBefore)
	res.Expired = res.ProbeAt.After(res.NotAfter)
	res.DaysLeft = daysBetween(res.ProbeAt, res.NotAfter)
	return nil
}

func daysBetween(from, to time.Time) int {
	d := int(to.Sub(from) / (24 * time.Hour))
	if d < 0 {
		return 0
	}
	return d
}

func isVerifyError(err error) bool {
	var verr *tls.CertificateVerificationError
	if errors.As(err, &verr) {
		return true
	}
	return strings.Contains(err.Error(), "certificate")
}

func dnString(n pkix.Name) string {
	var sb strings.Builder
	if len(n.CommonName) > 0 {
		sb.WriteString(n.CommonName)
	}
	if len(n.Organization) > 0 {
		if sb.Len() > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(strings.Join(n.Organization, "/"))
	}
	return sb.String()
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// LoadPEMRoots reads a PEM bundle and returns a CertPool, appending to the
// system pool when includeSystem is true.
func LoadPEMRoots(path string, includeSystem bool) (*x509.CertPool, error) {
	var pool *x509.CertPool
	if includeSystem {
		pool, _ = x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
	} else {
		pool = x509.NewCertPool()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rest := data
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate in %s: %w", path, err)
		}
		pool.AddCert(c)
		found = true
	}
	if !found {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in %s", path)
	}
	return pool, nil
}

// ParseFileCert reads a certificate file (PEM or DER) and returns a Result,
// without any network access.
func ParseFileCert(path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var der []byte
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	} else {
		der = data
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return Result{}, fmt.Errorf("parse certificate %q: %w", path, err)
	}
	now := time.Now().UTC()
	sans := append([]string{}, c.DNSNames...)
	sort.Strings(sans)
	return Result{
		Host:      path,
		Subject:   dnString(c.Subject),
		Issuer:    dnString(c.Issuer),
		Serial:    serialString(c.SerialNumber),
		NotBefore: c.NotBefore.UTC(),
		NotAfter:  c.NotAfter.UTC(),
		SigAlgo:   c.SignatureAlgorithm.String(),
		SANs:      sans,
		ChainLen:  1,
		ValidNow:  now.Before(c.NotAfter) && !now.Before(c.NotBefore),
		Expired:   now.After(c.NotAfter),
		DaysLeft:  daysBetween(now, c.NotAfter),
		ProbeAt:   now,
	}, nil
}

func serialString(n *big.Int) string {
	if n == nil {
		return ""
	}
	return n.String()
}
