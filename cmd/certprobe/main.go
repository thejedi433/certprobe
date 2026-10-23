// Command certprobe checks TLS certificate expiry on hosts and exits with a
// Nagios-style status code (0 ok, 1 warn, 2 crit), so it can drive cron
// alerts and CI pipelines. Pure Go, stdlib only.
//
// Usage:
//
//	certprobe [-json] [-warn-days N] [-crit-days N] [-timeout d] [-parallel N] [-ca file] [-strict] [-file cert.pem] HOST[:PORT] [HOST[:PORT]...]
package main

import (
	"bufio"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/thejedi433/certprobe/internal/cert"
	"github.com/thejedi433/certprobe/internal/report"
)

func main() {
	code, err := run(os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "certprobe:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

// run parses args, probes targets (or parses files), writes output, and
// returns the process exit code. Output is flushed before returning on all
// paths so buffered data is never lost, including warn/crit exits.
func run(args []string, stdout io.Writer) (int, error) {
	out := bufio.NewWriter(stdout)
	fs := flag.NewFlagSet("certprobe", flag.ContinueOnError)
	fs.SetOutput(out)
	warnDays := fs.Int("warn-days", 21, "warn when expiry is within N days")
	critDays := fs.Int("crit-days", 7, "crit when expiry is within N days")
	timeout := fs.Duration("timeout", 10*time.Second, "per-connection timeout")
	parallel := fs.Int("parallel", 8, "concurrent probes (1-64)")
	caFile := fs.String("ca", "", "PEM bundle of extra roots to trust")
	asFile := fs.String("file", "", "check a local certificate file (PEM/DER) instead of the network")
	strict := fs.Bool("strict", false, "unverified chain is crit, not warn")
	jsonMode := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		_ = out.Flush() // flag package wrote usage into out
		return 2, err
	}
	if *warnDays <= *critDays {
		_ = out.Flush()
		return 2, fmt.Errorf("-warn-days (%d) must be greater than -crit-days (%d)", *warnDays, *critDays)
	}
	if *parallel < 1 || *parallel > 64 {
		_ = out.Flush()
		return 2, fmt.Errorf("-parallel must be 1-64")
	}

	var results []cert.Result
	var err error
	if *asFile != "" || (fs.NArg() > 0 && looksLikeFile(fs.Arg(0))) {
		results, err = fileResults(fs.Args(), *asFile)
	} else {
		results, err = probeResults(fs, *timeout, *caFile, *parallel)
	}
	if err != nil {
		_ = out.Flush()
		return 2, err
	}

	lines := report.Lines(results, *warnDays, *critDays, *strict)
	code := report.ExitCode(lines)
	if *jsonMode {
		err = report.WriteJSON(out, lines, false)
	} else {
		err = report.Table(out, lines)
	}
	if ferr := out.Flush(); ferr != nil && err == nil {
		return 2, ferr
	}
	if err != nil {
		return 2, err
	}
	return code, nil
}

func probeResults(fs *flag.FlagSet, timeout time.Duration, caFile string, parallel int) ([]cert.Result, error) {
	targets, err := parseTargets(fs.Args())
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		fs.Usage()
		return nil, fmt.Errorf("no targets given")
	}
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	return probeAll(targets, timeout, pool, parallel), nil
}

func fileResults(args []string, fileFlag string) ([]cert.Result, error) {
	paths := args
	if fileFlag != "" {
		paths = append([]string{fileFlag}, paths...)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("-file requires a certificate path")
	}
	var results []cert.Result
	for _, p := range paths {
		r, err := cert.ParseFileCert(p)
		if err != nil {
			return nil, err
		}
		results = append(results, r)
	}
	return results, nil
}

// looksLikeFile distinguishes a local certificate path from a host spec.
func looksLikeFile(arg string) bool {
	if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "./") || strings.HasPrefix(arg, "../") ||
		strings.HasSuffix(arg, ".pem") || strings.HasSuffix(arg, ".crt") || strings.HasSuffix(arg, ".der") {
		return true
	}
	// Windows absolute path like C:\... (a port suffix would need digits after ':')
	if len(arg) >= 2 && arg[1] == ':' && ((arg[0] >= 'A' && arg[0] <= 'Z') || (arg[0] >= 'a' && arg[0] <= 'z')) {
		return true
	}
	return false
}

func loadPool(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	return cert.LoadPEMRoots(caFile, true)
}

// parseTargets expands positional args; "-" reads a list from stdin and
// "@file" reads a list from a file (one target per line, # comments ok).
func parseTargets(args []string) ([]cert.Target, error) {
	var targets []cert.Target
	add := func(r io.Reader, src string) error {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			t, err := cert.ParseTarget(line)
			if err != nil {
				return fmt.Errorf("%s: %w", src, err)
			}
			targets = append(targets, t)
		}
		return sc.Err()
	}
	for _, a := range args {
		if a == "-" {
			if err := add(os.Stdin, "stdin"); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(a, "@") {
			f, err := os.Open(a[1:])
			if err != nil {
				return nil, err
			}
			err = add(f, a[1:])
			f.Close()
			if err != nil {
				return nil, err
			}
			continue
		}
		t, err := cert.ParseTarget(a)
		if err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

func probeAll(targets []cert.Target, timeout time.Duration, pool *x509.CertPool, parallel int) []cert.Result {
	results := make([]cert.Result, len(targets))
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t cert.Target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r, _ := cert.Probe(t, timeout, pool)
			results[i] = r
		}(i, t)
	}
	wg.Wait()
	return results
}
