# certprobe

TLS certificate expiry prober with Nagios-style exit codes, built for cron
alerts and CI pipelines: "is any of my sites' certificates about to expire?"
answered in one line, machine-readable, zero dependencies.

Pure Go, stdlib only (`crypto/tls`, `crypto/x509`). Cross-platform:
Linux, macOS, Windows.

## Install

```sh
go install github.com/thejedi433/certprobe/cmd/certprobe@latest
```

## Usage

```sh
certprobe github.com google.com                     # probe hosts
certprobe -json example.com                         # JSON for dashboards
certprobe -warn-days 14 -crit-days 3 example.com    # custom thresholds
certprobe example.com:8443                          # non-default port
certprobe '@targets.txt'                            # host list from file
echo example.com | certprobe -                      # ...or stdin
certprobe -ca internal-ca.pem intranet.example      # custom root CA
certprobe -file /etc/letsencrypt/live/x/fullchain.pem  # local cert, no network
```

```
HOST:PORT       STATUS  DAYS  EXPIRES               VER  ISSUER
github.com:443  ok      37    2026-11-29T23:59:59Z  yes  Sectigo Public Server Authentication CA DV E36
git.example:443 crit    0     2026-10-15T09:21:02Z  no   Let's...                                    EXPIRED
mail.example:443 warn   9     2026-11-01T00:00:00Z  yes  R3
```

## Exit codes

| code | meaning                          |
|------|----------------------------------|
| 0    | all hosts healthy                |
| 1    | at least one host within warn-days |
| 2    | expired / expiring within crit-days / unreachable / unverified (with `-strict`) |
| 2    | usage or argument errors         |

A cron job is as simple as:

```cron
0 8 * * * certprobe '@/etc/certprobe/targets.txt' >/dev/null || logger certprobe-alert
```

## Behavior notes

- Expired or untrusted certificates are still fetched and reported (the tool
  re-dials skipping verification) — an expired cert is precisely what you
  want to see, not something the handshake should hide.
- `VER=no` means the system (or your `-ca` bundle) does not trust the chain;
  with `-strict` that alone is crit.
- `days_left` counts from probe time to `not_after` on the leaf certificate.
- Only TLS 1.2+ handshakes are attempted (`MinVersion`), matching current
  industry norms; older/negotiated-down endpoints surface as handshake errors.

## Flags

```
-warn-days N    warn when expiry is within N days (default 21)
-crit-days N    crit when expiry is within N days (default 7)
                must be < warn-days
-timeout dur    per-connection timeout (default 10s)
-parallel N     concurrent probes, 1-64 (default 8)
-ca file        PEM bundle of extra roots to trust
-file path      check local certificate file(s) (PEM or DER), no network
-strict         unverified chain is crit instead of warn
-json           JSON output instead of the table
```

## Development

```sh
go test -race -cover ./...
gofmt -l .   # must print nothing
go vet ./...
```

## License

MIT
