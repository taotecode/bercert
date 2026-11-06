# bercert

Keep Qiniu and Upyun CDN certificates in sync with [1Panel](https://1panel.cn/).

`bercert` checks the certificate each CDN domain actually serves against the certificate store in 1Panel. When a certificate is expired, missing, or close to expiry, it uploads a matching certificate from 1Panel and binds it to the domain. If no certificate covers the domain, it asks 1Panel to issue one (ACME DNS-01 or HTTP-01) and retries failed orders until they succeed.

## Features

- Qiniu CDN and Upyun CDN support
- Exact-SAN and single-label wildcard matching
- Read-only `scan` and `renew --dry-run`
- Certificate issuance through 1Panel when nothing covers a domain
- Retry with backoff until issuance succeeds
- Built-in daily scheduler in the server's local timezone; failed runs retry every 10 minutes
- Reuses already-uploaded certificates to avoid duplicates
- Verifies the binding through the provider API before reporting success
- No external dependencies — single static binary

## How it works

1. Read all certificates (PEM + private key) and ACME/DNS accounts from 1Panel.
2. Read each CDN domain's bound certificate and expiry from Qiniu/Upyun.
3. Decide: healthy, renew, issue, or no certificate.
4. Upload (or reuse) and bind, then re-read the domain to verify.

## Install

Download a release binary, or build from source:

```bash
go build -trimpath -o bin/bercert ./cmd/bercert
```

Cross-compile for a Linux server:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/bercert-linux-amd64 ./cmd/bercert
```

## Configure

Copy `.env.example` to `.env` (gitignored) and fill in the values:

| Variable | Meaning |
|---|---|
| `PANEL_BASE_URL` | 1Panel base URL, e.g. `https://panel.example.com` |
| `PANEL_API_KEY` | 1Panel API key |
| `PANEL_ISSUE_CERT` | request certificates from 1Panel when none covers a domain |
| `PANEL_ACME_ACCOUNT_ID` | ACME account ID; empty = first account |
| `PANEL_DNS_ACCOUNT_ID` | DNS account ID for DNS-01; empty = first account |
| `PANEL_ISSUE_TIMEOUT` | how long to wait for one issuance attempt (default `15m`) |
| `PANEL_ISSUE_RETRIES` | issuance attempts per run (default `3`, `0` = unlimited) |
| `PANEL_ISSUE_RETRY_DELAY` | delay between issuance attempts (default `2m`) |
| `QINIU_AK` / `QINIU_SK` | Qiniu keys |
| `UPYUN_TOKEN` | Upyun bearer token for reading certificate state |
| `UPYUN_USERNAME` / `UPYUN_PASSWORD` | Upyun console account, required for upload/bind |
| `RENEW_BEFORE_DAYS` | renew when remaining validity is below this many days (default `30`) |
| `VERIFY_TLS` | probe the real edge certificate over TLS (recommended when not behind a proxy) |
| `TLS_PROBE_TIMEOUT` / `EDGE_WAIT_TIMEOUT` | per-probe timeout and how long to wait for edge propagation |
| `INCLUDE_DOMAINS` / `EXCLUDE_DOMAINS` | comma-separated allow/deny lists |

Optional binding flags: `QINIU_FORCE_HTTPS`, `QINIU_HTTP2`, `QINIU_TLS_VERSIONS`, `UPYUN_FORCE_HTTPS`, `UPYUN_SOURCE_HTTPS`.

Create an Upyun token:

```bash
curl -X POST https://api.upyun.com/oauth/tokens \
  -d username="$UPYUN_USERNAME" -d password="$UPYUN_PASSWORD" \
  -d "code=$(openssl rand -hex 16)" -d "name=bercert" -d scope=global
```

Store the returned `access_token` in `UPYUN_TOKEN`.

## Usage

```bash
bercert doctor                  # read-only credential check
bercert scan                    # report only
bercert renew --dry-run         # show planned changes
bercert renew                   # apply
bercert schedule --at 04:17     # daily at 04:17 server-local time
bercert daemon --interval 24h   # simple loop instead
bercert version
```

Common flags: `--provider qiniu|upyun|all`, `--domain a.com,b.com`, `--renew-before 30d`, `--force`, `--issue`, `--no-issue`, `--retry-until-success`, `--allow-uncovered`, `--json`.

`RENEW_BEFORE_DAYS=30` renews anything the providers consider "under 30 days"; use `15` for a tighter window or `0` to only replace already-expired certificates. `--renew-before 15d` overrides the env value for one run.

Exit codes: `0` healthy/no action needed, `1` action pending, failure, or a certificate that cannot be covered.

## Scheduling

`bercert schedule` runs once at startup, then every day at `--at` using `time.Local` (the server timezone). A run with failures is retried after `--failure-retry` (default `10m`) until it succeeds, then the daily cadence resumes.

### systemd

`deploy/bercert.service` is a `Type=simple` unit that runs the scheduler with `Restart=always`.

```bash
scp bin/bercert-linux-amd64 root@panel-host:/tmp/bercert
scp .env root@panel-host:/tmp/bercert.env
scp -r deploy root@panel-host:/tmp/bercert-deploy
ssh root@panel-host '/tmp/bercert-deploy/install.sh /tmp/bercert /tmp/bercert.env'
```

The installer places the binary and a `0600` `.env` in `/opt/bercert`, removes an old `bercert.timer` if present, and enables the service.

```bash
systemctl status bercert.service
journalctl -u bercert.service -f
systemctl restart bercert.service
```

## Security

- `.env` and certificate material are gitignored; never commit them.
- The 1Panel API key and provider secrets should be restricted to the hosts that run bercert.
- `scan` and `renew --dry-run` are read-only. Use `--no-issue` if certificate creation must stay manual.
- Provider credentials need only certificate/domain permissions, not account-wide admin access.

## Limitations

- Upyun's open API token can read certificate state but returns `22308 Insufficient authority caused by scope` for writes. bercert therefore signs in to `console.upyun.com` with `UPYUN_USERNAME`/`UPYUN_PASSWORD` to upload, bind and migrate; the token is only used for reads.
- Upyun also requires the bucket's HTTPS acceleration function to be enabled. A bound certificate alone does not make the edge serve TLS: with `https: disabled` on the bucket the edge answers a TLS handshake failure (`21701` means the “自主域名 HTTPS 服务” has not been activated). `VERIFY_TLS=true` reports this as `edge-error` instead of healthy.
- Wildcards cover exactly one label: `*.example.com` does not cover `a.b.example.com`.
- Qiniu bindings can take 5–10 minutes to reach the edge; verification uses the provider API, not TLS.
- 1Panel issuance requires a configured ACME account and, for DNS-01, a DNS account with permission for the domain's zone.

## License

MIT — see [LICENSE](LICENSE).
