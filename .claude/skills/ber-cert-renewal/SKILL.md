---
name: ber-cert-renewal
description: Run and maintain bercert, the Go automation that keeps Qiniu and Upyun CDN certificates in sync with 1Panel: it detects expired/missing certificates, asks 1Panel to issue missing ones, retries until success, then uploads and binds them. Use when operating the renewal daemon or adding a provider.
---

# bercert operation

bercert compares the certificate each CDN domain actually serves with the certificate store in 1Panel. When a certificate is expired, missing, or inside the renewal window, it either reuses a matching 1Panel certificate or asks 1Panel to issue one, then uploads and binds it to the CDN provider.

## Data flow

1. 1Panel v2 API (`[[1panel-api]]`) → certificates, ACME/DNS accounts, issuance.
2. Qiniu API (`[[qiniu-cdn-api]]`) / Upyun API (`[[upyun-api]]`) → domains and bound certificate expiry. Upyun reads use the open API token; upload/bind use a signed-in `console.upyun.com` session (`UPYUN_USERNAME`/`UPYUN_PASSWORD`).
3. Matching: exact SAN first, then the longest wildcard covering exactly one label; newest `NotAfter` breaks ties.
4. Action: upload (reuse an already-uploaded cert with the same `NotAfter`), bind, re-read the domain to verify.

When nothing covers a domain, `PANEL_ISSUE_CERT=true` makes bercert create an ACME order in 1Panel, poll until `ready`, and retry failed orders (`PANEL_ISSUE_RETRIES`, `PANEL_ISSUE_RETRY_DELAY`).

## Commands

```bash
bercert doctor             # read-only credential check for all three APIs
bercert scan               # read-only report; exit 1 if anything needs attention
bercert renew --dry-run    # show exactly what would change
bercert renew              # apply changes
bercert schedule --at 04:17  # built-in daily scheduler in server-local time
bercert daemon --interval 24h
bercert version
```

Useful flags: `--provider qiniu|upyun|all`, `--domain a.com,b.com`, `--renew-before 30d`, `--force`, `--issue`/`--no-issue`, `--retry-until-success`, `--allow-uncovered`, `--json`.

## Scheduling

`bercert schedule` runs once at startup (`--run-now`, default true), then every day at `--at` in the server's `time.Local` timezone. If a run reports failures it retries after `--failure-retry` (default 10 minutes) until a run succeeds, then goes back to the daily schedule. This satisfies "retry until success" without one bad domain blocking the rest.

`deploy/bercert.service` runs exactly this command under systemd with `Restart=always`. Install:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/bercert-linux-amd64 ./cmd/bercert
scp bin/bercert-linux-amd64 root@panel-host:/tmp/bercert
scp .env root@panel-host:/tmp/bercert.env
scp -r deploy root@panel-host:/tmp/bercert-deploy
ssh root@panel-host '/tmp/bercert-deploy/install.sh /tmp/bercert /tmp/bercert.env'
```

The installer moves the binary and a 0600 `.env` to `/opt/bercert`, replaces any old timer with the service. Logs: `journalctl -u bercert.service -f`.

## Notifications

When bercert renews a certificate it sends an **updated** notification; certificates near expiry without a completed renewal send **expiring**; renewal, issuance or edge verification failures send **failed**. Upyun is fully automatic as long as ECDSA keys are uploaded in SEC1 form (`EC PRIVATE KEY`); bercert converts 1Panel's PKCS#8 keys automatically.

- Feishu custom bot: `FEISHU_WEBHOOK` (+ `FEISHU_SECRET`)
- WeCom group robot: `WECOM_WEBHOOK`
- Email: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TO`, `SMTP_TLS`

Enable with `NOTIFY_ENABLED=true`, test with `bercert notify-test`. Notifications are deduplicated per unresolved `(provider, domain, reason, certificate)` in `NOTIFY_STATE_FILE`.

## Decision rules

- No HTTPS/certificate bound → renew (or issue if none covers it).
- Bound certificate expired → renew.
- Bound certificate expires within `RENEW_BEFORE_DAYS` → renew. The scheduler reads this from `.env`; `--renew-before 30d` overrides it per run. Set `30` to match provider "under 30 days" warnings, `0` to only replace expired certificates.
- 1Panel certificate not newer than the bound one → skip.
- No covering certificate and issuance disabled → `no-cert`.

## Safety

- `scan` and `renew --dry-run` never change provider or 1Panel state.
- `renew`/`schedule` create certificate orders when issuance is enabled; use `--no-issue` to keep it read-only for missing certificates.
- Provider edge propagation takes minutes; verification uses provider API state rather than TLS.
- Issued certificates are reused by exact `PrimaryDomain`, so a failed order is retried instead of duplicating records every run.
