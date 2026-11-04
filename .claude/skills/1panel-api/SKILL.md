---
name: 1panel-api
description: Call the 1Panel v2 HTTP API with an API key to list SSL certificates, read PEM/private keys, and create or renew certificates through ACME (DNS or HTTP validation). Use when a task needs certificate material or certificate issuance from 1Panel.
---

# 1Panel v2 API

The panel base URL is configured with `PANEL_BASE_URL` (for example `https://panel.example.com`). Swagger at `/1panel/swagger/` requires a browser login session and cannot be used with an API key; the `/api/v2` JSON API can.

## Authentication

Every request needs two headers:

```text
1Panel-Token: md5("1panel" + PANEL_API_KEY + unix_seconds)
1Panel-Timestamp: unix_seconds
```

The timestamp must be the same integer used in the hash, in seconds (not milliseconds). Create the key under 1Panel `Settings > API Interface`.

```bash
TS=$(date +%s)
TOKEN=$(printf '1panel%s%s' "$PANEL_API_KEY" "$TS" | md5sum | cut -d' ' -f1)   # macOS: md5 -q
curl -s -H "1Panel-Token: $TOKEN" -H "1Panel-Timestamp: $TS" \
  "$PANEL_BASE_URL/api/v2/dashboard/base/os"
```

## Certificate endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v2/websites/ssl/search` | page certificates: `{"page":1,"pageSize":100}` |
| GET | `/api/v2/websites/ssl/{id}` | one certificate, incl. `pem`, `privateKey`, `status`, `message` |
| POST | `/api/v2/websites/ssl` | create a certificate record and start issuance |
| POST | `/api/v2/websites/ssl/obtain` | retry issuance for an existing record: `{"ID": id}` |
| POST | `/api/v2/websites/ssl/del` | delete: `{"ids":[id]}` |
| POST | `/api/v2/websites/ssl/upload` | import an existing PEM/key |

Certificate fields that matter: `id`, `primaryDomain`, `domains`, `pem`, `privateKey`, `status`, `message`, `expireDate`, `provider`, `acmeAccountId`, `dnsAccountId`, `keyType`, `autoRenew`.

`status`: `ready`, `applying`, `init`, `error`, `applyError`. Issuance is asynchronous — poll `/websites/ssl/{id}` until `ready` or an error state.

## Issuance accounts

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v2/websites/acme/search` | ACME accounts: `id`, `type` (`letsencrypt`, `zerossl`, ...), `keyType` |
| POST | `/api/v2/websites/dns/search` | DNS accounts: `id`, `name`, `type` (`TencentCloud`, ...) |

Create request body:

```json
{
  "primaryDomain": "cdn.example.com",
  "provider": "dnsAccount",
  "acmeAccountId": 3,
  "dnsAccountId": 1,
  "autoRenew": true,
  "keyType": "EC256",
  "description": "managed by bercert"
}
```

`provider` values: `dnsAccount` (DNS-01 via a configured DNS account), `http` (HTTP-01 through OpenResty), `dnsManual` (manual DNS records, not auto-issued). Response `data.id` is the certificate record ID.

## Gotchas

- Only `/api/v2/...` works with the API key. `/api/v1/...` and other paths may return an HTML "Access Temporarily Unavailable" page.
- The API returns HTTP 200 for some logical failures; check the JSON `code` (200 = success).
- `domains` is not authoritative for SANs — parse `pem` with x509 and use `DNSNames`.
- A wildcard `*.example.com` does **not** cover `a.b.example.com`; ensure requested names are exact when needed.
- Certificate records with `status` `error`/`applyError` can be retried with `/obtain`; ones stuck in `applying` return `InExecuting`.
- Issuing for a domain requires a DNS account with permission for its zone (for `dnsAccount`) or a reachable web server (for `http`).

The Go client in `internal/panel/panel.go` implements this API, including the async issue/poll/retry flow.
