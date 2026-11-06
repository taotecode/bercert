---
name: upyun-api
description: Operate Upyun (又拍云) buckets, CDN domains and HTTPS certificates. Reading uses api.upyun.com with a bearer token; certificate upload/bind/migration requires the console session at console.upyun.com.
---

# Upyun API

Two different surfaces:

- `https://api.upyun.com` — open API, bearer token (`Authorization: Bearer <token>`). Certificates are **read-only** here.
- `https://console.upyun.com` — console API, account session cookies. This is the only supported way to upload, bind and migrate certificates.

## Reading certificates (open API)

Create a token with form data:

```bash
curl -X POST https://api.upyun.com/oauth/tokens \
  -d username="$UPYUN_USERNAME" -d password="$UPYUN_PASSWORD" \
  -d "code=$(openssl rand -hex 16)" -d "name=bercert" -d scope=global
```

`access_token` is returned once. Scope enum: `global,bucket,operator,domain,cache,log,stats,oauth,security,srs`.

| Method | Path | Notes |
|---|---|---|
| GET | `/buckets?limit=100&page=1` | buckets, `https` function state, `domains[]` |
| GET | `/buckets/domains?bucket_name=X&page=1&limit=50` | domains for a bucket |
| GET | `/https/certificate/list?limit=100&domain=...` | map keyed by cert ID; `validity.end` in **milliseconds** |
| GET | `/https/certificate/info?crt_id=...` | one certificate |
| GET | `/https/services/manager?domain=...` | bindings: `certificate_id`, `https`, `force_https`, `source_https`, `validity` |

`https:true` on a binding means the certificate is configured for the domain. The **bucket-level** `https` field is the HTTPS acceleration function state (`enabled`/`disabled`) and is separate.

## Writing certificates (console session)

Sign in first; cookies carry the session:

```http
POST https://console.upyun.com/accounts/signin/
Content-Type: application/json

{"username":"...","password":"..."}
```

Success is `{"data":{"result":true}}`.

Then:

| Method | Path | Body / response |
|---|---|---|
| POST | `/api/https/certificate/` | `{"certificate": PEM, "private_key": PEM}` → `data.result.certificate_id` |
| POST | `/api/https/certificate/manager/` | `{"certificate_id","domain","https":true,"force_https","source_https"}` |
| POST | `/api/https/migrate/certificate` | replace a certificate: `{"old_crt_id","new_crt_id"}` |
| POST | `/api/https/migrate/domain` | fallback when bind returns code `21713`: `{"crt_id","domain_name"}` |
| GET | `/api/https/services/manager?domain=...` | `data.result[]` with the same binding fields |

Errors are reported inside `data` (`{"error_code":21713,"message":"..."}`) with HTTP 200, so check `error_code`, not only status.

## Certificate replacement flow

1. Upload the new certificate → new certificate ID.
2. Migrate every HTTPS domain from the old certificate to the new one:
   `POST /api/https/migrate/certificate` with `{"old_crt_id": old, "new_crt_id": new}`.
3. Poll `GET /api/https/services/manager?domain=...` until the domain reports the new certificate with `https:true`.

This is the console's “域名 HTTPS 配置迁移” flow; never submit the same migration twice.

## Why the console is required

The open API token, even with `scope=global`, returns on upload:

```json
{"type":"AccessDenied","error_code":"22308","message":"Insufficient authority caused by scope"}
```

The endpoint declares `x-scope: https`, but `https` is not an accepted value for `/oauth/tokens` (`No enum match for: https`). The console session is the working path used by bercert (`internal/upyun/console.go`).

## ECC private keys and edge TLS

Upyun's edge requires an ECDSA private key in **SEC1** form:

```text
-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----
```

1Panel returns PKCS#8 (`BEGIN PRIVATE KEY`). Uploading that form binds the certificate in the console but the edge cannot load it, so the domain returns a TLS `handshake_failure` with no certificate. Convert the PKCS#8 ECDSA key to SEC1 before uploading (`internal/certutil.ECKeyForUpyun` does this automatically).

Upyun deduplicates by **certificate chain content**, ignoring the key: re-uploading an already-known certificate returns its old ID and does **not** replace a PKCS#8 key. To fix an existing PKCS#8 upload, upload a certificate with a new serial (or a different valid chain) so Upyun creates a new record, then migrate the domain to it.

The bucket-level `https` field describes the default domain, not custom-domain HTTPS. A `disabled` value does not by itself prevent custom domains from serving certificates.

`internal/certutil.ProbeTLS` and `VERIFY_TLS=true` verify the real edge certificate.

## Gotchas

- `validity.end` is milliseconds in certificate list and bindings; `created_at` is seconds.
- Test domains (`*.test.upcdn.net`) appear in `/buckets`; exclude them.
- Certificate upload needs a matching key and valid chain.
- A wildcard `*.example.com` does not cover `a.b.example.com`.
- Repeated open-API calls can return `21000 RepeatCallInterface`; back off 2–4 s. The client retries twice.
- Console uploads create new certificate records each time; bercert reuses one by matching `NotAfter` from the open-API list.
