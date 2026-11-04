---
name: upyun-api
description: Operate Upyun (又拍云) buckets, CDN domains and HTTPS certificates. Reading uses api.upyun.com with a bearer token; certificate upload/bind requires the console session at console.upyun.com.
---

# Upyun API

Two different surfaces:

- `https://api.upyun.com` — open API, bearer token (`Authorization: Bearer <token>`). Certificates are **read-only** here.
- `https://console.upyun.com` — console API, account session cookies. This is the only supported way to upload and bind certificates.

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
| GET | `/buckets?limit=100&page=1` | buckets, HTTPS state, `domains[]` |
| GET | `/buckets/domains?bucket_name=X&page=1&limit=50` | domains for a bucket |
| GET | `/https/certificate/list?limit=100&domain=...` | map keyed by cert ID; `validity.end` in **milliseconds** |
| GET | `/https/certificate/info?crt_id=...` | one certificate |
| GET | `/https/services/manager?domain=...` | bindings: `certificate_id`, `https`, `force_https`, `source_https`, `validity` |

`https:true` on a binding means that certificate is active for the domain.

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
| POST | `/api/https/migrate/domain` | fallback when bind returns code `21713`: `{"crt_id","domain_name"}` |
| GET | `/api/https/services/manager?domain=...` | `data.result[]` with the same binding fields |

Errors are reported inside `data` (`{"error_code":21713,"message":"..."}`) with HTTP 200, so check `error_code`, not only status.

## Why the console is required

The open API token, even with `scope=global`, returns on upload:

```json
{"type":"AccessDenied","error_code":"22308","message":"Insufficient authority caused by scope"}
```

The endpoint declares `x-scope: https`, but `https` is not an accepted value for `/oauth/tokens` (`No enum match for: https`). The console session is the working path used by bercert (`internal/upyun/console.go`).

## Gotchas

- `validity.end` is milliseconds in certificate list and bindings; `created_at` is seconds.
- Test domains (`*.test.upcdn.net`) appear in `/buckets`; exclude them.
- Certificate upload needs a matching key and full chain.
- A wildcard `*.example.com` does not cover `a.b.example.com`.
- Repeated open-API calls can return `21000 RepeatCallInterface`; back off 2–4 s. The client retries twice.
- Console uploads create new certificate records each time; bercert reuses one by matching `NotAfter` from the open-API list.
