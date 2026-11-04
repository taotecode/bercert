---
name: upyun-api
description: Operate Upyun (又拍云) buckets, CDN domains and HTTPS certificates through api.upyun.com. Use when listing Upyun domains, inspecting bound certificate validity, uploading a certificate, or binding HTTPS.
---

# Upyun Service API

Base: `https://api.upyun.com`. Auth: `Authorization: Bearer <token>`.

## Creating a token

`POST /oauth/tokens` with **form** fields (not JSON):

```bash
curl -X POST https://api.upyun.com/oauth/tokens \
  -d username="$UPYUN_USERNAME" -d password="$UPYUN_PASSWORD" \
  -d "code=$(openssl rand -hex 16)" -d "name=ber-autocert" -d scope=global
```

`code` is a 20–32 char alphanumeric/dash string, unique per request. `name` ≤20 chars. Scope enum: `global,bucket,operator,domain,cache,log,stats,oauth,security,srs`. Response contains `access_token` **once** — store it (`UPYUN_TOKEN`). Max 10 tokens per account.

The official spec is at `https://api.upyun.com/doc/spec` (Swagger 2.0, discovered via `window.SPEC_PATH` in the SPA). It documents only the read endpoints for HTTPS.

## Verified read endpoints

| Method | Path | Notes |
|---|---|---|
| GET | `/buckets?limit=100&page=1` | buckets with `bucket_name`, `https` state and `domains[]` |
| GET | `/buckets/domains?bucket_name=X&page=1&limit=50` | domain list for one bucket |
| GET | `/https/certificate/list?limit=100&domain=...` | `result` is a map keyed by cert ID; `validity.end` in **milliseconds** |
| GET | `/https/certificate/info?crt_id=...` | one certificate |
| GET | `/https/services/manager?domain=...` | bindings; each has `certificate_id`, `https`, `force_https`, `source_https`, `validity` |

`https` on a binding means "this certificate is active for the domain". A bucket can be `"https":"disabled"` in `/buckets` while old cert bindings still exist.

## Undocumented write endpoints (server-verified)

These are not in the public spec but the handler rejects requests field-by-field, which reveals the contract:

| Method | Path | Required fields |
|---|---|---|
| POST | `/https/certificate` | `certificate` (PEM chain), `private_key` (PEM) |
| PUT | `/https/certificate` | `certificate_id` plus replacement `certificate` / `private_key` |
| POST | `/https/services/manager` | `domain`, `certificate_id`, plus `https`, `force_https`, `source_https` booleans |

Responses use `{"status":0,...}` on success. Errors look like:

```json
{"type":"InvalidParameter","error_code":"41001","field":"private_key","message":"Invalid parameter (private_key): Value is required but was not provided"}
```

**Important caveat:** a token created with `scope=global` could read everything but `POST /https/certificate` returned:

```json
{"type":"AccessDenied","error_code":"22308","message":"Insufficient authority caused by scope"}
```

Creating a token with `scope=https` is rejected (`No enum match for: https`), even though the endpoint declares `x-scope: https`. If write calls fail this way, create the API key in the Upyun console (API Key / 证书管理 scope) or fall back to the console. GET endpoints are unaffected.

## Gotchas

- `validity.end` is milliseconds in certificate list and bindings; `created_at` is seconds.
- Upyun test domains (`*.test.upcdn.net`) are always present in `/buckets`; exclude them from automation.
- Certificate upload needs a matching key and full chain; incomplete chains cause browser warnings.
- A wildcard `*.example.com` does not cover `a.b.example.com`.
- Binding to a domain that has never had HTTPS may require the bucket's HTTPS feature; bind with `https:true`.
- Repeated calls in quick succession return `21000 RepeatCallInterface` (HTTP 403). Back off 2–4 s and retry; `internal/upyun/upyun.go` retries twice automatically.

`internal/upyun/upyun.go` implements these calls.
