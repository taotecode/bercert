---
name: qiniu-cdn-api
description: Operate Qiniu Cloud CDN domains and certificates through the Fusion API (fusion.qiniuapi.com) and the domain API (api.qiniu.com). Use for listing domains, reading bound certificate expiry, uploading certificates, and enabling or replacing HTTPS.
---

# Qiniu CDN API

Credentials: `QINIU_AK` / `QINIU_SK`.

Two hosts, two **non-interchangeable** auth schemes:

| Host | Header | Signs |
|---|---|---|
| `api.qiniu.com` | `Authorization: Qiniu <AK>:<sig>` | full request (method, path, host, content-type, X-Qiniu-* headers, body) |
| `fusion.qiniuapi.com` | `Authorization: QBox <AK>:<sig>` | `path?query\n` only for JSON requests |

Signature: `urlsafe_base64(HMAC-SHA1(data, SK))`, prepend `AK:`. URL-safe base64 keeps `=` and maps `+`→`-`, `/`→`_`.

## Qiniu scheme (`api.qiniu.com`)

Signing text, in order:

```text
{Method} {PathWithQuery}
Host: api.qiniu.com
Content-Type: application/json        # only when a body exists
X-Qiniu-Date: 20260213T120000Z        # UTC, ±30s; also sent as a header
<blank line>
{body}                                # byte-for-byte the sent JSON
```

## QBox scheme (`fusion.qiniuapi.com`)

Signing text is exactly `{path}{?query}\n`. JSON body is **not** signed. Query order/empty values must match the URL (`?marker=&limit=10` signs with the empty `marker`). Wrong query → 401.

## Verified endpoints

Certificate management (QBox, host `fusion.qiniuapi.com`):

| Method | Path | Request / response |
|---|---|---|
| GET | `/sslcert?marker=&limit=100` | `certs[]` with `certid`, `name`, `common_name`, `dnsnames`, `not_before`, `not_after` |
| GET | `/sslcert/{certId}` | `cert` incl. `pri`, `ca` |
| POST | `/sslcert` | `{"name","pri","ca"}` → `{"certID":"..."}` |
| DELETE | `/sslcert/{certId}` | only when unbound |

Domain management (Qiniu scheme, host `api.qiniu.com`):

| Method | Path | Notes |
|---|---|---|
| GET | `/domain?limit=100` | list; no `marker` → no pagination |
| GET | `/domain/{name}` | includes `protocol` and `https.{certId,forceHttps,http2Enable,tlsVersions}` |
| PUT | `/domain/{name}/sslize` | enable HTTPS first time; body `certId`, `forceHttps`, `http2Enable`, optional `tlsVersions` |
| PUT | `/domain/{name}/httpsconf` | replace certificate on an already-HTTPS domain; same body |

`tlsVersions` must be a **JSON array** (`["TLSv1.1","TLSv1.2","TLSv1.3"]`). The docs show a slash-separated string, but the API returns `cannot unmarshal string into ... []fusion.TlsVersion` if you send one.

## Verified data shape

`GET /domain/{name}` returns:

```json
{"protocol":"https","https":{"certId":"68ba56a1ee89e2d3d077d079","forceHttps":false,"http2Enable":true,"tlsVersions":["TLSv1.0","TLSv1.1","TLSv1.2","TLSv1.3"]}}
```

`not_after` is Unix seconds. Certificates uploaded but unbound stay in `/sslcert` forever; a bound cert is only visible through the domain's `https.certId`.

## Gotchas

- `GET /domain` does **not** include `https`; fetch `/domain/{name}` for the bound cert ID.
- Upload requires a full chain (`ca` = leaf + intermediates), matching private key, valid dates; failures: `400323` chain, `400324` key mismatch, `400325` parse.
- If the domain is not on HTTPS, `httpsconf` fails (`400302`) — must call `sslize` first.
- Binding takes 5–10 minutes to reach the edge; API state changes immediately.
- QPS limit 10. Use only UTC time within ±30 seconds.
- Wildcard certs cover their domains; do not upload duplicates.

`internal/qiniu/qiniu.go` implements both schemes; `internal/qiniu/qiniu_test.go` pins the signing strings.
