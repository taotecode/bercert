# Contributing

Thanks for helping improve bercert.

## Development

```bash
git clone https://github.com/taotecode/bercert.git
cd bercert
cp .env.example .env    # optional; tests do not need credentials
go test ./...
go vet ./...
go build ./...
```

## Guidelines

- Keep the code dependency-free unless a dependency is clearly justified.
- Add tests for decision logic, signing, and argument handling.
- Never commit credentials, private keys, `logo/`, or `.env`.
- Run `gofmt -w .` before submitting.
- API clients should stay small and isolated by provider (`internal/panel`, `internal/qiniu`, `internal/upyun`).

## Pull requests

Describe the provider/API behavior you verified and include relevant API error codes. For new providers, add a client package, provider-specific tests, and a skill under `.claude/skills/`.
