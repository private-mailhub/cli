# mailhub-cli agent instructions

- This repository is a Go 1.27 Common CLI for Mailhub.
- Keep production code under `cmd/` and `internal/`; do not expose credentials or personal data in
  output, errors, or logs.
- Preserve the macOS Keychain service `private-mailhub.mailhub-cli` and account `default`.
- Keep config files at mode 0600 in a mode 0700 `mailhub` directory and update them atomically.
- Use `gofmt`, `go vet ./...`, `go test ./...`, and `go test -race ./...` before delivery.
- Keep API calls behind `internal/api` and command validation/output behind `internal/cli`.
- Write all code review feedback in English, including findings, explanations, summaries, and comments.
