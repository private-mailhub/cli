# mailhub-cli

Command-line interface for [Mailhub](https://private-mailhub.com).

## Install

Build the binary with Go 1.27 or newer on macOS:

```sh
go build -o mailhub ./cmd/mailhub
```

The CLI stores its API key in the macOS Keychain under the service
`private-mailhub.mailhub-cli` and account `default`. Non-secret metadata is stored in
`mailhub/config.json` below the platform user configuration directory (normally
`~/Library/Application Support` on macOS) with 0600 permissions.

## Commands

```text
mailhub auth login [--no-browser]
mailhub auth status
mailhub auth logout
mailhub auth keys list [--json]
mailhub auth keys revoke <key-id>
mailhub alias list [--json]
mailhub alias create [--label <label>] [--json]
mailhub alias on <id-or-email>
mailhub alias off <id-or-email>
mailhub alias label <id-or-email> <label>
mailhub alias label <id-or-email> --clear
mailhub completion <zsh|bash|fish>
mailhub version
```

`auth login` uses the device authorization flow. Use `--no-browser` to print the verification URL
and user code without launching a browser. API requests use `https://private-mailhub.com` by default;
`MAILHUB_API_URL` and `MAILHUB_TOKEN` override the configured endpoint and Keychain credential.

The CLI never prints or logs the raw API key. Successful commands exit with 0, API and network
errors with 1, invalid arguments with 2, and missing or expired authentication with 3.
