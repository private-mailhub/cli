<p align="center">
  <img src="docs/logo.png" alt="Mailhub logo" width="120" />
</p>

<h1 align="center">Mailhub CLI</h1>

<p align="center">
  Manage your Mailhub relay addresses from the terminal.
</p>

<p align="center">
  <a href="https://private-mailhub.com">Mailhub</a> ·
  <a href="https://github.com/private-mailhub/cli">Source</a> ·
  <a href="https://github.com/private-mailhub/cli/issues">Issues</a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/private-mailhub/cli/ci.yml?branch=main&label=CI" alt="CI status" />
  <img src="https://img.shields.io/badge/Go-1.27-00ADD8.svg" alt="Go 1.27" />
  <img src="https://img.shields.io/badge/platform-macOS%20arm64%20%7C%20amd64-lightgrey.svg" alt="Supported platforms: macOS arm64 and amd64" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue.svg" alt="AGPL-3.0 license" /></a>
</p>

`mailhub` is the command-line client for [Mailhub](https://private-mailhub.com). Authenticate a
device through the browser, then manage relay email aliases and API keys without leaving your
terminal.

> **Early release:** the current CLI version is `0.1.0`. The supported release targets are macOS
> Apple Silicon (`arm64`) and Intel (`amd64`).

## Server compatibility

This CLI uses a device-authorization and API-key contract provided by Mailhub's
[`backend`](https://github.com/private-mailhub/backend) service, with browser approval provided by
[`frontend`](https://github.com/private-mailhub/frontend). The related backend and frontend pull
requests add these server and approval flows. Until both changes are merged and deployed together,
authentication, API-key, and alias commands cannot be used end-to-end against the production service.

Use those commands only with a Mailhub server that implements the contract above and accepts its API
keys for the relay endpoints. `mailhub version`, `mailhub completion`, and local help work without a
server.

## Contents

- [What you can do](#what-you-can-do)
- [Server compatibility](#server-compatibility)
- [Requirements](#requirements)
- [Install](#install)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [Credentials and security](#credentials-and-security)
- [Exit codes](#exit-codes)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## What you can do

- Sign in with a compatible Mailhub server's browser-based device authorization flow.
- List, create, enable, disable, and label relay email aliases on a compatible server.
- List and revoke API keys on a compatible server.
- Use `--json` output for scripts and automation where supported.
- Generate shell completions for Zsh, Bash, and Fish.

## Requirements

- macOS with Apple Silicon or Intel, including a working macOS Keychain.
- Go 1.27 or newer when building from source.
- A compatible Mailhub server and account. See [Server compatibility](#server-compatibility).

## Install

### Install with Homebrew

Homebrew builds the CLI from the tagged Go source for your Mac:

```bash
brew tap private-mailhub/cli https://github.com/private-mailhub/cli.git
brew install private-mailhub/cli/mailhub
mailhub version
```

The formula lives in [`Formula/mailhub.rb`](Formula/mailhub.rb) in this repository. The explicit tap
URL is required because this repository is named `cli`, without Homebrew's usual
`homebrew-` prefix. Homebrew updates the tap with `brew update`.

If you installed `mailhub` from the former `private-mailhub/tap` repository, switch to this tap:

```bash
brew uninstall private-mailhub/tap/mailhub
brew untap private-mailhub/tap
brew tap private-mailhub/cli https://github.com/private-mailhub/cli.git
brew install private-mailhub/cli/mailhub
```

Uninstalling the formula does not remove the CLI's Keychain credential or configuration file.

### Build from source

Clone the repository and build the binary:

```bash
git clone https://github.com/private-mailhub/cli.git
cd cli

go build -trimpath -o mailhub ./cmd/mailhub
./mailhub version
```

Place `mailhub` somewhere on your `PATH` when you are ready to use it without the `./` prefix.

### Install with Go

If your Go bin directory is already on `PATH`, you can install the command directly:

```bash
go install github.com/private-mailhub/mailhub-cli/cmd/mailhub@main
mailhub version
```

The Go module keeps its original `mailhub-cli` path for compatibility after the repository rename.

Prebuilt binaries are not published. Homebrew builds from source; you can also build or install the
CLI with Go directly.

## Quick start

Once `mailhub` is available on your `PATH` and you have a compatible server:

### 1. Authenticate

The default flow opens the Mailhub approval page in your browser:

```bash
mailhub auth login
```

For a remote shell or a machine without a browser, print the URL and one-time code instead:

```bash
mailhub auth login --no-browser
```

You can give the device a recognizable name:

```bash
mailhub auth login --device-name "Work Mac"
```

Open the printed URL, sign in to Mailhub, approve the request, and return to the terminal. The CLI
waits for approval and stores the resulting API key automatically.

### 2. Check authentication

```bash
mailhub auth status
```

### 3. Manage aliases

```bash
# List aliases
mailhub alias list

# Create an alias with an optional label
mailhub alias create --label newsletter

# Disable or enable an alias by ID or exact relay email
mailhub alias off 12
mailhub alias on 12

# Change or clear its label
mailhub alias label 12 shopping
mailhub alias label 12 --clear
```

### 4. Finish a session

With a Keychain credential, `logout` revokes the current API key on the server and removes the
local credential. With `MAILHUB_TOKEN`, it revokes that environment-supplied key but leaves any
saved Keychain credential unchanged:

```bash
mailhub auth logout
```

## Command reference

Run `mailhub <command> --help` for the authoritative help text and flags. All authentication,
API-key, and alias commands below require a compatible server; see
[Server compatibility](#server-compatibility).

### Authentication and API keys

| Command | Description |
| --- | --- |
| `mailhub auth login` | Authenticate the current device. |
| `mailhub auth login --no-browser` | Print the approval URL instead of opening a browser. |
| `mailhub auth login --device-name <name>` | Set the name shown on the approval page. |
| `mailhub auth status` | Show the current key ID and expiry; with `MAILHUB_TOKEN`, report environment-based authentication only. |
| `mailhub auth logout` | Revoke the current key; clear the Keychain credential only when it is the active credential. |
| `mailhub auth keys list` | List API keys. |
| `mailhub auth keys list --json` | List API keys as JSON. |
| `mailhub auth keys revoke <key-id>` | Revoke one API key by ID. |

### Relay aliases

| Command | Description |
| --- | --- |
| `mailhub alias list` | List relay aliases in a human-readable table. |
| `mailhub alias list --json` | List relay aliases as JSON. |
| `mailhub alias create` | Create a random relay alias. |
| `mailhub alias create --label <label>` | Create an alias with a label. |
| `mailhub alias create --json` | Create an alias and print the response as JSON. |
| `mailhub alias on <id-or-email>` | Enable an alias. |
| `mailhub alias off <id-or-email>` | Disable an alias. |
| `mailhub alias label <id-or-email> <label>` | Set an alias label. |
| `mailhub alias label <id-or-email> --clear` | Clear an alias label. |

Alias identifiers can be the numeric alias ID or the exact relay email address shown by
`mailhub alias list`. Labels are limited to 100 characters.

### Other commands

```bash
# Generate completion scripts
mailhub completion zsh
mailhub completion bash
mailhub completion fish

# Print the CLI version
mailhub version
```

For example, load Zsh completions for the current shell with:

```bash
eval "$(mailhub completion zsh)"
```

## Configuration

### API endpoint

The default API origin is `https://private-mailhub.com`. For a login flow or a command using
`MAILHUB_TOKEN`, select an alternate origin with the global `--api-url` flag or `MAILHUB_API_URL`:

```bash
mailhub --api-url https://staging.example.com alias list
MAILHUB_API_URL=https://staging.example.com mailhub alias list
```

The flag takes precedence over `MAILHUB_API_URL`, which takes precedence over the default origin.
The value must be an absolute origin. Do not append `/api`, a path, a query string, or a fragment;
HTTPS is required except for loopback development URLs such as `http://localhost:8080`.

After `auth login`, the Keychain credential is bound to the origin used for that login. Supplying a
different `--api-url` or `MAILHUB_API_URL` with that saved credential is rejected; log in again at
the new origin. A `MAILHUB_TOKEN` environment credential can be used with an explicit origin.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `MAILHUB_API_URL` | Selects the origin for login and `MAILHUB_TOKEN` flows; it cannot replace the origin bound to a saved Keychain credential. |
| `MAILHUB_TOKEN` | Uses a compatible server's API key from the environment instead of the macOS Keychain. |
| `MAILHUB_CONFIG_DIR` | Overrides the directory used for non-secret CLI metadata. |

`MAILHUB_TOKEN` is useful for CI and automation. Prefer a secret manager or the CI platform's
secret store, and never put the token in a command argument or committed script.

## Credentials and security

- The API key is stored in the macOS Keychain under service
  `private-mailhub.mailhub-cli` and account `default`.
- The CLI stores only non-secret metadata in `mailhub/config.json` below the platform user
  configuration directory. On macOS, this is normally
  `~/Library/Application Support/mailhub/config.json`.
- The metadata directory is created with `0700` permissions and the config file with `0600`
  permissions.
- When a compatible server returns a raw API key during login, the CLI saves it in the Keychain and
  never prints or writes it to logs.
- Key expiry is a server policy. The CLI warns when saved expiry metadata indicates seven days or
  less remaining.
- On a compatible server, `auth logout` revokes the server-side key before deleting the local
  Keychain credential. When using `MAILHUB_TOKEN`, it cannot remove the environment variable for
  you; unset it after logout.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Command completed successfully. |
| `1` | API, network, or server error. |
| `2` | Invalid command, flag, or argument. |
| `3` | Authentication is missing, expired, or revoked. |

Errors are written to `stderr`; JSON and normal command output are written to `stdout`.

## Development

### Project layout

| Path | Responsibility |
| --- | --- |
| `cmd/mailhub` | Binary entrypoint. |
| `internal/api` | Mailhub HTTP client and response contracts. |
| `internal/cli` | Cobra commands, validation, output, and exit codes. |
| `internal/credentials` | Keychain access and local metadata. |
| `internal/platform` | Browser-launch and platform helpers. |

### Run checks locally

```bash
# Format check
test -z "$(gofmt -l .)"

# Static analysis and tests
go vet ./...
go test ./...
go test -race ./...

# Build the CLI
go build -trimpath -o mailhub ./cmd/mailhub
```

The same checks run in GitHub Actions. CI builds macOS binaries for both Apple Silicon (`darwin/arm64`)
and Intel (`darwin/amd64`), and audits, builds, and tests the Homebrew formula.

### Publish a Homebrew update

After tagging and publishing a CLI release, update the source tag and SHA-256 checksum in
`Formula/mailhub.rb`. Calculate the checksum from the release's GitHub source archive. Audit and
build the formula from source before merging the update:

```bash
brew audit --strict private-mailhub/cli/mailhub
brew install --build-from-source private-mailhub/cli/mailhub
brew test private-mailhub/cli/mailhub
```

The formula version comes from the tag in its source URL.

## Contributing

Issues and pull requests are welcome. Before opening a pull request:

1. Keep changes focused and explain the user-visible behavior.
2. Add or update tests for command, API, credential, or security behavior.
3. Run `gofmt`, `go vet ./...`, `go test ./...`, and `go test -race ./...`.
4. Never include API keys, personal email addresses, or real user data in code, tests, logs, or
   screenshots.

## License

Mailhub CLI is licensed under the [GNU Affero General Public License v3.0](LICENSE).
