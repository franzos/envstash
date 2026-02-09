# envstash

A CLI tool for managing `.env` files across git branches. Save, version, diff, restore, and share environment variables with optional encryption.

## Install

**From crates.io:**

```bash
cargo install envstash
```

**Pre-built binaries:**

Download the latest release from [GitHub Releases](https://github.com/franzos/envstash/releases) and extract the binary to a directory in your `PATH`:

```bash
# macOS (Apple Silicon)
curl -sL https://github.com/franzos/envstash/releases/latest/download/envstash-aarch64-apple-darwin.tar.gz | tar xz
sudo mv envstash /usr/local/bin/

# macOS (Intel)
curl -sL https://github.com/franzos/envstash/releases/latest/download/envstash-x86_64-apple-darwin.tar.gz | tar xz
sudo mv envstash /usr/local/bin/

# Linux (x86_64)
curl -sL https://github.com/franzos/envstash/releases/latest/download/envstash-x86_64-unknown-linux-gnu.tar.gz | tar xz
sudo mv envstash /usr/local/bin/
```

**Debian/Ubuntu:**

Download the `.deb` from [GitHub Releases](https://github.com/franzos/envstash/releases) and install:

```bash
sudo dpkg -i envstash_*_amd64.deb
```

**Fedora/RHEL:**

Download the `.rpm` from [GitHub Releases](https://github.com/franzos/envstash/releases) and install:

```bash
sudo rpm -i envstash-*.x86_64.rpm
```

## Quick start

```bash
# Initialize the store
envstash init

# Save the current .env file
envstash save

# Save with a note
envstash save -m "trying new DB config"

# List saved versions
envstash ls

# Restore a saved version
envstash checkout 1

# See what changed between versions
envstash diff 1 2
```

## Features

- **Version .env files** per git branch and commit
- **Diff** variables by name (order-independent)
- **Restore** saved versions to disk, or inject into the shell environment
- **Share** exports with teammates (with optional GPG or password encryption)
- **Dump/load** the entire store for backup and migration
- **Works outside git repos** using folder path as identifier

## Commands

| Command | Description |
|---------|-------------|
| `envstash init` | Initialize the store (choose encryption mode) |
| `envstash save [file] [-m msg]` | Save a `.env` file with optional message |
| `envstash ls` | List saved versions on the current branch |
| `envstash diff <a> <b>` | Diff two versions (by number or hash) |
| `envstash checkout <version>` | Restore a version to disk |
| `envstash env [version]` | Print `export` statements for shell eval |
| `envstash exec [version] -- <cmd>` | Run a command with saved env vars |
| `envstash log` | Show what changed between consecutive versions |
| `envstash rm <version>` | Remove saved versions |
| `envstash global` | List all projects with saved .env files |
| `envstash share [--to <target>]` | Export a version for sharing |
| `envstash import [--from <source>]` | Import a shared export |
| `envstash dump <path>` | Export the entire store |
| `envstash load <path>` | Import a full dump |

## Encryption

Three modes, chosen at init time:

```bash
envstash init                                    # no encryption
envstash init --encrypt gpg --recipient <key_id> # GPG (supports Yubikey)
envstash init --encrypt password                 # password-based (argon2id)
```

Running `envstash init --encrypt gpg` without `--recipient` lists available GPG keys.

Architecture (inspired by [Tomb](https://github.com/dyne/Tomb)):
- A random AES-256-GCM key encrypts variable values at rest
- The AES key is wrapped with GPG or a password-derived key
- Metadata (branches, timestamps, file paths) stays plaintext for fast queries
- GPG mode: one Yubikey touch per gpg-agent cache window, not per operation

The key file location can be overridden with `--key-file` or `ENVSTASH_KEY_FILE`.

## Shell integration

```bash
# Load variables into current shell
eval $(envstash env)

# Run a one-off command with saved variables
envstash exec -- npm start

# Isolated mode (only saved variables, no inherited env)
envstash exec --isolated -- npm test
```

Supports `bash`, `fish`, and `json` output via `--shell`.

## Sharing

```bash
# Export latest version to stdout
envstash share > export.env

# Encrypted export (password)
envstash share --encrypt --encryption-method password > export.enc

# Encrypted export (GPG, one or more recipients)
envstash share --encrypt --recipient <key_id> > export.gpg

# Import
envstash import export.env
cat export.enc | envstash import --password secret

# Full store backup
envstash dump backup.json
envstash load backup.json
```

### Remote sharing

Share and import via paste services, GitHub Gists, email, or SSH:

```bash
# Upload to 0x0.st (default paste service)
envstash share --to
# Custom paste instance
envstash share --to https://my.paste.service

# Import from a URL (paste, raw gist, etc.)
envstash import --from https://0x0.st/abc.env

# Create a GitHub Gist (requires `gh auth login`)
envstash share --to gist
# Public gist
envstash share --to gist --public
# Import from a gist URL
envstash import --from https://gist.github.com/user/abc123

# Send via email (uses msmtp or sendmail)
envstash share --to email:teammate@example.com

# Pipe to remote envstash via SSH
envstash share --to ssh://user@server
# Pipe from remote envstash via SSH
envstash import --from ssh://user@server
```

All transport backends work with encryption:

```bash
envstash share --encrypt --encryption-method password --to
envstash import --from https://0x0.st/abc.env --password secret
```

The default target for bare `--to` can be changed in `~/.config/envstash/config.toml`:

```toml
[share]
default_to = "https://my.paste.service"
# or any other target: "ssh://user@host", "gist", "email:team@example.com"

[share.headers]
Authorization = "Bearer mytoken"
```

## Storage

Data lives in `~/.local/share/envstash/`:

```
~/.local/share/envstash/
├── store.db    # SQLite (mode 0600)
└── key.gpg     # AES key wrapped in GPG/password (mode 0600)
```

## Building

```bash
cargo build --release
```

## License

GPL-3.0
