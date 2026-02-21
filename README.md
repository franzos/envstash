# envstash

<p align="center">
  <img src="assets/logo.svg" alt="envstash" width="480">
</p>
<p align="center">
  A CLI tool for managing <code>.env</code> files across git branches. Save, version, diff, restore, and share environment variables with optional encryption.
</p>

## Install

| Method | Command |
|--------|---------|
| Cargo | `cargo install envstash` |
| Homebrew | `brew tap franzos/tap && brew install envstash` |
| Debian/Ubuntu | Download [`.deb`](https://github.com/franzos/envstash/releases) — `sudo dpkg -i envstash_*_amd64.deb` |
| Fedora/RHEL | Download [`.rpm`](https://github.com/franzos/envstash/releases) — `sudo rpm -i envstash-*.x86_64.rpm` |
| Guix | `guix install -L <panther> envstash` ([Panther channel](https://github.com/franzos/panther)) |

Pre-built binaries for Linux (x86_64), macOS (Apple Silicon, Intel) on [GitHub Releases](https://github.com/franzos/envstash/releases).

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

# Restore a saved version (by hash prefix, or number)
envstash checkout abcdef12
envstash checkout 1

# See what changed between versions
envstash diff abcdef12 9f3e7a01
```

Versions can be referenced by **hash prefix** (stable, tab-completable) or by **number** (convenient shortcut, but changes as new versions are saved).

## Features

- **Version .env files** per git branch and commit
- **Diff** variables by name (order-independent)
- **Restore** saved versions to disk, or inject into the shell environment
- **Send/receive** exports with teammates (with optional GPG or password encryption)
- **Dump/load** the entire store for backup and migration
- **Works outside git repos** using folder path as identifier

## Commands

| Command | Description |
|---------|-------------|
| `envstash init` | Initialize the store (choose encryption mode) |
| `envstash save [file] [-m msg]` | Save a `.env` file with optional message |
| `envstash ls` | List saved versions on the current branch |
| `envstash diff <a> <b>` | Diff two versions (by hash prefix) |
| `envstash checkout <version>` | Restore a version to disk |
| `envstash env [version]` | Print `export` statements for shell eval |
| `envstash exec [version] -- <cmd>` | Run a command with saved env vars |
| `envstash log` | Show what changed between consecutive versions |
| `envstash rm <version>` | Remove saved versions |
| `envstash global` | List all projects with saved .env files |
| `envstash send [--to <target>]` | Send a version (stdout, paste, gist, email, ssh) |
| `envstash receive [--from <source>]` | Receive a shared version |
| `envstash dump <path>` | Export the entire store |
| `envstash load <path>` | Import a full dump |
| `envstash man` | Show usage examples and detailed guide |

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

### Tab completion

Enable tab-completion for version hashes (and all subcommands/flags):

```bash
# Bash (~/.bashrc)
source <(COMPLETE=bash envstash)

# Zsh (~/.zshrc)
source <(COMPLETE=zsh envstash)

# Fish (~/.config/fish/config.fish)
source (COMPLETE=fish envstash | psub)
```

## Sharing

```bash
# Export latest version to stdout
envstash send > export.env

# Encrypted export (password)
envstash send --encrypt --encryption-method password > export.enc

# Encrypted export (GPG, one or more recipients)
envstash send --encrypt --recipient <key_id> > export.gpg

# Receive
envstash receive export.env
cat export.enc | envstash receive --password secret

# Full store backup
envstash dump backup.json
envstash load backup.json
```

### Remote sharing

Send and receive via paste services, GitHub Gists, email, or SSH:

```bash
# Upload to 0x0.st (default paste service)
envstash send --to
# Custom paste instance
envstash send --to https://my.paste.service

# Receive from a URL (paste, raw gist, etc.)
envstash receive --from https://0x0.st/abc.env

# Create a GitHub Gist (requires `gh auth login`)
envstash send --to gist
# Public gist
envstash send --to gist --public
# Receive from a gist URL
envstash receive --from https://gist.github.com/user/abc123

# Send via email (uses msmtp or sendmail)
envstash send --to email:teammate@example.com

# Pipe to remote envstash via SSH
envstash send --to ssh://user@server
# Pipe from remote envstash via SSH
envstash receive --from ssh://user@server
```

All transport backends work with encryption:

```bash
envstash send --encrypt --encryption-method password --to
envstash receive --from https://0x0.st/abc.env --password secret
```

The default target for bare `--to` can be changed in `~/.config/envstash/config.toml`:

```toml
[send]
default_to = "https://my.paste.service"
# or any other target: "ssh://user@host", "gist", "email:team@example.com"

[send.headers]
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
cargo test

# Network-dependent tests (paste, gist) are ignored by default
cargo test -- --ignored
```

## License

GPL-3.0
