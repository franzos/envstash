# envmgr

A CLI tool for managing `.env` files across git branches. Save, version, diff, restore, and share environment variables with optional encryption.

## Quick start

```bash
# Initialize the store
envmgr init

# Save the current .env file
envmgr save

# Save with a note
envmgr save -m "trying new DB config"

# List saved versions
envmgr list

# Restore a saved version
envmgr apply 1

# See what changed between versions
envmgr diff 1 2
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
| `envmgr init` | Initialize the store (choose encryption mode) |
| `envmgr save [file] [-m msg]` | Save a `.env` file with optional message |
| `envmgr list` | List saved versions on the current branch |
| `envmgr diff <a> <b>` | Diff two versions (by number or hash) |
| `envmgr apply <version>` | Restore a version to disk |
| `envmgr env [version]` | Print `export` statements for shell eval |
| `envmgr exec [version] -- <cmd>` | Run a command with saved env vars |
| `envmgr history` | Show what changed between consecutive versions |
| `envmgr delete <version>` | Remove saved versions |
| `envmgr global` | List all projects with saved .env files |
| `envmgr share` | Export a version for sharing |
| `envmgr import <file>` | Import a shared export |
| `envmgr dump <path>` | Export the entire store |
| `envmgr load <path>` | Import a full dump |

## Encryption

Three modes, chosen at init time:

```bash
envmgr init                    # no encryption
envmgr init --encrypt gpg      # GPG (supports Yubikey)
envmgr init --encrypt password # password-based (argon2id)
```

Architecture (inspired by [Tomb](https://github.com/dyne/Tomb)):
- A random AES-256-GCM key encrypts variable values at rest
- The AES key is wrapped with GPG or a password-derived key
- Metadata (branches, timestamps, file paths) stays plaintext for fast queries
- GPG mode: one Yubikey touch per gpg-agent cache window, not per operation

The key file location can be overridden with `--key-file` or `ENVMGR_KEY_FILE`.

## Shell integration

```bash
# Load variables into current shell
eval $(envmgr env)

# Run a one-off command with saved variables
envmgr exec -- npm start

# Isolated mode (only saved variables, no inherited env)
envmgr exec --isolated -- npm test
```

Supports `bash`, `fish`, and `json` output via `--shell`.

## Sharing

```bash
# Export latest version to stdout
envmgr share > export.env

# Encrypted export
envmgr share --encrypt --encryption-method password > export.enc

# Import
envmgr import export.env
cat export.enc | envmgr import --password secret

# Full store backup
envmgr dump backup.json
envmgr load backup.json
```

## Storage

Data lives in `~/.local/share/envmgr/`:

```
~/.local/share/envmgr/
├── store.db    # SQLite (mode 0600)
└── key.gpg     # AES key wrapped in GPG/password (mode 0600)
```

## Building

```bash
cargo build --release
```

## License

TBD
