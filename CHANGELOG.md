## [0.1.12]

### Security
- Subprocesses (`gpg`, `gh`, `ssh`, `msmtp`, `sendmail`) now run with `ENVSTASH_PASSWORD` and `ENVSTASH_KEY_FILE` scrubbed from the child env
- SSH destinations are validated (reject leading `-`, control characters) and spawned with `--` argv separator to prevent option injection
- Email recipients are validated (reject leading `-`, CRLF, control characters, malformed addresses) and spawned with `--` argv separator to prevent argv/header injection
- `send --to gist` now uses `tempfile::NamedTempFile` (randomized name, auto-cleanup) instead of a predictable path
- `checkout` (apply) refuses to write through a symlink and writes with mode 0600 on unix
- `save` refuses to read through a symlink
- `dump` refuses to write through a pre-planted symlink at the output path
- Enforce 0600 on existing files during `apply`/`dump` (not just on new files) — `OpenOptions::mode` only applies at creation, so a pre-existing world-readable target would otherwise retain its old mode
- `exec` also strips `ENVSTASH_KEY_FILE` from the child environment (not just `ENVSTASH_PASSWORD`)
- `receive --from <gist>` now invokes `gh gist view` with `--` separator to block option injection on the gist id
- Base64 auto-decode requires decoded bytes to start with `EVPW` (transport v1) or `-----BEGIN PGP`; opaque bytes pass through unchanged
- GPG/SSH/email child-stdin is now explicitly closed before `wait`, eliminating a deadlock class and surfacing "stdin unavailable" errors

### Added
- `queries::get_configs` for batched config lookups (one SELECT instead of N)
- `crypto::aes::build_cipher`, `encrypt_with_cipher`, `decrypt_with_cipher` for reusing an AES cipher across a batch of entries

### Changed
- **Breaking:** `--password <literal>` removed from `send`, `receive`, `dump`, `load` — use `--password-file <path>` (mode 0600 required on unix), `ENVSTASH_PASSWORD`, or the interactive prompt
- **Breaking:** `[send.headers]` is now a per-host map `[send.headers."host"]` — use `"*"` for a global fallback; auth headers are automatically stripped for `http://` targets unless the host is `localhost`/`127.0.0.1`
- `init` errors instead of silently writing empty string when `--key-file` path is not valid UTF-8
- Bulk operations (`save`, `receive`, `load`, `rm --branch`, `rm --all`) now run inside a single SQLite transaction — faster on large batches, and leaves the database consistent if a write is interrupted
- `save` / `get_save_entries` build the AES cipher once per save and reuse it across every entry, trimming per-entry key-schedule overhead
- `load_encryption_key` fetches `encryption_mode` and `key_file` in a single SELECT
- `log` (history) no longer decrypts the same save twice in adjacent iterations
- `ls` memoizes the on-disk `.env` hash per file path instead of re-reading the file per row
- `disk_content_hash` now returns `Result<Option<String>>` — IO and parse errors propagate on `save`/`send`; on `ls` they are logged as a single warning per path and treated as "unknown" so the listing stays non-fatal

### Build
- Release profile uses `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`, `panic = "abort"` — binary drops from ~8.2 MB to ~6.3 MB

## [0.1.11] - 2026-03-28

### Added
- Tab completion for file paths in `save`, `checkout --dest`, `receive`, `dump`, `load`
- Tab completion for file paths and version hashes in `diff`

### Changed
- Clippy fixes across the codebase

## [0.1.10] - 2026-03-02

### Changed
- Bump

## [0.1.9] - 2026-03-01

### Changed
- Encryption keys are zeroed from memory after use
- Env output validates variable names to prevent shell injection
- Graceful error handling when HOME is not set

## [0.1.8] - 2026-02-20

### Added
- `man` command with usage examples and detailed guide
- Context-aware help: bare `envstash` hides Setup when store is initialized, hides completion tip when already configured

### Changed
- Bare `envstash` now shows dynamic help instead of clap's static help

## [0.1.7] - 2026-02-11

### Fixed
- Network-dependent tests (paste, gist) skipped in CI

## [0.1.6] - 2026-02-09

### Added
- Shell tab-completion for version hashes (bash, zsh, fish)

### Changed
- `ls` and `log` now show content hashes as primary version identifiers
- Numeric indices still work as a convenient shortcut
- CLI commands renamed to follow Unix conventions: 
  - `share` → `send`
  - `import` → `receive`
- Config section `[share]` → `[send]`

## [0.1.5] - 2026-02-09

### Changed
- CLI commands renamed to follow Unix conventions:
  - `list` → `ls`
  - `delete` → `rm`
  - `history` → `log`
  - `apply` → `checkout` (`co`)
- Old command names still work as hidden aliases
- `init` moved to its own "Setup" section in `--help`

## [0.1.4] - 2026-02-08

### Changed
- `init --encrypt gpg`: lists available keys, requires explicit `--recipient` selection
- `share --encrypt`: requires explicit `--recipient` (supports multiple recipients)
- `dump --encrypt`: defaults to the store's GPG recipient instead of git signing key

### Added
- `share --to`: upload to 0x0.st, or `--to <url>` for a custom paste service
- `share --to gist`: create a GitHub Gist via gh CLI
- `share --to email:<addr>`: send via msmtp or sendmail
- `share --to ssh://user@host`: pipe to remote envstash import
- `import --from <url>`: fetch exports from URLs, gist URLs, or SSH
- `share --public`: create public gists (default: secret)
- Config file (`~/.config/envstash/config.toml`) for setting the default `--to` target
