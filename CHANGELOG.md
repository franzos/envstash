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
