# kdub

Cross-platform OpenPGP key lifecycle management with smart card support.
A single static binary that handles identity creation, key backup/rotation,
and YubiKey provisioning. Based on [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

**Supported platforms:** Linux (x86_64 static), macOS (universal binary), Tails OS

## Installation

### Binary download

```bash
# Linux (static musl binary)
curl -LO https://github.com/bramswenson/kdub/releases/latest/download/kdub-linux-amd64
chmod +x kdub-linux-amd64 && sudo mv kdub-linux-amd64 /usr/local/bin/kdub

# macOS (universal binary)
curl -LO https://github.com/bramswenson/kdub/releases/latest/download/kdub-macos-universal
chmod +x kdub-macos-universal && sudo mv kdub-macos-universal /usr/local/bin/kdub
```

### From source

```bash
cargo install --git https://github.com/bramswenson/kdub.git
```

Requires Rust stable (see [rustup.rs](https://rustup.rs) for installation).

### System dependencies

kdub needs smart card middleware installed on the host. Use the bundled
installer or install manually:

```bash
# Bundled installer (detects OS)
curl -sSf https://raw.githubusercontent.com/bramswenson/kdub/main/scripts/install-deps.sh | bash

# Or manually:
# Debian/Ubuntu: apt install gnupg scdaemon pcscd libccid yubikey-manager jq
# Fedora:        dnf install gnupg2 pcsc-lite yubikey-manager jq
# Arch:          pacman -S gnupg pcsclite ccid yubikey-manager jq
# macOS:         brew install gnupg pinentry-mac yubikey-manager jq
```

After installing, verify your setup:

```bash
kdub doctor
```

### Tails OS

Tails resets installed packages on reboot. After each boot:

```bash
scripts/tails-install-deps.sh
```

On first use, wire XDG directories into Tails persistent storage:

```bash
scripts/tails-setup-persistence.sh
```

## Quick start

```bash
# Initialize directories and config
kdub init

# Check system readiness
kdub doctor

# Create an identity (disable networking first!)
kdub key create "Alice Smith <alice@example.com>"

# Backup keys
kdub key backup 0xKEYID

# Set up smart card and provision
kdub card setup
kdub card provision 0xKEYID

# Enable touch requirement (YubiKey 5+)
kdub card touch
```

---

## Command reference

### Global options

These options apply to all commands:

```
--batch              Non-interactive mode; fail instead of prompting
                     Also enabled by: BATCH_MODE=true or CI=true
--verbose, -v        Verbose output (repeat for debug: -vv)
--quiet, -q          Suppress informational output
--config <PATH>      Config file path
                     Default: $XDG_CONFIG_HOME/kdub/config.toml
--data-dir <PATH>    Data directory (identities, backups)
                     Default: $XDG_DATA_HOME/kdub
--no-color           Disable colored output
                     Also enabled by: NO_COLOR=1
```

---

### `kdub init`

Initialize kdub directories and configuration files.

```
kdub init [--force]
```

| Flag | Description |
|------|-------------|
| `--force` | Overwrite existing config files |

**Behavior:**

- Creates `$XDG_CONFIG_HOME/kdub/`, `$XDG_DATA_HOME/kdub/{identities,backups}`, `$XDG_STATE_HOME/kdub/`
- Writes default `config.toml` (skip if exists, unless `--force`)
- Installs GPG config templates: `gpg.conf`, `gpg-agent.conf`, `scdaemon.conf`
- Configures `dirmngr.conf` if `KDUB_TOR_PROXY` is set
- Platform-specific pinentry and agent socket paths

**Example:**

```bash
kdub init
# Created /home/alice/.config/kdub/config.toml
# Created /home/alice/.local/share/kdub/identities/
# Created /home/alice/.local/share/kdub/backups/
# Installed gpg.conf, gpg-agent.conf, scdaemon.conf
```

---

### `kdub doctor`

Check system dependencies and report readiness.

```
kdub doctor [--json]
```

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

**Checks performed:**

| Dependency | Required | Notes |
|------------|----------|-------|
| `gpg` | Yes | GnuPG 2.2+ |
| `gpg-agent` | Yes | Usually bundled with gpg |
| `scdaemon` | For card ops | Smart card daemon |
| `pcscd` | For card ops | PC/SC service (running) |
| `jq` | No | JSON processing |
| `ykman` | No | YubiKey Manager (for touch policy, extended info) |

**Example output:**

```
System check:
  gpg          2.4.5     ok
  gpg-agent    2.4.5     ok
  scdaemon     2.4.5     ok
  pcscd        running   ok
  jq           1.7.1     ok
  ykman        5.4.0     ok
  YubiKey      5.4.3 NFC (serial: 12345678)

Config:
  config dir   /home/alice/.config/kdub    ok
  data dir     /home/alice/.local/share/kdub    ok
  platform     linux

All checks passed.
```

**JSON output** (`--json`):

```json
{
  "dependencies": {
    "gpg": { "version": "2.4.5", "status": "ok", "path": "/usr/bin/gpg" },
    "scdaemon": { "version": "2.4.5", "status": "ok", "path": "/usr/lib/gnupg/scdaemon" },
    "pcscd": { "status": "running" },
    "jq": { "version": "1.7.1", "status": "ok", "path": "/usr/bin/jq" },
    "ykman": { "version": "5.4.0", "status": "ok", "path": "/usr/bin/ykman" }
  },
  "yubikey": {
    "model": "YubiKey 5 NFC",
    "serial": "12345678",
    "firmware": "5.4.3"
  },
  "config": {
    "config_dir": "/home/alice/.config/kdub",
    "data_dir": "/home/alice/.local/share/kdub",
    "platform": "linux"
  },
  "status": "ok"
}
```

---

### `kdub version`

Print version, build info, and linked library versions.

```
kdub version
```

```
kdub 0.1.0 (abc1234 2026-03-15)
  target: x86_64-unknown-linux-musl
  rpgp:   0.14.0
  clap:   4.5.0
```

---

### `kdub completions`

Generate shell completions.

```
kdub completions <bash|zsh|fish>
```

```bash
# Add to ~/.bashrc
eval "$(kdub completions bash)"

# Or write to file
kdub completions zsh > ~/.zfunc/_kdub
```

---

### `kdub key create`

Create a new OpenPGP identity with certify-only master key and sign/encrypt/auth subkeys.

```
kdub key create <IDENTITY> [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `IDENTITY` | User ID string: `"Name <email>"` |

| Flag | Default | Description |
|------|---------|-------------|
| `--key-type <TYPE>` | auto-detect | `ed25519` or `rsa4096`; auto-detects from connected YubiKey |
| `--expiration <DURATION>` | `2y` | Subkey expiration: `1y`, `2y`, `6m`, `90d`, `never` |
| `--passphrase <PASS>` | auto-generate | Certify key passphrase (visible in process listings) |
| `--passphrase-stdin` | false | Read passphrase from stdin (one line). Preferred for scripts |

**Behavior:**

- Master (certify-only) key has no expiration
- Three subkeys created: sign, encrypt, authenticate — all with `--expiration`
- If no `--key-type`: checks connected YubiKey (YK5+ → ed25519, YK4 → rsa4096), falls back to `KDUB_KEY_TYPE` env var, then config, then `ed25519`
- If no `--passphrase` and interactive: generates a 24-char passphrase, displays once
- Key generation uses ephemeral GNUPGHOME on tmpfs (key material never touches persistent disk)
- Saves metadata to `$DATA_DIR/identities/$FINGERPRINT.json`
- After creation, prompts to run `key backup` (skipped in batch mode)

**Batch mode:** Passphrase required via `--passphrase`, `--passphrase-stdin`, or `KDUB_PASSPHRASE` env var. No prompts. Backup prompt skipped.

**Example:**

```bash
# Auto-detect key type from YubiKey
kdub key create "Alice Smith <alice@example.com>"

# Explicit options
kdub key create "Work <work@corp.com>" --key-type rsa4096 --expiration 1y

# CI/scripting (env var — preferred, not visible in process listings)
KDUB_PASSPHRASE="$SECRET" kdub --batch key create "CI Bot <ci@corp.com>" --key-type ed25519

# CI/scripting (stdin pipe)
echo "$SECRET" | kdub --batch key create "CI Bot <ci@corp.com>" --passphrase-stdin --key-type ed25519
```

---

### `kdub key list`

List all managed identities and their key status.

```
kdub key list [--json]
```

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON array |

**Example output:**

```
Managed identities:

  Alice Smith <alice@example.com>
    Fingerprint: D3B9C00B365DC5B752A6554A0630571A396BC2A7
    Key type:    ed25519
    Created:     2026-01-15
    Subkeys:
      [S] sign       ed25519  expires 2028-01-15
      [E] encrypt    cv25519  expires 2028-01-15
      [A] auth       ed25519  expires 2028-01-15
    Card:        YubiKey 5 NFC (serial: 12345678)
    Backed up:   2026-01-15

  Work <work@corp.com>
    Fingerprint: AABBCCDD...
    Key type:    rsa4096
    Created:     2025-06-01
    Subkeys:
      [S] sign       rsa4096  EXPIRED 2026-06-01
      [E] encrypt    rsa4096  EXPIRED 2026-06-01
      [A] auth       rsa4096  EXPIRED 2026-06-01
    Backed up:   2025-06-01
```

Expiration color coding: expired subkeys in red, expiring within 90 days in yellow.

**JSON output** (`--json`):

```json
[
  {
    "identity": "Alice Smith <alice@example.com>",
    "fingerprint": "D3B9C00B365DC5B752A6554A0630571A396BC2A7",
    "key_type": "ed25519",
    "created": "2026-01-15",
    "subkeys": [
      { "usage": "sign", "algorithm": "ed25519", "expires": "2028-01-15", "status": "valid" },
      { "usage": "encrypt", "algorithm": "cv25519", "expires": "2028-01-15", "status": "valid" },
      { "usage": "auth", "algorithm": "ed25519", "expires": "2028-01-15", "status": "valid" }
    ],
    "card": { "model": "YubiKey 5 NFC", "serial": "12345678" },
    "backed_up": "2026-01-15"
  }
]
```

---

### `kdub key backup`

Export keys and revocation certificate to the data directory.

```
kdub key backup <KEY_ID> [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `KEY_ID` | Key ID or fingerprint |

| Flag | Default | Description |
|------|---------|-------------|
| `--passphrase <PASS>` | prompt | Certify key passphrase (visible in process listings) |
| `--passphrase-stdin` | false | Read passphrase from stdin (one line) |

**Creates** `$DATA_DIR/backups/$FINGERPRINT/`:

- `certify-key.asc` — armored secret certify key
- `subkeys.asc` — armored secret subkeys (full key bundle; rPGP cannot export subkeys separately)
- `public-key.asc` — armored public key
- `ownertrust.txt` — trust database export
- `revocation-cert.asc` — pre-generated revocation certificate

**Batch mode:** `--passphrase` required for non-interactive export.

**Example:**

```bash
kdub key backup 0x0630571A396BC2A7
# Backed up to /home/alice/.local/share/kdub/backups/D3B9C00B.../
#   certify-key.asc
#   subkeys.asc
#   public-key.asc
#   ownertrust.txt
#   revocation-cert.asc
```

---

### `kdub key restore`

Import keys from a previous backup.

```
kdub key restore <FINGERPRINT> [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `FINGERPRINT` | Fingerprint matching backup directory name |

| Flag | Default | Description |
|------|---------|-------------|
| `--passphrase <PASS>` | prompt | Certify key passphrase (visible in process listings) |
| `--passphrase-stdin` | false | Read passphrase from stdin (one line) |

**Behavior:**

- Reads from `$DATA_DIR/backups/$FINGERPRINT/`
- Imports: `public-key.asc`, `certify-key.asc`, `ownertrust.txt`
- Fails if backup directory not found

**Example:**

```bash
kdub key restore D3B9C00B365DC5B752A6554A0630571A396BC2A7
```

---

### `kdub key renew`

Extend expiration of existing subkeys without generating new key material.

```
kdub key renew <IDENTITY> [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `IDENTITY` | Identity name, email, or key ID |

| Flag | Default | Description |
|------|---------|-------------|
| `--expiration <DURATION>` | `2y` | New expiration from today |
| `--passphrase <PASS>` | prompt | Certify key passphrase (visible in process listings) |
| `--passphrase-stdin` | false | Read passphrase from stdin (one line) |

**Behavior:**

- Extends expiration on all three subkeys (sign, encrypt, auth)
- Updates metadata with renewal timestamp
- Exports updated public key to backup directory (if backup exists)
- Prompts to run `key backup` after renewal (skipped in batch mode)

**When to use:** Subkeys approaching expiration, no security concerns.

**Example:**

```bash
kdub key renew "Alice Smith" --expiration 2y
```

---

### `kdub key rotate`

Generate new subkeys, optionally revoking old ones. Full key rotation.

```
kdub key rotate <IDENTITY> [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `IDENTITY` | Identity name, email, or key ID |

| Flag | Default | Description |
|------|---------|-------------|
| `--key-type <TYPE>` | auto-detect | Algorithm for new subkeys |
| `--expiration <DURATION>` | `2y` | New subkey expiration |
| `--passphrase <PASS>` | prompt | Certify key passphrase (visible in process listings) |
| `--passphrase-stdin` | false | Read passphrase from stdin (one line) |
| `--revoke-old` | false | Revoke old subkeys |

**Behavior:**

- Creates three new subkeys (sign, encrypt, auth) under the existing certify key
- `--revoke-old`: revokes previous subkeys with proper revocation signatures
- Updates metadata with rotation timestamp
- Prompts to run `card provision` and `key backup` (skipped in batch mode)

**When to use:**

| Scenario | Command |
|----------|---------|
| Annual maintenance | `kdub key rotate "Alice"` |
| Suspected compromise | `kdub key rotate "Alice" --revoke-old` |
| Algorithm upgrade | `kdub key rotate "Alice" --key-type ed25519 --revoke-old` |

---

### `kdub key publish`

Publish public key to one or more destinations.

```
kdub key publish <KEY_ID> [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `KEY_ID` | Key ID or fingerprint |

| Flag | Default | Description |
|------|---------|-------------|
| `--keyserver` | false | Upload to keys.openpgp.org |
| `--github` | false | Upload to GitHub (requires `GITHUB_TOKEN`) |
| `--wkd <PATH>` | — | Export for Web Key Directory at webroot path |
| `--file <PATH>` | — | Export armored public key to file |
| `--all` | false | Publish to all enabled destinations |

**Batch mode:** At least one destination flag required. Interactive mode prompts for each.

**Tor support:** Set `KDUB_TOR_PROXY` (e.g., `socks5h://127.0.0.1:9050`) to route
keyserver traffic through Tor. Use `socks5h://` (note the `h`) to route DNS queries through the proxy, preventing DNS leaks.

**Example:**

```bash
# Single destination
kdub key publish 0xKEYID --keyserver

# Multiple destinations
kdub key publish 0xKEYID --keyserver --github --file pubkey.asc

# All destinations
kdub key publish 0xKEYID --all
```

---

### `kdub card info`

Display OpenPGP smart card status. If a YubiKey is detected and `ykman` is
available, also shows YubiKey-specific details.

```
kdub card info [--json]
```

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |

**Example output:**

```
OpenPGP Card:
  Manufacturer:  Yubico
  Serial:        12345678
  Version:       3.4
  PIN retries:   3 / 0 / 3 (user / reset / admin)
  Signature key: ed25519 [S] D3B9...2A7
  Encrypt key:   cv25519 [E] D3B9...2A7
  Auth key:      ed25519 [A] D3B9...2A7
  KDF:           enabled
  Touch policy:  sign=on, encrypt=on, auth=on

YubiKey:
  Model:         YubiKey 5 NFC
  Firmware:      5.4.3
  Serial:        12345678
  Best key type: ed25519
```

**JSON output** (`--json`):

```json
{
  "card": {
    "manufacturer": "Yubico",
    "serial": "12345678",
    "version": "3.4",
    "pin_retries": { "user": 3, "reset": 0, "admin": 3 },
    "keys": {
      "signature": { "algorithm": "ed25519", "fingerprint": "D3B9..." },
      "encryption": { "algorithm": "cv25519", "fingerprint": "D3B9..." },
      "authentication": { "algorithm": "ed25519", "fingerprint": "D3B9..." }
    },
    "kdf": true,
    "touch_policy": { "sign": "on", "encrypt": "on", "auth": "on" }
  },
  "yubikey": {
    "model": "YubiKey 5 NFC",
    "firmware": "5.4.3",
    "serial": "12345678"
  }
}
```

---

### `kdub card setup`

Configure smart card PINs, KDF, and cardholder metadata.

```
kdub card setup [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--identity <ID>` | — | GPG identity to extract name/email for card fields |
| `--url <URL>` | — | Public key URL to store on card |
| `--admin-pin <PIN>` | prompt | Current admin PIN |
| `--new-admin-pin <PIN>` | auto-generate | New admin PIN (8 numeric digits) |
| `--new-user-pin <PIN>` | auto-generate | New user PIN (6 numeric digits) |
| `--skip-kdf` | false | Skip KDF (PIN hashing) setup |
| `--factory-pins` | false | Card has factory default PINs (123456 / 12345678) |

**Interactive only.** Card setup always requires interactive confirmation — `--batch` is not
accepted. PINs and admin credentials can be provided via flags or env vars, but the confirmation
prompt ("Type 'yes' to proceed") must be answered interactively or piped via stdin.

**Behavior:**

- Detects factory PIN state (or trusts `--factory-pins`)
- Shows what will be changed (KDF, PINs, cardholder info)
- Requires confirmation: type `yes` to proceed
- Enables KDF for on-card PIN hashing (unless `--skip-kdf` or unsupported)
- Changes admin PIN, then user PIN
- Sets cardholder name/email from `--identity` (if provided)
- Sets public key URL from `--url` (if provided)
- Displays new PINs once — **record them before continuing**

**Example:**

```bash
# Interactive setup with factory-fresh card
kdub card setup --factory-pins --identity "Alice Smith <alice@example.com>"

# Scripted (pipe confirmation via stdin)
echo "yes" | kdub card setup --factory-pins \
  --new-admin-pin 87654321 --new-user-pin 654321
```

---

### `kdub card provision`

Transfer subkeys to smart card. **This moves keys — the local copy becomes
a GPG-compatible stub pointing to the card.** After provisioning, the secret
key material exists only on the card and in your backup.

```
kdub card provision <KEY_ID> [OPTIONS]
```

| Argument | Description |
|----------|-------------|
| `KEY_ID` | Key ID or fingerprint to provision |

| Flag | Default | Description |
|------|---------|-------------|
| `--admin-pin <PIN>` | prompt | Card admin PIN (visible in process listings) |
| `--admin-pin-stdin` | false | Read admin PIN from stdin (one line) |
| `--passphrase <PASS>` | prompt | Certify key passphrase (visible in process listings) |
| `--passphrase-stdin` | false | Read passphrase from stdin (one line) |

**Interactive only.** Card provision always requires interactive confirmation — `--batch` is
not accepted. This operation is irrecoverable without a backup.

**Behavior:**

- **Pre-flight: backup must exist** — refuses if `$DATA_DIR/backups/$FINGERPRINT/` is missing.
  Run `kdub key backup` first. This check cannot be overridden.
- Rejects if card PINs are at factory defaults (run `card setup` first)
- Shows summary: key fingerprint, card serial, which slots will be written
- Requires confirmation: type `yes` to proceed
- Transfers subkeys to card slots:
  - Sign key → slot 1
  - Encrypt key → slot 2
  - Auth key → slot 3
- Verifies transfer: reads card status, confirms slots populated
- **Replaces local key with GPG-compatible stub** (GNU S2K mode 1002 with card serial).
  GPG will show these as `ssb>` (key on card).
- Updates metadata with card serial and provisioned timestamp
- **After provisioning:** signing/decryption require the physical card. `key renew`/`key rotate`
  require restoring from backup first.

**Example:**

```bash
kdub card provision 0x0630571A396BC2A7

# Scripted (pipe confirmation, provide credentials via env)
echo "yes" | KDUB_ADMIN_PIN="$PIN" KDUB_PASSPHRASE="$PASS" \
  kdub card provision 0xKEYID
```

---

### `kdub card reset`

Factory reset the OpenPGP applet. **Destructive — erases all keys and PINs on the card.**

```
kdub card reset
```

**Interactive only.** Card reset always requires interactive confirmation — `--batch` is not
accepted. This is the most destructive operation kdub can perform.

**Behavior:**

- Shows current card status (serial number, what keys are loaded) as a warning
- Requires confirmation: **type the card serial number** to proceed (not just "yes" — prevents
  wrong-card accidents)
- Resets to factory default PINs: user=123456, admin=12345678
- Does NOT affect other YubiKey applets (FIDO2, OTP, etc.)

**Example:**

```bash
# Must type the card serial number when prompted
kdub card reset
# Card serial: 12345678
# Type '12345678' to confirm factory reset: 12345678
```

---

### `kdub card touch`

Configure YubiKey touch policy for OpenPGP operations. Requires YubiKey 5 or later.

```
kdub card touch [OPTIONS]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--admin-pin <PIN>` | prompt | YubiKey admin PIN (visible in process listings) |
| `--admin-pin-stdin` | false | Read admin PIN from stdin (one line) |
| `--policy <POLICY>` | `on` | Touch policy: `on`, `off`, `fixed`, `cached`, `cached-fixed` |

**Policy options:**

| Policy | Description |
|--------|-------------|
| `on` | Touch required; can be changed later |
| `off` | No touch required |
| `fixed` | Touch required; **cannot be changed without reset** |
| `cached` | Touch required; cached for 15 seconds |
| `cached-fixed` | Cached touch; **cannot be changed without reset** |

**Interactive only.** Card touch always requires interactive confirmation — `--batch` is not
accepted. The `fixed` and `cached-fixed` policies require typing `yes` (cannot be changed
without card reset).

**Behavior:**

- Sets policy for all three operations: sign, decrypt, authenticate
- Reversible policies (`on`, `off`, `cached`): `y/N` confirmation prompt
- Irreversible policies (`fixed`, `cached-fixed`): type `yes` to confirm
- Requires `ykman` to be installed
- Fails on YubiKey 4 or earlier

**Example:**

```bash
kdub card touch --policy cached
```

---

## Configuration

### Config file

`$XDG_CONFIG_HOME/kdub/config.toml` (created by `kdub init`):

```toml
# Key generation defaults
[key]
type = "ed25519"           # "ed25519" or "rsa4096"
expiration = "2y"          # Duration: "1y", "2y", "6m", "90d", "never"

# Smart card defaults
[card]
touch_policy = "on"        # "on", "off", "fixed", "cached", "cached-fixed"

# Network
[network]
tor_proxy = ""             # e.g., "socks5h://127.0.0.1:9050"
keyserver = "hkps://keys.openpgp.org"

# Publishing
[publish]
github_token_env = "GITHUB_TOKEN"   # Env var name containing GitHub token
```

### Environment variables

Environment variables use the `KDUB_*` prefix:

| Variable | Equivalent config | Description |
|----------|-------------------|-------------|
| `KDUB_KEY_TYPE` | `key.type` | Default key algorithm |
| `KDUB_EXPIRATION` | `key.expiration` | Default subkey expiration |
| `KDUB_CONFIG_DIR` | `--config` parent | Config directory override |
| `KDUB_DATA_DIR` | `--data-dir` | Data directory override |
| `KDUB_STATE_DIR` | — | State directory override |
| `KDUB_TOR_PROXY` | `network.tor_proxy` | SOCKS5 proxy for keyserver traffic |
| `KDUB_PASSPHRASE` | `--passphrase` | Certify key passphrase (preferred over CLI flag in CI) |
| `KDUB_ADMIN_PIN` | `--admin-pin` | Card admin PIN (preferred over CLI flag in CI) |
| `KDUB_USER_PIN` | `--new-user-pin` | Card user PIN (preferred over CLI flag in CI) |
| `BATCH_MODE` | `--batch` | Non-interactive mode |
| `CI` | `--batch` | Also enables batch mode |
| `NO_COLOR` | `--no-color` | Disable colored output |
| `GITHUB_TOKEN` | — | GitHub API token for `key publish --github` |

### Precedence

CLI flags > environment variables > config file > compiled defaults

---

## Daily usage

After provisioning, your smart card works with standard GPG and SSH tools:

```bash
# Sign
echo "test" | gpg --armor --clearsign
git commit -S -m "signed commit"

# Encrypt/decrypt
gpg --recipient alice@example.com --encrypt doc.txt
gpg --decrypt doc.txt.gpg

# SSH via gpg-agent
export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
ssh user@host
```

## Key lifecycle cheat sheet

| Scenario | Command |
|----------|---------|
| First time setup | `kdub init && kdub doctor` |
| Create identity | `kdub key create "Name <email>"` |
| Backup keys | `kdub key backup 0xKEYID` |
| Provision card | `kdub card setup && kdub card provision 0xKEYID` |
| Subkeys expiring | `kdub key renew "Name"` |
| Annual rotation | `kdub key rotate "Name"` |
| Suspected compromise | `kdub key rotate "Name" --revoke-old` |
| New card, same keys | `kdub key restore FINGERPRINT && kdub card provision 0xKEYID` |

## Platform support

| Feature | Tails | Linux | macOS |
|---------|-------|-------|-------|
| Key management | Yes | Yes | Yes |
| Smart card ops | Yes | Yes | Yes |
| Ephemeral GNUPGHOME | /dev/shm (tmpfs) | /dev/shm or XDG_RUNTIME_DIR | RAM disk |
| Touch policy | Yes (YK5+) | Yes (YK5+) | Yes (YK5+) |

## YubiKey compatibility

| Feature | YubiKey 4 | YubiKey 5 (fw 5.2.3+) |
|---------|-----------|------------------------|
| RSA 4096 | Yes | Yes |
| ed25519 / cv25519 | No | Yes |
| Touch policy | No | Yes |
| KDF (PIN hashing) | No | Yes |

Key type is auto-detected from the connected YubiKey.

## Error conventions

All errors are written to stderr. Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Usage error (bad arguments) |
| 3 | Missing dependency |
| 4 | Key not found |
| 5 | Card not found or communication error |
| 6 | Operation cancelled by user |
| 7 | Batch mode requires missing flag |

Error messages follow the format:

```
error: <short description>
  <detail or suggestion>
```

## Security considerations

- **Disable networking** before generating or handling key material
- **Certify key passphrase** is the most critical secret — store it physically separate from the YubiKey
- **PINs** protect smart card operations — record them separately from the card
- Ephemeral GNUPGHOME on tmpfs ensures key material never touches persistent disk
- **Batch mode**: `--passphrase` and `--admin-pin` flag values are visible in process listings (`/proc/PID/cmdline`). Prefer `KDUB_PASSPHRASE` / `KDUB_ADMIN_PIN` env vars or `--passphrase-stdin` / `--admin-pin-stdin` in sensitive environments
- On Tails, persistent storage is encrypted at rest

## Troubleshooting

### "No smart card detected"

- Ensure the YubiKey / smart card is inserted
- `sudo systemctl start pcscd` (Linux)
- `ykman info` to verify connectivity

### "Card communication error"

- Kill stale daemons: `gpgconf --kill gpg-agent && gpgconf --kill scdaemon`
- Re-insert the card

### "Unsupported key type for this card"

- YubiKey 4 only supports RSA. Use `--key-type rsa4096`

### "No secret key"

- Ensure the correct card is inserted
- Re-learn card: `gpg-connect-agent "scd serialno" "learn --force" /bye`

## Development

### Prerequisites

- Rust stable ([rustup.rs](https://rustup.rs))
- cargo-nextest (`cargo install cargo-nextest`)
- cargo-insta (`cargo install cargo-insta`)
- hk (`brew install hk` or `cargo install hk`)
- pkl (`brew install pkl`)
- GnuPG 2.2+ (for integration tests using gpg-as-oracle)

### Build

```bash
cargo build
cargo build --release
cargo run -- --help
```

### Test

```bash
cargo nextest run              # all tests
cargo nextest run test_name    # single test
cargo nextest run --lib        # unit tests only
cargo nextest run --test '*'   # integration tests only
cargo insta review             # review snapshot changes
```

### Lint and Format

```bash
cargo clippy -- -D warnings
cargo fmt
cargo fmt -- --check
```

### Coverage

```bash
cargo llvm-cov nextest --html
```

### Security Audit

```bash
cargo deny check
cargo audit
```

### Full Validation

```bash
cargo fmt -- --check && cargo clippy -- -D warnings && cargo nextest run
```

### Git Hooks

```bash
hk install     # set up pre-commit + pre-push hooks
hk check       # run checks manually
hk fix         # run fixes manually
```

### Releasing

Uses [cargo-release](https://github.com/crate-ci/cargo-release) for version management and [git-cliff](https://git-cliff.org) for changelog generation.

```bash
cargo release patch    # 0.1.0 → 0.1.1  (bug fixes)
cargo release minor    # 0.1.0 → 0.2.0  (new features)
cargo release major    # 0.1.0 → 1.0.0  (breaking changes)
```

This automatically: bumps version in all Cargo.toml files → generates CHANGELOG.md → commits → tags → pushes. The tag push triggers the release CI workflow which builds binaries and creates a GitHub Release.

For a dry run: `cargo release patch --dry-run`

## License

MIT
