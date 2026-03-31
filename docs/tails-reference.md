# Tails OS Reference

Version-specific details for Tails partition layout and persistent storage.
Used to verify kdub's `tails persist` output matches native Tails behavior.

## Tails 7.6

### Partition Layout

| Partition | Size | Start Sector | End Sector | Type | Label | Flags |
|-----------|------|-------------|------------|------|-------|-------|
| sdd1 | 8.0 GiB | 2048 | 16775390 | EFI System (FAT32) | Tails | boot, hidden, legacy_boot, esp, no_automount |
| sdd2 | remaining | 16777216 | end-2048 | Linux reserved (LUKS2) | TailsData | -- |

- GPT partition type GUID for sdd2: `8DA63339-0007-60C0-C436-083AC8230908`
- Tails resizes partition 1 from ~1.9 GiB (ISO) to 8 GiB on first boot

### LUKS Configuration

- Version: LUKS2
- Cipher: aes-xts-plain64, 512-bit key
- PBKDF: argon2id (auto-benchmarked, ~4 iterations, 1GB memory, 4 threads)
- Filesystem inside: ext4, label `TailsData`

### persistence.conf (14 entries)

Tab-separated, one per line:

```
/etc/NetworkManager/system-connections	source=nm-system-connections
/etc/cups	source=cups-configuration
/home/amnesia	source=dotfiles,link
/home/amnesia/.electrum	source=electrum
/home/amnesia/.gnupg	source=gnupg
/home/amnesia/.mozilla/firefox/bookmarks	source=bookmarks
/home/amnesia/.purple	source=pidgin
/home/amnesia/.ssh	source=openssh-client
/home/amnesia/.thunderbird	source=thunderbird
/home/amnesia/Persistent	source=Persistent
/var/cache/apt/archives	source=apt/cache
/var/lib/apt/lists	source=apt/lists
/var/lib/gdm3/settings/persistent	source=greeter-settings
/var/lib/tca	source=tca
```

### Directory Layout (mount root)

Root ownership: `770 root:root`

Root-owned directories:
- `apt/` (700), `apt/cache/` (700), `apt/lists/` (700)
- `nm-system-connections/` (755)
- `tca/` (700)
- `cups-configuration/` (755)
- `greeter-settings/` (700)
- `.tails/` (710), `.tails/migrations/` (750)
- `lost+found/` (700, created by mkfs)

Amnesia-owned directories (uid 1000):
- `Persistent/` (700), `gnupg/` (700), `dotfiles/` (700)
- `bookmarks/` (700), `electrum/` (700), `openssh-client/` (700)
- `pidgin/` (700), `thunderbird/` (700)
- `.tails/dont-ask-again/` (700)
