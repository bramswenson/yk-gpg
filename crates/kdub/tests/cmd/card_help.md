# Card command help text

Verify help text is available for all card subcommands.

## card subcommand help

```console
$ kdub card --help
Smart card operations

Usage: kdub card [OPTIONS] <COMMAND>

Commands:
  info       Display OpenPGP smart card status
  setup      Configure smart card PINs, KDF, and metadata
  provision  Transfer subkeys to smart card
  reset      Factory reset the OpenPGP applet
  touch      Configure YubiKey touch policy
  help       Print this message or the help of the given subcommand(s)

Options:
...

```

## card info help

```console
$ kdub card info --help
Display OpenPGP smart card status

Usage: kdub card info [OPTIONS]

Options:
...
      --json                 Output as JSON
...

```

## card provision help

```console
$ kdub card provision --help
Transfer subkeys to smart card

Usage: kdub card provision [OPTIONS] <KEY_ID>
...
      --admin-pin <ADMIN_PIN>    Card admin PIN (visible in process listings)
...
      --passphrase <PASSPHRASE>  Certify key passphrase (visible in process listings)
...

```

## card reset help

```console
$ kdub card reset --help
Factory reset the OpenPGP applet
...

```

## card touch help

```console
$ kdub card touch --help
Configure YubiKey touch policy
...
      --policy <POLICY>
...

```

