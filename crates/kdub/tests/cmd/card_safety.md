# Card operation safety model

All card-modifying commands reject `--batch` mode for safety.
These tests verify the safety model across all card commands.

## card setup rejects batch

```console
$ kdub --batch card setup --factory-pins
? 5
error: card error: card setup requires interactive confirmation -- --batch is not supported

```

## card provision rejects batch

```console
$ kdub --batch card provision DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF
? 5
error: card error: card provision requires interactive confirmation -- --batch is not supported

```

## card reset rejects batch

```console
$ kdub --batch card reset
? 5
error: card error: card reset requires interactive confirmation -- --batch is not supported

```

## card touch rejects batch

```console
$ kdub --batch card touch --policy on
? 5
error: card error: card touch requires interactive confirmation -- --batch is not supported

```

## card touch invalid policy

Invalid policy values are caught by clap before reaching the handler.

```console
$ kdub card touch --policy invalid
? 2
error: invalid value 'invalid' for '--policy <POLICY>'
  [possible values: on, off, fixed, cached, cached-fixed]

For more information, try '--help'.

```

