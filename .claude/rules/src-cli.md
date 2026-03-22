---
globs: crates/kdub/src/**/*.rs
---

# CLI Binary Crate Rules

## Clap Structure

- Use clap derive macros (`#[derive(Parser)]`, `#[derive(Subcommand)]`).
- Use `ValueEnum` for enums exposed as CLI arguments.
- One module per command in `commands/` directory.
- Command modules export `pub fn run(args: &FooArgs, global: &GlobalOpts) -> Result<(), KdubError>`.

## Error Handling

- Use `color-eyre` for error reports at the binary boundary.
- Convert `KdubError` to `eyre::Report` at the dispatch layer.
- Map `KdubError` variants to exit codes via `exit_code()` method.

## Handlers

- CLI handlers are thin — delegate all logic to `kdub-lib`.
- No business logic in command handlers. Parse arguments, call library functions, format output.

## Interactive Input

- Use `dialoguer` for interactive prompts.
- Move `String` values into `SecretString` immediately after capture from dialoguer — never hold secrets in plain `String` longer than necessary.

## Logging

- Use `tracing` for structured logging.
- Never log secret values (PINs, passphrases, tokens) in tracing spans or events.
- Verbosity levels: `-v` for debug, `-vv` for trace.

## Secret Input

- All commands accepting secrets must support `--passphrase-stdin` / `--admin-pin-stdin` / `--user-pin-stdin` and corresponding `KDUB_*` env vars.
- `--passphrase` and `--admin-pin` CLI flags work but warn about process listing visibility.
