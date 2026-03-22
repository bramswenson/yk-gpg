@README.md

# kdub — Developer Guide

## Project Architecture

kdub is a Rust workspace with two crates:

- **`crates/kdub`** — binary crate. Thin CLI layer using clap derive. Delegates all logic to the library.
- **`crates/kdub-lib`** — library crate. All domain logic, types, validation, and platform-specific code.

The project ports a bash/mise GPG key management tool to a single static Rust binary. See `PLAN.md` for the full implementation plan and `README.md` for the CLI specification.

## Build, Test, Lint

```bash
cargo build                              # debug build
cargo build --release                    # release build
cargo nextest run                        # run all tests
cargo nextest run test_name              # run single test
cargo nextest run --lib                  # unit tests only
cargo nextest run --test '*'             # integration tests only
cargo clippy --all-targets -- -D warnings  # lint (warnings are errors)
cargo fmt                                # format code
cargo fmt -- --check                     # check formatting
cargo deny check                         # dependency audit
cargo audit                              # security audit
cargo llvm-cov nextest --html            # coverage report
```

## TDD Workflow

All new functionality follows test-driven development:

1. **Write a failing test** that captures the desired behavior.
2. **Run the test** and verify it fails for the expected reason.
3. **Implement** the minimum code to make the test pass.
4. **Run the test** and verify it passes.
5. **Refactor** while keeping tests green.

For snapshot tests, use insta:

```bash
INSTA_UPDATE=new cargo nextest run       # run tests, write new snapshots
cargo insta review                       # interactively accept/reject snapshots
```

Never blindly accept snapshots. Review each one to confirm it matches expected output.

## Error Handling

- **Library (`kdub-lib`):** Use `thiserror` with `#[from]` for error conversion chains. All errors go through a single `KdubError` enum.
- **Binary (`kdub`):** Use `color-eyre` for error reports with context and backtraces.
- Error variants must use newtypes, never raw credential values. `KeyNotFound(Fingerprint)` not `KeyNotFound(String)`.
- No `unwrap()` in library code. Use `?` for propagation, `.expect("reason")` only where the invariant is provably infallible.
- `unwrap()` is acceptable in test code.

## Type System and Newtypes

Newtype wrappers enforce validation at parse time:

- `Fingerprint([u8; 20])` — V4 fingerprint. `FromStr` validates hex + length, normalizes uppercase. Implements `Display`.
- `KeyId(String)` — validated hex, `0x` prefix stripped on parse.
- `AdminPin(SecretString)` — validates 8 numeric digits.
- `UserPin(SecretString)` — validates 6 numeric digits.
- `FactoryPin` — unit struct sentinel with `const USER`/`const ADMIN` values.
- `Passphrase(SecretString)` — rejects empty. No other validation.
- `GithubToken(SecretString)` — rejects empty. No format validation.

### Secret Type Rules

- **`Display` is banned** on `AdminPin`, `UserPin`, `FactoryPin`, `Passphrase`, `GithubToken`. Use `secrecy::ExposeSecret` for deliberate access.
- **Never use secret types as `tracing` span or event fields.** Tracing fields are captured in logs and spans — secret data must not leak there.
- **`SecretString`** for all sensitive data. Never store secrets in plain `String`.
- Identifier types (`Fingerprint`, `KeyId`, `KeyType`) implement `Display` + `FromStr` normally.

## Code Conventions

- All public items require doc comments (`///`).
- `#[non_exhaustive]` on all public enums.
- `const` defaults in `defaults.rs` — no magic strings or numbers in business logic.
- `cfg(target_os)` for platform-specific dispatch.
- Config precedence: CLI flags > env vars > config file > compiled defaults.
- Synchronous only — no tokio/async runtime.
- File permissions: directories `0o700`, files `0o600`.

## Git Hooks

```bash
hk install     # set up pre-commit + pre-push hooks
hk check       # run checks manually
hk fix         # run fixes manually
```

## Dependencies of Note

- `pgp` (rPGP) — OpenPGP implementation. Use version 0.19+, not 0.14.
- `secrecy` — `SecretString`, `ExposeSecret`.
- `clap` — CLI parsing with derive macros.
- `thiserror` — library error types.
- `color-eyre` — binary error reporting.
- `serde` / `toml` — config file parsing.
- `tracing` — structured logging.
- `dialoguer` — interactive prompts (move `String` into `SecretString` immediately after capture).
- `insta` — snapshot testing.
- `rstest` — parameterized tests.
- `mockall` — trait mocking.
- `assert_cmd` — CLI integration tests.
- `tempfile` — isolated test directories.
