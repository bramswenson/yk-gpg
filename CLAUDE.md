# kdub — Developer Guide

## Project Architecture

kdub is a Rust workspace with two crates:

- **`crates/kdub`** — binary crate. Thin CLI layer using clap derive. Delegates all logic to the library.
- **`crates/kdub-lib`** — library crate. All domain logic, types, validation, and platform-specific code.

See `README.md` for the full CLI specification, command reference, and user-facing documentation.

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
