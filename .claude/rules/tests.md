---
globs: crates/*/tests/**/*.rs,crates/*/src/**/*test*
---

# Test Rules

## Test Framework

- `cargo nextest run` as the test runner (not `cargo test`).
- `rstest` for parameterized and fixture-based tests.
- `insta` for snapshot testing — use `INSTA_UPDATE=new cargo nextest run` then `cargo insta review`.
- `mockall` for trait mocking (mock `KeyExecutor`, `CardExecutor`, `SystemDeps`).
- `assert_cmd` for CLI integration tests (invoke the binary, assert stdout/stderr/exit code).
- `tempfile` for isolated test directories — never write to the real filesystem.

## Test Categories

- **Unit tests** (`#[cfg(test)] mod tests`): test individual functions and types in isolation.
- **Mock tests**: verify control flow and interaction patterns using mockall trait mocks.
- **GPG-as-oracle tests**: verify cryptographic correctness by running real gpg commands against generated keys. These are integration tests.
- **CLI integration tests** (`tests/` directory): invoke the compiled binary with `assert_cmd`, verify output and exit codes.

## Conventions

- `unwrap()` is acceptable in test code.
- Use `#[ignore]` on tests that require hardware (smart card) or external services.
- Test names should describe the behavior being tested, not the implementation.
- Each new command gets at least one `#[ignore]` test anchor to be filled in during implementation.
