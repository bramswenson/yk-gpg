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

## Test Key Fixtures

- **Never call `keygen::generate_key()` in tests** unless testing key generation itself.
- Library unit tests: use `include_str!("../tests/fixtures/test_key.asc")` and `SignedSecretKey::from_armor_single()` to load a pre-generated key in milliseconds.
- Integration tests: use the shared `fixture.rs` module (`fixture::setup_key()`, `fixture::setup_two_keys()`, `fixture::setup_key_with_backup()`).
- Fixture key passphrase: `"testpass123"`. Fingerprint: `fixture::FINGERPRINT`.
- Key generation is CPU-bound (~5s per Ed25519 key). The fixture approach eliminates this cost for 40+ tests.

## Mocking Strategy

- Mock at I/O boundaries: `KeyExecutor`, `CardExecutor`, `SystemDeps` via `mockall`.
- Do NOT mock crypto operations — use pre-generated fixture keys instead. Real PGP keys ensure correctness; mocking crypto tests nothing useful.
- Pure logic (validation, parsing, type conversions): test directly, no mocks or fixtures needed.

## Conventions

- `unwrap()` is acceptable in test code.
- Use `#[ignore]` on tests that require hardware (smart card) or external services.
- Test names should describe the behavior being tested, not the implementation.
- Each new command gets at least one `#[ignore]` test anchor to be filled in during implementation.
- Use `rstest` `#[case]` for parameterized validation tests (types, parsing).
