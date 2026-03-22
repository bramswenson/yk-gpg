---
globs: .github/workflows/**
---

# CI Workflow Rules

## Test Runner

- Use `cargo-nextest` for running tests (not `cargo test`).
- Install via `cargo install cargo-nextest` or `taiki-e/install-action`.

## Coverage

- Use `cargo-llvm-cov` for code coverage.
- Generate LCOV output for CI integration: `cargo llvm-cov nextest --lcov --output-path lcov.info`.

## Dependency Auditing

- `cargo deny check` for license compliance and advisory database checks.
- `cargo audit` as a secondary advisory check.
- Both must pass in CI.

## Platform Matrix

- Run on both `ubuntu-latest` and `macos-latest`.
- macOS-specific gotchas:
  - BSD `tr` rejects raw binary — use `openssl rand -base64` instead of `/dev/urandom`.
  - 104-byte Unix socket path limit — keep `GNUPGHOME` paths short.
  - Pinentry path: `/usr/bin/false` (not `/bin/false`).

## Workflow Structure

- Lint job: `cargo fmt -- --check`, `cargo clippy --all-targets -- -D warnings`, `cargo deny check`.
- Test job: `cargo nextest run` on both platforms.
- Coverage job: `cargo llvm-cov nextest` on Linux only.
