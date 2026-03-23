---
name: check
description: Run full validation — format, lint, deny, test
---

# Full Validation Check

Run the complete validation pipeline:

```bash
cargo fmt -- --check && cargo clippy --all-targets -- -D warnings && cargo deny check && cargo audit && cargo nextest run
```

If any step fails, stop and report the failure. Do not continue to subsequent steps.

- **Format check** (`cargo fmt -- --check`): Ensures all code is formatted. Fix with `cargo fmt`.
- **Clippy** (`cargo clippy --all-targets -- -D warnings`): Lint with warnings as errors.
- **Deny** (`cargo deny check`): License compliance and advisory database.
- **Audit** (`cargo audit`): Security advisory check.
- **Tests** (`cargo nextest run`): Full test suite.
