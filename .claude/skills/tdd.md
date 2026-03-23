---
name: tdd
description: Run TDD cycle — write failing test, implement, verify, refactor
---

# TDD Cycle

Follow these steps strictly:

1. **Write a failing test** that captures the desired behavior. Place it in the appropriate module (`#[cfg(test)] mod tests` for unit tests, `tests/` for integration tests).

2. **Run the test and verify it fails:**
   ```bash
   cargo nextest run <test_name>
   ```
   Confirm the failure is for the expected reason (compilation error or assertion failure matching the unimplemented behavior), not an unrelated error.

3. **Implement** the minimum code to make the test pass. Do not add functionality beyond what the test requires.

4. **Run the test and verify it passes:**
   ```bash
   cargo nextest run <test_name>
   ```

5. **Run the full suite** to check for regressions:
   ```bash
   cargo nextest run
   ```

6. **Refactor** if needed while keeping all tests green. Run `cargo clippy --all-targets -- -D warnings` and `cargo fmt` after refactoring.

7. **If using insta snapshots**, review them:
   ```bash
   INSTA_UPDATE=new cargo nextest run
   cargo insta review
   ```

Repeat for the next behavior.
