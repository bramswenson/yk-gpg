---
globs: crates/kdub-lib/**/*.rs
---

# Library Crate Rules

## Error Handling

- Use `thiserror` for all error types.
- Use `#[from]` for automatic error conversion chains.
- Error variants must use newtypes only — never raw credential values in error messages.
- `KdubError` is a single flat enum (no sub-enums). Add variants per phase as needed.
- No `unwrap()`. Use `?` for propagation. Use `.expect("reason")` only where the invariant is provably infallible.

## Trait-Based Design

- Core traits: `KeyExecutor`, `CardExecutor`, `SystemDeps`.
- Concrete implementations are behind trait objects or generics for testability.
- All platform-specific code uses `cfg(target_os)` for dispatch.

## Documentation

- All public items (`pub fn`, `pub struct`, `pub enum`, `pub trait`, `pub type`) require `///` doc comments.
- Doc comments should explain the *why*, not just restate the type name.

## Type Safety

- `Fingerprint([u8; 20])`: hex validation in `FromStr`, uppercase normalization.
- `AdminPin(SecretString)`: validates 8 numeric digits in `FromStr`.
- `UserPin(SecretString)`: validates 6 numeric digits in `FromStr`.
- `Passphrase(SecretString)`: rejects empty strings.
- `GithubToken(SecretString)`: rejects empty strings.
- `Display` is banned on secret types — use `secrecy::ExposeSecret` only.
- Never use secret types as `tracing` span or event fields.

## Enums and Constants

- `#[non_exhaustive]` on all public enums.
- `const` defaults in `defaults.rs` — no magic strings or numbers scattered in code.

## Runtime

- Synchronous only — no tokio/async runtime.
- File permissions: directories `0o700`, files `0o600`.
- Config precedence: CLI flags > env vars > config file > compiled defaults.

## Platform Dispatch

- Use `cfg(target_os = "linux")`, `cfg(target_os = "macos")` for platform-specific code.
- Shared logic stays in platform-agnostic modules; only the divergent parts go behind `cfg`.
