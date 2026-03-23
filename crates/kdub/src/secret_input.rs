use std::io::BufRead;

use kdub_lib::error::KdubError;
use kdub_lib::types::ParseError;
use secrecy::{ExposeSecret, SecretString};

/// Resolve a secret value using the standard precedence:
/// 1. CLI flag value (`flag_value`)
/// 2. stdin (if `stdin_flag` is true — read one line)
/// 3. Environment variable (`env_var_name`)
/// 4. Interactive prompt (using `dialoguer::Password`)
///
/// In batch mode, returns an error if no value is available from
/// steps 1-3 (interactive prompting is not allowed).
pub fn resolve_secret<T: std::str::FromStr<Err = ParseError>>(
    flag_value: Option<&str>,
    stdin_flag: bool,
    env_var_name: &str,
    prompt: &str,
    batch: bool,
) -> Result<T, KdubError> {
    // 1. CLI flag
    if let Some(val) = flag_value {
        return val.parse::<T>().map_err(KdubError::Parse);
    }

    // 2. stdin
    if stdin_flag {
        let line = read_line_from_stdin()?;
        return line.expose_secret().parse::<T>().map_err(KdubError::Parse);
    }

    // 3. Environment variable
    if let Ok(val) = std::env::var(env_var_name)
        && !val.is_empty()
    {
        return val.parse::<T>().map_err(KdubError::Parse);
    }

    // 4. Interactive prompt (only in non-batch mode)
    if batch {
        return Err(KdubError::UsageError(
            "batch mode requires secret via flag, stdin, or env var".to_string(),
        ));
    }

    let input = dialoguer::Password::new()
        .with_prompt(prompt)
        .interact()
        .map_err(|e| KdubError::Io(std::io::Error::other(e)))?;

    input.parse::<T>().map_err(KdubError::Parse)
}

/// Read a single line from stdin.
fn read_line_from_stdin() -> Result<SecretString, KdubError> {
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line).map_err(KdubError::Io)?;
    if line.is_empty() {
        return Err(KdubError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "no input on stdin",
        )));
    }
    Ok(SecretString::from(line.trim().to_string()))
}

/// Validate that at most one stdin-consuming flag is set.
/// Multiple `--*-stdin` flags would race for the same stdin stream.
pub fn check_stdin_conflicts(flags: &[(&str, bool)]) -> Result<(), KdubError> {
    let active: Vec<&str> = flags
        .iter()
        .filter(|(_, set)| *set)
        .map(|(name, _)| *name)
        .collect();
    if active.len() > 1 {
        return Err(KdubError::UsageError(format!(
            "conflicting stdin flags: {} — only one can read stdin",
            active.join(", ")
        )));
    }
    Ok(())
}
