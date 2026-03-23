mod card;
mod completions;
mod doctor;
mod init;
mod key;
mod update;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use color_eyre::eyre;
use directories::ProjectDirs;
use kdub_lib::error::KdubError;

use crate::cli::{Cli, Command, GlobalOpts};

pub fn dispatch(cli: Cli, shutdown: &Arc<AtomicBool>) -> eyre::Result<ExitCode> {
    // Check for early shutdown before dispatching
    if shutdown.load(Ordering::Relaxed) {
        eprintln!("error: interrupted");
        return Ok(ExitCode::from(6));
    }

    // Update command has a different error type (eyre, not KdubError)
    // because all update logic is CLI-only and does not use kdub-lib errors.
    if let Command::Update(ref args) = cli.command {
        return match update::run(args, &cli.global) {
            Ok(()) => Ok(ExitCode::SUCCESS),
            Err(e) => Err(e),
        };
    }

    let result = match cli.command {
        Command::Init(ref args) => init::run(args, &cli.global),
        Command::Doctor(ref args) => doctor::run(args, &cli.global),
        Command::Version => {
            let version = env!("CARGO_PKG_VERSION");
            let git_sha = option_env!("VERGEN_GIT_SHA").unwrap_or("unknown");
            let short_sha = if git_sha.len() >= 7 {
                &git_sha[..7]
            } else {
                git_sha
            };
            let build_date = option_env!("KDUB_BUILD_DATE").unwrap_or("unknown");
            let target = option_env!("KDUB_TARGET").unwrap_or("unknown");

            println!("kdub {version} ({short_sha} {build_date})");
            println!("  target: {target}");
            Ok(())
        }
        Command::Completions(ref args) => completions::run(args),
        Command::Key { ref cmd } => key::run(cmd, &cli.global),
        Command::Card { ref cmd } => card::run(cmd, &cli.global),
        Command::Update(_) => unreachable!(),
    };

    let is_ok = result.is_ok();
    let exit = match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    };

    // Print update notice on success only, and not after `kdub update` itself
    if is_ok && !cli.global.quiet && !matches!(cli.command, Command::Update(_)) {
        crate::updater::maybe_print_update_notice();
    }

    Ok(exit)
}

/// Resolve the data directory path.
pub(crate) fn resolve_data_dir(global: &GlobalOpts) -> Result<PathBuf, KdubError> {
    if let Some(ref d) = global.data_dir {
        return Ok(d.clone());
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("kdub"));
    }
    let proj_dirs = ProjectDirs::from("", "", "kdub").ok_or_else(|| {
        KdubError::Config("could not determine home directory for data paths".to_string())
    })?;
    Ok(proj_dirs.data_dir().to_path_buf())
}

/// Normalize a key ID or fingerprint to uppercase hex without 0x prefix.
pub(crate) fn normalize_key_id(key_id: &str) -> Result<String, KdubError> {
    let trimmed = key_id.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_part.is_empty() {
        return Err(KdubError::InvalidKeyId(
            "key ID cannot be empty".to_string(),
        ));
    }
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KdubError::InvalidKeyId(format!(
            "invalid hex characters in key ID: {hex_part}"
        )));
    }
    Ok(hex_part.to_ascii_uppercase())
}

/// Convenience alias used by command stubs.
pub(crate) type CmdResult = Result<(), KdubError>;
