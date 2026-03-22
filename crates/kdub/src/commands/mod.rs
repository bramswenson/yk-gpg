mod card;
mod completions;
mod doctor;
mod init;
mod key;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use color_eyre::eyre;
use kdub_lib::error::KdubError;

use crate::cli::{Cli, Command};

pub fn dispatch(cli: Cli, shutdown: &Arc<AtomicBool>) -> eyre::Result<ExitCode> {
    // Check for early shutdown before dispatching
    if shutdown.load(Ordering::Relaxed) {
        eprintln!("error: interrupted");
        return Ok(ExitCode::from(6));
    }

    let result = match cli.command {
        Command::Init(args) => init::run(&args, &cli.global),
        Command::Doctor(args) => doctor::run(&args, &cli.global),
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
        Command::Completions(args) => completions::run(&args),
        Command::Key { cmd } => key::run(&cmd, &cli.global),
        Command::Card { cmd } => card::run(&cmd, &cli.global),
    };

    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(e) => {
            eprintln!("error: {e}");
            Ok(ExitCode::from(e.exit_code() as u8))
        }
    }
}

/// Convenience alias used by command stubs.
pub(crate) type CmdResult = Result<(), KdubError>;
