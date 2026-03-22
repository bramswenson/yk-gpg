mod cli;
mod commands;
// Used by command implementations in later phases.
#[allow(dead_code)]
mod secret_input;

use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use clap::Parser;
use color_eyre::eyre;

use crate::cli::Cli;

fn main() -> eyre::Result<ExitCode> {
    color_eyre::install()?;

    // Signal handler: set SHUTDOWN flag on SIGINT / SIGTERM
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))?;

    // CI / BATCH_MODE pre-parse: inject --batch if either env var is truthy
    let inject_batch = is_truthy_env("CI") || is_truthy_env("BATCH_MODE");

    let cli = if inject_batch {
        let mut args: Vec<String> = std::env::args().collect();
        // Insert --batch right after the binary name (position 1) so it is
        // parsed as a global flag before any subcommand.
        if !args.iter().any(|a| a == "--batch") {
            args.insert(1, "--batch".to_string());
        }
        Cli::parse_from(args)
    } else {
        Cli::parse()
    };

    // Tracing subscriber: verbosity from --verbose / --quiet
    let filter = match (cli.global.quiet, cli.global.verbose) {
        (true, _) => "error",
        (_, 0) => "warn",
        (_, 1) => "info",
        (_, 2) => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_env_var("KDUB_LOG")
                .try_from_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_writer(std::io::stderr)
        .init();

    commands::dispatch(cli, &shutdown)
}

/// Check whether an environment variable is set to a truthy value.
fn is_truthy_env(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}
