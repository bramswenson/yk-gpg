//! Handler for the `kdub update` subcommand.

use crate::cli::{GlobalOpts, UpdateArgs};

/// Delegate to the updater module, translating CLI args into the update workflow.
pub fn run(args: &UpdateArgs, global: &GlobalOpts) -> color_eyre::Result<()> {
    crate::updater::run_update(args.check, args.yes || global.batch)
}
