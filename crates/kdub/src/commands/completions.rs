use clap::CommandFactory;
use clap_complete::{Shell, generate};
use std::io;

use crate::cli::{Cli, CompletionsArgs, ShellType};

use super::CmdResult;

pub fn run(args: &CompletionsArgs) -> CmdResult {
    let mut cmd = Cli::command();
    let shell = match args.shell {
        ShellType::Bash => Shell::Bash,
        ShellType::Zsh => Shell::Zsh,
        ShellType::Fish => Shell::Fish,
    };
    generate(shell, &mut cmd, "kdub", &mut io::stdout());
    Ok(())
}
