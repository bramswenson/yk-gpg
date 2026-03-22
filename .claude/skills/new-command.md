---
name: new-command
description: Scaffold a new clap subcommand
---

# Scaffold New Command

When adding a new CLI subcommand, follow these steps:

1. **Create the command module** at `crates/kdub/src/commands/<name>.rs`:
   ```rust
   use clap::Args;
   use kdub_lib::KdubError;
   use crate::GlobalOpts;

   /// Short description of the command.
   #[derive(Debug, Args)]
   pub struct <Name>Args {
       // Add arguments and flags here
   }

   /// Execute the <name> command.
   pub fn run(args: &<Name>Args, global: &GlobalOpts) -> Result<(), KdubError> {
       todo!("implement <name> command")
   }
   ```

2. **Add the variant** to the `Command` enum in `crates/kdub/src/cli.rs`:
   ```rust
   /// Short description of the command.
   <Name>(<Name>Args),
   ```

3. **Add dispatch** in `crates/kdub/src/commands/mod.rs`:
   ```rust
   pub mod <name>;
   ```
   And in the match arm:
   ```rust
   Command::<Name>(args) => <name>::run(args, global),
   ```

4. **Create a test anchor** in `crates/kdub/tests/cmd_<name>.rs`:
   ```rust
   use assert_cmd::Command;

   #[test]
   #[ignore] // TODO: implement
   fn test_<name>_basic() {
       let mut cmd = Command::cargo_bin("kdub").unwrap();
       cmd.arg("<name>");
       cmd.assert().success();
   }
   ```

5. **Run validation** to ensure the scaffold compiles:
   ```bash
   cargo build && cargo nextest run
   ```
