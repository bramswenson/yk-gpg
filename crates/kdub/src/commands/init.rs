use directories::ProjectDirs;
use kdub_lib::init::{InitOptions, detect_platform, run_init};

use crate::cli::{GlobalOpts, InitArgs};

use super::CmdResult;

pub fn run(args: &InitArgs, global: &GlobalOpts) -> CmdResult {
    let platform = detect_platform();

    // Resolve XDG paths. ProjectDirs gives us standard locations.
    let proj_dirs = ProjectDirs::from("", "", "kdub").ok_or_else(|| {
        kdub_lib::error::KdubError::Config(
            "could not determine home directory for XDG paths".to_string(),
        )
    })?;

    // config_dir: respect KDUB_CONFIG_DIR / XDG_CONFIG_HOME, else platform default
    let config_dir = if let Ok(dir) = std::env::var("KDUB_CONFIG_DIR") {
        std::path::PathBuf::from(dir)
    } else if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        std::path::PathBuf::from(xdg).join("kdub")
    } else {
        proj_dirs.config_dir().to_path_buf()
    };

    // data_dir: respect --data-dir / KDUB_DATA_DIR / XDG_DATA_HOME, else platform default
    let data_dir = if let Some(d) = &global.data_dir {
        d.clone()
    } else if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(xdg).join("kdub")
    } else {
        proj_dirs.data_dir().to_path_buf()
    };

    // state_dir: skip on Tails, else respect XDG_STATE_HOME
    let state_dir = if platform == "tails" {
        None
    } else if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        Some(std::path::PathBuf::from(xdg).join("kdub"))
    } else {
        Some(
            proj_dirs
                .state_dir()
                .unwrap_or(proj_dirs.data_dir())
                .to_path_buf(),
        )
    };

    // tor_proxy from env var
    let tor_proxy = std::env::var("KDUB_TOR_PROXY")
        .ok()
        .filter(|v| !v.is_empty());

    let opts = InitOptions {
        config_dir,
        data_dir,
        state_dir,
        force: args.force,
        platform,
        tor_proxy,
    };

    let actions = run_init(&opts)?;

    if !global.quiet {
        for action in &actions {
            println!("{action}");
        }
    }

    Ok(())
}
