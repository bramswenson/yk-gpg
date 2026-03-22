use directories::ProjectDirs;
use kdub_lib::doctor::{RealSystemDeps, run_doctor};
use kdub_lib::error::KdubError;

use crate::cli::{DoctorArgs, GlobalOpts};

use super::CmdResult;

pub fn run(args: &DoctorArgs, global: &GlobalOpts) -> CmdResult {
    let deps = RealSystemDeps;

    // Resolve XDG paths (same logic as init command)
    let proj_dirs = ProjectDirs::from("", "", "kdub").ok_or_else(|| {
        KdubError::Config("could not determine home directory for XDG paths".to_string())
    })?;

    // Respect KDUB_CONFIG_DIR / XDG_CONFIG_HOME, else platform default
    let config_dir = if let Ok(dir) = std::env::var("KDUB_CONFIG_DIR") {
        std::path::PathBuf::from(dir)
    } else if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        std::path::PathBuf::from(xdg).join("kdub")
    } else {
        proj_dirs.config_dir().to_path_buf()
    };

    // Respect --data-dir / KDUB_DATA_DIR / XDG_DATA_HOME, else platform default
    let data_dir = if let Some(d) = &global.data_dir {
        d.clone()
    } else if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(xdg).join("kdub")
    } else {
        proj_dirs.data_dir().to_path_buf()
    };

    let report = run_doctor(&deps, &config_dir, &data_dir)?;

    if args.json {
        let json = report.to_json()?;
        println!("{json}");
    } else if !global.quiet {
        print!("{}", report.to_plain_text());
    }

    Ok(())
}
