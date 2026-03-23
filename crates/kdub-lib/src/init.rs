use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::config::{
    DIRMNGR_CONF, GPG_CONF, default_config_toml, generate_gpg_agent_conf, generate_scdaemon_conf,
};
use crate::error::KdubError;

/// Options controlling the `init` command behaviour.
pub struct InitOptions {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    /// `None` when running on Tails (no persistent state dir).
    pub state_dir: Option<PathBuf>,
    pub force: bool,
    /// Platform string: "tails", "macos", or "linux".
    pub platform: String,
    /// If set, install `dirmngr.conf` with Tor proxy routing.
    pub tor_proxy: Option<String>,
}

/// Run the init command: create directories, install configuration files.
///
/// Returns a list of human-readable action descriptions (one per action taken).
pub fn run_init(opts: &InitOptions) -> Result<Vec<String>, KdubError> {
    let mut actions = Vec::new();

    // --- Create directories ---

    create_dir_mode(&opts.config_dir, 0o700, &mut actions)?;

    let identities_dir = opts.data_dir.join("identities");
    let backups_dir = opts.data_dir.join("backups");
    create_dir_mode(&opts.data_dir, 0o700, &mut actions)?;
    create_dir_mode(&identities_dir, 0o700, &mut actions)?;
    create_dir_mode(&backups_dir, 0o700, &mut actions)?;

    if let Some(ref state_dir) = opts.state_dir {
        create_dir_mode(state_dir, 0o700, &mut actions)?;
    }

    // --- Write config.toml ---

    let config_toml_path = opts.config_dir.join("config.toml");
    if !config_toml_path.exists() || opts.force {
        let content = default_config_toml();
        write_file_mode(&config_toml_path, &content, 0o600)?;
        if opts.force && config_toml_path.exists() {
            actions.push(format!("Overwrote {}", config_toml_path.display()));
        } else {
            actions.push(format!("Created  {}", config_toml_path.display()));
        }
    } else {
        actions.push(format!(
            "Skipped  {} (already exists, use --force to overwrite)",
            config_toml_path.display()
        ));
    }

    // --- Install GPG configs (always overwrite) ---

    let gpg_conf_path = opts.config_dir.join("gpg.conf");
    write_file_mode(&gpg_conf_path, GPG_CONF, 0o600)?;
    actions.push(format!("Installed {}", gpg_conf_path.display()));

    let gpg_agent_conf_path = opts.config_dir.join("gpg-agent.conf");
    let gpg_agent_content = generate_gpg_agent_conf(&opts.platform);
    write_file_mode(&gpg_agent_conf_path, &gpg_agent_content, 0o600)?;
    actions.push(format!("Installed {}", gpg_agent_conf_path.display()));

    let scdaemon_conf_path = opts.config_dir.join("scdaemon.conf");
    let scdaemon_content = generate_scdaemon_conf(&opts.platform);
    write_file_mode(&scdaemon_conf_path, &scdaemon_content, 0o600)?;
    actions.push(format!("Installed {}", scdaemon_conf_path.display()));

    // dirmngr.conf only if tor_proxy is set
    if opts.tor_proxy.is_some() {
        let dirmngr_conf_path = opts.config_dir.join("dirmngr.conf");
        write_file_mode(&dirmngr_conf_path, DIRMNGR_CONF, 0o600)?;
        actions.push(format!("Installed {}", dirmngr_conf_path.display()));
    }

    Ok(actions)
}

/// Detect the current platform as a string: "tails", "macos", or "linux".
pub fn detect_platform() -> String {
    if cfg!(target_os = "macos") {
        return "macos".to_string();
    }

    // Check for Tails OS via /etc/os-release
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        // Tails sets ID=tails or TAILS_PRODUCT_NAME
        for line in content.lines() {
            if line.starts_with("ID=") {
                let val = line.trim_start_matches("ID=").trim_matches('"');
                if val == "tails" {
                    return "tails".to_string();
                }
            }
        }
    }

    "linux".to_string()
}

/// Create a directory (and parents) with the specified Unix mode.
fn create_dir_mode(path: &Path, mode: u32, actions: &mut Vec<String>) -> Result<(), KdubError> {
    let existed = path.exists();
    fs::create_dir_all(path)?;
    fs::set_permissions(path, Permissions::from_mode(mode))?;
    if existed {
        actions.push(format!("Verified  {}/", path.display()));
    } else {
        actions.push(format!("Created   {}/", path.display()));
    }
    Ok(())
}

/// Write a file and set its Unix permissions.
fn write_file_mode(path: &Path, content: &str, mode: u32) -> Result<(), KdubError> {
    fs::write(path, content)?;
    fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_init_creates_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        let actions = run_init(&opts).unwrap();
        assert!(!actions.is_empty());

        // Directories exist
        assert!(opts.config_dir.exists());
        assert!(opts.data_dir.exists());
        assert!(opts.data_dir.join("identities").exists());
        assert!(opts.data_dir.join("backups").exists());
        assert!(base.join("state").exists());

        // Files exist
        assert!(opts.config_dir.join("config.toml").exists());
        assert!(opts.config_dir.join("gpg.conf").exists());
        assert!(opts.config_dir.join("gpg-agent.conf").exists());
        assert!(opts.config_dir.join("scdaemon.conf").exists());

        // dirmngr.conf should NOT exist (no tor_proxy)
        assert!(!opts.config_dir.join("dirmngr.conf").exists());
    }

    #[test]
    fn test_run_init_no_state_dir_on_tails() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: None, // Tails
            force: false,
            platform: "tails".to_string(),
            tor_proxy: None,
        };

        let actions = run_init(&opts).unwrap();
        // No state dir should be created
        let state_mentioned = actions.iter().any(|a| a.contains("state"));
        assert!(!state_mentioned);
    }

    #[test]
    fn test_run_init_with_tor_proxy() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: Some("socks5h://127.0.0.1:9050".to_string()),
        };

        let actions = run_init(&opts).unwrap();
        assert!(opts.config_dir.join("dirmngr.conf").exists());
        assert!(actions.iter().any(|a| a.contains("dirmngr.conf")));
    }

    #[test]
    fn test_run_init_skips_existing_config_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        // First run creates config.toml
        run_init(&opts).unwrap();

        // Overwrite config.toml with custom content
        let config_path = opts.config_dir.join("config.toml");
        fs::write(&config_path, "# custom content\n").unwrap();

        // Second run without --force should skip config.toml
        let actions = run_init(&opts).unwrap();
        assert!(
            actions
                .iter()
                .any(|a| a.contains("Skipped") && a.contains("config.toml"))
        );

        // Custom content should be preserved
        let content = fs::read_to_string(&config_path).unwrap();
        assert_eq!(content, "# custom content\n");
    }

    #[test]
    fn test_run_init_force_overwrites_config_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts_no_force = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        // First run creates config.toml
        run_init(&opts_no_force).unwrap();

        // Overwrite with custom content
        let config_path = opts_no_force.config_dir.join("config.toml");
        fs::write(&config_path, "# custom content\n").unwrap();

        // Second run WITH --force should overwrite
        let opts_force = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: true,
            platform: "linux".to_string(),
            tor_proxy: None,
        };
        let actions = run_init(&opts_force).unwrap();
        assert!(
            actions
                .iter()
                .any(|a| a.contains("Overwrote") && a.contains("config.toml"))
        );

        // Should be the default config, not our custom content
        let content = fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("[key]"));
    }

    #[test]
    fn test_dir_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        run_init(&opts).unwrap();

        let check_mode = |path: &Path, expected: u32| {
            let meta = fs::metadata(path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode,
                expected,
                "wrong mode for {}: {:o} != {:o}",
                path.display(),
                mode,
                expected
            );
        };

        check_mode(&opts.config_dir, 0o700);
        check_mode(&opts.data_dir, 0o700);
        check_mode(&opts.data_dir.join("identities"), 0o700);
        check_mode(&opts.data_dir.join("backups"), 0o700);
        check_mode(&base.join("state"), 0o700);
    }

    #[test]
    fn test_file_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        run_init(&opts).unwrap();

        let check_mode = |path: &Path, expected: u32| {
            let meta = fs::metadata(path).unwrap();
            let mode = meta.permissions().mode() & 0o777;
            assert_eq!(
                mode,
                expected,
                "wrong mode for {}: {:o} != {:o}",
                path.display(),
                mode,
                expected
            );
        };

        check_mode(&opts.config_dir.join("config.toml"), 0o600);
        check_mode(&opts.config_dir.join("gpg.conf"), 0o600);
        check_mode(&opts.config_dir.join("gpg-agent.conf"), 0o600);
        check_mode(&opts.config_dir.join("scdaemon.conf"), 0o600);
    }

    #[test]
    fn test_gpg_conf_content() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        run_init(&opts).unwrap();

        let content = fs::read_to_string(opts.config_dir.join("gpg.conf")).unwrap();
        assert!(content.contains("cert-digest-algo SHA512"));
        assert!(content.contains("throw-keyids"));
    }

    #[test]
    fn test_gpg_agent_conf_content() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        run_init(&opts).unwrap();

        let content = fs::read_to_string(opts.config_dir.join("gpg-agent.conf")).unwrap();
        assert!(content.contains("default-cache-ttl 60"));
        assert!(content.contains("enable-ssh-support"));
    }

    #[test]
    fn test_scdaemon_conf_content() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path();

        let opts = InitOptions {
            config_dir: base.join("config"),
            data_dir: base.join("data"),
            state_dir: Some(base.join("state")),
            force: false,
            platform: "linux".to_string(),
            tor_proxy: None,
        };

        run_init(&opts).unwrap();

        let content = fs::read_to_string(opts.config_dir.join("scdaemon.conf")).unwrap();
        assert!(content.contains("disable-ccid"));
    }

    #[test]
    fn test_detect_platform_not_empty() {
        let platform = detect_platform();
        assert!(!platform.is_empty());
        // On this test machine, should be "linux" or "macos"
        assert!(platform == "linux" || platform == "macos" || platform == "tails");
    }
}
