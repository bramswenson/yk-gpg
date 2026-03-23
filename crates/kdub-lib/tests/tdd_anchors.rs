//! TDD anchor tests for Phase B commands.
//! These are #[ignore]d stubs — un-ignore and implement in Phase B.

use std::fs;
use std::os::unix::fs::PermissionsExt;

use kdub_lib::doctor::{DaemonStatus, DepInfo, DepStatus, SystemDeps, run_doctor};
use kdub_lib::init::{InitOptions, run_init};

#[test]
fn test_init_creates_config_dir() {
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

    // Config dir created with mode 0700
    assert!(opts.config_dir.exists());
    let mode = fs::metadata(&opts.config_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);

    // config.toml created with mode 0600
    let config_toml = opts.config_dir.join("config.toml");
    assert!(config_toml.exists());
    let mode = fs::metadata(&config_toml).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // gpg.conf with correct content
    let gpg_conf = fs::read_to_string(opts.config_dir.join("gpg.conf")).unwrap();
    assert!(gpg_conf.contains("cert-digest-algo SHA512"));

    // gpg-agent.conf with cache settings
    let agent_conf = fs::read_to_string(opts.config_dir.join("gpg-agent.conf")).unwrap();
    assert!(agent_conf.contains("default-cache-ttl 60"));

    // scdaemon.conf with disable-ccid
    let scd_conf = fs::read_to_string(opts.config_dir.join("scdaemon.conf")).unwrap();
    assert!(scd_conf.contains("disable-ccid"));

    // dirmngr.conf should NOT exist (no KDUB_TOR_PROXY)
    assert!(!opts.config_dir.join("dirmngr.conf").exists());

    // Data dirs created
    assert!(opts.data_dir.join("identities").exists());
    assert!(opts.data_dir.join("backups").exists());

    // State dir created
    assert!(base.join("state").exists());
}

#[test]
fn test_init_skip_without_force() {
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

    // First init
    run_init(&opts).unwrap();

    // Write custom config.toml
    let config_path = opts.config_dir.join("config.toml");
    fs::write(&config_path, "# custom\n").unwrap();

    // Second init without --force: config.toml should be unchanged
    let actions = run_init(&opts).unwrap();
    assert!(
        actions
            .iter()
            .any(|a| a.contains("Skipped") && a.contains("config.toml"))
    );
    let content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(content, "# custom\n");
}

#[test]
fn test_init_force_overwrites() {
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

    // First init
    run_init(&opts).unwrap();

    // Write custom config.toml
    let config_path = opts.config_dir.join("config.toml");
    fs::write(&config_path, "# custom\n").unwrap();

    // Second init WITH --force: config.toml should be overwritten
    let force_opts = InitOptions {
        config_dir: base.join("config"),
        data_dir: base.join("data"),
        state_dir: Some(base.join("state")),
        force: true,
        platform: "linux".to_string(),
        tor_proxy: None,
    };
    let actions = run_init(&force_opts).unwrap();
    assert!(
        actions
            .iter()
            .any(|a| a.contains("Overwrote") && a.contains("config.toml"))
    );
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("[key]")); // default config restored
}

#[test]
fn test_doctor_reports_missing_deps() {
    // Phase B: kdub doctor reports missing gpg, scdaemon, etc.
    // Uses a mock that returns gpg as missing → overall_ok should be false.
    struct MockMissingGpg;

    impl SystemDeps for MockMissingGpg {
        fn check_command(&self, name: &str) -> Option<DepInfo> {
            match name {
                "gpg" => None, // required, missing
                "gpg-agent" => Some(DepInfo {
                    version: "2.4.5".to_string(),
                    path: std::path::PathBuf::from("/usr/bin/gpg-agent"),
                }),
                _ => None,
            }
        }
        fn check_pcscd(&self) -> DaemonStatus {
            DaemonStatus::NotRunning
        }
        fn check_scdaemon(&self) -> Option<DepInfo> {
            None
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let config = tmp.path().join("config");
    let data = tmp.path().join("data");
    fs::create_dir_all(&config).unwrap();
    fs::create_dir_all(&data).unwrap();

    let report = run_doctor(&MockMissingGpg, &config, &data).unwrap();

    // gpg is required and missing → overall_ok must be false
    assert!(!report.overall_ok);

    // gpg should be reported as Missing
    let gpg = report
        .dependencies
        .iter()
        .find(|d| d.name == "gpg")
        .expect("gpg should be in the report");
    assert!(matches!(gpg.status, DepStatus::Missing));

    // gpg-agent should be reported as Ok
    let agent = report
        .dependencies
        .iter()
        .find(|d| d.name == "gpg-agent")
        .expect("gpg-agent should be in the report");
    assert!(matches!(agent.status, DepStatus::Ok { .. }));

    // Optional deps missing should not affect overall_ok (but gpg being missing does)
    let jq = report
        .dependencies
        .iter()
        .find(|d| d.name == "jq")
        .expect("jq should be in the report");
    assert!(matches!(jq.status, DepStatus::Missing));
}

#[test]
fn test_version_includes_git_sha() {
    // Phase B: kdub version includes git sha and build target.
    // Verified via CLI integration test in crates/kdub/tests/cli.rs::version_shows_build_info.
    // The vergen env vars (VERGEN_GIT_SHA, KDUB_BUILD_DATE, KDUB_TARGET) are embedded at
    // compile time by build.rs in crates/kdub. This lib crate has no binary to test directly.
}

#[test]
fn test_completions_bash_valid() {
    // Phase B: kdub completions bash produces valid bash completion script.
    // Real integration tests live in crates/kdub/tests/cli.rs:
    //   completions_bash_produces_output
    //   completions_zsh_produces_output
    //   completions_fish_produces_output
    // This lib crate has no binary to invoke, so the anchor simply passes.
}
