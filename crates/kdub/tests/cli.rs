use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use rstest::rstest;

#[test]
fn help_shows_all_commands() {
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("version"))
        .stdout(predicate::str::contains("completions"))
        .stdout(predicate::str::contains("key"))
        .stdout(predicate::str::contains("card"));
}

#[test]
fn help_snapshot() {
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .arg("--help")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    insta::assert_snapshot!(stdout);
}

#[test]
fn key_help_shows_subcommands() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["key", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("backup"))
        .stdout(predicate::str::contains("restore"))
        .stdout(predicate::str::contains("renew"))
        .stdout(predicate::str::contains("rotate"))
        .stdout(predicate::str::contains("publish"));
}

#[test]
fn card_help_shows_subcommands() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("info"))
        .stdout(predicate::str::contains("setup"))
        .stdout(predicate::str::contains("provision"))
        .stdout(predicate::str::contains("reset"))
        .stdout(predicate::str::contains("touch"));
}

#[test]
fn version_prints_version() {
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains("kdub"));
}

#[test]
fn version_shows_build_info() {
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("version")
        .assert()
        .success()
        .stdout(predicate::str::contains(format!(
            "kdub {}",
            env!("CARGO_PKG_VERSION")
        )))
        .stdout(predicate::str::contains("target:"));
}

#[test]
fn doctor_runs_successfully() {
    // doctor is now implemented — it should exit 0 and produce output
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("doctor")
        .assert()
        .success()
        .stdout(predicate::str::contains("System check:"));
}

#[test]
fn doctor_json_produces_valid_json() {
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["dependencies"].is_object());
    assert!(parsed["config"].is_object());
    assert!(parsed["status"].is_string());
}

#[test]
fn doctor_quiet_suppresses_output() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--quiet", "doctor"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// ---------------------------------------------------------------------------
// init command integration tests
// ---------------------------------------------------------------------------

#[test]
fn init_creates_expected_files() {
    let tmp = tempfile::tempdir().unwrap();

    // Use XDG env vars to redirect all paths into the temp dir
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("init")
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        // Clear tor proxy so dirmngr.conf is not created
        .env_remove("KDUB_TOR_PROXY")
        .assert()
        .success();

    // Check that XDG-based paths were created
    let xdg_config = tmp.path().join("config_home").join("kdub");
    let xdg_data = tmp.path().join("data_home").join("kdub");

    assert!(xdg_config.join("config.toml").exists());
    assert!(xdg_config.join("gpg.conf").exists());
    assert!(xdg_config.join("gpg-agent.conf").exists());
    assert!(xdg_config.join("scdaemon.conf").exists());
    assert!(!xdg_config.join("dirmngr.conf").exists());

    assert!(xdg_data.join("identities").exists());
    assert!(xdg_data.join("backups").exists());
}

#[test]
fn init_force_overwrites_config() {
    let tmp = tempfile::tempdir().unwrap();

    let run_init = |force: bool| {
        let mut cmd = Command::cargo_bin("kdub").unwrap();
        cmd.arg("init")
            .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
            .env("XDG_DATA_HOME", tmp.path().join("data_home"))
            .env("XDG_STATE_HOME", tmp.path().join("state_home"))
            .env_remove("KDUB_TOR_PROXY");
        if force {
            cmd.arg("--force");
        }
        cmd.assert().success();
    };

    // First init
    run_init(false);

    let config_path = tmp
        .path()
        .join("config_home")
        .join("kdub")
        .join("config.toml");

    // Overwrite with custom content
    fs::write(&config_path, "# custom\n").unwrap();

    // Second init without --force
    run_init(false);
    let content = fs::read_to_string(&config_path).unwrap();
    assert_eq!(
        content, "# custom\n",
        "config.toml should NOT be overwritten without --force"
    );

    // Third init with --force
    run_init(true);
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(
        content.contains("[key]"),
        "config.toml should be overwritten with --force"
    );
}

#[test]
fn init_with_data_dir_override() {
    let tmp = tempfile::tempdir().unwrap();
    let custom_data = tmp.path().join("custom_data");

    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--data-dir", custom_data.to_str().unwrap(), "init"])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_TOR_PROXY")
        .assert()
        .success();

    assert!(custom_data.join("identities").exists());
    assert!(custom_data.join("backups").exists());
}

#[test]
fn init_with_tor_proxy_creates_dirmngr() {
    let tmp = tempfile::tempdir().unwrap();

    Command::cargo_bin("kdub")
        .unwrap()
        .arg("init")
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env("KDUB_TOR_PROXY", "socks5h://127.0.0.1:9050")
        .assert()
        .success();

    let dirmngr = tmp
        .path()
        .join("config_home")
        .join("kdub")
        .join("dirmngr.conf");
    assert!(
        dirmngr.exists(),
        "dirmngr.conf should exist when KDUB_TOR_PROXY is set"
    );
}

// ---------------------------------------------------------------------------
// completions command integration tests
// ---------------------------------------------------------------------------

#[rstest]
#[case("bash", "_kdub")]
#[case("zsh", "#compdef kdub")]
#[case("fish", "kdub")]
fn completions_produces_output(#[case] shell: &str, #[case] expected: &str) {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["completions", shell])
        .assert()
        .success()
        .stdout(predicate::str::contains(expected));
}

#[test]
fn init_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();

    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--quiet", "init"])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_TOR_PROXY")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}
