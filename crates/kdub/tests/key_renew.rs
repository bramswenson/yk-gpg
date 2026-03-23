mod fixture;

use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

/// Helper to run kdub commands with isolated environment (no fixture data dir).
fn kdub_cmd(tmp: &tempfile::TempDir, data_dir: &std::path::Path) -> Command {
    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE");
    cmd
}

#[test]
fn test_key_renew_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Run renew
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "renew",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
            "--expiration",
            "3y",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key renewed successfully"))
        .stdout(predicate::str::contains("Renewed subkey"))
        .stdout(predicate::str::contains("3y"));

    // Verify metadata has renewed timestamp
    let meta_path = data_dir
        .join("identities")
        .join(format!("{}.json", fixture::FINGERPRINT));
    let meta_content = fs::read_to_string(&meta_path).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();
    assert!(
        meta["renewed"].is_string(),
        "renewed timestamp should be set"
    );
}

#[test]
fn test_key_renew_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Renew by name instead of fingerprint
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "renew",
            "Test Fixture",
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key renewed successfully"));
}

#[test]
fn test_key_renew_missing_passphrase_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Renew without passphrase in batch mode should fail
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "renew", fixture::FINGERPRINT])
        .assert()
        .failure()
        .stderr(predicate::str::contains("batch").or(predicate::str::contains("passphrase")));
}

#[test]
fn test_key_renew_wrong_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "renew",
            fixture::FINGERPRINT,
            "--passphrase",
            "wrongpassword",
        ])
        .assert()
        .failure();
}

#[test]
fn test_key_renew_nonexistent_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();

    kdub_cmd(&tmp, &data_dir)
        .args([
            "key",
            "renew",
            "NoSuchPerson",
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .assert()
        .failure();
}

#[test]
fn test_key_renew_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .arg("--quiet")
        .args([
            "key",
            "renew",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "quiet mode should produce no stdout"
    );
}

#[test]
fn test_key_renew_with_env_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "renew", fixture::FINGERPRINT])
        .env("KDUB_PASSPHRASE", fixture::PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("Key renewed successfully"));
}
