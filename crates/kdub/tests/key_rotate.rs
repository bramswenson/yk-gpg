use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

/// Helper: create a key and return (data_dir, fingerprint).
fn create_test_key(tmp: &tempfile::TempDir) -> (std::path::PathBuf, String) {
    let data_dir = tmp.path().join("data");

    let output = Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args([
            "key",
            "create",
            "Rotate Test <rotate@example.com>",
            "--passphrase",
            "testpass123",
            "--key-type",
            "ed25519",
        ])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE")
        .output()
        .unwrap();

    assert!(output.status.success(), "key create failed");

    // Extract fingerprint from output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let fp_line = stdout
        .lines()
        .find(|l| l.contains("Fingerprint:"))
        .expect("should contain Fingerprint line");
    let fingerprint = fp_line.split(':').next_back().unwrap().trim().to_string();

    (data_dir, fingerprint)
}

#[test]
fn test_key_rotate_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, fingerprint) = create_test_key(&tmp);

    // Run rotate
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["key", "rotate", &fingerprint, "--passphrase", "testpass123"])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"))
        .stdout(predicate::str::contains("Created new"));

    // Verify metadata has rotated timestamp
    let meta_path = data_dir
        .join("identities")
        .join(format!("{fingerprint}.json"));
    let meta_content = fs::read_to_string(&meta_path).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&meta_content).unwrap();
    assert!(
        meta["rotated"].is_string(),
        "rotated timestamp should be set"
    );
}

#[test]
fn test_key_rotate_revoke_old() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, fingerprint) = create_test_key(&tmp);

    // Run rotate with --revoke-old
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args([
            "key",
            "rotate",
            &fingerprint,
            "--passphrase",
            "testpass123",
            "--revoke-old",
        ])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"))
        .stdout(predicate::str::contains("Revoked old subkey"))
        .stdout(predicate::str::contains("Created new"))
        .stdout(predicate::str::contains("Old subkeys: revoked"));
}

#[test]
fn test_key_rotate_missing_passphrase_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, fingerprint) = create_test_key(&tmp);

    // Rotate without passphrase in batch mode should fail
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["key", "rotate", &fingerprint])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .failure()
        .stderr(predicate::str::contains("batch").or(predicate::str::contains("passphrase")));
}

#[test]
fn test_key_rotate_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, _fingerprint) = create_test_key(&tmp);

    // Rotate by name instead of fingerprint
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args([
            "key",
            "rotate",
            "Rotate Test",
            "--passphrase",
            "testpass123",
        ])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"));
}

#[test]
fn test_key_rotate_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, fingerprint) = create_test_key(&tmp);

    let output = Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .arg("--quiet")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["key", "rotate", &fingerprint, "--passphrase", "testpass123"])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_PASSPHRASE")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(
        output.stdout.is_empty(),
        "quiet mode should produce no stdout"
    );
}

#[test]
fn test_key_rotate_with_env_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, fingerprint) = create_test_key(&tmp);

    Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["key", "rotate", &fingerprint])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env("KDUB_PASSPHRASE", "testpass123")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"));
}

#[test]
fn test_key_rotate_with_key_type_override() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, fingerprint) = create_test_key(&tmp);

    // Rotate with explicit key type
    Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args([
            "key",
            "rotate",
            &fingerprint,
            "--passphrase",
            "testpass123",
            "--key-type",
            "ed25519",
        ])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"))
        .stdout(predicate::str::contains("ed25519"));
}
