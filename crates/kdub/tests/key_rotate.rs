mod fixture;

use std::fs;

use predicates::prelude::*;
use serde_json::json;

#[test]
fn test_key_rotate_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Run rotate
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "rotate",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"))
        .stdout(predicate::str::contains("Created new"));

    // Verify metadata has rotated timestamp
    let meta_path = data_dir
        .join("identities")
        .join(format!("{}.json", fixture::FINGERPRINT));
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
    let data_dir = fixture::setup_key(&tmp);

    // Run rotate with --revoke-old
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "rotate",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
            "--revoke-old",
        ])
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
    let data_dir = fixture::setup_key(&tmp);

    // Rotate without passphrase in batch mode should fail
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "rotate", fixture::FINGERPRINT])
        .assert()
        .failure()
        .stderr(predicate::str::contains("batch").or(predicate::str::contains("passphrase")));
}

#[test]
fn test_key_rotate_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Rotate by name instead of fingerprint
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "rotate",
            "Test Fixture",
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"));
}

#[test]
fn test_key_rotate_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .arg("--quiet")
        .args([
            "key",
            "rotate",
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
fn test_key_rotate_with_env_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "rotate", fixture::FINGERPRINT])
        .env("KDUB_PASSPHRASE", fixture::PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"));
}

/// Test that corrupted metadata key_type produces a clear error rather than silently falling back.
/// Fix 3: replace `.unwrap_or(KeyType::Ed25519)` with proper error propagation.
#[test]
fn test_key_rotate_corrupted_metadata_key_type() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Corrupt the key_type in metadata
    let meta_path = data_dir
        .join("identities")
        .join(format!("{}.json", fixture::FINGERPRINT));
    let content = fs::read_to_string(&meta_path).unwrap();
    let mut meta: serde_json::Value = serde_json::from_str(&content).unwrap();
    meta["key_type"] = json!("notakeytype");
    fs::write(&meta_path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();

    // Rotate should fail with a descriptive error about corrupted metadata
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "rotate",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("corrupted metadata"));
}

/// Test that successful rotate output does not contain stale "not yet implemented" warning.
/// Fix 4: the tracing::warn! placeholder was removed.
#[test]
fn test_key_rotate_no_stale_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "rotate",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "rotate should succeed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("not yet implemented"),
        "stderr should not contain stale 'not yet implemented' warning, got: {stderr}"
    );
}

#[test]
fn test_key_rotate_with_key_type_override() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Rotate with explicit key type
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "rotate",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
            "--key-type",
            "ed25519",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Key rotated successfully"))
        .stdout(predicate::str::contains("ed25519"));
}
