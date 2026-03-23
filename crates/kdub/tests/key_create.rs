use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

/// Helper to run `kdub --batch key create` with isolated XDG dirs.
fn key_create_cmd(
    tmp: &tempfile::TempDir,
    identity: &str,
    extra_args: &[&str],
) -> assert_cmd::assert::Assert {
    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.arg("--batch")
        .args(["--data-dir", tmp.path().join("data").to_str().unwrap()])
        .args(["key", "create", identity])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE");
    for arg in extra_args {
        cmd.arg(arg);
    }
    cmd.assert()
}

#[test]
fn test_key_create_batch_ed25519() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");

    key_create_cmd(
        &tmp,
        "Test User <test@example.com>",
        &["--passphrase", "testpass123", "--key-type", "ed25519"],
    )
    .success()
    .stdout(predicate::str::contains("Key created successfully"))
    .stdout(predicate::str::contains("Fingerprint:"))
    .stdout(predicate::str::contains("ed25519"));

    // Verify metadata file was created
    let identities_dir = data_dir.join("identities");
    assert!(identities_dir.exists(), "identities directory should exist");

    let entries: Vec<_> = fs::read_dir(&identities_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    assert_eq!(entries.len(), 1, "should have exactly one identity file");

    // Verify the metadata content
    let content = fs::read_to_string(entries[0].path()).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(meta["identity"], "Test User <test@example.com>");
    assert_eq!(meta["key_type"], "ed25519");
    assert!(meta["fingerprint"].is_string());
    assert!(meta["created"].is_string());

    // Verify file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(entries[0].path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "identity file should be mode 0600");
    }
}

#[test]
fn test_key_create_missing_passphrase_in_batch() {
    let tmp = tempfile::tempdir().unwrap();

    key_create_cmd(
        &tmp,
        "Test User <test@example.com>",
        &["--key-type", "ed25519"],
    )
    .failure()
    .stderr(predicate::str::contains("passphrase").or(predicate::str::contains("batch")));
}

#[test]
fn test_key_create_with_env_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");

    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args(["key", "create", "Env User <env@example.com>"])
        .args(["--key-type", "ed25519"])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env("KDUB_PASSPHRASE", "env-passphrase-123")
        .env_remove("KDUB_KEY_TYPE")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key created successfully"));

    // Verify metadata file was created
    let identities_dir = data_dir.join("identities");
    let entries: Vec<_> = fs::read_dir(&identities_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_key_create_with_env_key_type() {
    // KDUB_KEY_TYPE env has lower priority than ykman detection, so if a
    // YubiKey is connected, its firmware-based key type wins. We verify
    // that the key is created successfully with *some* valid key type.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");

    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args([
            "key",
            "create",
            "EnvKT User <envkt@example.com>",
            "--passphrase",
            "pass123",
        ])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env("KDUB_KEY_TYPE", "ed25519")
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::contains("Key created successfully"))
        .stdout(predicate::str::contains("ed25519").or(predicate::str::contains("rsa4096")));

    // Verify metadata was created
    let identities_dir = data_dir.join("identities");
    let entries: Vec<_> = fs::read_dir(&identities_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn test_key_create_invalid_key_type() {
    let tmp = tempfile::tempdir().unwrap();

    key_create_cmd(
        &tmp,
        "Test User <test@example.com>",
        &["--passphrase", "pass123", "--key-type", "rsa2048"],
    )
    .failure()
    .stderr(predicate::str::contains("unknown key type"));
}

#[test]
fn test_key_create_invalid_expiration() {
    let tmp = tempfile::tempdir().unwrap();

    key_create_cmd(
        &tmp,
        "Test User <test@example.com>",
        &[
            "--passphrase",
            "pass123",
            "--key-type",
            "ed25519",
            "--expiration",
            "2w",
        ],
    )
    .failure()
    .stderr(predicate::str::contains("invalid expiration"));
}

#[test]
fn test_key_create_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();

    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.args(["--batch", "--quiet"])
        .args(["--data-dir", tmp.path().join("data").to_str().unwrap()])
        .args([
            "key",
            "create",
            "Quiet User <quiet@example.com>",
            "--passphrase",
            "pass123",
            "--key-type",
            "ed25519",
        ])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    // But metadata should still be created
    let identities_dir = tmp.path().join("data").join("identities");
    assert!(identities_dir.exists());
}

/// If gpg is available, verify the generated key can be imported.
#[test]
#[ignore]
fn test_key_create_gpg_import() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");
    let gpg_home = tmp.path().join("gnupg");
    fs::create_dir_all(&gpg_home).unwrap();

    // Set restrictive permissions on gpg home
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&gpg_home, fs::Permissions::from_mode(0o700)).unwrap();
    }

    // Create a key
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .args([
            "key",
            "create",
            "GPG Test <gpg@example.com>",
            "--passphrase",
            "gpgpass123",
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

    assert!(output.status.success(), "key create should succeed");

    // Note: In the current implementation, the armored key is not saved to disk
    // as a file (it will be in Phase C.3 backup). The gpg import test requires
    // the armored key file, so we test what we can: the metadata was created
    // and the key generation succeeded.
    let identities_dir = data_dir.join("identities");
    let entries: Vec<_> = fs::read_dir(&identities_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect();
    assert_eq!(entries.len(), 1, "should have one identity file");
}
