use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

/// Helper to run kdub commands with isolated environment.
fn kdub_cmd(tmp: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.arg("--batch")
        .args(["--data-dir", tmp.path().join("data").to_str().unwrap()])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE");
    cmd
}

/// Create a key and return its fingerprint.
fn create_key(tmp: &tempfile::TempDir) -> String {
    let output = kdub_cmd(tmp)
        .args([
            "key",
            "create",
            "Backup Test <backup@example.com>",
            "--passphrase",
            "testpass123",
            "--key-type",
            "ed25519",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "key create should succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Extract fingerprint from "  Fingerprint: <HEX>" line
    for line in stdout.lines() {
        if line.contains("Fingerprint:") {
            return line.split(':').nth(1).unwrap().trim().to_string();
        }
    }
    panic!("Fingerprint not found in output: {stdout}");
}

#[test]
fn test_key_backup_creates_files() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let data_dir = tmp.path().join("data");

    // Run backup
    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up to"));

    // Verify backup files exist
    let backup_dir = data_dir.join("backups").join(&fingerprint);
    assert!(backup_dir.exists(), "backup directory should exist");
    assert!(backup_dir.join("certify-key.asc").exists());
    assert!(backup_dir.join("subkeys.asc").exists());
    assert!(backup_dir.join("public-key.asc").exists());
    assert!(backup_dir.join("ownertrust.txt").exists());
    assert!(backup_dir.join("revocation-cert.asc").exists());
}

#[test]
fn test_key_backup_with_0x_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);

    // Run backup with 0x prefix
    kdub_cmd(&tmp)
        .args(["key", "backup", &format!("0x{fingerprint}")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up to"));
}

#[test]
fn test_key_backup_nonexistent_key() {
    let tmp = tempfile::tempdir().unwrap();

    kdub_cmd(&tmp)
        .args(["key", "backup", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_key_backup_updates_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let data_dir = tmp.path().join("data");

    // Before backup, backed_up should be null
    let meta_path = data_dir
        .join("identities")
        .join(format!("{fingerprint}.json"));
    let content = fs::read_to_string(&meta_path).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(
        meta["backed_up"].is_null(),
        "backed_up should be null before backup"
    );

    // Run backup
    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success();

    // After backup, backed_up should be set
    let content = fs::read_to_string(&meta_path).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(
        meta["backed_up"].is_string(),
        "backed_up should be set after backup"
    );
}

#[test]
fn test_key_restore_from_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let data_dir = tmp.path().join("data");

    // Create backup
    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success();

    // Delete the key file from identities (simulating fresh restore)
    let key_path = data_dir
        .join("identities")
        .join(format!("{fingerprint}.key"));
    assert!(key_path.exists(), "key file should exist after create");
    fs::remove_file(&key_path).unwrap();

    // Run restore
    kdub_cmd(&tmp)
        .args(["key", "restore", &fingerprint])
        .assert()
        .success()
        .stdout(predicate::str::contains("Restored key"));

    // Verify key file was restored
    assert!(key_path.exists(), "key file should be restored");
}

#[test]
fn test_key_restore_nonexistent_backup() {
    let tmp = tempfile::tempdir().unwrap();

    kdub_cmd(&tmp)
        .args(["key", "restore", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_key_backup_file_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let data_dir = tmp.path().join("data");

    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let backup_dir = data_dir.join("backups").join(&fingerprint);

        // Directory should be 0700
        let dir_mode = fs::metadata(&backup_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "backup dir should be mode 0700");

        // Files should be 0600
        for name in &[
            "certify-key.asc",
            "subkeys.asc",
            "public-key.asc",
            "ownertrust.txt",
            "revocation-cert.asc",
        ] {
            let path = backup_dir.join(name);
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} should be mode 0600");
        }
    }
}

#[test]
fn test_key_backup_public_key_parseable() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let data_dir = tmp.path().join("data");

    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success();

    // Verify public-key.asc content
    let public_key = fs::read_to_string(
        data_dir
            .join("backups")
            .join(&fingerprint)
            .join("public-key.asc"),
    )
    .unwrap();
    assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    assert!(!public_key.contains("BEGIN PGP PRIVATE KEY BLOCK"));
}

#[test]
fn test_key_backup_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);

    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.args(["--batch", "--quiet"])
        .args(["--data-dir", tmp.path().join("data").to_str().unwrap()])
        .args(["key", "backup", &fingerprint])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_key_restore_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let data_dir = tmp.path().join("data");

    // Create backup
    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success();

    // Delete the key file
    let key_path = data_dir
        .join("identities")
        .join(format!("{fingerprint}.key"));
    fs::remove_file(&key_path).unwrap();

    // Restore with --quiet
    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.args(["--batch", "--quiet"])
        .args(["--data-dir", tmp.path().join("data").to_str().unwrap()])
        .args(["key", "restore", &fingerprint])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE")
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

/// If gpg is available and supports the key algorithm, verify the backed-up
/// public key can be imported.
#[test]
fn test_backup_restore_gpg_import() {
    // Skip if gpg is not available
    let gpg_version_output = match std::process::Command::new("gpg").arg("--version").output() {
        Ok(o) => o,
        Err(_) => {
            eprintln!("skipping gpg import test: gpg not found");
            return;
        }
    };

    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let data_dir = tmp.path().join("data");

    // Create backup
    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success();

    // Set up isolated gpg home
    let gpg_home = tmp.path().join("gnupg");
    fs::create_dir_all(&gpg_home).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&gpg_home, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let public_key_path = data_dir
        .join("backups")
        .join(&fingerprint)
        .join("public-key.asc");

    // Import public key into gpg
    let import_output = std::process::Command::new("gpg")
        .args(["--homedir", gpg_home.to_str().unwrap()])
        .args(["--batch", "--import"])
        .arg(&public_key_path)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&import_output.stderr);

    // Some GPG versions don't support Ed25519 (algorithm 27/EdDSA).
    // Skip the test rather than fail when the system GPG is too old.
    if !import_output.status.success() {
        if stderr.contains("Unknown algorithm") || stderr.contains("unsupported public-key") {
            let version_str = String::from_utf8_lossy(&gpg_version_output.stdout);
            eprintln!(
                "skipping gpg import test: system gpg does not support Ed25519 keys. \
                 GPG version: {}",
                version_str.lines().next().unwrap_or("unknown")
            );
            return;
        }
        panic!("gpg --import failed unexpectedly: {stderr}");
    }

    // Import ownertrust
    let ownertrust_path = data_dir
        .join("backups")
        .join(&fingerprint)
        .join("ownertrust.txt");

    let trust_output = std::process::Command::new("gpg")
        .args(["--homedir", gpg_home.to_str().unwrap()])
        .args(["--batch", "--import-ownertrust"])
        .arg(&ownertrust_path)
        .output()
        .unwrap();

    assert!(
        trust_output.status.success(),
        "gpg --import-ownertrust should succeed: {}",
        String::from_utf8_lossy(&trust_output.stderr)
    );
}
