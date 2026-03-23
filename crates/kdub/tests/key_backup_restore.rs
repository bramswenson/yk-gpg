use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;

mod fixture;

/// Helper to run kdub commands with isolated environment.
fn kdub_cmd(tmp: &tempfile::TempDir, data_dir: &std::path::Path) -> Command {
    fixture::kdub_cmd_with_data_dir(tmp, data_dir)
}

#[test]
fn test_key_backup_creates_files() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Run backup
    kdub_cmd(&tmp, &data_dir)
        .args(["key", "backup", fixture::FINGERPRINT])
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up to"));

    // Verify backup files exist
    let backup_dir = data_dir.join("backups").join(fixture::FINGERPRINT);
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
    let data_dir = fixture::setup_key(&tmp);

    // Run backup with 0x prefix
    kdub_cmd(&tmp, &data_dir)
        .args(["key", "backup", &format!("0x{}", fixture::FINGERPRINT)])
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up to"));
}

#[test]
fn test_key_backup_nonexistent_key() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    kdub_cmd(&tmp, &data_dir)
        .args(["key", "backup", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_key_backup_updates_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Before backup, backed_up should be null
    let meta_path = data_dir
        .join("identities")
        .join(format!("{}.json", fixture::FINGERPRINT));
    let content = fs::read_to_string(&meta_path).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert!(
        meta["backed_up"].is_null(),
        "backed_up should be null before backup"
    );

    // Run backup
    kdub_cmd(&tmp, &data_dir)
        .args(["key", "backup", fixture::FINGERPRINT])
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
    let data_dir = fixture::setup_key_with_backup(&tmp);

    // Delete the key file from identities (simulating fresh restore)
    let key_path = data_dir
        .join("identities")
        .join(format!("{}.key", fixture::FINGERPRINT));
    assert!(key_path.exists(), "key file should exist after setup");
    fs::remove_file(&key_path).unwrap();

    // Run restore
    kdub_cmd(&tmp, &data_dir)
        .args(["key", "restore", fixture::FINGERPRINT])
        .assert()
        .success()
        .stdout(predicate::str::contains("Restored key"));

    // Verify key file was restored
    assert!(key_path.exists(), "key file should be restored");
}

#[test]
fn test_key_restore_nonexistent_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    kdub_cmd(&tmp, &data_dir)
        .args(["key", "restore", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}

#[test]
fn test_key_backup_file_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    kdub_cmd(&tmp, &data_dir)
        .args(["key", "backup", fixture::FINGERPRINT])
        .assert()
        .success();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let backup_dir = data_dir.join("backups").join(fixture::FINGERPRINT);

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
    let data_dir = fixture::setup_key(&tmp);

    kdub_cmd(&tmp, &data_dir)
        .args(["key", "backup", fixture::FINGERPRINT])
        .assert()
        .success();

    // Verify public-key.asc content
    let public_key = fs::read_to_string(
        data_dir
            .join("backups")
            .join(fixture::FINGERPRINT)
            .join("public-key.asc"),
    )
    .unwrap();
    assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    assert!(!public_key.contains("BEGIN PGP PRIVATE KEY BLOCK"));
}

#[test]
fn test_key_backup_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let mut cmd = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir);
    cmd.args(["--quiet"])
        .args(["key", "backup", fixture::FINGERPRINT])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_key_restore_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key_with_backup(&tmp);

    // Delete the key file
    let key_path = data_dir
        .join("identities")
        .join(format!("{}.key", fixture::FINGERPRINT));
    fs::remove_file(&key_path).unwrap();

    // Restore with --quiet
    let mut cmd = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir);
    cmd.args(["--quiet"])
        .args(["key", "restore", fixture::FINGERPRINT])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

/// Test that `--passphrase` flag is accepted by `key backup` and wired through.
/// The backup command resolves the passphrase for use in generating the revocation cert.
#[test]
fn test_key_backup_with_passphrase_flag() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // Run backup with explicit passphrase — should succeed
    kdub_cmd(&tmp, &data_dir)
        .args([
            "key",
            "backup",
            fixture::FINGERPRINT,
            "--passphrase",
            fixture::PASSPHRASE,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up to"));
}

/// Test that `KDUB_PASSPHRASE` env var is accepted by `key backup`.
#[test]
fn test_key_backup_with_env_passphrase() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let mut cmd = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir);
    cmd.args(["key", "backup", fixture::FINGERPRINT])
        .env("KDUB_PASSPHRASE", fixture::PASSPHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up to"));
}

/// If gpg is available and supports the key algorithm, verify the backed-up
/// public key can be imported.
#[test]
#[ignore]
fn test_backup_restore_gpg_import() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key_with_backup(&tmp);

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
        .join(fixture::FINGERPRINT)
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
            let gpg_version_output = std::process::Command::new("gpg")
                .arg("--version")
                .output()
                .unwrap();
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
        .join(fixture::FINGERPRINT)
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
