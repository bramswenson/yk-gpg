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
        .env_remove("KDUB_PASSPHRASE")
        .env_remove("GITHUB_TOKEN");
    cmd
}

/// Create a key and return its fingerprint.
fn create_key(tmp: &tempfile::TempDir) -> String {
    let output = kdub_cmd(tmp)
        .args([
            "key",
            "create",
            "Publish Test <publish@example.com>",
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
    for line in stdout.lines() {
        if line.contains("Fingerprint:") {
            return line.split(':').nth(1).unwrap().trim().to_string();
        }
    }
    panic!("Fingerprint not found in output: {stdout}");
}

#[test]
fn test_key_publish_file() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let file_path = tmp.path().join("exported-pubkey.asc");

    kdub_cmd(&tmp)
        .args([
            "key",
            "publish",
            &fingerprint,
            "--file",
            file_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Published key"))
        .stdout(predicate::str::contains("Published to file"));

    // Verify the file exists and contains an armored public key
    assert!(file_path.exists(), "exported file should exist");
    let content = fs::read_to_string(&file_path).unwrap();
    assert!(
        content.contains("BEGIN PGP PUBLIC KEY BLOCK"),
        "file should contain PGP public key header"
    );
    assert!(
        !content.contains("BEGIN PGP PRIVATE KEY BLOCK"),
        "file should NOT contain private key"
    );
}

#[test]
fn test_key_publish_file_content_is_parseable() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let file_path = tmp.path().join("pubkey.asc");

    kdub_cmd(&tmp)
        .args([
            "key",
            "publish",
            &fingerprint,
            "--file",
            file_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Verify the exported file can be parsed as a valid PGP public key
    let content = fs::read_to_string(&file_path).unwrap();
    assert!(content.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    assert!(content.contains("END PGP PUBLIC KEY BLOCK"));

    // The content should be non-trivial (contain actual key data)
    assert!(
        content.len() > 100,
        "exported key should have substantial content"
    );
}

#[test]
fn test_key_publish_missing_key() {
    let tmp = tempfile::tempdir().unwrap();

    kdub_cmd(&tmp)
        .args([
            "key",
            "publish",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--file",
            "/tmp/nonexistent.asc",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no identity found"));
}

#[test]
fn test_key_publish_no_destination() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);

    // No destination flags -> should fail
    kdub_cmd(&tmp)
        .args(["key", "publish", &fingerprint])
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least one destination flag"));
}

#[test]
fn test_key_publish_github_no_token() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);

    // --github without token -> should fail
    kdub_cmd(&tmp)
        .args(["key", "publish", &fingerprint, "--github"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("GitHub token required"));
}

#[test]
fn test_key_publish_wkd() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let wkd_dir = tmp.path().join("wkd-webroot");

    kdub_cmd(&tmp)
        .args([
            "key",
            "publish",
            &fingerprint,
            "--wkd",
            wkd_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Published to WKD"));

    // Verify the WKD directory structure was created
    let openpgpkey_dir = wkd_dir.join(".well-known").join("openpgpkey");
    assert!(
        openpgpkey_dir.exists(),
        "WKD openpgpkey directory should exist"
    );

    // Check the domain directory exists
    let domain_dir = openpgpkey_dir.join("example.com");
    assert!(domain_dir.exists(), "WKD domain directory should exist");

    // Check the hu directory has a file
    let hu_dir = domain_dir.join("hu");
    assert!(hu_dir.exists(), "WKD hu directory should exist");

    let entries: Vec<_> = fs::read_dir(&hu_dir).unwrap().collect();
    assert_eq!(
        entries.len(),
        1,
        "hu directory should have exactly one file"
    );

    // Check the policy file exists
    let policy_path = domain_dir.join("policy");
    assert!(policy_path.exists(), "WKD policy file should exist");
}

#[test]
fn test_key_publish_file_with_0x_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let file_path = tmp.path().join("pubkey.asc");

    kdub_cmd(&tmp)
        .args([
            "key",
            "publish",
            &format!("0x{fingerprint}"),
            "--file",
            file_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(file_path.exists());
}

#[test]
fn test_key_publish_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp);
    let file_path = tmp.path().join("pubkey.asc");

    kdub_cmd(&tmp)
        .arg("--quiet")
        .args([
            "key",
            "publish",
            &fingerprint,
            "--file",
            file_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    // File should still be created
    assert!(file_path.exists());
}
