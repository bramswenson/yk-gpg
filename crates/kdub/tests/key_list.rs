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
fn create_key(tmp: &tempfile::TempDir, identity: &str) -> String {
    let output = kdub_cmd(tmp)
        .args([
            "key",
            "create",
            identity,
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
fn test_key_list_empty() {
    let tmp = tempfile::tempdir().unwrap();

    kdub_cmd(&tmp)
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No managed identities"));
}

#[test]
fn test_key_list_empty_json() {
    let tmp = tempfile::tempdir().unwrap();

    let output = kdub_cmd(&tmp)
        .args(["key", "list", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 0);
}

#[test]
fn test_key_list_shows_created_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp, "Alice Smith <alice@example.com>");

    kdub_cmd(&tmp)
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Managed identities:"))
        .stdout(predicate::str::contains("Alice Smith <alice@example.com>"))
        .stdout(predicate::str::contains(&fingerprint))
        .stdout(predicate::str::contains("ed25519"));
}

#[test]
fn test_key_list_shows_multiple_identities() {
    let tmp = tempfile::tempdir().unwrap();
    create_key(&tmp, "Alice Smith <alice@example.com>");
    create_key(&tmp, "Bob Jones <bob@example.com>");

    let output = kdub_cmd(&tmp).args(["key", "list"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Alice Smith <alice@example.com>"));
    assert!(stdout.contains("Bob Jones <bob@example.com>"));
}

#[test]
fn test_key_list_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp, "Alice Smith <alice@example.com>");

    let output = kdub_cmd(&tmp)
        .args(["key", "list", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");

    assert!(parsed.is_array());
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 1);

    let entry = &arr[0];
    assert_eq!(entry["identity"], "Alice Smith <alice@example.com>");
    assert_eq!(entry["fingerprint"], fingerprint);
    assert_eq!(entry["key_type"], "ed25519");
    assert!(entry["created"].is_string());
}

#[test]
fn test_key_list_json_multiple() {
    let tmp = tempfile::tempdir().unwrap();
    create_key(&tmp, "Alice Smith <alice@example.com>");
    create_key(&tmp, "Bob Jones <bob@example.com>");

    let output = kdub_cmd(&tmp)
        .args(["key", "list", "--json"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert_eq!(parsed.as_array().unwrap().len(), 2);
}

#[test]
fn test_key_list_quiet_suppresses_output() {
    let tmp = tempfile::tempdir().unwrap();
    create_key(&tmp, "Quiet User <quiet@example.com>");

    let mut cmd = Command::cargo_bin("kdub").unwrap();
    cmd.args(["--batch", "--quiet"])
        .args(["--data-dir", tmp.path().join("data").to_str().unwrap()])
        .args(["key", "list"])
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
fn test_key_list_json_ignores_quiet() {
    // --json should still produce output even with --quiet
    let tmp = tempfile::tempdir().unwrap();
    create_key(&tmp, "JSON User <json@example.com>");

    let output = Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "--quiet"])
        .args(["--data-dir", tmp.path().join("data").to_str().unwrap()])
        .args(["key", "list", "--json"])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert_eq!(parsed.as_array().unwrap().len(), 1);
}

#[test]
fn test_key_list_shows_backed_up_status() {
    let tmp = tempfile::tempdir().unwrap();
    let fingerprint = create_key(&tmp, "Backup User <backup@example.com>");

    // Before backup, list should NOT show "Backed up"
    let output = kdub_cmd(&tmp).args(["key", "list"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("Backed up:"));

    // Run backup
    kdub_cmd(&tmp)
        .args(["key", "backup", &fingerprint])
        .assert()
        .success();

    // After backup, list should show "Backed up" date
    kdub_cmd(&tmp)
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up:"));
}

#[test]
fn test_key_list_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    create_key(&tmp, "Snapshot User <snapshot@example.com>");

    let output = kdub_cmd(&tmp).args(["key", "list"]).output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    // Redact the dynamic fingerprint and date for snapshot stability
    let redacted = redact_dynamic_fields(&stdout);
    insta::assert_snapshot!(redacted);
}

/// Redact fingerprints (40 hex chars) and dates (YYYY-MM-DD) for stable snapshots.
fn redact_dynamic_fields(input: &str) -> String {
    let fingerprint_re = regex::Regex::new(r"[A-F0-9]{40}").unwrap();
    let date_re = regex::Regex::new(r"\d{4}-\d{2}-\d{2}").unwrap();
    let result = fingerprint_re.replace_all(input, "<FINGERPRINT>");
    date_re.replace_all(&result, "<DATE>").to_string()
}
