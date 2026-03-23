mod fixture;

use predicates::prelude::*;

#[test]
fn test_key_list_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No managed identities"));
}

#[test]
fn test_key_list_empty_json() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("data");

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
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
    let data_dir = fixture::setup_key(&tmp);

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Managed identities:"))
        .stdout(predicate::str::contains(fixture::IDENTITY))
        .stdout(predicate::str::contains(fixture::FINGERPRINT))
        .stdout(predicate::str::contains("ed25519"));
}

#[test]
fn test_key_list_shows_multiple_identities() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_two_keys(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "list"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(fixture::IDENTITY));
    assert!(stdout.contains(fixture::IDENTITY_2));
}

#[test]
fn test_key_list_json_output() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
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
    assert_eq!(entry["identity"], fixture::IDENTITY);
    assert_eq!(entry["fingerprint"], fixture::FINGERPRINT);
    assert_eq!(entry["key_type"], "ed25519");
    assert!(entry["created"].is_string());
}

#[test]
fn test_key_list_json_multiple() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_two_keys(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
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
    let data_dir = fixture::setup_key(&tmp);

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .arg("--quiet")
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

#[test]
fn test_key_list_json_ignores_quiet() {
    // --json should still produce output even with --quiet
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .arg("--quiet")
        .args(["key", "list", "--json"])
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
    let data_dir = fixture::setup_key(&tmp);

    // Before backup, list should NOT show "Backed up"
    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "list"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("Backed up:"));

    // Run backup
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "backup", fixture::FINGERPRINT])
        .assert()
        .success();

    // After backup, list should show "Backed up" date
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Backed up:"));
}

#[test]
fn test_key_list_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    let output = fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "list"])
        .output()
        .unwrap();

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
