mod fixture;

use std::fs;

use predicates::prelude::*;

#[test]
fn test_key_publish_file() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);
    let file_path = tmp.path().join("exported-pubkey.asc");

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "publish",
            fixture::FINGERPRINT,
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
    let data_dir = fixture::setup_key(&tmp);
    let file_path = tmp.path().join("pubkey.asc");

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "publish",
            fixture::FINGERPRINT,
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
    let data_dir = fixture::setup_key(&tmp);

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
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
    let data_dir = fixture::setup_key(&tmp);

    // No destination flags -> should fail
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "publish", fixture::FINGERPRINT])
        .assert()
        .failure()
        .stderr(predicate::str::contains("at least one destination flag"));
}

#[test]
fn test_key_publish_github_no_token() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);

    // --github without token -> should fail
    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args(["key", "publish", fixture::FINGERPRINT, "--github"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("GitHub token required"));
}

#[test]
fn test_key_publish_wkd() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = fixture::setup_key(&tmp);
    let wkd_dir = tmp.path().join("wkd-webroot");

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "publish",
            fixture::FINGERPRINT,
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
    let domain_dir = openpgpkey_dir.join("test.example");
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
    let data_dir = fixture::setup_key(&tmp);
    let file_path = tmp.path().join("pubkey.asc");

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .args([
            "key",
            "publish",
            &format!("0x{}", fixture::FINGERPRINT),
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
    let data_dir = fixture::setup_key(&tmp);
    let file_path = tmp.path().join("pubkey.asc");

    fixture::kdub_cmd_with_data_dir(&tmp, &data_dir)
        .arg("--quiet")
        .args([
            "key",
            "publish",
            fixture::FINGERPRINT,
            "--file",
            file_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());

    // File should still be created
    assert!(file_path.exists());
}
