use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn card_provision_batch_rejected() {
    // card provision MUST reject --batch mode for safety
    Command::cargo_bin("kdub")
        .unwrap()
        .args([
            "--batch",
            "card",
            "provision",
            "D3B9C00B365DC5B752A6554A0630571A396BC2A7",
            "--admin-pin",
            "87654321",
            "--passphrase",
            "testpassphrase",
        ])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn card_provision_requires_card_or_tty() {
    // Without a card, provision should fail with a card/TTY error.
    // In CI stdin is not a TTY, so we expect TTY error or card error.
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args([
            "card",
            "provision",
            "D3B9C00B365DC5B752A6554A0630571A396BC2A7",
            "--admin-pin",
            "87654321",
            "--passphrase",
            "testpassphrase",
        ])
        .write_stdin("yes\n")
        .assert()
        .failure();

    // Should fail with either TTY requirement, backup missing, or card not found
    result.stderr(
        predicate::str::contains("smart card")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive"))
            .or(predicate::str::contains("backup")),
    );
}

#[test]
fn card_provision_no_backup() {
    // Provision without backup should fail with backup-related error.
    // We use a temp data dir to ensure no backup exists.
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    // Create identity store with a fake key file and metadata
    std::fs::create_dir_all(data_dir.join("identities")).unwrap();
    let fp = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
    // Write minimal metadata
    let metadata = serde_json::json!({
        "identity": "Test <test@example.com>",
        "fingerprint": fp,
        "key_type": "ed25519",
        "created": "2026-01-01T00:00:00Z",
    });
    std::fs::write(
        data_dir.join("identities").join(format!("{fp}.json")),
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();

    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args([
            "card",
            "provision",
            fp,
            "--admin-pin",
            "87654321",
            "--passphrase",
            "testpassphrase",
        ])
        .env("KDUB_DATA_DIR", data_dir.to_str().unwrap())
        .write_stdin("yes\n")
        .assert()
        .failure();

    // Should fail with either TTY requirement or backup-related message
    result.stderr(
        predicate::str::contains("backup")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive")),
    );
}

#[test]
fn card_provision_help_shows_flags() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "provision", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--admin-pin"))
        .stdout(predicate::str::contains("--passphrase"))
        .stdout(predicate::str::contains("--admin-pin-stdin"))
        .stdout(predicate::str::contains("--passphrase-stdin"));
}

#[test]
fn card_provision_help_no_force_flag() {
    // Provision must NOT accept --force (safety requirement)
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "provision", "--help"])
        .assert()
        .success();

    output.stdout(predicate::str::contains("--force").not());
}
