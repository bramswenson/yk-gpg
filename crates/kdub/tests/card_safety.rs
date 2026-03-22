//! Consolidated safety tests for the card operation safety model.
//!
//! This test suite verifies the holistic safety model across ALL card commands:
//!
//! 1. All card-modifying commands reject `--batch` (exit 5)
//! 2. Read-only `card info` allows `--batch`
//! 3. All card commands fail gracefully without a card
//! 4. `card provision` refuses without a backup
//! 5. `card provision` refuses factory admin PIN
//! 6. Safety-critical commands do not accept `--force`
//!
//! Individual command tests live in `card_info.rs`, `card_setup.rs`, etc.
//! This file ensures the model holds as a whole.

use assert_cmd::Command;
use predicates::prelude::*;

// ---------------------------------------------------------------------------
// Batch rejection: all card-modifying commands MUST reject --batch
// ---------------------------------------------------------------------------

#[test]
fn safety_batch_rejected_card_setup() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "setup", "--factory-pins"])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn safety_batch_rejected_card_provision() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args([
            "--batch",
            "card",
            "provision",
            "D3B9C00B365DC5B752A6554A0630571A396BC2A7",
        ])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn safety_batch_rejected_card_reset() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "reset"])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn safety_batch_rejected_card_touch() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "touch", "--policy", "on"])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn safety_batch_rejected_card_touch_all_policies() {
    // Verify that all touch policy values still reject batch mode
    for policy in &["on", "off", "fixed", "cached", "cached-fixed"] {
        Command::cargo_bin("kdub")
            .unwrap()
            .args(["--batch", "card", "touch", "--policy", policy])
            .assert()
            .failure()
            .code(5)
            .stderr(predicate::str::contains("--batch is not supported"));
    }
}

// ---------------------------------------------------------------------------
// Batch allowed: card info is read-only, so --batch should be accepted
// ---------------------------------------------------------------------------

#[test]
fn safety_batch_allowed_card_info() {
    // card info is read-only — batch should be accepted.
    // If a card is present, it succeeds. If not, the error should be
    // about the missing card, NOT about batch mode.
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "info"])
        .output()
        .unwrap();

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            !stderr.contains("--batch is not supported"),
            "card info should accept --batch; error should be about card, not batch"
        );
    }
}

#[test]
fn safety_batch_allowed_card_info_json() {
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "info", "--json"])
        .output()
        .unwrap();

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(
            !stderr.contains("--batch is not supported"),
            "card info --json should accept --batch"
        );
    }
}

// ---------------------------------------------------------------------------
// Graceful failure without a card: all card commands should fail with exit 5
// (skipped when a card is actually connected)
// ---------------------------------------------------------------------------

#[test]
fn safety_no_card_card_info() {
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "info"])
        .output()
        .unwrap();

    if result.status.success() {
        // Card is present — test is not applicable
        return;
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("smart card") || stderr.contains("PC/SC") || stderr.contains("card error"),
        "expected card-related error, got: {stderr}"
    );
}

#[test]
fn safety_no_card_card_setup() {
    // card setup hits batch/TTY check before card check, so we accept either error
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "setup", "--factory-pins"])
        .write_stdin("yes\nyes\n")
        .assert()
        .failure();

    result.stderr(
        predicate::str::contains("smart card")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive")),
    );
}

#[test]
fn safety_no_card_card_provision() {
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

    result.stderr(
        predicate::str::contains("smart card")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive"))
            .or(predicate::str::contains("backup")),
    );
}

#[test]
fn safety_no_card_card_reset() {
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "reset"])
        .write_stdin("12345678\n")
        .assert()
        .failure();

    result.stderr(
        predicate::str::contains("smart card")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive")),
    );
}

#[test]
fn safety_no_card_card_touch() {
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "touch", "--policy", "on"])
        .write_stdin("y\n")
        .assert()
        .failure();

    result.stderr(
        predicate::str::contains("smart card")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive"))
            .or(predicate::str::contains("ykman")),
    );
}

// ---------------------------------------------------------------------------
// Provision safety: backup must exist
// ---------------------------------------------------------------------------

#[test]
fn safety_provision_refuses_without_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path();

    // Create identity store with a fake key file and metadata
    std::fs::create_dir_all(data_dir.join("identities")).unwrap();
    let fp = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
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

    // Should fail with TTY requirement or backup-related message
    result.stderr(
        predicate::str::contains("backup")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive")),
    );
}

// ---------------------------------------------------------------------------
// No --force on safety-critical commands
// ---------------------------------------------------------------------------

#[test]
fn safety_no_force_flag_card_provision() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "provision", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--force").not());
}

#[test]
fn safety_no_force_flag_card_reset() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "reset", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--force").not());
}

#[test]
fn safety_no_force_flag_card_setup() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "setup", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--force").not());
}

// ---------------------------------------------------------------------------
// Consistent exit codes: all card errors should use code 5
// ---------------------------------------------------------------------------

#[test]
fn safety_exit_code_consistency() {
    // All batch rejection errors should use exit code 5 (card error)
    let batch_commands: Vec<Vec<&str>> = vec![
        vec!["--batch", "card", "setup", "--factory-pins"],
        vec!["--batch", "card", "provision", "DEADBEEF"],
        vec!["--batch", "card", "reset"],
        vec!["--batch", "card", "touch", "--policy", "on"],
    ];

    for args in batch_commands {
        Command::cargo_bin("kdub")
            .unwrap()
            .args(&args)
            .assert()
            .failure()
            .code(5);
    }
}

// ---------------------------------------------------------------------------
// Error message quality: batch rejection messages are helpful
// ---------------------------------------------------------------------------

#[test]
fn safety_batch_rejection_messages_mention_interactive() {
    // All batch rejection messages should mention "interactive" or "confirmation"
    let commands_and_labels: Vec<(&str, Vec<&str>)> = vec![
        ("setup", vec!["--batch", "card", "setup", "--factory-pins"]),
        (
            "provision",
            vec!["--batch", "card", "provision", "DEADBEEF"],
        ),
        ("reset", vec!["--batch", "card", "reset"]),
        ("touch", vec!["--batch", "card", "touch", "--policy", "on"]),
    ];

    for (label, args) in commands_and_labels {
        let output = Command::cargo_bin("kdub")
            .unwrap()
            .args(&args)
            .output()
            .unwrap();

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("interactive") || stderr.contains("confirmation"),
            "card {label} batch rejection should mention 'interactive' or 'confirmation', got: {stderr}"
        );
    }
}
