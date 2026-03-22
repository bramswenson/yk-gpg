use assert_cmd::Command;
use predicates::prelude::*;

/// Helper: check if a smart card is connected by running card info.
/// Returns true if card info succeeds (card present).
fn card_is_connected() -> bool {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "info"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn card_info_no_card_fails_gracefully() {
    if card_is_connected() {
        // Card is present — verify it succeeds instead
        Command::cargo_bin("kdub")
            .unwrap()
            .args(["card", "info"])
            .assert()
            .success();
        return;
    }
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "info"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("smart card")
                .or(predicate::str::contains("PC/SC"))
                .or(predicate::str::contains("card error")),
        );
}

#[test]
fn card_info_json_no_card_fails_gracefully() {
    if card_is_connected() {
        Command::cargo_bin("kdub")
            .unwrap()
            .args(["card", "info", "--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("serial"));
        return;
    }
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "info", "--json"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("smart card")
                .or(predicate::str::contains("PC/SC"))
                .or(predicate::str::contains("card error")),
        );
}

#[test]
fn card_info_batch_is_allowed() {
    // card info is read-only, so --batch should be accepted.
    // Error should be about missing card, not batch mode.
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "info"])
        .output()
        .unwrap();

    if result.status.success() {
        // Card present — batch is allowed, success is fine
        return;
    }
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !stderr.contains("batch"),
        "card info should accept --batch; error should be about card, not batch mode"
    );
}

#[test]
fn card_info_quiet_no_card_still_shows_error() {
    if card_is_connected() {
        // With card present, quiet mode just suppresses output
        Command::cargo_bin("kdub")
            .unwrap()
            .args(["--quiet", "card", "info"])
            .assert()
            .success();
        return;
    }
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--quiet", "card", "info"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("smart card")
                .or(predicate::str::contains("PC/SC"))
                .or(predicate::str::contains("card error")),
        );
}

#[test]
fn card_info_help_shows_json_flag() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "info", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--json"));
}
