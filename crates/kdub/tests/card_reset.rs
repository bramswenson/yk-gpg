use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn card_reset_batch_rejected() {
    // card reset MUST reject --batch mode for safety — this is the most
    // destructive operation in kdub and must always be interactive
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "reset"])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn card_reset_requires_card_or_tty() {
    // Without a card, reset should fail with a card/TTY error.
    // In CI stdin is not a TTY, so we expect TTY error or card error.
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "reset"])
        .write_stdin("12345678\n")
        .assert()
        .failure();

    // Should fail with either TTY requirement or card not found
    result.stderr(
        predicate::str::contains("smart card")
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive")),
    );
}

#[test]
fn card_reset_help_no_force_flag() {
    // card reset must NOT accept --force (removed per safety model)
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "reset", "--help"])
        .assert()
        .success();

    output.stdout(predicate::str::contains("--force").not());
}

#[test]
fn card_reset_help_shows_description() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "reset", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Factory reset"));
}
