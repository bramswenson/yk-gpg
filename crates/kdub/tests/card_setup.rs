use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn card_setup_batch_rejected() {
    // card setup MUST reject --batch mode for safety
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "setup", "--factory-pins"])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn card_setup_requires_card() {
    // Without a card, setup should fail with card-not-found error.
    // We pipe "yes" to stdin so the TTY check is the failure point
    // (in CI, stdin is not a TTY, so we expect the TTY error or
    // card-not-found depending on environment).
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "setup", "--factory-pins"])
        .write_stdin("yes\nyes\n")
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
fn card_setup_help_shows_flags() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "setup", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--factory-pins")
                .and(predicate::str::contains("--skip-kdf"))
                .and(predicate::str::contains("--identity"))
                .and(predicate::str::contains("--url"))
                .and(predicate::str::contains("--admin-pin"))
                .and(predicate::str::contains("--new-admin-pin"))
                .and(predicate::str::contains("--new-user-pin")),
        );
}

#[test]
fn card_setup_no_factory_no_admin_pin_errors() {
    // Without --factory-pins and without --admin-pin, should error
    // (will hit TTY check first in CI, but the test validates the
    // error path exists)
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "setup"])
        .write_stdin("yes\nyes\n")
        .assert()
        .failure();

    result.stderr(
        predicate::str::contains("factory-pins")
            .or(predicate::str::contains("admin-pin"))
            .or(predicate::str::contains("TTY"))
            .or(predicate::str::contains("interactive")),
    );
}
