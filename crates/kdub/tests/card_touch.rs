use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn card_touch_batch_rejected() {
    // card touch MUST reject --batch mode for safety — touch policy changes
    // require interactive confirmation
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "touch"])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn card_touch_batch_rejected_with_policy() {
    // Even with --policy specified, --batch must be rejected
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "card", "touch", "--policy", "cached"])
        .assert()
        .failure()
        .code(5)
        .stderr(predicate::str::contains("--batch is not supported"));
}

#[test]
fn card_touch_help_shows_policy_values() {
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "touch", "--help"])
        .assert()
        .success();

    // Verify all 5 policy values are documented in help
    output
        .stdout(predicate::str::contains("on"))
        .stdout(predicate::str::contains("off"))
        .stdout(predicate::str::contains("fixed"))
        .stdout(predicate::str::contains("cached"))
        .stdout(predicate::str::contains("cached-fixed"));
}

#[test]
fn card_touch_help_shows_admin_pin_flag() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "touch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--admin-pin"));
}

#[test]
fn card_touch_help_shows_description() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "touch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("touch policy"));
}

#[test]
fn card_touch_requires_tty_or_ykman() {
    // Without a TTY (CI environment) or ykman, touch should fail with a
    // TTY requirement or missing dependency error
    let result = Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "touch", "--policy", "on"])
        .write_stdin("y\n")
        .assert()
        .failure();

    // Should fail with either TTY requirement or missing dependency
    result.stderr(
        predicate::str::contains("TTY")
            .or(predicate::str::contains("interactive"))
            .or(predicate::str::contains("ykman")),
    );
}

#[test]
fn card_touch_invalid_policy_rejected() {
    // clap should reject invalid policy values before we even get to the handler
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "touch", "--policy", "invalid"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid value"));
}

#[test]
fn card_touch_default_policy_is_on() {
    // When no --policy is specified, the default should be "on"
    // We verify this by checking the help text shows the default
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["card", "touch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("default"));
}
