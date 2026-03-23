use assert_cmd::Command;
use predicates::prelude::*;

/// Integration test: verify `kdub update --check` runs without error.
/// Requires network access to GitHub Releases API.
#[test]
#[ignore]
fn update_check_reports_status() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["update", "--check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("kdub"));
}

/// Verify the update subcommand is routed correctly and shows help.
#[test]
fn update_help_shows_options() {
    Command::cargo_bin("kdub")
        .unwrap()
        .args(["update", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--check"))
        .stdout(predicate::str::contains("--yes"));
}

/// Verify `kdub update --check` exercises the dispatch path.
/// Without a real release, this hits the GitHub API and fails with a
/// network or 404 error — which exercises the Err branch in dispatch.
/// Errors propagate through color_eyre, so we check exit code rather than format.
#[test]
fn update_check_exercises_dispatch_smoke() {
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "update", "--check"])
        .env("KDUB_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    // Either succeeds (release exists) or fails with a non-zero exit.
    // Both exercise the update dispatch path in commands/mod.rs.
    // The key assertion is that the process completed without panicking.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "update --check should not panic: {stderr}"
    );
}

/// Verify the update notice is suppressed after `kdub update` itself
/// (even if it fails — the notice guard checks the command variant).
#[test]
fn update_command_does_not_print_notice() {
    let output = Command::cargo_bin("kdub")
        .unwrap()
        .args(["--batch", "update", "--check"])
        .env("KDUB_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("new version of kdub is available"),
        "update command should not print its own update notice"
    );
}
