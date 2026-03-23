//! Pre-generated test key fixture.
//!
//! Provides a pre-generated Ed25519 key (with backup) that tests can copy into
//! their isolated tempdirs instead of generating a fresh key each time.
//! Key generation is CPU-bound (~5s per Ed25519 key), so reusing a fixture
//! eliminates ~40 redundant key generations from the test suite.

// Each integration test file compiles as its own crate, so not every test file
// uses every item from this shared module. Suppress the resulting warnings.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// Fingerprint of the pre-generated primary fixture key.
pub const FINGERPRINT: &str = "0105FE2978E65225F20C80CB6463DE6279091425";

/// Identity of the pre-generated primary fixture key.
pub const IDENTITY: &str = "Test Fixture <fixture@test.example>";

/// Passphrase used for both fixture keys.
pub const PASSPHRASE: &str = "testpass123";

/// Fingerprint of the second fixture key (for multi-key tests).
pub const FINGERPRINT_2: &str = "64D0979D8C9ECAAB6A2BF286BAD0E72D3F573C19";

/// Identity of the second fixture key.
pub const IDENTITY_2: &str = "Second Fixture <second@test.example>";

/// Path to the fixture data directory (relative to the test binary).
fn fixture_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// Copy a specific fixture key's identity files into the given data directory.
fn copy_identity(data_dir: &Path, fingerprint: &str) {
    let dest_identities = data_dir.join("identities");
    std::fs::create_dir_all(&dest_identities).unwrap();

    let src = fixture_source().join("identities");
    for ext in &["json", "key"] {
        let filename = format!("{fingerprint}.{ext}");
        let src_file = src.join(&filename);
        assert!(
            src_file.exists(),
            "Required fixture file missing: {} — run `cargo nextest run -p kdub-lib generate_fixture_key` to regenerate",
            src_file.display()
        );
        std::fs::copy(&src_file, dest_identities.join(&filename)).unwrap();
    }
}

/// Copy the primary fixture key (identities only, no backups) into a test's data directory.
/// Returns the data directory path.
pub fn setup_key(tmp: &tempfile::TempDir) -> PathBuf {
    let data_dir = tmp.path().join("data");
    copy_identity(&data_dir, FINGERPRINT);
    data_dir
}

/// Copy both fixture keys into a test's data directory (for multi-key tests).
/// Returns the data directory path.
pub fn setup_two_keys(tmp: &tempfile::TempDir) -> PathBuf {
    let data_dir = tmp.path().join("data");
    copy_identity(&data_dir, FINGERPRINT);
    copy_identity(&data_dir, FINGERPRINT_2);
    data_dir
}

/// Copy the fixture key with backups into a test's data directory.
/// Returns the data directory path.
pub fn setup_key_with_backup(tmp: &tempfile::TempDir) -> PathBuf {
    let data_dir = setup_key(tmp);

    let dest_backups = data_dir.join("backups").join(FINGERPRINT);
    std::fs::create_dir_all(&dest_backups).unwrap();

    let src = fixture_source().join("backups").join(FINGERPRINT);
    for entry in std::fs::read_dir(&src).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), dest_backups.join(entry.file_name())).unwrap();
    }

    data_dir
}

/// Create a kdub Command with isolated environment pointing at the given data dir.
pub fn kdub_cmd_with_data_dir(tmp: &tempfile::TempDir, data_dir: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::cargo_bin("kdub").unwrap();
    cmd.arg("--batch")
        .args(["--data-dir", data_dir.to_str().unwrap()])
        .env("XDG_CONFIG_HOME", tmp.path().join("config_home"))
        .env("XDG_DATA_HOME", tmp.path().join("data_home"))
        .env("XDG_STATE_HOME", tmp.path().join("state_home"))
        .env_remove("KDUB_KEY_TYPE")
        .env_remove("KDUB_PASSPHRASE")
        .env_remove("GITHUB_TOKEN");
    cmd
}
