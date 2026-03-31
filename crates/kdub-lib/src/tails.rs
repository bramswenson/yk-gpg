//! Tails OS detection, environment inspection, and persistence configuration.
//!
//! Provides types and functions for detecting whether the host is Tails OS,
//! checking persistence and network state, and generating persistence.conf
//! entries for the Tails persistent volume.

use std::path::Path;

use serde::Serialize;

use crate::defaults::{TAILS_PERSISTENCE_CONF_ENTRIES, TAILS_PERSISTENCE_MOUNT};
use crate::error::KdubError;

/// Snapshot of the current Tails environment state.
///
/// Captures OS version, persistence mount status, network connectivity,
/// and whether the kdub binary itself lives on persistent storage.
#[derive(Debug, Clone, Serialize)]
pub struct TailsEnvironment {
    /// Tails OS version string (e.g. "7.5").
    pub version: String,
    /// Whether the Tails persistent volume is mounted.
    pub persistence_mounted: bool,
    /// Whether at least one non-loopback network interface has carrier.
    pub network_connected: bool,
    /// Whether the running kdub binary is on persistent storage.
    pub kdub_on_persistent: bool,
}

/// Detect whether the host is Tails OS by reading an os-release file.
///
/// Takes a configurable path so tests can point at a tempfile instead of
/// the real `/etc/os-release`. Returns `Some(version)` if the file
/// contains `TAILS_PRODUCT_NAME`, or `None` if not Tails or the file
/// is missing.
pub fn detect_tails(os_release_path: &Path) -> Option<String> {
    let contents = std::fs::read_to_string(os_release_path).ok()?;

    let mut is_tails = false;
    let mut version = None;

    for line in contents.lines() {
        if let Some(value) = line.strip_prefix("TAILS_PRODUCT_NAME=") {
            let value = value.trim_matches('"');
            if !value.is_empty() {
                is_tails = true;
            }
        }
        if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version = Some(value.trim_matches('"').to_string());
        }
    }

    if is_tails { version } else { None }
}

/// Check whether the Tails persistent volume is mounted.
///
/// Returns `true` if the `TAILS_PERSISTENCE_MOUNT` directory exists.
pub fn check_persistence_mounted() -> bool {
    Path::new(TAILS_PERSISTENCE_MOUNT).exists()
}

/// Check whether any non-loopback network interface has carrier in a given
/// sysfs net directory.
///
/// Scans the directory for subdirectories (one per interface), skips `lo`,
/// and checks each interface's `carrier` file for `"1"`. Returns `true` if
/// at least one non-loopback interface has carrier.
#[cfg(target_os = "linux")]
pub fn check_network_carrier(net_dir: &Path) -> bool {
    let entries = match std::fs::read_dir(net_dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "lo" {
            continue;
        }
        let carrier_path = entry.path().join("carrier");
        if let Ok(carrier) = std::fs::read_to_string(&carrier_path)
            && carrier.trim() == "1"
        {
            return true;
        }
    }
    false
}

/// Check whether any non-loopback network interface has carrier (link up).
///
/// On Linux, reads `/sys/class/net`, skips `lo`, and checks each
/// interface's `carrier` file for `"1"`. On non-Linux platforms, always
/// returns `false` (Tails is Linux-only).
#[cfg(target_os = "linux")]
pub fn check_network_connected() -> bool {
    check_network_carrier(Path::new("/sys/class/net"))
}

/// Non-Linux stub: Tails is Linux-only, so network detection always returns false.
#[cfg(not(target_os = "linux"))]
pub fn check_network_connected() -> bool {
    false
}

/// Check if a given path string is on Tails persistent storage.
///
/// Returns `true` if the path contains the Tails persistence mount point
/// or the `.local/bin/kdub` dotfiles location where Tails persistence
/// symlinks the binary.
pub fn is_path_on_persistent(path: &str) -> bool {
    path.contains(TAILS_PERSISTENCE_MOUNT) || path.contains(".local/bin/kdub")
}

/// Check whether the running kdub binary resides on persistent storage.
///
/// Returns `true` if `std::env::current_exe()` contains the Tails
/// persistence mount path or `.local/bin/kdub`.
pub fn check_kdub_on_persistent() -> bool {
    std::env::current_exe()
        .map(|p| is_path_on_persistent(&p.to_string_lossy()))
        .unwrap_or(false)
}

/// Detect the full Tails environment using the real `/etc/os-release`.
///
/// Convenience wrapper that calls [`detect_tails`] with the hardcoded
/// system path, then populates all environment fields. Returns `None`
/// if the host is not Tails.
pub fn detect_tails_environment() -> Option<TailsEnvironment> {
    let version = detect_tails(Path::new("/etc/os-release"))?;
    Some(TailsEnvironment {
        version,
        persistence_mounted: check_persistence_mounted(),
        network_connected: check_network_connected(),
        kdub_on_persistent: check_kdub_on_persistent(),
    })
}

/// Generate a persistence.conf file from the configured entries.
///
/// Produces tab-separated lines suitable for writing to the Tails
/// persistent volume's `persistence.conf`. Each line has the format
/// `destination\toptions`.
pub fn generate_persistence_conf() -> String {
    TAILS_PERSISTENCE_CONF_ENTRIES
        .iter()
        .map(|(dest, opts)| format!("{dest}\t{opts}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Determine how to obtain the kdub binary for the current architecture.
///
/// - For `x86_64`: returns `Ok(None)` — use the currently running binary
///   (Tails is x86_64, so the current binary is already the right arch).
/// - For `aarch64`: returns `Ok(Some(url))` with the GitHub release
///   download URL for the x86_64-unknown-linux-gnu build.
/// - For other architectures: returns `Err(KdubError::TailsPersist)`.
pub fn resolve_kdub_binary_source(
    current_arch: &str,
    current_version: &str,
) -> Result<Option<String>, KdubError> {
    match current_arch {
        "x86_64" => Ok(None),
        "aarch64" => {
            let url = format!(
                "https://github.com/bramswenson/kdub/releases/download/v{current_version}/kdub-v{current_version}-x86_64-unknown-linux-gnu.tar.gz"
            );
            Ok(Some(url))
        }
        other => Err(KdubError::TailsPersist(format!(
            "unsupported architecture for Tails: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_tails_from_os_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("os-release");
        std::fs::write(
            &path,
            r#"TAILS_PRODUCT_NAME="Tails"
NAME="Tails"
VERSION_ID="7.5"
ID=tails
"#,
        )
        .unwrap();

        let result = detect_tails(&path);
        assert_eq!(result, Some("7.5".to_string()));
    }

    #[test]
    fn detect_tails_not_tails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("os-release");
        std::fs::write(
            &path,
            r#"NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
"#,
        )
        .unwrap();

        let result = detect_tails(&path);
        assert_eq!(result, None);
    }

    #[test]
    fn detect_tails_missing_file() {
        let result = detect_tails(Path::new("/nonexistent/path/os-release"));
        assert_eq!(result, None);
    }

    #[test]
    fn generate_persistence_conf_format() {
        let conf = generate_persistence_conf();
        let lines: Vec<&str> = conf.lines().collect();
        assert_eq!(lines.len(), 3);
        for line in &lines {
            let parts: Vec<&str> = line.split('\t').collect();
            assert_eq!(parts.len(), 2, "each line must be tab-separated: {line}");
        }
        // Verify all 3 destination paths are present
        let expected_destinations = [
            "/home/amnesia",
            "/home/amnesia/.gnupg",
            "/home/amnesia/Persistent",
        ];
        for dest in &expected_destinations {
            assert!(
                conf.contains(dest),
                "persistence.conf should contain {dest}"
            );
        }
    }

    #[test]
    fn resolve_binary_source_x86_64_uses_current() {
        let result = resolve_kdub_binary_source("x86_64", "1.0.0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn resolve_binary_source_aarch64_downloads() {
        let result = resolve_kdub_binary_source("aarch64", "1.2.3");
        assert!(result.is_ok());
        let url = result.unwrap().expect("should return Some(url)");
        assert!(url.contains("github.com/bramswenson/kdub/releases"));
        assert!(url.contains("v1.2.3"));
        assert!(url.contains("x86_64-unknown-linux-gnu.tar.gz"));
    }

    #[test]
    fn resolve_binary_source_unknown_arch_errors() {
        let result = resolve_kdub_binary_source("mips", "1.0.0");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, KdubError::TailsPersist(_)));
    }

    #[test]
    fn persistence_conf_snapshot() {
        let conf = generate_persistence_conf();
        insta::assert_snapshot!(conf);
    }

    #[test]
    fn persist_unsupported_error_snapshot() {
        let msg = "Persistent storage requires Linux (cryptsetup/parted).\n\
        Options:\n  \
        - Boot from the USB and configure persistence via Tails Welcome Screen\n  \
        - Run this command from a Linux machine or VM\n  \
        - See: https://github.com/bramswenson/kdub/issues/7 (VM guide)";
        insta::assert_snapshot!(msg);
    }

    // ── is_path_on_persistent tests ──────────────────────────────────

    #[test]
    fn is_path_on_persistent_tails_persistence_mount() {
        assert!(is_path_on_persistent(
            "/live/persistence/TailsData_unlocked/dotfiles/.local/bin/kdub"
        ));
    }

    #[test]
    fn is_path_on_persistent_local_bin() {
        assert!(is_path_on_persistent("/home/amnesia/.local/bin/kdub"));
    }

    #[test]
    fn is_path_on_persistent_usr_local_bin() {
        assert!(!is_path_on_persistent("/usr/local/bin/kdub"));
    }

    #[test]
    fn is_path_on_persistent_tmp() {
        assert!(!is_path_on_persistent("/tmp/kdub"));
    }

    #[test]
    fn is_path_on_persistent_empty() {
        assert!(!is_path_on_persistent(""));
    }

    // ── check_network_carrier tests (Linux only) ─────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn check_network_carrier_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!check_network_carrier(dir.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_network_carrier_only_loopback() {
        let dir = tempfile::tempdir().unwrap();
        let lo_dir = dir.path().join("lo");
        std::fs::create_dir(&lo_dir).unwrap();
        std::fs::write(lo_dir.join("carrier"), "1\n").unwrap();
        assert!(!check_network_carrier(dir.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_network_carrier_eth0_down() {
        let dir = tempfile::tempdir().unwrap();
        let lo_dir = dir.path().join("lo");
        std::fs::create_dir(&lo_dir).unwrap();
        std::fs::write(lo_dir.join("carrier"), "1\n").unwrap();

        let eth0_dir = dir.path().join("eth0");
        std::fs::create_dir(&eth0_dir).unwrap();
        std::fs::write(eth0_dir.join("carrier"), "0\n").unwrap();

        assert!(!check_network_carrier(dir.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_network_carrier_eth0_up() {
        let dir = tempfile::tempdir().unwrap();
        let lo_dir = dir.path().join("lo");
        std::fs::create_dir(&lo_dir).unwrap();
        std::fs::write(lo_dir.join("carrier"), "1\n").unwrap();

        let eth0_dir = dir.path().join("eth0");
        std::fs::create_dir(&eth0_dir).unwrap();
        std::fs::write(eth0_dir.join("carrier"), "1\n").unwrap();

        assert!(check_network_carrier(dir.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_network_carrier_wlan0_up() {
        let dir = tempfile::tempdir().unwrap();
        let lo_dir = dir.path().join("lo");
        std::fs::create_dir(&lo_dir).unwrap();
        std::fs::write(lo_dir.join("carrier"), "1\n").unwrap();

        let wlan0_dir = dir.path().join("wlan0");
        std::fs::create_dir(&wlan0_dir).unwrap();
        std::fs::write(wlan0_dir.join("carrier"), "1\n").unwrap();

        assert!(check_network_carrier(dir.path()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_network_carrier_nonexistent_dir() {
        assert!(!check_network_carrier(Path::new(
            "/nonexistent/sys/class/net"
        )));
    }
}
