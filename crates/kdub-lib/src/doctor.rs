use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::KdubError;
use crate::init::detect_platform;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information about a found dependency binary.
#[derive(Debug, Clone, Serialize)]
pub struct DepInfo {
    pub version: String,
    pub path: PathBuf,
}

/// Status of a daemon (pcscd).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonStatus {
    Running,
    NotRunning,
    /// macOS uses CryptoTokenKit — pcscd not needed.
    NotApplicable,
}

/// Check result for a single dependency.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DepCheck {
    pub name: String,
    pub required: bool,
    pub status: DepStatus,
}

/// The status outcome of a dependency check.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DepStatus {
    /// Dependency found.
    Ok { version: String, path: PathBuf },
    /// Daemon check (pcscd).
    Daemon { daemon_status: DaemonStatus },
    /// Not found.
    Missing,
    /// Recommended but not required for kdub itself.
    Recommended { reason: String },
}

/// Full doctor report.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub dependencies: Vec<DepCheck>,
    pub config_dir: PathBuf,
    pub config_dir_exists: bool,
    pub data_dir: PathBuf,
    pub data_dir_exists: bool,
    pub platform: String,
    pub overall_ok: bool,
    /// Tails-specific environment info, if running on Tails.
    pub tails: Option<crate::tails::TailsEnvironment>,
}

// ---------------------------------------------------------------------------
// Trait for mockable system dependency checking
// ---------------------------------------------------------------------------

/// Abstraction over system dependency checks, enabling unit testing with mocks.
pub trait SystemDeps {
    /// Look up a command by name: find its path and parse its version.
    fn check_command(&self, name: &str) -> Option<DepInfo>;

    /// Check whether the pcscd daemon is running (Linux) or not applicable (macOS).
    fn check_pcscd(&self) -> DaemonStatus;

    /// Check for scdaemon — may live in PATH or in well-known lib directories.
    fn check_scdaemon(&self) -> Option<DepInfo>;
}

// ---------------------------------------------------------------------------
// Real implementation
// ---------------------------------------------------------------------------

/// Production implementation that shells out to real binaries.
pub struct RealSystemDeps;

impl SystemDeps for RealSystemDeps {
    fn check_command(&self, name: &str) -> Option<DepInfo> {
        check_command_real(name)
    }

    fn check_pcscd(&self) -> DaemonStatus {
        if cfg!(target_os = "macos") {
            DaemonStatus::NotApplicable
        } else {
            check_pcscd_linux()
        }
    }

    fn check_scdaemon(&self) -> Option<DepInfo> {
        check_scdaemon_real()
    }
}

/// Find a command in PATH and parse its version.
fn check_command_real(name: &str) -> Option<DepInfo> {
    // Find the binary path via `which`
    let which_output = std::process::Command::new("which")
        .arg(name)
        .output()
        .ok()?;

    if !which_output.status.success() {
        return None;
    }

    let path = PathBuf::from(
        String::from_utf8_lossy(&which_output.stdout)
            .trim()
            .to_string(),
    );

    // Parse version
    let version = parse_version(name, &path);

    Some(DepInfo { version, path })
}

/// Parse the version string from a command's `--version` output.
fn parse_version(name: &str, path: &Path) -> String {
    let output = std::process::Command::new(path).arg("--version").output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return "unknown".to_string(),
    };

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    let text = if text.trim().is_empty() {
        // Some tools output version to stderr
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        text
    };

    // Parse version number from output.
    // Common patterns:
    //   gpg (GnuPG) 2.4.5
    //   jq-1.7.1
    //   ykman version: 5.4.0
    //   gpg-agent (GnuPG) 2.4.5
    extract_version_from_text(name, &text)
}

/// Extract a version number from a `--version` output line.
fn extract_version_from_text(_name: &str, text: &str) -> String {
    // Take the first line (most tools put version on line 1).
    let first_line = text.lines().next().unwrap_or("");

    // Try to find a semver-like pattern: digits.digits (optionally .digits...)
    for word in first_line.split_whitespace() {
        // Strip leading non-digit chars (e.g. "jq-1.7.1" → "1.7.1")
        let cleaned = word.trim_start_matches(|c: char| !c.is_ascii_digit());
        if looks_like_version(cleaned) {
            return cleaned.to_string();
        }
    }

    // Fallback: look at the rest of the text for a version
    for line in text.lines().skip(1) {
        for word in line.split_whitespace() {
            let cleaned = word.trim_start_matches(|c: char| !c.is_ascii_digit());
            if looks_like_version(cleaned) {
                return cleaned.to_string();
            }
        }
    }

    "unknown".to_string()
}

/// Heuristic: a string looks like a version if it starts with a digit and contains a dot.
fn looks_like_version(s: &str) -> bool {
    let first = s.chars().next();
    first.is_some_and(|c| c.is_ascii_digit()) && s.contains('.')
}

/// Check if pcscd is available on Linux — either running as a process
/// or available via systemd socket activation (pcscd.socket).
fn check_pcscd_linux() -> DaemonStatus {
    // Check for running process first
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(cmdline) = std::fs::read_to_string(entry.path().join("cmdline"))
                && cmdline.contains("pcscd")
            {
                return DaemonStatus::Running;
            }
        }
    }

    // Not running as a process — check if pcscd.socket is active (socket activation).
    // Modern Linux (including Tails) starts pcscd on demand via systemd socket.
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["is-active", "pcscd.socket"])
        .output()
        && output.status.success()
    {
        return DaemonStatus::Running;
    }

    DaemonStatus::NotRunning
}

/// Check for scdaemon in PATH and well-known lib directories.
fn check_scdaemon_real() -> Option<DepInfo> {
    // First try PATH
    if let Some(info) = check_command_real("scdaemon") {
        return Some(info);
    }

    // Well-known locations where gpg bundles install scdaemon
    let well_known = [
        "/usr/lib/gnupg/scdaemon",
        "/usr/lib/gnupg2/scdaemon",
        "/usr/local/lib/gnupg/scdaemon",
        "/opt/homebrew/lib/gnupg/scdaemon",
    ];

    for location in &well_known {
        let path = Path::new(location);
        if path.exists() {
            let version = parse_version("scdaemon", path);
            return Some(DepInfo {
                version,
                path: path.to_path_buf(),
            });
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Doctor logic (pure, testable)
// ---------------------------------------------------------------------------

/// Run all doctor checks and produce a report.
///
/// This is pure logic — all system interaction goes through the `SystemDeps` trait.
/// The Tails environment is passed in as a parameter, not detected inside this function.
pub fn run_doctor(
    deps: &dyn SystemDeps,
    config_dir: &Path,
    data_dir: &Path,
    tails: Option<crate::tails::TailsEnvironment>,
) -> Result<DoctorReport, KdubError> {
    let mut checks: Vec<DepCheck> = Vec::new();
    let any_required_missing = false;

    // gpg — recommended
    match deps.check_command("gpg") {
        Some(info) => checks.push(DepCheck {
            name: "gpg".to_string(),
            required: false,
            status: DepStatus::Ok {
                version: info.version,
                path: info.path,
            },
        }),
        None => {
            checks.push(DepCheck {
                name: "gpg".to_string(),
                required: false,
                status: DepStatus::Recommended {
                    reason: "needed for git signing, encrypt/decrypt".to_string(),
                },
            });
        }
    }

    // gpg-agent — recommended
    match deps.check_command("gpg-agent") {
        Some(info) => checks.push(DepCheck {
            name: "gpg-agent".to_string(),
            required: false,
            status: DepStatus::Ok {
                version: info.version,
                path: info.path,
            },
        }),
        None => {
            checks.push(DepCheck {
                name: "gpg-agent".to_string(),
                required: false,
                status: DepStatus::Recommended {
                    reason: "needed for agent operations, SSH authentication".to_string(),
                },
            });
        }
    }

    // scdaemon — for card ops (not strictly required)
    match deps.check_scdaemon() {
        Some(info) => checks.push(DepCheck {
            name: "scdaemon".to_string(),
            required: false,
            status: DepStatus::Ok {
                version: info.version,
                path: info.path,
            },
        }),
        None => checks.push(DepCheck {
            name: "scdaemon".to_string(),
            required: false,
            status: DepStatus::Missing,
        }),
    }

    // pcscd — for card ops (daemon check)
    let pcscd_status = deps.check_pcscd();
    checks.push(DepCheck {
        name: "pcscd".to_string(),
        required: false,
        status: DepStatus::Daemon {
            daemon_status: pcscd_status,
        },
    });

    // ykman — optional
    match deps.check_command("ykman") {
        Some(info) => checks.push(DepCheck {
            name: "ykman".to_string(),
            required: false,
            status: DepStatus::Ok {
                version: info.version,
                path: info.path,
            },
        }),
        None => checks.push(DepCheck {
            name: "ykman".to_string(),
            required: false,
            status: DepStatus::Missing,
        }),
    }

    let platform = detect_platform();

    Ok(DoctorReport {
        dependencies: checks,
        config_dir: config_dir.to_path_buf(),
        config_dir_exists: config_dir.exists(),
        data_dir: data_dir.to_path_buf(),
        data_dir_exists: data_dir.exists(),
        platform,
        overall_ok: !any_required_missing,
        tails,
    })
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

impl DoctorReport {
    /// Render as human-readable plain text.
    pub fn to_plain_text(&self) -> String {
        let mut out = String::new();

        out.push_str("System check:\n");
        for dep in &self.dependencies {
            let (version_or_status, ok_str) = match &dep.status {
                DepStatus::Ok { version, .. } => (version.clone(), "ok".to_string()),
                DepStatus::Daemon { daemon_status } => match daemon_status {
                    DaemonStatus::Running => ("running".to_string(), "ok".to_string()),
                    DaemonStatus::NotRunning => ("not running".to_string(), "warning".to_string()),
                    DaemonStatus::NotApplicable => ("n/a".to_string(), "ok".to_string()),
                },
                DepStatus::Missing => {
                    let label = if dep.required { "MISSING" } else { "not found" };
                    ("—".to_string(), label.to_string())
                }
                DepStatus::Recommended { reason } => {
                    ("—".to_string(), format!("recommended ({reason})"))
                }
            };
            out.push_str(&format!(
                "  {:<12} {:<12} {}\n",
                dep.name, version_or_status, ok_str
            ));
        }

        out.push('\n');
        out.push_str("Config:\n");

        let config_status = if self.config_dir_exists {
            "ok"
        } else {
            "missing"
        };
        out.push_str(&format!(
            "  {:<12} {}    {}\n",
            "config dir",
            self.config_dir.display(),
            config_status
        ));

        let data_status = if self.data_dir_exists {
            "ok"
        } else {
            "missing"
        };
        out.push_str(&format!(
            "  {:<12} {}    {}\n",
            "data dir",
            self.data_dir.display(),
            data_status
        ));

        out.push_str(&format!("  {:<12} {}\n", "platform", self.platform));

        if let Some(ref tails) = self.tails {
            out.push_str("\nTails environment:\n");
            out.push_str(&format!(
                "  {:<16} {:<12} ok\n",
                "Tails version", tails.version
            ));
            let persist_status = if tails.persistence_mounted {
                "mounted    ok"
            } else {
                "not mounted  MISSING"
            };
            out.push_str(&format!("  {:<16} {}\n", "Persistent", persist_status));
            if tails.network_connected {
                out.push_str(&format!(
                    "  {:<16} {}\n",
                    "Network", "connected  WARN  (disable networking for key ceremony!)"
                ));
            } else {
                out.push_str(&format!("  {:<16} {}\n", "Network", "disconnected ok"));
            }
            let kdub_status = if tails.kdub_on_persistent {
                "persistent ok"
            } else {
                "not persistent WARN"
            };
            out.push_str(&format!("  {:<16} {}\n", "kdub location", kdub_status));
        }

        out.push('\n');
        if self.overall_ok {
            out.push_str("All checks passed.\n");
        } else {
            out.push_str("Some required dependencies are missing.\n");
        }

        out
    }

    /// Render as JSON.
    pub fn to_json(&self) -> Result<String, KdubError> {
        // Build the JSON structure matching the spec from README.
        let mut deps_map = serde_json::Map::new();
        for dep in &self.dependencies {
            let value = match &dep.status {
                DepStatus::Ok { version, path } => serde_json::json!({
                    "version": version,
                    "status": "ok",
                    "path": path.to_string_lossy(),
                }),
                DepStatus::Daemon { daemon_status } => {
                    let status_str = match daemon_status {
                        DaemonStatus::Running => "running",
                        DaemonStatus::NotRunning => "not_running",
                        DaemonStatus::NotApplicable => "not_applicable",
                    };
                    serde_json::json!({ "status": status_str })
                }
                DepStatus::Missing => serde_json::json!({ "status": "missing" }),
                DepStatus::Recommended { reason } => serde_json::json!({
                    "status": "recommended",
                    "reason": reason,
                }),
            };
            deps_map.insert(dep.name.clone(), value);
        }

        let mut report = serde_json::json!({
            "dependencies": deps_map,
            "config": {
                "config_dir": self.config_dir.to_string_lossy(),
                "config_dir_exists": self.config_dir_exists,
                "data_dir": self.data_dir.to_string_lossy(),
                "data_dir_exists": self.data_dir_exists,
                "platform": self.platform,
            },
            "status": if self.overall_ok { "ok" } else { "error" },
        });

        if let Some(ref tails) = self.tails {
            report["tails"] = serde_json::json!({
                "version": tails.version,
                "persistence_mounted": tails.persistence_mounted,
                "network_connected": tails.network_connected,
                "kdub_on_persistent": tails.kdub_on_persistent,
            });
        }

        serde_json::to_string_pretty(&report).map_err(|e| KdubError::Config(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock system deps for unit testing.
    struct MockDeps {
        commands: std::collections::HashMap<String, Option<DepInfo>>,
        pcscd: DaemonStatus,
        scdaemon: Option<DepInfo>,
    }

    impl MockDeps {
        fn all_present() -> Self {
            let mut commands = std::collections::HashMap::new();
            commands.insert(
                "gpg".to_string(),
                Some(DepInfo {
                    version: "2.4.5".to_string(),
                    path: PathBuf::from("/usr/bin/gpg"),
                }),
            );
            commands.insert(
                "gpg-agent".to_string(),
                Some(DepInfo {
                    version: "2.4.5".to_string(),
                    path: PathBuf::from("/usr/bin/gpg-agent"),
                }),
            );
            commands.insert(
                "ykman".to_string(),
                Some(DepInfo {
                    version: "5.4.0".to_string(),
                    path: PathBuf::from("/usr/bin/ykman"),
                }),
            );

            Self {
                commands,
                pcscd: DaemonStatus::Running,
                scdaemon: Some(DepInfo {
                    version: "2.4.5".to_string(),
                    path: PathBuf::from("/usr/lib/gnupg/scdaemon"),
                }),
            }
        }
    }

    impl SystemDeps for MockDeps {
        fn check_command(&self, name: &str) -> Option<DepInfo> {
            self.commands.get(name).and_then(|v| v.clone())
        }

        fn check_pcscd(&self) -> DaemonStatus {
            self.pcscd.clone()
        }

        fn check_scdaemon(&self) -> Option<DepInfo> {
            self.scdaemon.clone()
        }
    }

    #[test]
    fn test_all_deps_present() {
        let deps = MockDeps::all_present();
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();

        assert!(report.overall_ok);
        assert!(report.config_dir_exists);
        assert!(report.data_dir_exists);
        assert_eq!(report.dependencies.len(), 5); // gpg, gpg-agent, scdaemon, pcscd, ykman
    }

    #[test]
    fn test_missing_recommended_dep() {
        let mut deps = MockDeps::all_present();
        deps.commands.insert("gpg".to_string(), None);

        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();

        // gpg is recommended, not required — overall still ok
        assert!(report.overall_ok);
        let gpg = report
            .dependencies
            .iter()
            .find(|d| d.name == "gpg")
            .unwrap();
        assert!(matches!(gpg.status, DepStatus::Recommended { .. }));
    }

    #[test]
    fn test_missing_optional_dep() {
        let mut deps = MockDeps::all_present();
        deps.commands.insert("ykman".to_string(), None);

        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();

        // Still overall ok — ykman is optional
        assert!(report.overall_ok);
    }

    #[test]
    fn test_pcscd_not_applicable_on_macos() {
        let mut deps = MockDeps::all_present();
        deps.pcscd = DaemonStatus::NotApplicable;

        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();

        assert!(report.overall_ok);
        let pcscd = report
            .dependencies
            .iter()
            .find(|d| d.name == "pcscd")
            .unwrap();
        match &pcscd.status {
            DepStatus::Daemon { daemon_status } => {
                assert_eq!(*daemon_status, DaemonStatus::NotApplicable);
            }
            other => panic!("expected Daemon status, got {other:?}"),
        }
    }

    #[test]
    fn test_pcscd_not_running_on_linux() {
        let mut deps = MockDeps::all_present();
        deps.pcscd = DaemonStatus::NotRunning;

        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();

        // pcscd is not required, so overall still ok
        assert!(report.overall_ok);
        let pcscd = report
            .dependencies
            .iter()
            .find(|d| d.name == "pcscd")
            .unwrap();
        match &pcscd.status {
            DepStatus::Daemon { daemon_status } => {
                assert_eq!(*daemon_status, DaemonStatus::NotRunning);
            }
            other => panic!("expected Daemon status, got {other:?}"),
        }
    }

    #[test]
    fn test_config_dir_missing() {
        let deps = MockDeps::all_present();
        let config = PathBuf::from("/nonexistent/config/kdub");
        let data = PathBuf::from("/nonexistent/data/kdub");

        let report = run_doctor(&deps, &config, &data, None).unwrap();

        assert!(!report.config_dir_exists);
        assert!(!report.data_dir_exists);
        // Still overall ok if required deps are present
        assert!(report.overall_ok);
    }

    #[test]
    fn test_plain_text_output() {
        let deps = MockDeps::all_present();
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();
        let text = report.to_plain_text();

        assert!(text.contains("System check:"));
        assert!(text.contains("gpg"));
        assert!(text.contains("2.4.5"));
        assert!(text.contains("Config:"));
        assert!(text.contains("config dir"));
        assert!(text.contains("data dir"));
        assert!(text.contains("platform"));
        assert!(text.contains("All checks passed."));
    }

    #[test]
    fn test_plain_text_missing_recommended_dep() {
        let mut deps = MockDeps::all_present();
        deps.commands.insert("gpg".to_string(), None);

        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();
        let text = report.to_plain_text();

        assert!(text.contains("recommended"));
        assert!(text.contains("All checks passed."));
    }

    #[test]
    fn test_json_output() {
        let deps = MockDeps::all_present();
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();
        let json_str = report.to_json().unwrap();

        // Should be valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert!(parsed["dependencies"]["gpg"]["version"].is_string());
        assert_eq!(parsed["dependencies"]["gpg"]["status"], "ok");
        assert!(parsed["config"]["config_dir"].is_string());
        assert!(parsed["config"]["platform"].is_string());
    }

    #[test]
    fn test_json_output_missing_recommended_dep() {
        let mut deps = MockDeps::all_present();
        deps.commands.insert("gpg".to_string(), None);

        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();
        let json_str = report.to_json().unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["dependencies"]["gpg"]["status"], "recommended");
    }

    #[test]
    fn test_version_extraction() {
        // gpg style
        assert_eq!(
            extract_version_from_text("gpg", "gpg (GnuPG) 2.4.5"),
            "2.4.5"
        );

        // jq style
        assert_eq!(extract_version_from_text("jq", "jq-1.7.1"), "1.7.1");

        // ykman style
        assert_eq!(
            extract_version_from_text("ykman", "YubiKey Manager (ykman) version: 5.4.0"),
            "5.4.0"
        );

        // gpg-agent style
        assert_eq!(
            extract_version_from_text("gpg-agent", "gpg-agent (GnuPG) 2.4.5"),
            "2.4.5"
        );

        // Unknown format
        assert_eq!(
            extract_version_from_text("unknown", "no version here"),
            "unknown"
        );
    }

    #[test]
    fn test_looks_like_version() {
        assert!(looks_like_version("2.4.5"));
        assert!(looks_like_version("1.7.1"));
        assert!(looks_like_version("5.4.0"));
        assert!(!looks_like_version("abc"));
        assert!(!looks_like_version(""));
        assert!(!looks_like_version("123")); // no dot
    }

    #[test]
    fn test_missing_gpg_is_recommended_not_required() {
        let mut deps = MockDeps::all_present();
        deps.commands.insert("gpg".to_string(), None);

        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let report = run_doctor(&deps, &config, &data, None).unwrap();
        assert!(report.overall_ok); // gpg is recommended, not required
        let gpg = report
            .dependencies
            .iter()
            .find(|d| d.name == "gpg")
            .unwrap();
        assert!(matches!(gpg.status, DepStatus::Recommended { .. }));
    }

    #[test]
    fn test_doctor_plain_text_with_tails() {
        let deps = MockDeps::all_present();
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let tails = Some(crate::tails::TailsEnvironment {
            version: "7.5".to_string(),
            persistence_mounted: true,
            network_connected: false,
            kdub_on_persistent: true,
        });

        let report = run_doctor(&deps, &config, &data, tails).unwrap();

        let mut settings = insta::Settings::clone_current();
        // Redact tempdir paths (Linux: /tmp/.tmpXXXXXX, macOS: /var/folders/.../T/.tmpXXXXXX)
        settings.add_filter(r"[^\s]+/\.tmp\w+", "[TEMPDIR]");
        settings.add_filter(r"\b(linux|macos)\b", "[PLATFORM]");
        settings.bind(|| {
            insta::assert_snapshot!(report.to_plain_text());
        });
    }

    #[test]
    fn test_doctor_json_with_tails() {
        let deps = MockDeps::all_present();
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let tails = Some(crate::tails::TailsEnvironment {
            version: "7.5".to_string(),
            persistence_mounted: true,
            network_connected: false,
            kdub_on_persistent: true,
        });

        let report = run_doctor(&deps, &config, &data, tails).unwrap();
        let json = report.to_json().unwrap();

        let mut settings = insta::Settings::clone_current();
        // Redact tempdir paths (Linux: /tmp/.tmpXXXXXX, macOS: /var/folders/.../T/.tmpXXXXXX)
        settings.add_filter(r#"[^\s"]+/\.tmp\w+"#, "[TEMPDIR]");
        settings.add_filter(r#""(linux|macos)""#, r#""[PLATFORM]""#);
        settings.bind(|| {
            insta::assert_snapshot!(json);
        });
    }

    #[test]
    fn test_plain_text_missing_required_dep_shows_missing_label() {
        // Construct a report directly with a required=true, Missing dep to exercise
        // the "MISSING" label branch in to_plain_text().
        let report = DoctorReport {
            dependencies: vec![DepCheck {
                name: "required-tool".to_string(),
                required: true,
                status: DepStatus::Missing,
            }],
            config_dir: std::path::PathBuf::from("/some/config"),
            config_dir_exists: true,
            data_dir: std::path::PathBuf::from("/some/data"),
            data_dir_exists: true,
            platform: "linux".to_string(),
            overall_ok: false,
            tails: None,
        };
        let text = report.to_plain_text();
        assert!(
            text.contains("MISSING"),
            "expected MISSING in output, got: {text}"
        );
        // Should NOT say "not found" for required deps.
        assert!(
            !text.contains("not found"),
            "required dep should say MISSING not 'not found', got: {text}"
        );
        assert!(
            text.contains("Some required dependencies are missing."),
            "got: {text}"
        );
    }

    #[test]
    fn test_plain_text_config_dir_does_not_exist() {
        let report = DoctorReport {
            dependencies: vec![],
            config_dir: std::path::PathBuf::from("/nonexistent/config"),
            config_dir_exists: false,
            data_dir: std::path::PathBuf::from("/nonexistent/data"),
            data_dir_exists: false,
            platform: "linux".to_string(),
            overall_ok: true,
            tails: None,
        };
        let text = report.to_plain_text();
        // Both config dir and data dir should show "missing" when they don't exist.
        let missing_count = text.matches("missing").count();
        assert!(
            missing_count >= 2,
            "expected at least 2 'missing' occurrences for non-existent dirs, got: {text}"
        );
    }

    #[test]
    fn test_plain_text_tails_network_connected_and_persistence_not_mounted() {
        let deps = MockDeps::all_present();
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let tails = Some(crate::tails::TailsEnvironment {
            version: "7.5".to_string(),
            persistence_mounted: false,
            network_connected: true,
            kdub_on_persistent: false,
        });

        let report = run_doctor(&deps, &config, &data, tails).unwrap();
        let text = report.to_plain_text();

        // Network connected should show WARN.
        assert!(
            text.contains("WARN") && text.contains("disable networking"),
            "expected network warning, got: {text}"
        );
        // Persistence not mounted should show MISSING.
        assert!(
            text.contains("not mounted") && text.contains("MISSING"),
            "expected persistence MISSING warning, got: {text}"
        );
        // kdub not on persistent should show WARN.
        assert!(
            text.contains("not persistent"),
            "expected kdub location warning, got: {text}"
        );
    }

    #[test]
    fn test_tails_environment_in_report() {
        let deps = MockDeps::all_present();
        let tmp = tempfile::tempdir().unwrap();
        let config = tmp.path().join("config");
        let data = tmp.path().join("data");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&data).unwrap();

        let tails = Some(crate::tails::TailsEnvironment {
            version: "7.5".to_string(),
            persistence_mounted: true,
            network_connected: false,
            kdub_on_persistent: true,
        });

        let report = run_doctor(&deps, &config, &data, tails).unwrap();
        assert!(report.tails.is_some());
        let t = report.tails.unwrap();
        assert_eq!(t.version, "7.5");
        assert!(t.persistence_mounted);
        assert!(!t.network_connected);
    }
}
