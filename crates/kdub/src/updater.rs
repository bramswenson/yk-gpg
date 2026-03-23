//! Self-update logic: version check cache, update notice, and update execution.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use semver::Version;
use serde::{Deserialize, Serialize};

/// Ed25519 public key for verifying signed release archives.
/// Generated with `zipsign gen-key` — the corresponding private key
/// is stored as a GitHub Actions secret and never committed to the repo.
const ZIPSIGN_PUBLIC_KEY: [u8; 32] = *include_bytes!("../zipsign-public.key");

const CHECK_INTERVAL: Duration = Duration::from_secs(86400); // 24 hours
const CHECK_TIMEOUT: Duration = Duration::from_secs(3);
const GITHUB_REPO_OWNER: &str = "bramswenson";
const GITHUB_REPO_NAME: &str = "kdub";

/// Cached result of a version check against the GitHub Releases API.
#[derive(Serialize, Deserialize)]
struct UpdateCache {
    latest_version: String,
    checked_at: u64, // Unix epoch seconds
}

/// Returns the platform cache directory for kdub, or None if the home directory
/// cannot be determined.
fn cache_dir_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "kdub").map(|d| d.cache_dir().to_path_buf())
}

/// Returns the path to the update-check cache file within the given base directory.
fn cache_file_path(base: &Path) -> PathBuf {
    base.join("update-check.json")
}

/// Reads and deserializes the JSON cache file from the given base directory.
/// Returns None on any error (missing file, parse failure, etc.).
fn read_cache(base: &Path) -> Option<UpdateCache> {
    let path = cache_file_path(base);
    let contents = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Writes a version check result to the JSON cache file in the given base directory.
/// Creates parent directories with 0o700 permissions (on Unix) and the cache file with 0o600.
fn write_cache(base: &Path, version: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(base)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_secs();

        let cache = UpdateCache {
            latest_version: version.to_string(),
            checked_at: now,
        };

        let json = serde_json::to_string(&cache).map_err(std::io::Error::other)?;
        let path = cache_file_path(base);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;

        file.write_all(json.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(base)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(std::io::Error::other)?
            .as_secs();

        let cache = UpdateCache {
            latest_version: version.to_string(),
            checked_at: now,
        };

        let json = serde_json::to_string(&cache).map_err(std::io::Error::other)?;
        let path = cache_file_path(base);

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        file.write_all(json.as_bytes())?;
    }

    Ok(())
}

/// Returns true if the update cache exists and was written less than CHECK_INTERVAL ago.
fn cache_is_fresh(base: &Path) -> bool {
    let cache = match read_cache(base) {
        Some(c) => {
            tracing::debug!(version = %c.latest_version, "cache hit");
            c
        }
        None => {
            tracing::debug!("cache miss: no valid cache file found");
            return false;
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let fresh = now.saturating_sub(cache.checked_at) < CHECK_INTERVAL.as_secs();
    tracing::debug!(
        fresh,
        age_secs = now.saturating_sub(cache.checked_at),
        "cache freshness check"
    );
    fresh
}

/// Fetch the latest release version from GitHub. Returns `None` on any error.
fn fetch_latest_version() -> Option<String> {
    tracing::debug!("fetching latest version from GitHub Releases API");
    let agent = ureq::Agent::new_with_config(
        ureq::config::Config::builder()
            .timeout_global(Some(CHECK_TIMEOUT))
            .build(),
    );
    let response = match agent
        .get("https://api.github.com/repos/bramswenson/kdub/releases/latest")
        .header("Accept", "application/vnd.github.v3+json")
        .header("User-Agent", concat!("kdub/", env!("CARGO_PKG_VERSION")))
        .call()
    {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(
                error = %e,
                "GitHub API request failed — if running on Tails/Tor, check SOCKS proxy \
                 connectivity (proxy handshake, DNS-over-Tor, circuit timeouts)"
            );
            return None;
        }
    };
    let body: serde_json::Value = match response.into_body().read_json() {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, "failed to parse GitHub API response body as JSON");
            return None;
        }
    };
    let tag = match body["tag_name"].as_str() {
        Some(t) => t,
        None => {
            tracing::debug!("GitHub API response missing 'tag_name' field");
            return None;
        }
    };
    let version = tag.trim_start_matches('v').to_string();
    tracing::debug!(version = %version, "fetched latest version from GitHub");
    Some(version)
}

/// Check for a newer version and write a notice to `writer` if one is available.
///
/// Uses a 24-hour cache to avoid hitting the GitHub API on every invocation.
/// Respects `KDUB_NO_UPDATE_CHECK=1` env var.
/// Terminal guard lives in the public wrapper [`maybe_print_update_notice`].
fn check_and_notify(writer: &mut impl Write, cache_base: &Path) {
    if std::env::var("KDUB_NO_UPDATE_CHECK").ok().as_deref() == Some("1") {
        tracing::debug!("update check suppressed by KDUB_NO_UPDATE_CHECK=1");
        return;
    }

    let latest_str = if cache_is_fresh(cache_base) {
        match read_cache(cache_base) {
            Some(c) => c.latest_version,
            None => {
                tracing::warn!("cache was fresh but re-read failed");
                return;
            }
        }
    } else {
        match fetch_latest_version() {
            Some(v) => {
                let _ = write_cache(cache_base, &v);
                v
            }
            None => {
                tracing::warn!("unable to determine latest version (network fetch failed)");
                return;
            }
        }
    };

    let latest = match Version::parse(&latest_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(version = %latest_str, error = %e, "cached version is not valid semver");
            return;
        }
    };
    let current = match Version::parse(env!("CARGO_PKG_VERSION")) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "current CARGO_PKG_VERSION is not valid semver");
            return;
        }
    };

    tracing::debug!(%current, %latest, "version comparison");
    if latest > current {
        let _ = writeln!(
            writer,
            "A new version of kdub is available: v{current} → v{latest}\nRun `kdub update` to upgrade."
        );
    }
}

/// What the update command should do after comparing versions.
#[derive(Debug, PartialEq)]
enum UpdateAction {
    /// Current version is equal to or newer than the latest release.
    UpToDate { current: Version, latest: Version },
    /// A newer version exists; report it (--check mode).
    Available { current: Version, latest: Version },
    /// A newer version exists; prompt and install.
    Install { current: Version, latest: Version },
}

/// Determine the update action based on version comparison and flags.
fn determine_update_action(current: &Version, latest: &Version, check_only: bool) -> UpdateAction {
    if current >= latest {
        UpdateAction::UpToDate {
            current: current.clone(),
            latest: latest.clone(),
        }
    } else if check_only {
        UpdateAction::Available {
            current: current.clone(),
            latest: latest.clone(),
        }
    } else {
        UpdateAction::Install {
            current: current.clone(),
            latest: latest.clone(),
        }
    }
}

/// Execute the self-update workflow: check the latest version, and optionally
/// download and install it. When installing, verifies the zipsign ed25519ph
/// signature before replacing the current binary.
pub fn run_update(check_only: bool, skip_confirm: bool) -> color_eyre::Result<()> {
    let updater = self_update::backends::github::Update::configure()
        .repo_owner(GITHUB_REPO_OWNER)
        .repo_name(GITHUB_REPO_NAME)
        .bin_name("kdub")
        .bin_path_in_archive("{{ bin }}")
        .current_version(env!("CARGO_PKG_VERSION"))
        .target(self_update::get_target())
        .verifying_keys([ZIPSIGN_PUBLIC_KEY])
        .show_download_progress(true)
        // Disable self_update's built-in confirmation — we prompt ourselves via dialoguer
        .no_confirm(true)
        .build()?;

    let latest_release = updater.get_latest_release()?;
    let latest_version_str = latest_release.version.trim_start_matches('v');
    let current = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let latest = Version::parse(latest_version_str)?;

    match determine_update_action(&current, &latest, check_only) {
        UpdateAction::UpToDate { current, latest } => {
            println!("kdub is up to date (v{current}, latest: v{latest})");
            return Ok(());
        }
        UpdateAction::Available { current, latest } => {
            println!("Update available: v{current} → v{latest}");
            return Ok(());
        }
        UpdateAction::Install { current, latest } => {
            if !skip_confirm {
                let confirmed = dialoguer::Confirm::new()
                    .with_prompt(format!("Update kdub v{current} → v{latest}?"))
                    .default(false)
                    .interact()?;
                if !confirmed {
                    println!("Update cancelled.");
                    return Ok(());
                }
            }

            tracing::info!(from = %current, to = %latest, "downloading update");
            match updater.update() {
                Ok(status) => {
                    let installed_version = status.version().trim_start_matches('v');
                    println!("kdub updated successfully: v{current} → v{installed_version}",);

                    if let Some(base) = cache_dir_path()
                        && let Err(e) = write_cache(&base, installed_version)
                    {
                        tracing::warn!(error = %e, "failed to write post-update cache");
                    }
                }
                Err(self_update::errors::Error::Io(ref io_err))
                    if io_err.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    let exe_path = std::env::current_exe()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "kdub".to_string());
                    eprintln!("error: insufficient permissions to update kdub at {exe_path}");
                    eprintln!("Try running with elevated privileges (e.g., sudo kdub update)");
                    return Err(self_update::errors::Error::Io(std::io::Error::new(
                        io_err.kind(),
                        io_err.to_string(),
                    ))
                    .into());
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    Ok(())
}

/// Print an update notice to stderr if a newer version is available.
///
/// Respects `KDUB_NO_UPDATE_CHECK=1` env var, `--quiet` flag (checked by caller),
/// and only runs when stderr is a terminal. Failures are silently ignored.
pub fn maybe_print_update_notice() {
    if !std::io::stderr().is_terminal() {
        return;
    }
    let Some(base) = cache_dir_path() else { return };
    check_and_notify(&mut std::io::stderr(), &base);
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_cache_round_trip() {
        let tmp = TempDir::new().unwrap();
        write_cache(tmp.path(), "1.2.3").unwrap();

        let cache = read_cache(tmp.path()).unwrap();
        assert_eq!(cache.latest_version, "1.2.3");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now.abs_diff(cache.checked_at) <= 2);
    }

    #[test]
    fn test_cache_freshness_current() {
        let tmp = TempDir::new().unwrap();
        write_cache(tmp.path(), "1.0.0").unwrap();
        assert!(cache_is_fresh(tmp.path()));
    }

    #[test]
    fn test_cache_freshness_expired() {
        let tmp = TempDir::new().unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expired_at = now - 90000; // 25 hours ago

        let cache = UpdateCache {
            latest_version: "1.0.0".to_string(),
            checked_at: expired_at,
        };
        let json = serde_json::to_string(&cache).unwrap();

        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(tmp.path())
            .unwrap();

        let path = cache_file_path(tmp.path());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(json.as_bytes()).unwrap();

        assert!(!cache_is_fresh(tmp.path()));
    }

    #[test]
    fn test_missing_cache_is_not_fresh() {
        let tmp = TempDir::new().unwrap();
        assert!(!cache_is_fresh(tmp.path()));
    }

    #[test]
    fn test_corrupt_cache_returns_none() {
        let tmp = TempDir::new().unwrap();

        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(tmp.path())
            .unwrap();

        let path = cache_file_path(tmp.path());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(b"this is not valid json \x00\xff").unwrap();

        assert!(read_cache(tmp.path()).is_none());
    }

    #[test]
    fn test_notice_when_update_available() {
        let tmp = TempDir::new().unwrap();
        write_cache(tmp.path(), "99.0.0").unwrap();

        let mut writer: Vec<u8> = Vec::new();
        check_and_notify(&mut writer, tmp.path());

        let output = String::from_utf8(writer).unwrap();
        assert!(
            output.contains("new version"),
            "expected 'new version' in: {output}"
        );
        assert!(output.contains("99.0.0"), "expected '99.0.0' in: {output}");
    }

    #[test]
    fn test_no_notice_when_current_is_latest() {
        let tmp = TempDir::new().unwrap();
        write_cache(tmp.path(), env!("CARGO_PKG_VERSION")).unwrap();

        let mut writer: Vec<u8> = Vec::new();
        check_and_notify(&mut writer, tmp.path());

        assert!(
            writer.is_empty(),
            "expected no output but got: {}",
            String::from_utf8_lossy(&writer)
        );
    }

    #[test]
    fn test_no_notice_when_env_var_set() {
        // SAFETY: nextest runs each test in its own process, so mutating env is safe.
        unsafe { std::env::set_var("KDUB_NO_UPDATE_CHECK", "1") };

        let tmp = TempDir::new().unwrap();
        // Cache a version newer than current — without the env var guard, this would print a notice
        write_cache(tmp.path(), "99.0.0").unwrap();

        let mut writer: Vec<u8> = Vec::new();
        check_and_notify(&mut writer, tmp.path());

        assert!(
            writer.is_empty(),
            "expected no output with KDUB_NO_UPDATE_CHECK=1 but got: {}",
            String::from_utf8_lossy(&writer)
        );
    }

    #[test]
    fn test_action_up_to_date() {
        let current = Version::parse("1.0.0").unwrap();
        let latest = Version::parse("1.0.0").unwrap();
        assert_eq!(
            determine_update_action(&current, &latest, false),
            UpdateAction::UpToDate {
                current: current.clone(),
                latest: latest.clone(),
            }
        );
    }

    #[test]
    fn test_action_up_to_date_when_ahead() {
        let current = Version::parse("2.0.0").unwrap();
        let latest = Version::parse("1.0.0").unwrap();
        assert_eq!(
            determine_update_action(&current, &latest, false),
            UpdateAction::UpToDate {
                current: current.clone(),
                latest: latest.clone(),
            }
        );
    }

    #[test]
    fn test_action_available_check_only() {
        let current = Version::parse("1.0.0").unwrap();
        let latest = Version::parse("2.0.0").unwrap();
        assert_eq!(
            determine_update_action(&current, &latest, true),
            UpdateAction::Available {
                current: current.clone(),
                latest: latest.clone(),
            }
        );
    }

    #[test]
    fn test_action_install() {
        let current = Version::parse("1.0.0").unwrap();
        let latest = Version::parse("2.0.0").unwrap();
        assert_eq!(
            determine_update_action(&current, &latest, false),
            UpdateAction::Install {
                current: current.clone(),
                latest: latest.clone(),
            }
        );
    }

    #[test]
    fn test_action_prerelease_available() {
        let current = Version::parse("1.0.0").unwrap();
        let latest = Version::parse("2.0.0-rc.1").unwrap();
        assert_eq!(
            determine_update_action(&current, &latest, true),
            UpdateAction::Available {
                current: current.clone(),
                latest: latest.clone(),
            }
        );
    }

    #[test]
    fn test_no_notice_when_cached_version_is_older() {
        let tmp = TempDir::new().unwrap();
        // Cache a version older than current — no notice should appear
        write_cache(tmp.path(), "0.0.1").unwrap();

        let mut writer: Vec<u8> = Vec::new();
        check_and_notify(&mut writer, tmp.path());

        assert!(
            writer.is_empty(),
            "expected no output for older cached version but got: {}",
            String::from_utf8_lossy(&writer)
        );
    }

    #[test]
    fn test_no_notice_when_cache_missing_and_network_unavailable() {
        // Empty dir with no cache — fetch_latest_version will fail (no network in tests),
        // so check_and_notify should return silently
        let tmp = TempDir::new().unwrap();

        let mut writer: Vec<u8> = Vec::new();
        check_and_notify(&mut writer, tmp.path());

        assert!(
            writer.is_empty(),
            "expected no output when network unavailable but got: {}",
            String::from_utf8_lossy(&writer)
        );
    }

    #[test]
    fn test_cache_dir_path_returns_some() {
        // Verifies cache_dir_path works on this system (home dir resolvable)
        assert!(cache_dir_path().is_some());
    }

    #[test]
    fn test_current_version_parses_as_semver() {
        Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    }

    #[test]
    fn test_version_comparison_newer() {
        let newer = Version::parse("0.2.0").unwrap();
        let older = Version::parse("0.1.0").unwrap();
        assert!(newer > older);
    }

    #[test]
    fn test_version_comparison_same() {
        let a = Version::parse("0.1.0").unwrap();
        let b = Version::parse("0.1.0").unwrap();
        assert!(a <= b);
    }

    #[test]
    fn test_version_comparison_prerelease() {
        // Pre-release is greater than a prior stable release.
        let rc = Version::parse("0.2.0-rc.1").unwrap();
        let older = Version::parse("0.1.0").unwrap();
        assert!(rc > older);

        // Stable release is greater than pre-release of the same version per semver.
        let stable = Version::parse("0.2.0").unwrap();
        assert!(stable > rc);
    }

    #[test]
    fn test_no_notice_when_cached_version_is_invalid_semver() {
        let tmp = TempDir::new().unwrap();
        write_cache(tmp.path(), "not-a-version").unwrap();
        let mut writer: Vec<u8> = Vec::new();
        check_and_notify(&mut writer, tmp.path());
        assert!(
            writer.is_empty(),
            "expected no output for invalid semver but got: {}",
            String::from_utf8_lossy(&writer)
        );
    }

    #[test]
    fn test_cache_overwrite() {
        let tmp = TempDir::new().unwrap();
        write_cache(tmp.path(), "1.0.0").unwrap();
        write_cache(tmp.path(), "2.0.0").unwrap();
        let cache = read_cache(tmp.path()).unwrap();
        assert_eq!(cache.latest_version, "2.0.0");
    }

    #[test]
    fn test_action_install_when_current_is_prerelease() {
        let current = Version::parse("1.0.0-alpha.1").unwrap();
        let latest = Version::parse("1.0.0").unwrap();
        assert_eq!(
            determine_update_action(&current, &latest, false),
            UpdateAction::Install {
                current: current.clone(),
                latest: latest.clone(),
            }
        );
    }
}
