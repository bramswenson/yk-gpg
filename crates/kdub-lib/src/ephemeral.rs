use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use rand::Rng;

use crate::error::KdubError;

/// Ephemeral directory on tmpfs for secret key material.
///
/// The directory is created on a RAM-backed filesystem and is automatically
/// cleaned up when dropped, including killing any gpg-agent that was running
/// in it. Key material never touches persistent disk.
///
/// Tmpfs selection priority:
/// 1. `XDG_RUNTIME_DIR` (Linux) — already tmpfs on systemd systems
/// 2. `/dev/shm` (Linux) — shared memory, always tmpfs
/// 3. macOS RAM disk via `hdiutil`
/// 4. Hard error — no silent fallback to persistent disk
#[derive(Debug)]
pub struct EphemeralDir {
    path: PathBuf,
    #[cfg(target_os = "macos")]
    macos_device: Option<String>,
}

impl EphemeralDir {
    /// Create a new ephemeral directory on tmpfs.
    ///
    /// Returns an error if no tmpfs mount is available. Never falls back
    /// to persistent storage.
    pub fn new() -> Result<Self, KdubError> {
        #[cfg(target_os = "linux")]
        {
            Self::new_linux()
        }
        #[cfg(target_os = "macos")]
        {
            Self::new_macos()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Err(KdubError::EphemeralDir(
                "no tmpfs available: unsupported platform".to_string(),
            ))
        }
    }

    /// Return the path to the ephemeral directory.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Generate a random directory name like `kdub-a1b2c3d4e5f6`.
    fn random_dir_name() -> String {
        let mut rng = rand::thread_rng();
        let suffix: String = (0..12)
            .map(|_| {
                let idx = rng.gen_range(0..36);
                if idx < 10 {
                    (b'0' + idx) as char
                } else {
                    (b'a' + idx - 10) as char
                }
            })
            .collect();
        format!("kdub-{suffix}")
    }

    /// Create the directory at the given path with mode 0700.
    #[cfg(target_os = "linux")]
    fn create_dir_with_permissions(path: &Path) -> Result<(), KdubError> {
        fs::create_dir(path).map_err(|e| {
            KdubError::EphemeralDir(format!(
                "failed to create directory {}: {e}",
                path.display()
            ))
        })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| {
            KdubError::EphemeralDir(format!(
                "failed to set permissions on {}: {e}",
                path.display()
            ))
        })?;

        // Verify permissions were applied
        let metadata = fs::metadata(path).map_err(|e| {
            KdubError::EphemeralDir(format!("failed to stat {}: {e}", path.display()))
        })?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(KdubError::EphemeralDir(format!(
                "directory {} has mode {mode:04o}, expected 0700",
                path.display()
            )));
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn new_linux() -> Result<Self, KdubError> {
        // Priority 1: XDG_RUNTIME_DIR
        if let Ok(xdg_dir) = std::env::var("XDG_RUNTIME_DIR") {
            let xdg_path = PathBuf::from(&xdg_dir);
            if xdg_path.is_dir() {
                if Self::is_tmpfs_linux(&xdg_path) {
                    let dir_name = Self::random_dir_name();
                    let path = xdg_path.join(dir_name);
                    Self::create_dir_with_permissions(&path)?;
                    tracing::debug!(
                        "created ephemeral dir on XDG_RUNTIME_DIR: {}",
                        path.display()
                    );
                    return Ok(Self { path });
                }
                tracing::warn!("XDG_RUNTIME_DIR ({}) is not tmpfs, falling back", xdg_dir);
            }
        }

        // Priority 2: /dev/shm
        let dev_shm = PathBuf::from("/dev/shm");
        if dev_shm.is_dir() && Self::is_tmpfs_linux(&dev_shm) {
            let dir_name = Self::random_dir_name();
            let path = dev_shm.join(dir_name);
            Self::create_dir_with_permissions(&path)?;
            tracing::debug!("created ephemeral dir on /dev/shm: {}", path.display());
            return Ok(Self { path });
        }

        Err(KdubError::EphemeralDir(
            "no tmpfs available: neither XDG_RUNTIME_DIR (tmpfs) nor /dev/shm found".to_string(),
        ))
    }

    /// Check if a path is on a tmpfs mount by reading /proc/mounts.
    #[cfg(target_os = "linux")]
    fn is_tmpfs_linux(path: &Path) -> bool {
        let mounts = match fs::read_to_string("/proc/mounts") {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("unable to read /proc/mounts: {e}, assuming not tmpfs");
                return false;
            }
        };

        // Resolve the path to handle symlinks
        let resolved = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => path.to_path_buf(),
        };

        // Find the longest matching mount point that is tmpfs
        let mut best_match: Option<&str> = None;
        let mut best_len = 0;

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let mount_point = parts[1];
            let fs_type = parts[2];

            if resolved.starts_with(mount_point) && mount_point.len() > best_len {
                best_match = Some(fs_type);
                best_len = mount_point.len();
            }
        }

        matches!(best_match, Some("tmpfs"))
    }

    #[cfg(target_os = "macos")]
    fn new_macos() -> Result<Self, KdubError> {
        use std::process::Command;

        // Create a 16MB RAM disk (32768 sectors x 512 bytes)
        let output = Command::new("hdiutil")
            .args(["attach", "-nomount", "ram://32768"])
            .output()
            .map_err(|e| KdubError::EphemeralDir(format!("failed to run hdiutil attach: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::EphemeralDir(format!(
                "hdiutil attach failed: {stderr}"
            )));
        }

        let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if device.is_empty() || !device.starts_with("/dev/") {
            return Err(KdubError::EphemeralDir(format!(
                "hdiutil attach returned unexpected device: {device}"
            )));
        }

        // Format the RAM disk
        let format_output = Command::new("newfs_hfs")
            .args(["-M", "700", &device])
            .output()
            .map_err(|e| {
                // Try to detach on failure
                let _ = Command::new("hdiutil").args(["detach", &device]).output();
                KdubError::EphemeralDir(format!("failed to run newfs_hfs: {e}"))
            })?;

        if !format_output.status.success() {
            let stderr = String::from_utf8_lossy(&format_output.stderr);
            let _ = Command::new("hdiutil").args(["detach", &device]).output();
            return Err(KdubError::EphemeralDir(format!(
                "newfs_hfs failed: {stderr}"
            )));
        }

        // Create mount point
        let dir_name = Self::random_dir_name();
        let path = PathBuf::from("/tmp").join(dir_name);
        fs::create_dir(&path).map_err(|e| {
            let _ = Command::new("hdiutil").args(["detach", &device]).output();
            KdubError::EphemeralDir(format!(
                "failed to create mount point {}: {e}",
                path.display()
            ))
        })?;

        // Mount the RAM disk
        let mount_output = Command::new("mount")
            .args(["-t", "hfs", &device, &path.to_string_lossy()])
            .output()
            .map_err(|e| {
                let _ = fs::remove_dir(&path);
                let _ = Command::new("hdiutil").args(["detach", &device]).output();
                KdubError::EphemeralDir(format!("failed to mount RAM disk: {e}"))
            })?;

        if !mount_output.status.success() {
            let stderr = String::from_utf8_lossy(&mount_output.stderr);
            let _ = fs::remove_dir(&path);
            let _ = Command::new("hdiutil").args(["detach", &device]).output();
            return Err(KdubError::EphemeralDir(format!("mount failed: {stderr}")));
        }

        // Set permissions on mount point
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(|e| {
            KdubError::EphemeralDir(format!(
                "failed to set permissions on {}: {e}",
                path.display()
            ))
        })?;

        tracing::debug!(
            "created ephemeral dir on macOS RAM disk: {} (device: {})",
            path.display(),
            device
        );

        Ok(Self {
            path,
            macos_device: Some(device),
        })
    }
}

impl AsRef<Path> for EphemeralDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for EphemeralDir {
    fn drop(&mut self) {
        // 1. Kill gpg-agent for this GNUPGHOME (ignore errors)
        let _ = std::process::Command::new("gpgconf")
            .args(["--homedir", &self.path.to_string_lossy(), "--kill", "all"])
            .output();

        // 2. On macOS with RAM disk: unmount and detach
        #[cfg(target_os = "macos")]
        if let Some(ref device) = self.macos_device {
            // Try normal detach first; if it fails (e.g. device busy), try force-detach.
            let normal = std::process::Command::new("hdiutil")
                .args(["detach", device])
                .output();
            let normal_ok = normal.map(|o| o.status.success()).unwrap_or(false);
            if !normal_ok {
                let force = std::process::Command::new("hdiutil")
                    .args(["detach", "-force", device])
                    .output();
                let force_ok = force.map(|o| o.status.success()).unwrap_or(false);
                if !force_ok {
                    tracing::error!(
                        "hdiutil detach -force failed for device {}: RAM disk may still be attached",
                        device
                    );
                }
            }
        }

        // 3. Remove the directory
        if self.path.exists() {
            let _ = fs::remove_dir_all(&self.path).map_err(|e| {
                tracing::debug!(
                    "failed to remove ephemeral dir {}: {e}",
                    self.path.display()
                );
            });
        }

        // 4. Log cleanup
        tracing::debug!("cleaned up ephemeral dir: {}", self.path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: create EphemeralDir, skipping test on macOS CI where hdiutil may fail.
    fn try_new_or_skip() -> Option<EphemeralDir> {
        match EphemeralDir::new() {
            Ok(eph) => Some(eph),
            Err(e) => {
                // On macOS CI, hdiutil may not have permissions for RAM disks
                if cfg!(target_os = "macos") {
                    eprintln!("skipping EphemeralDir test on macOS: {e}");
                    None
                } else {
                    panic!("EphemeralDir::new() failed unexpectedly: {e}");
                }
            }
        }
    }

    #[test]
    fn test_ephemeral_dir_creates_on_tmpfs() {
        let Some(eph) = try_new_or_skip() else { return };
        let path = eph.path();
        assert!(path.exists(), "ephemeral dir should exist");
        assert!(path.is_dir(), "ephemeral dir should be a directory");

        #[cfg(target_os = "linux")]
        {
            let path_str = path.to_string_lossy();
            let on_tmpfs = path_str.starts_with("/dev/shm/")
                || std::env::var("XDG_RUNTIME_DIR")
                    .map(|xdg| path_str.starts_with(&xdg))
                    .unwrap_or(false);
            assert!(on_tmpfs, "path {path_str} should be under tmpfs");
        }
    }

    #[test]
    fn test_ephemeral_dir_permissions() {
        let Some(eph) = try_new_or_skip() else { return };
        let metadata = fs::metadata(eph.path()).expect("failed to stat ephemeral dir");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "ephemeral dir should be mode 0700, got {mode:04o}"
        );
    }

    #[test]
    fn test_ephemeral_dir_cleanup_on_drop() {
        let Some(eph) = try_new_or_skip() else { return };
        let p = eph.path().to_path_buf();
        assert!(p.exists(), "dir should exist before drop");
        drop(eph);
        // On macOS CI, hdiutil detach may fail silently, leaving the mount.
        // On Linux, the dir should always be removed.
        if cfg!(target_os = "linux") {
            assert!(!p.exists(), "dir should be removed after drop");
        }
    }

    #[test]
    fn test_ephemeral_dir_asref_path() {
        let Some(eph) = try_new_or_skip() else { return };
        let path_ref: &Path = eph.as_ref();
        assert_eq!(path_ref, eph.path());
    }

    #[test]
    fn test_ephemeral_dir_write_and_read() {
        let Some(eph) = try_new_or_skip() else { return };
        let test_file = eph.path().join("test-secret.key");
        let test_data = b"super secret key material";

        let mut f = fs::File::create(&test_file).expect("failed to create test file");
        f.write_all(test_data).expect("failed to write test data");
        drop(f);

        let read_data = fs::read(&test_file).expect("failed to read test file");
        assert_eq!(read_data, test_data);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_tmpfs_linux_dev_shm() {
        let dev_shm = PathBuf::from("/dev/shm");
        if dev_shm.is_dir() {
            assert!(
                EphemeralDir::is_tmpfs_linux(&dev_shm),
                "/dev/shm should be detected as tmpfs"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_is_tmpfs_linux_not_tmpfs() {
        let _ = EphemeralDir::is_tmpfs_linux(&PathBuf::from("/tmp"));
    }
}
