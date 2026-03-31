//! Partition, LUKS, and filesystem operations for Tails persistent storage.
//!
//! Provides a trait-based abstraction over system tools (`parted`, `cryptsetup`,
//! `mkfs.ext4`, `mount`/`umount`) and an orchestration function that creates an
//! encrypted persistent volume on a Tails USB drive, populates it with kdub
//! configuration, and cleans up on failure.

use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use tracing::{debug, warn};

use crate::config::{
    DIRMNGR_CONF, GPG_CONF, default_config_toml, generate_gpg_agent_conf, generate_scdaemon_conf,
};
use crate::defaults;
use crate::defaults::{TAILS_LUKS_MAPPER_NAME, TAILS_PARTITION_LABEL, TAILS_PARTITION_TYPE_GUID};
use crate::error::KdubError;
use crate::types::Passphrase;

/// Abstracts system commands for partition/LUKS/filesystem operations.
///
/// Passphrase is `&str` (not `&Passphrase`) because the trait operates at the
/// system boundary where the secret must be piped to stdin. The caller uses
/// `passphrase.expose_secret()` before calling trait methods.
#[cfg_attr(test, mockall::automock)]
pub trait TailsSystemDeps {
    /// Create a GPT partition in free space after the Tails system partition.
    fn create_partition(&self, device: &Path) -> Result<PathBuf, KdubError>;
    /// LUKS2 format a partition. Passphrase piped via stdin, never on command line.
    fn luks_format(&self, partition: &Path, passphrase: &str) -> Result<(), KdubError>;
    /// Open a LUKS container. Returns the mapper device path.
    fn luks_open(
        &self,
        partition: &Path,
        passphrase: &str,
        name: &str,
    ) -> Result<PathBuf, KdubError>;
    /// Close a LUKS container.
    fn luks_close(&self, name: &str) -> Result<(), KdubError>;
    /// Create an ext4 filesystem with a label.
    fn mkfs_ext4(&self, device: &Path, label: &str) -> Result<(), KdubError>;
    /// Mount a filesystem to a target path.
    fn mount(&self, device: &Path, target: &Path) -> Result<(), KdubError>;
    /// Unmount a filesystem.
    fn umount(&self, target: &Path) -> Result<(), KdubError>;
    /// Create the Tails persistence directory layout with correct ownership.
    ///
    /// Sets the mount root to `770 root:root`, writes `persistence.conf`,
    /// and creates all directories with the ownership Tails expects:
    /// root-owned system dirs and uid 1000 (amnesia) user dirs.
    fn setup_persistence_layout(&self, mount_point: &Path) -> Result<(), KdubError>;
    /// Check if a system command exists in PATH.
    fn command_exists(&self, name: &str) -> bool;
}

/// Linux implementation that shells out to system tools.
///
/// Each method invokes the corresponding CLI utility (`parted`, `cryptsetup`,
/// `mkfs.ext4`, `mount`, `umount`) via `sudo` for privilege escalation.
/// Passphrase-bearing commands pipe the secret via stdin to avoid exposing
/// it in the process table. `sudo` prompts for the user's password on the
/// first invocation and caches the credential for subsequent calls.
#[cfg(target_os = "linux")]
pub struct LinuxTailsSystemDeps;

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
fn sudo_mkdir_chown(path: &Path, mode: &str, uid: u32, gid: u32) -> Result<(), KdubError> {
    // sudo mkdir -p
    let mkdir_out = Command::new("sudo")
        .args(["mkdir", "-p"])
        .arg(path)
        .output()
        .map_err(|e| KdubError::TailsPersist(format!("failed to mkdir {}: {e}", path.display())))?;
    if !mkdir_out.status.success() {
        let stderr = String::from_utf8_lossy(&mkdir_out.stderr);
        return Err(KdubError::TailsPersist(format!(
            "mkdir {} failed: {stderr}",
            path.display()
        )));
    }
    // sudo chmod
    let chmod_out = Command::new("sudo")
        .args(["chmod", mode])
        .arg(path)
        .output()
        .map_err(|e| KdubError::TailsPersist(format!("failed to chmod {}: {e}", path.display())))?;
    if !chmod_out.status.success() {
        let stderr = String::from_utf8_lossy(&chmod_out.stderr);
        return Err(KdubError::TailsPersist(format!(
            "chmod {} failed: {stderr}",
            path.display()
        )));
    }
    // sudo chown
    let chown_out = Command::new("sudo")
        .args(["chown", &format!("{uid}:{gid}")])
        .arg(path)
        .output()
        .map_err(|e| KdubError::TailsPersist(format!("failed to chown {}: {e}", path.display())))?;
    if !chown_out.status.success() {
        let stderr = String::from_utf8_lossy(&chown_out.stderr);
        return Err(KdubError::TailsPersist(format!(
            "chown {} failed: {stderr}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl TailsSystemDeps for LinuxTailsSystemDeps {
    fn create_partition(&self, device: &Path) -> Result<PathBuf, KdubError> {
        // Replicate Tails' first-boot partitioning:
        // 1. Randomize disk GUID (Tails checks it was changed from the ISO default)
        // 2. Resize partition 1 to 8 GiB
        // 3. Resize the FAT filesystem inside partition 1 to fill the expanded partition
        // The --fix flag tells parted to repair the GPT backup header automatically.

        // Step 1: Randomize disk GUID.
        // Tails' verify_partition_table checks that the GUID was changed from
        // the ISO's hardcoded value 17B81DA0-8B1E-4269-9C39-FE5C7B9B58A3.
        debug!(?device, "randomizing disk GUID");
        let guid_output = Command::new("sudo")
            .args(["sgdisk", "--randomize-guids"])
            .arg(device)
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to randomize disk GUID: {e}")))?;
        if !guid_output.status.success() {
            let stderr = String::from_utf8_lossy(&guid_output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "sgdisk --randomize-guids failed: {stderr}"
            )));
        }

        // Step 2: Resize partition 1 to 8 GiB.
        debug!(
            ?device,
            "resizing partition 1 to {}",
            defaults::TAILS_PARTITION1_SIZE
        );
        let resize_output = Command::new("sudo")
            .args(["parted", "--fix", "--script"])
            .arg(device)
            .args(["resizepart", "1", defaults::TAILS_PARTITION1_SIZE])
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to resize partition 1: {e}")))?;
        if !resize_output.status.success() {
            let stderr = String::from_utf8_lossy(&resize_output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "parted resizepart 1 failed: {stderr}"
            )));
        }
        debug!("partition 1 resized");

        // Step 3: Resize the FAT filesystem inside partition 1 to fill the
        // expanded partition. Tails' verify_partition_table checks that the
        // FAT filesystem was resized, not just the partition boundary.
        let device_str = device.to_string_lossy();
        let part1_path = if device_str.ends_with(|c: char| c.is_ascii_digit()) {
            format!("{device_str}p1")
        } else {
            format!("{device_str}1")
        };
        debug!(part1 = %part1_path, "resizing FAT filesystem");
        let fatresize_output = Command::new("sudo")
            .args(["fatresize", "-f", "-s", "8Gi"])
            .arg(&part1_path)
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to run fatresize: {e}")))?;
        if !fatresize_output.status.success() {
            let stderr = String::from_utf8_lossy(&fatresize_output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "fatresize failed: {stderr}"
            )));
        }
        debug!("FAT filesystem resized");

        // Read current partition table to find where to start.
        debug!(?device, "reading partition table");
        let print_output = Command::new("sudo")
            .args(["parted", "--fix", "--script", "--machine"])
            .arg(device)
            .arg("print")
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to run parted print: {e}")))?;

        if !print_output.status.success() {
            let stderr = String::from_utf8_lossy(&print_output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "parted print failed: {stderr}"
            )));
        }

        // Parse the last partition's end position from machine-readable output.
        // Machine format lines look like: "1:32.3kB:4295MB:4295MB:fat32:Tails:;"
        let stdout = String::from_utf8_lossy(&print_output.stdout);
        let start = stdout
            .lines()
            .rfind(|line| line.starts_with(|c: char| c.is_ascii_digit()) && line.contains(':'))
            .and_then(|line| line.split(':').nth(2))
            .ok_or_else(|| {
                KdubError::TailsPersist(
                    "could not determine partition end from parted output".to_string(),
                )
            })?
            .to_string();

        debug!(?start, "creating partition after existing partitions");

        // Create the partition in the free space.
        let mkpart_output = Command::new("sudo")
            .args(["parted", "--fix", "--script"])
            .arg(device)
            .args(["mkpart", TAILS_PARTITION_LABEL, "ext4", &start, "100%"])
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to run parted mkpart: {e}")))?;

        if !mkpart_output.status.success() {
            let stderr = String::from_utf8_lossy(&mkpart_output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "parted mkpart failed: {stderr}"
            )));
        }

        // Re-query partition table to find the newly created partition number.
        debug!("re-reading partition table after mkpart");
        let reprint_output = Command::new("sudo")
            .args(["parted", "--fix", "--script", "--machine"])
            .arg(device)
            .arg("print")
            .output()
            .map_err(|e| {
                KdubError::TailsPersist(format!("failed to re-read partition table: {e}"))
            })?;

        if !reprint_output.status.success() {
            let stderr = String::from_utf8_lossy(&reprint_output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "parted print failed after mkpart: {stderr}"
            )));
        }

        // Machine format: "NUMBER:START:END:SIZE:FSTYPE:NAME:FLAGS;"
        // The last partition line (highest number) is our newly created partition.
        let reprint_stdout = String::from_utf8_lossy(&reprint_output.stdout);
        let part_number = reprint_stdout
            .lines()
            .rfind(|line| line.starts_with(|c: char| c.is_ascii_digit()) && line.contains(':'))
            .and_then(|line| line.split(':').next())
            .ok_or_else(|| {
                KdubError::TailsPersist(
                    "could not determine new partition number from parted output".to_string(),
                )
            })?
            .to_string();

        // Set the partition type GUID with sgdisk.
        debug!(part_number, "setting partition type GUID");
        let sgdisk_output = Command::new("sudo")
            .arg("sgdisk")
            .arg("-t")
            .arg(format!("{part_number}:{TAILS_PARTITION_TYPE_GUID}"))
            .arg(device)
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to run sgdisk: {e}")))?;

        if !sgdisk_output.status.success() {
            let stderr = String::from_utf8_lossy(&sgdisk_output.stderr);
            return Err(KdubError::TailsPersist(format!("sgdisk failed: {stderr}")));
        }

        // Build the partition device path.
        let device_str = device.to_string_lossy();
        let partition_path = if device_str.ends_with(|c: char| c.is_ascii_digit()) {
            PathBuf::from(format!("{device_str}p{part_number}"))
        } else {
            PathBuf::from(format!("{device_str}{part_number}"))
        };

        debug!(?partition_path, "partition created");
        Ok(partition_path)
    }

    fn luks_format(&self, partition: &Path, passphrase: &str) -> Result<(), KdubError> {
        debug!(?partition, "formatting partition with LUKS2");
        let mut child = Command::new("sudo")
            .arg("cryptsetup")
            .args([
                "luksFormat",
                "--batch-mode",
                "--type=luks2",
                "--pbkdf=argon2id",
                "--key-file=-",
            ])
            .arg(partition)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                KdubError::TailsPersist(format!("failed to spawn cryptsetup luksFormat: {e}"))
            })?;

        {
            let stdin = child.stdin.as_mut().expect("stdin was configured as piped");
            stdin.write_all(passphrase.as_bytes()).map_err(|e| {
                KdubError::TailsPersist(format!("failed to write passphrase to cryptsetup: {e}"))
            })?;
        } // drop the &mut borrow; the owned ChildStdin remains in child.stdin until wait_with_output closes it

        let output = child.wait_with_output().map_err(|e| {
            KdubError::TailsPersist(format!("cryptsetup luksFormat wait failed: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "cryptsetup luksFormat failed: {stderr}"
            )));
        }

        debug!("LUKS format complete");
        Ok(())
    }

    fn luks_open(
        &self,
        partition: &Path,
        passphrase: &str,
        name: &str,
    ) -> Result<PathBuf, KdubError> {
        debug!(?partition, name, "opening LUKS container");
        let mut child = Command::new("sudo")
            .arg("cryptsetup")
            .args(["luksOpen", "--key-file=-"])
            .arg(partition)
            .arg(name)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                KdubError::TailsPersist(format!("failed to spawn cryptsetup luksOpen: {e}"))
            })?;

        {
            let stdin = child.stdin.as_mut().expect("stdin was configured as piped");
            stdin.write_all(passphrase.as_bytes()).map_err(|e| {
                KdubError::TailsPersist(format!("failed to write passphrase to cryptsetup: {e}"))
            })?;
        } // drop the &mut borrow; the owned ChildStdin remains in child.stdin until wait_with_output closes it

        let output = child.wait_with_output().map_err(|e| {
            KdubError::TailsPersist(format!("cryptsetup luksOpen wait failed: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "cryptsetup luksOpen failed: {stderr}"
            )));
        }

        let mapper_path = PathBuf::from(format!("/dev/mapper/{name}"));
        debug!(?mapper_path, "LUKS container opened");
        Ok(mapper_path)
    }

    fn luks_close(&self, name: &str) -> Result<(), KdubError> {
        debug!(name, "closing LUKS container");
        let output = Command::new("sudo")
            .args(["cryptsetup", "luksClose", name])
            .output()
            .map_err(|e| {
                KdubError::TailsPersist(format!("failed to run cryptsetup luksClose: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "cryptsetup luksClose failed: {stderr}"
            )));
        }

        debug!("LUKS container closed");
        Ok(())
    }

    fn mkfs_ext4(&self, device: &Path, label: &str) -> Result<(), KdubError> {
        debug!(?device, label, "creating ext4 filesystem");
        let output = Command::new("sudo")
            .arg("mkfs.ext4")
            .args(["-L", label])
            .arg(device)
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to run mkfs.ext4: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::TailsPersist(format!(
                "mkfs.ext4 failed: {stderr}"
            )));
        }

        debug!("ext4 filesystem created");
        Ok(())
    }

    fn mount(&self, device: &Path, target: &Path) -> Result<(), KdubError> {
        debug!(?device, ?target, "mounting filesystem");
        let output = Command::new("sudo")
            .arg("mount")
            .arg(device)
            .arg(target)
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to run mount: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::TailsPersist(format!("mount failed: {stderr}")));
        }

        debug!("filesystem mounted");
        Ok(())
    }

    fn umount(&self, target: &Path) -> Result<(), KdubError> {
        debug!(?target, "unmounting filesystem");
        let output = Command::new("sudo")
            .arg("umount")
            .arg(target)
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to run umount: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::TailsPersist(format!("umount failed: {stderr}")));
        }

        debug!("filesystem unmounted");
        Ok(())
    }

    fn setup_persistence_layout(&self, mount_point: &Path) -> Result<(), KdubError> {
        debug!(?mount_point, "setting up persistence directory layout");

        // Fix mount root ownership (mkfs creates as root, but mode may differ)
        // Temporarily set mount root to 777 so populate_persistence (running as
        // the current user) can write into subdirectories. The orchestrator
        // tightens this to 770 root:root after population completes.
        let chmod_out = Command::new("sudo")
            .args(["chmod", "777"])
            .arg(mount_point)
            .output()
            .map_err(|e| KdubError::TailsPersist(format!("failed to chmod mount root: {e}")))?;
        if !chmod_out.status.success() {
            let stderr = String::from_utf8_lossy(&chmod_out.stderr);
            return Err(KdubError::TailsPersist(format!(
                "chmod mount root failed: {stderr}"
            )));
        }

        // Write persistence.conf as root via sudo tee
        let conf_content = crate::tails::generate_persistence_conf();
        let conf_path = mount_point.join("persistence.conf");
        let mut child = Command::new("sudo")
            .args(["tee"])
            .arg(&conf_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                KdubError::TailsPersist(format!("failed to write persistence.conf: {e}"))
            })?;
        {
            let stdin = child.stdin.as_mut().expect("stdin was configured as piped");
            stdin.write_all(conf_content.as_bytes()).map_err(|e| {
                KdubError::TailsPersist(format!("failed to write persistence.conf content: {e}"))
            })?;
        }
        let tee_out = child
            .wait_with_output()
            .map_err(|e| KdubError::TailsPersist(format!("tee wait failed: {e}")))?;
        if !tee_out.status.success() {
            let stderr = String::from_utf8_lossy(&tee_out.stderr);
            return Err(KdubError::TailsPersist(format!(
                "tee persistence.conf failed: {stderr}"
            )));
        }
        // Set permissions and ownership on persistence.conf.
        // Tails' tpsd checks that persistence.conf is owned by the
        // tails-persistence-setup user (uid 115, gid 122). Features
        // are only shown as active when this ownership matches.
        let _ = Command::new("sudo")
            .args(["chmod", "600"])
            .arg(&conf_path)
            .output();
        let _ = Command::new("sudo")
            .args(["chown", "115:122"])
            .arg(&conf_path)
            .output();

        // Only create directories for features in persistence.conf.
        // Other features (cups, NetworkManager, apt, greeter-settings, tca)
        // are left for the user to enable via the Tails Persistent Storage UI,
        // which creates the directories with the correct Tails-internal content.
        sudo_mkdir_chown(&mount_point.join("Persistent"), "700", 1000, 1000)?;
        sudo_mkdir_chown(&mount_point.join("gnupg"), "700", 1000, 1000)?;
        sudo_mkdir_chown(&mount_point.join("dotfiles"), "700", 1000, 1000)?;

        debug!("persistence directory layout created");
        Ok(())
    }

    fn command_exists(&self, name: &str) -> bool {
        Command::new("which")
            .arg(name)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// Options for creating persistent storage.
///
/// Bundles all user-provided inputs needed to create an encrypted Tails
/// persistent volume: target device, LUKS passphrase, pre-seeding toggle,
/// and the path to the kdub binary to install.
pub struct PersistOptions {
    /// Target USB device path.
    pub device: PathBuf,
    /// LUKS encryption passphrase.
    pub passphrase: Passphrase,
    /// Skip kdub config pre-seeding.
    pub skip_preseed: bool,
    /// Path to the kdub binary to copy into persistence.
    pub kdub_binary_path: PathBuf,
    /// Suppress user-facing status messages.
    pub quiet: bool,
}

/// Create encrypted persistent storage on a Tails USB.
///
/// Linux only. Requires root for partition and LUKS operations.
///
/// Orchestrates the full lifecycle: partition creation, LUKS formatting,
/// filesystem creation, mounting, populating the volume with kdub files,
/// and cleanup. If population fails, LUKS is still closed to avoid leaving
/// an open encrypted volume.
pub fn create_persistent_storage(
    deps: &dyn TailsSystemDeps,
    opts: &PersistOptions,
) -> Result<(), KdubError> {
    // Platform gate
    if cfg!(not(target_os = "linux")) {
        return Err(KdubError::TailsUnsupported(
            "persistent storage creation requires Linux".to_string(),
        ));
    }

    // Check required tools
    check_required_tools(deps)?;

    // Create partition
    if !opts.quiet {
        eprintln!("Creating partition...");
    }
    debug!(?opts.device, "creating partition");
    let partition = deps.create_partition(&opts.device)?;

    // LUKS format (includes argon2id KDF benchmarking — may take several seconds)
    if !opts.quiet {
        eprintln!("Encrypting partition (benchmarking KDF, this may take a moment)...");
    }
    debug!(?partition, "formatting LUKS");
    deps.luks_format(&partition, opts.passphrase.expose_secret())?;

    // LUKS open
    if !opts.quiet {
        eprintln!("Opening encrypted volume...");
    }
    debug!(?partition, "opening LUKS container");
    let mapper_device = deps.luks_open(
        &partition,
        opts.passphrase.expose_secret(),
        TAILS_LUKS_MAPPER_NAME,
    )?;

    // From here on, we must close LUKS even if subsequent steps fail.
    let result = create_and_populate(
        deps,
        &mapper_device,
        &opts.kdub_binary_path,
        opts.skip_preseed,
        opts.quiet,
    );

    // Cleanup: always attempt to close LUKS
    if let Err(close_err) = deps.luks_close(TAILS_LUKS_MAPPER_NAME) {
        warn!(
            ?close_err,
            "failed to close LUKS during cleanup; encrypted volume may remain unlocked"
        );
        // If the main operation succeeded but close failed, report close error.
        // If both failed, report the original error.
        if result.is_ok() {
            return Err(close_err);
        }
    }

    result
}

/// Inner helper: create filesystem, mount, populate, unmount.
///
/// Separated from the main orchestration so that LUKS cleanup can run
/// regardless of whether this function succeeds.
fn create_and_populate(
    deps: &dyn TailsSystemDeps,
    mapper_device: &Path,
    kdub_binary_path: &Path,
    skip_preseed: bool,
    quiet: bool,
) -> Result<(), KdubError> {
    // Create ext4 filesystem
    if !quiet {
        eprintln!("Creating filesystem...");
    }
    debug!(?mapper_device, "creating ext4 filesystem");
    deps.mkfs_ext4(mapper_device, TAILS_PARTITION_LABEL)?;

    // Mount to temp dir
    let mount_dir = tempfile::tempdir()
        .map_err(|e| KdubError::TailsPersist(format!("failed to create temp mount point: {e}")))?;
    let mount_point = mount_dir.path().to_path_buf();

    debug!(?mount_point, "mounting filesystem");
    deps.mount(mapper_device, &mount_point)?;

    // Create Tails-native directory layout with correct ownership
    if !quiet {
        eprintln!("Setting up persistence directory layout...");
    }
    deps.setup_persistence_layout(&mount_point)?;

    // Populate, then always unmount
    if !quiet {
        eprintln!("Writing configuration and kdub binary...");
    }
    let populate_result = populate_persistence(&mount_point, kdub_binary_path, skip_preseed);

    // Tighten mount root permissions to 770 root:root (matching Tails-native).
    // This runs regardless of populate success — best-effort before umount.
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("sudo")
            .args(["chmod", "770"])
            .arg(&mount_point)
            .output();
        let _ = Command::new("sudo")
            .args(["chown", "root:root"])
            .arg(&mount_point)
            .output();
    }

    debug!(?mount_point, "unmounting filesystem");
    let umount_result = deps.umount(&mount_point);

    // Return populate error first, then umount error
    populate_result?;
    umount_result
}

/// Check that required system tools are available.
///
/// Verifies that `parted`, `cryptsetup`, `mkfs.ext4`, and `sgdisk` exist in PATH.
/// Returns a helpful error listing any missing tools with install instructions.
fn check_required_tools(deps: &dyn TailsSystemDeps) -> Result<(), KdubError> {
    let required = ["parted", "cryptsetup", "mkfs.ext4", "sgdisk", "fatresize"];
    let missing: Vec<_> = required
        .iter()
        .filter(|t| !deps.command_exists(t))
        .collect();
    if !missing.is_empty() {
        return Err(KdubError::TailsPersist(format!(
            "missing required tools: {}. Install with: sudo apt install parted cryptsetup e2fsprogs gdisk fatresize",
            missing
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    Ok(())
}

/// Populate the mounted persistence volume with kdub files.
///
/// Copies the kdub binary and optionally pre-seeds GPG and kdub configuration
/// files for the Tails platform. Directory layout and `persistence.conf` are
/// created by `setup_persistence_layout` before this function runs.
fn populate_persistence(
    mount_point: &Path,
    kdub_binary: &Path,
    skip_preseed: bool,
) -> Result<(), KdubError> {
    debug!(?mount_point, "populating persistence volume");

    // Create subdirectories under dotfiles (parent dotfiles/ created by setup_persistence_layout)
    let dotfiles_bin_dir = mount_point.join("dotfiles/.local/bin");
    let dotfiles_config_dir = mount_point.join("dotfiles/.config/kdub");

    create_dir_mode(&dotfiles_bin_dir, 0o700)?;
    create_dir_mode(&dotfiles_config_dir, 0o700)?;

    // Copy kdub binary
    let kdub_dest = dotfiles_bin_dir.join("kdub");
    fs::copy(kdub_binary, &kdub_dest).map_err(|e| {
        KdubError::TailsPersist(format!(
            "failed to copy kdub binary from {} to {}: {e}",
            kdub_binary.display(),
            kdub_dest.display()
        ))
    })?;
    fs::set_permissions(&kdub_dest, Permissions::from_mode(0o700))?;
    debug!(?kdub_dest, "copied kdub binary");

    // Pre-seed configuration files unless skipped
    if !skip_preseed {
        debug!("pre-seeding configuration files");

        // GPG configs in gnupg directory (created by setup_persistence_layout)
        let gnupg_dir = mount_point.join("gnupg");
        write_file_mode(&gnupg_dir.join("gpg.conf"), GPG_CONF, 0o600)?;

        let gpg_agent_content = generate_gpg_agent_conf("tails");
        write_file_mode(&gnupg_dir.join("gpg-agent.conf"), &gpg_agent_content, 0o600)?;

        let scdaemon_content = generate_scdaemon_conf("tails");
        write_file_mode(&gnupg_dir.join("scdaemon.conf"), &scdaemon_content, 0o600)?;

        write_file_mode(&gnupg_dir.join("dirmngr.conf"), DIRMNGR_CONF, 0o600)?;

        // kdub config.toml
        let config_toml = default_config_toml();
        write_file_mode(
            &dotfiles_config_dir.join("config.toml"),
            &config_toml,
            0o600,
        )?;

        debug!("configuration pre-seeding complete");
    }

    debug!("persistence volume populated");
    Ok(())
}

/// Create a directory (and parents) with the specified Unix mode.
fn create_dir_mode(path: &Path, mode: u32) -> Result<(), KdubError> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(())
}

/// Write a file and set its Unix permissions.
fn write_file_mode(path: &Path, content: &str, mode: u32) -> Result<(), KdubError> {
    fs::write(path, content)?;
    fs::set_permissions(path, Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use mockall::predicate;

    use super::*;

    // --- check_required_tools tests ---

    #[test]
    fn test_check_required_tools_all_present() {
        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists()
            .with(predicate::eq("parted"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("cryptsetup"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("mkfs.ext4"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("sgdisk"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("fatresize"))
            .returning(|_| true);

        let result = check_required_tools(&mock);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_required_tools_missing() {
        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists()
            .with(predicate::eq("parted"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("cryptsetup"))
            .returning(|_| false);
        mock.expect_command_exists()
            .with(predicate::eq("mkfs.ext4"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("sgdisk"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("fatresize"))
            .returning(|_| true);

        let result = check_required_tools(&mock);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cryptsetup"),
            "error should mention missing tool: {err}"
        );
        assert!(
            err.contains("sudo apt install"),
            "error should include install instructions: {err}"
        );
        assert!(
            err.contains("gdisk"),
            "error should mention gdisk package: {err}"
        );
    }

    // --- platform gate test ---

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_platform_gate_non_linux() {
        let mock = MockTailsSystemDeps::new();
        let opts = PersistOptions {
            device: PathBuf::from("/dev/sdb"),
            passphrase: "testpassphrase".parse().unwrap(),
            skip_preseed: false,
            kdub_binary_path: PathBuf::from("/usr/bin/kdub"),
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, KdubError::TailsUnsupported(_)));
    }

    // --- populate_persistence tests ---

    #[test]
    fn test_populate_persistence_creates_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let mount_point = tmp.path();

        // Pre-create directories that setup_persistence_layout would have created
        fs::create_dir_all(mount_point.join("gnupg")).unwrap();
        fs::create_dir_all(mount_point.join("dotfiles")).unwrap();

        // Create a fake binary to copy
        let binary_dir = tempfile::tempdir().unwrap();
        let binary_path = binary_dir.path().join("kdub");
        fs::write(&binary_path, b"#!/bin/sh\necho fake").unwrap();

        let result = populate_persistence(mount_point, &binary_path, false);
        assert!(result.is_ok(), "populate failed: {result:?}");

        // Verify directory structure created by populate_persistence
        assert!(mount_point.join("dotfiles/.local/bin").is_dir());
        assert!(mount_point.join("dotfiles/.config/kdub").is_dir());
    }

    #[test]
    fn test_populate_persistence_copies_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let mount_point = tmp.path();

        // Pre-create directories that setup_persistence_layout would have created
        fs::create_dir_all(mount_point.join("gnupg")).unwrap();
        fs::create_dir_all(mount_point.join("dotfiles")).unwrap();

        let binary_dir = tempfile::tempdir().unwrap();
        let binary_path = binary_dir.path().join("kdub");
        let binary_content = b"ELF-fake-binary-content";
        fs::write(&binary_path, binary_content).unwrap();

        populate_persistence(mount_point, &binary_path, false).unwrap();

        let dest = mount_point.join("dotfiles/.local/bin/kdub");
        assert!(dest.exists(), "kdub binary should be copied");
        let copied = fs::read(&dest).unwrap();
        assert_eq!(copied, binary_content, "binary content should match");

        // Verify binary is executable (0o700)
        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "binary should be executable: {mode:o}");
    }

    #[test]
    fn test_populate_persistence_skip_preseed() {
        let tmp = tempfile::tempdir().unwrap();
        let mount_point = tmp.path();

        // Pre-create directories that setup_persistence_layout would have created
        fs::create_dir_all(mount_point.join("gnupg")).unwrap();
        fs::create_dir_all(mount_point.join("dotfiles")).unwrap();

        let binary_dir = tempfile::tempdir().unwrap();
        let binary_path = binary_dir.path().join("kdub");
        fs::write(&binary_path, b"fake-binary").unwrap();

        populate_persistence(mount_point, &binary_path, true).unwrap();

        // Binary should still exist
        assert!(mount_point.join("dotfiles/.local/bin/kdub").exists());

        // Config files should NOT be written when skip_preseed is true
        assert!(
            !mount_point.join("gnupg/gpg.conf").exists(),
            "gpg.conf should not exist with skip_preseed"
        );
        assert!(
            !mount_point.join("gnupg/gpg-agent.conf").exists(),
            "gpg-agent.conf should not exist with skip_preseed"
        );
        assert!(
            !mount_point.join("gnupg/scdaemon.conf").exists(),
            "scdaemon.conf should not exist with skip_preseed"
        );
        assert!(
            !mount_point.join("gnupg/dirmngr.conf").exists(),
            "dirmngr.conf should not exist with skip_preseed"
        );
        assert!(
            !mount_point
                .join("dotfiles/.config/kdub/config.toml")
                .exists(),
            "config.toml should not exist with skip_preseed"
        );
    }

    #[test]
    fn test_populate_persistence_preseed_writes_configs() {
        let tmp = tempfile::tempdir().unwrap();
        let mount_point = tmp.path();

        // Pre-create directories that setup_persistence_layout would have created
        fs::create_dir_all(mount_point.join("gnupg")).unwrap();
        fs::create_dir_all(mount_point.join("dotfiles")).unwrap();

        let binary_dir = tempfile::tempdir().unwrap();
        let binary_path = binary_dir.path().join("kdub");
        fs::write(&binary_path, b"fake-binary").unwrap();

        populate_persistence(mount_point, &binary_path, false).unwrap();

        // GPG configs should exist in gnupg/
        let gpg_conf = fs::read_to_string(mount_point.join("gnupg/gpg.conf")).unwrap();
        assert!(gpg_conf.contains("cert-digest-algo SHA512"));

        let gpg_agent_conf = fs::read_to_string(mount_point.join("gnupg/gpg-agent.conf")).unwrap();
        assert!(gpg_agent_conf.contains("pinentry-program /usr/bin/pinentry-gnome3"));

        let scdaemon_conf = fs::read_to_string(mount_point.join("gnupg/scdaemon.conf")).unwrap();
        assert!(scdaemon_conf.contains("disable-ccid"));

        let dirmngr_conf = fs::read_to_string(mount_point.join("gnupg/dirmngr.conf")).unwrap();
        assert!(dirmngr_conf.contains("keyserver"));

        // kdub config.toml
        let config_toml =
            fs::read_to_string(mount_point.join("dotfiles/.config/kdub/config.toml")).unwrap();
        assert!(config_toml.contains("[key]"));
    }

    #[test]
    fn test_populate_persistence_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let mount_point = tmp.path();

        // Pre-create directories that setup_persistence_layout would have created
        fs::create_dir_all(mount_point.join("gnupg")).unwrap();
        fs::create_dir_all(mount_point.join("dotfiles")).unwrap();

        let binary_dir = tempfile::tempdir().unwrap();
        let binary_path = binary_dir.path().join("kdub");
        fs::write(&binary_path, b"fake-binary").unwrap();

        populate_persistence(mount_point, &binary_path, false).unwrap();

        let check_dir_mode = |path: &Path, expected: u32| {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                expected,
                "wrong mode for {}: {:o} != {:o}",
                path.display(),
                mode,
                expected
            );
        };

        let check_file_mode = |path: &Path, expected: u32| {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                expected,
                "wrong mode for {}: {:o} != {:o}",
                path.display(),
                mode,
                expected
            );
        };

        // Directories created by populate_persistence should be 0o700
        check_dir_mode(&mount_point.join("dotfiles/.local/bin"), 0o700);
        check_dir_mode(&mount_point.join("dotfiles/.config/kdub"), 0o700);

        // Files should be 0o600 (except binary which is 0o700)
        check_file_mode(&mount_point.join("gnupg/gpg.conf"), 0o600);
        check_file_mode(&mount_point.join("gnupg/gpg-agent.conf"), 0o600);
        check_file_mode(
            &mount_point.join("dotfiles/.config/kdub/config.toml"),
            0o600,
        );
    }

    // --- Full flow orchestration tests ---

    #[test]
    #[cfg(target_os = "linux")]
    fn test_create_persistent_storage_full_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        fs::write(&binary_path, b"fake-binary").unwrap();

        let device = PathBuf::from("/dev/sdb");
        let partition = PathBuf::from("/dev/sdb2");
        let mapper_device = PathBuf::from(format!("/dev/mapper/{TAILS_LUKS_MAPPER_NAME}"));

        let mut mock = MockTailsSystemDeps::new();

        // All tools present
        mock.expect_command_exists().returning(|_| true);

        // create_partition
        let partition_clone = partition.clone();
        mock.expect_create_partition()
            .with(predicate::eq(device.clone()))
            .times(1)
            .returning(move |_| Ok(partition_clone.clone()));

        // luks_format
        mock.expect_luks_format()
            .with(predicate::eq(partition.clone()), predicate::always())
            .times(1)
            .returning(|_, _| Ok(()));

        // luks_open
        let mapper_clone = mapper_device.clone();
        mock.expect_luks_open()
            .with(
                predicate::eq(partition.clone()),
                predicate::always(),
                predicate::eq(TAILS_LUKS_MAPPER_NAME),
            )
            .times(1)
            .returning(move |_, _, _| Ok(mapper_clone.clone()));

        // mkfs_ext4
        mock.expect_mkfs_ext4()
            .with(
                predicate::eq(mapper_device.clone()),
                predicate::eq(TAILS_PARTITION_LABEL),
            )
            .times(1)
            .returning(|_, _| Ok(()));

        // mount — just succeed
        mock.expect_mount().times(1).returning(|_, _| Ok(()));

        // setup_persistence_layout — create dirs that populate needs
        mock.expect_setup_persistence_layout()
            .times(1)
            .returning(|mount_point| {
                fs::create_dir_all(mount_point.join("gnupg")).unwrap();
                fs::create_dir_all(mount_point.join("dotfiles")).unwrap();
                Ok(())
            });

        // umount — just succeed
        mock.expect_umount().times(1).returning(|_| Ok(()));

        // luks_close
        mock.expect_luks_close()
            .with(predicate::eq(TAILS_LUKS_MAPPER_NAME))
            .times(1)
            .returning(|_| Ok(()));

        let opts = PersistOptions {
            device,
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: true,
            kdub_binary_path: binary_path,
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_ok(), "full flow failed: {result:?}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_create_persistent_storage_cleanup_on_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        // Do NOT create the binary file — populate will fail when trying to copy it.

        let device = PathBuf::from("/dev/sdb");
        let partition = PathBuf::from("/dev/sdb2");
        let mapper_device = PathBuf::from(format!("/dev/mapper/{TAILS_LUKS_MAPPER_NAME}"));

        let mut mock = MockTailsSystemDeps::new();

        // All tools present
        mock.expect_command_exists().returning(|_| true);

        // create_partition succeeds
        let partition_clone = partition.clone();
        mock.expect_create_partition()
            .returning(move |_| Ok(partition_clone.clone()));

        // luks_format succeeds
        mock.expect_luks_format().returning(|_, _| Ok(()));

        // luks_open succeeds
        let mapper_clone = mapper_device.clone();
        mock.expect_luks_open()
            .returning(move |_, _, _| Ok(mapper_clone.clone()));

        // mkfs_ext4 succeeds
        mock.expect_mkfs_ext4().returning(|_, _| Ok(()));

        // mount succeeds
        mock.expect_mount().returning(|_, _| Ok(()));

        // setup_persistence_layout succeeds (creates dirs that populate needs)
        mock.expect_setup_persistence_layout()
            .times(1)
            .returning(|mount_point| {
                // Create dirs that populate_persistence expects
                fs::create_dir_all(mount_point.join("gnupg")).unwrap();
                fs::create_dir_all(mount_point.join("dotfiles")).unwrap();
                Ok(())
            });

        // umount should still be called during cleanup
        mock.expect_umount().times(1).returning(|_| Ok(()));

        // luks_close MUST be called even though populate will fail
        mock.expect_luks_close()
            .with(predicate::eq(TAILS_LUKS_MAPPER_NAME))
            .times(1)
            .returning(|_| Ok(()));

        let opts = PersistOptions {
            device,
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: false,
            kdub_binary_path: binary_path, // does not exist — will cause populate to fail
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err(), "should fail because binary doesn't exist");
        // The important assertion is that luks_close was called (times(1) above).
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_create_persistent_storage_missing_tools() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        fs::write(&binary_path, b"fake").unwrap();

        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists()
            .with(predicate::eq("parted"))
            .returning(|_| false);
        mock.expect_command_exists()
            .with(predicate::eq("cryptsetup"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("mkfs.ext4"))
            .returning(|_| false);
        mock.expect_command_exists()
            .with(predicate::eq("sgdisk"))
            .returning(|_| true);
        mock.expect_command_exists()
            .with(predicate::eq("fatresize"))
            .returning(|_| true);

        let opts = PersistOptions {
            device: PathBuf::from("/dev/sdb"),
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: false,
            kdub_binary_path: binary_path,
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parted"), "error should mention parted: {err}");
        assert!(
            err.contains("mkfs.ext4"),
            "error should mention mkfs.ext4: {err}"
        );
    }

    // --- Individual failure stage tests ---

    #[test]
    #[cfg(target_os = "linux")]
    fn test_partition_creation_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        fs::write(&binary_path, b"fake").unwrap();

        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists().returning(|_| true);
        mock.expect_create_partition()
            .returning(|_| Err(KdubError::TailsPersist("partition failed".into())));
        // luks_format, luks_open, mkfs_ext4, mount, umount, luks_close should NOT be called.

        let opts = PersistOptions {
            device: PathBuf::from("/dev/sdb"),
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: true,
            kdub_binary_path: binary_path,
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("partition failed"),
            "error should propagate partition failure: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_luks_format_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        fs::write(&binary_path, b"fake").unwrap();

        let partition = PathBuf::from("/dev/sdb2");

        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists().returning(|_| true);

        let partition_clone = partition.clone();
        mock.expect_create_partition()
            .returning(move |_| Ok(partition_clone.clone()));

        mock.expect_luks_format()
            .returning(|_, _| Err(KdubError::TailsPersist("luks format failed".into())));
        // luks_open, mkfs_ext4, mount, umount, luks_close should NOT be called.

        let opts = PersistOptions {
            device: PathBuf::from("/dev/sdb"),
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: true,
            kdub_binary_path: binary_path,
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("luks format failed"),
            "error should propagate luks format failure: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_mkfs_failure_still_closes_luks() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        fs::write(&binary_path, b"fake").unwrap();

        let partition = PathBuf::from("/dev/sdb2");
        let mapper_device = PathBuf::from(format!("/dev/mapper/{TAILS_LUKS_MAPPER_NAME}"));

        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists().returning(|_| true);

        let partition_clone = partition.clone();
        mock.expect_create_partition()
            .returning(move |_| Ok(partition_clone.clone()));

        mock.expect_luks_format().returning(|_, _| Ok(()));

        let mapper_clone = mapper_device.clone();
        mock.expect_luks_open()
            .returning(move |_, _, _| Ok(mapper_clone.clone()));

        mock.expect_mkfs_ext4()
            .returning(|_, _| Err(KdubError::TailsPersist("mkfs failed".into())));

        // luks_close MUST be called for cleanup even though mkfs failed.
        mock.expect_luks_close()
            .with(predicate::eq(TAILS_LUKS_MAPPER_NAME))
            .times(1)
            .returning(|_| Ok(()));

        let opts = PersistOptions {
            device: PathBuf::from("/dev/sdb"),
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: true,
            kdub_binary_path: binary_path,
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("mkfs failed"),
            "error should propagate mkfs failure: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_mount_failure_still_closes_luks() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        fs::write(&binary_path, b"fake").unwrap();

        let partition = PathBuf::from("/dev/sdb2");
        let mapper_device = PathBuf::from(format!("/dev/mapper/{TAILS_LUKS_MAPPER_NAME}"));

        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists().returning(|_| true);

        let partition_clone = partition.clone();
        mock.expect_create_partition()
            .returning(move |_| Ok(partition_clone.clone()));

        mock.expect_luks_format().returning(|_, _| Ok(()));

        let mapper_clone = mapper_device.clone();
        mock.expect_luks_open()
            .returning(move |_, _, _| Ok(mapper_clone.clone()));

        mock.expect_mkfs_ext4().returning(|_, _| Ok(()));

        mock.expect_mount()
            .returning(|_, _| Err(KdubError::TailsPersist("mount failed".into())));

        // umount should NOT be called since mount failed, but the inner
        // create_and_populate calls mount then umount in sequence. Since
        // mount returns an error, umount won't run, but it needs to be
        // set up in case the flow differs.

        // luks_close MUST be called for cleanup.
        mock.expect_luks_close()
            .with(predicate::eq(TAILS_LUKS_MAPPER_NAME))
            .times(1)
            .returning(|_| Ok(()));

        let opts = PersistOptions {
            device: PathBuf::from("/dev/sdb"),
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: true,
            kdub_binary_path: binary_path,
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("mount failed"),
            "error should propagate mount failure: {err}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_setup_layout_failure_still_closes_luks() {
        let tmp = tempfile::tempdir().unwrap();
        let binary_path = tmp.path().join("kdub");
        fs::write(&binary_path, b"fake").unwrap();

        let partition = PathBuf::from("/dev/sdb2");
        let mapper_device = PathBuf::from(format!("/dev/mapper/{TAILS_LUKS_MAPPER_NAME}"));

        let mut mock = MockTailsSystemDeps::new();
        mock.expect_command_exists().returning(|_| true);

        let partition_clone = partition.clone();
        mock.expect_create_partition()
            .returning(move |_| Ok(partition_clone.clone()));

        mock.expect_luks_format().returning(|_, _| Ok(()));

        let mapper_clone = mapper_device.clone();
        mock.expect_luks_open()
            .returning(move |_, _, _| Ok(mapper_clone.clone()));

        mock.expect_mkfs_ext4().returning(|_, _| Ok(()));

        mock.expect_mount().returning(|_, _| Ok(()));

        // setup_persistence_layout fails — early return before populate/umount
        mock.expect_setup_persistence_layout()
            .returning(|_| Err(KdubError::TailsPersist("layout setup failed".into())));

        // luks_close MUST be called even though setup_persistence_layout failed
        mock.expect_luks_close()
            .with(predicate::eq(TAILS_LUKS_MAPPER_NAME))
            .times(1)
            .returning(|_| Ok(()));

        let opts = PersistOptions {
            device: PathBuf::from("/dev/sdb"),
            passphrase: "test-passphrase-123".parse().unwrap(),
            skip_preseed: true,
            kdub_binary_path: binary_path,
            quiet: true,
        };

        let result = create_persistent_storage(&mock, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("layout setup failed"),
            "error should propagate layout setup failure: {err}"
        );
    }
}
