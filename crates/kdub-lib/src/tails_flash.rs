//! Block device discovery, safety validation, and image writing for Tails USB flashing.
//!
//! Provides platform-specific block device enumeration (Linux via `lsblk`, macOS via
//! `diskutil`), safety checks to prevent accidental writes to non-removable or mounted
//! devices, and a chunked image writer with progress reporting.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;
use tracing::{debug, info};

use crate::defaults;
use crate::error::KdubError;

/// Information about a detected block device.
///
/// Populated by platform-specific discovery (`lsblk` on Linux, `diskutil` on macOS)
/// and used by the safety validator and display formatter.
#[derive(Debug, Clone, Serialize)]
pub struct BlockDevice {
    /// Device path (e.g. `/dev/sdb` or `/dev/disk2`).
    pub path: PathBuf,
    /// Human-readable model name.
    pub model: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Whether the device is removable/hotplug.
    pub removable: bool,
    /// Mount points of any child filesystems (empty if unmounted).
    pub mount_points: Vec<String>,
    /// Ordered teardown commands to unmount all filesystems on this device.
    /// Commands are in the correct order: unmount first, then close LUKS.
    #[serde(skip)]
    pub unmount_commands: Vec<String>,
}

/// Abstracts block device operations for testability.
///
/// Platform implementations enumerate removable devices; tests use
/// `MockBlockDeviceOps` via mockall.
#[cfg_attr(test, mockall::automock)]
pub trait BlockDeviceOps {
    /// List removable block devices suitable for flashing.
    fn list_removable_devices(&self) -> Result<Vec<BlockDevice>, KdubError>;
}

/// Linux block device discovery using `lsblk`.
#[cfg(target_os = "linux")]
pub struct LinuxBlockDeviceOps;

#[cfg(target_os = "linux")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl BlockDeviceOps for LinuxBlockDeviceOps {
    /// List removable block devices by running `lsblk --json`.
    fn list_removable_devices(&self) -> Result<Vec<BlockDevice>, KdubError> {
        let output = std::process::Command::new("lsblk")
            .args([
                "--json",
                "--output",
                "NAME,SIZE,MODEL,HOTPLUG,MOUNTPOINT,TYPE",
                "--bytes",
            ])
            .output()
            .map_err(|e| KdubError::TailsFlash(format!("failed to run lsblk: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::TailsFlash(format!("lsblk failed: {stderr}")));
        }

        let json = String::from_utf8_lossy(&output.stdout);
        debug!(bytes = json.len(), "lsblk JSON output received");
        parse_lsblk_json(&json)
    }
}

/// Recursively collect mount points and teardown commands from a device tree.
///
/// Walks the full lsblk JSON tree to find mount points at any depth,
/// including nested structures like partition → LUKS → filesystem mount.
/// Teardown commands are generated in the correct order: unmount filesystems
/// first (deepest first), then close LUKS/crypt containers.
fn collect_mount_info(
    node: &serde_json::Value,
    mount_points: &mut Vec<String>,
    unmount_commands: &mut Vec<String>,
) {
    // Recurse into children first (depth-first: inner mounts before outer closes).
    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            collect_mount_info(child, mount_points, unmount_commands);
        }
    }

    let name = node.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let dev_type = node.get("type").and_then(|v| v.as_str()).unwrap_or("");

    // Collect mount point and generate umount command.
    if let Some(mp) = node.get("mountpoint").and_then(|v| v.as_str())
        && !mp.is_empty()
        && !mount_points.contains(&mp.to_string())
    {
        mount_points.push(mp.to_string());
        unmount_commands.push(format!("sudo umount {mp}"));
    }

    // Generate cryptsetup close for LUKS containers (after their mounts are handled).
    if dev_type == "crypt" && !name.is_empty() {
        unmount_commands.push(format!("sudo cryptsetup close {name}"));
    }
}

/// Parse lsblk JSON output into a list of removable block devices.
///
/// Filters for whole disks (`TYPE == "disk"`) that are hotplug-removable
/// (`HOTPLUG == true` or `"1"`) and meet the minimum size requirement.
/// Mount points are collected recursively from the full device tree.
pub fn parse_lsblk_json(json: &str) -> Result<Vec<BlockDevice>, KdubError> {
    let root: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| KdubError::TailsFlash(format!("invalid lsblk JSON: {e}")))?;

    let block_devices = root
        .get("blockdevices")
        .and_then(|v| v.as_array())
        .ok_or_else(|| KdubError::TailsFlash("missing 'blockdevices' array in lsblk".into()))?;

    let mut devices = Vec::new();

    for dev in block_devices {
        // Only consider whole disks.
        let dev_type = dev.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if dev_type != "disk" {
            continue;
        }

        // Check hotplug/removable status.
        let hotplug = match dev.get("hotplug") {
            Some(serde_json::Value::Bool(b)) => *b,
            Some(serde_json::Value::String(s)) => s == "1" || s == "true",
            Some(serde_json::Value::Number(n)) => n.as_u64() == Some(1),
            _ => false,
        };

        if !hotplug {
            continue;
        }

        let name = dev.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let size_bytes = parse_lsblk_size(dev.get("size"));
        let model = dev
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .trim()
            .to_string();

        // Skip devices below minimum size.
        if size_bytes < defaults::TAILS_MIN_USB_SIZE_BYTES {
            debug!(
                device = name,
                size_bytes, "skipping undersized removable device"
            );
            continue;
        }

        // Collect mount points and teardown commands recursively.
        // This catches nested structures like partition → LUKS → mount.
        let mut mount_points = Vec::new();
        let mut unmount_commands = Vec::new();
        collect_mount_info(dev, &mut mount_points, &mut unmount_commands);

        devices.push(BlockDevice {
            path: PathBuf::from(format!("/dev/{name}")),
            model,
            size_bytes,
            removable: true,
            mount_points,
            unmount_commands,
        });
    }

    Ok(devices)
}

/// Parse lsblk size field which can be a number or string.
fn parse_lsblk_size(value: Option<&serde_json::Value>) -> u64 {
    match value {
        Some(serde_json::Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(serde_json::Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

/// macOS block device discovery using `diskutil`.
#[cfg(target_os = "macos")]
pub struct MacOSBlockDeviceOps;

#[cfg(target_os = "macos")]
#[cfg_attr(coverage_nightly, coverage(off))]
impl BlockDeviceOps for MacOSBlockDeviceOps {
    /// List removable block devices by running `diskutil list` and `diskutil info`.
    fn list_removable_devices(&self) -> Result<Vec<BlockDevice>, KdubError> {
        let list_output = std::process::Command::new("diskutil")
            .args(["list", "-plist"])
            .output()
            .map_err(|e| KdubError::TailsFlash(format!("failed to run diskutil list: {e}")))?;

        if !list_output.status.success() {
            let stderr = String::from_utf8_lossy(&list_output.stderr);
            return Err(KdubError::TailsFlash(format!(
                "diskutil list failed: {stderr}"
            )));
        }

        let disk_ids = parse_diskutil_list(&list_output.stdout)?;
        debug!(count = disk_ids.len(), "discovered disk identifiers");

        let mut devices = Vec::new();
        for disk_id in &disk_ids {
            let info_output = std::process::Command::new("diskutil")
                .args(["info", "-plist", &format!("/dev/{disk_id}")])
                .output()
                .map_err(|e| {
                    KdubError::TailsFlash(format!("failed to run diskutil info {disk_id}: {e}"))
                })?;

            if !info_output.status.success() {
                debug!(disk = disk_id, "diskutil info failed, skipping");
                continue;
            }

            match parse_diskutil_info(&info_output.stdout) {
                Ok(dev)
                    if dev.removable && dev.size_bytes >= defaults::TAILS_MIN_USB_SIZE_BYTES =>
                {
                    devices.push(dev);
                }
                Ok(dev) => {
                    debug!(
                        disk = disk_id,
                        removable = dev.removable,
                        size = dev.size_bytes,
                        "skipping non-qualifying disk"
                    );
                }
                Err(e) => {
                    debug!(disk = disk_id, error = %e, "failed to parse diskutil info, skipping");
                }
            }
        }

        Ok(devices)
    }
}

/// Parse `diskutil list -plist` output to extract whole-disk identifiers.
///
/// Looks for the `AllDisksAndPartitions` key and extracts each dictionary's
/// `DeviceIdentifier` value.
pub fn parse_diskutil_list(data: &[u8]) -> Result<Vec<String>, KdubError> {
    let dict: plist::Dictionary = plist::from_bytes(data)
        .map_err(|e| KdubError::TailsFlash(format!("invalid diskutil list plist: {e}")))?;

    let all_disks = dict
        .get("AllDisksAndPartitions")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            KdubError::TailsFlash("missing 'AllDisksAndPartitions' in diskutil plist".into())
        })?;

    let mut identifiers = Vec::new();
    for entry in all_disks {
        if let Some(id) = entry
            .as_dictionary()
            .and_then(|d| d.get("DeviceIdentifier"))
            .and_then(|v| v.as_string())
        {
            identifiers.push(id.to_string());
        }
    }

    Ok(identifiers)
}

/// Parse `diskutil info -plist /dev/diskN` output for a single disk.
///
/// Extracts device path, model name, size, removable status, and mount point
/// from the plist dictionary.
pub fn parse_diskutil_info(data: &[u8]) -> Result<BlockDevice, KdubError> {
    let dict: plist::Dictionary = plist::from_bytes(data)
        .map_err(|e| KdubError::TailsFlash(format!("invalid diskutil info plist: {e}")))?;

    let device_node = dict
        .get("DeviceNode")
        .and_then(|v| v.as_string())
        .ok_or_else(|| KdubError::TailsFlash("missing DeviceNode in diskutil info".into()))?;

    let model = dict
        .get("MediaName")
        .and_then(|v| v.as_string())
        .unwrap_or("Unknown")
        .to_string();

    let size_bytes = dict
        .get("Size")
        .and_then(|v| v.as_unsigned_integer())
        .or_else(|| dict.get("TotalSize").and_then(|v| v.as_unsigned_integer()))
        .unwrap_or_else(|| {
            tracing::debug!(
                device = device_node,
                "no Size/TotalSize in diskutil plist, defaulting to 0"
            );
            0
        });

    // Check both "Removable" and "RemovableMedia" keys.
    let removable = dict
        .get("Removable")
        .and_then(|v| v.as_boolean())
        .or_else(|| dict.get("RemovableMedia").and_then(|v| v.as_boolean()))
        .unwrap_or_else(|| {
            tracing::debug!(
                device = device_node,
                "no Removable/RemovableMedia in diskutil plist, defaulting to non-removable"
            );
            false
        });

    // Collect mount point if present.
    let mut mount_points = Vec::new();
    if let Some(mp) = dict.get("MountPoint").and_then(|v| v.as_string())
        && !mp.is_empty()
    {
        mount_points.push(mp.to_string());
    }

    let unmount_commands = mount_points
        .iter()
        .map(|mp| format!("sudo umount {mp}"))
        .collect();

    Ok(BlockDevice {
        path: PathBuf::from(device_node),
        model,
        size_bytes,
        removable,
        mount_points,
        unmount_commands,
    })
}

/// Validate that a device is safe to write to.
///
/// Rejects non-removable devices, devices with mounted partitions, and devices
/// that are too small for Tails (< 8 GB). All three conditions must pass before
/// image writing proceeds.
pub fn validate_flash_target(device: &BlockDevice) -> Result<(), KdubError> {
    if !device.removable {
        return Err(KdubError::TailsFlash(format!(
            "{} is not a removable device",
            device.path.display()
        )));
    }
    if !device.mount_points.is_empty() {
        let cmds = if device.unmount_commands.is_empty() {
            device
                .mount_points
                .iter()
                .map(|mp| format!("  sudo umount {mp}"))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            format!("  {}", device.unmount_commands.join("\n  "))
        };
        return Err(KdubError::TailsFlash(format!(
            "{} has mounted filesystems. Run these commands first:\n\n{}",
            device.path.display(),
            cmds
        )));
    }
    if device.size_bytes < defaults::TAILS_MIN_USB_SIZE_BYTES {
        return Err(KdubError::TailsFlash(format!(
            "{} is too small ({:.1} GB, minimum 8 GB)",
            device.path.display(),
            device.size_bytes as f64 / 1_000_000_000.0
        )));
    }
    Ok(())
}

/// Relocate the GPT backup header to the end of the device.
///
/// After writing a disk image via `dd`, the GPT backup header is positioned
/// at the end of the *image*, not the end of the *device*. This leaves the
/// remaining space unrecognized by partitioning tools. Running `sgdisk -e`
/// moves the backup header to the correct location so the full device
/// capacity is available for new partitions (e.g., persistent storage).
///
/// # Errors
///
/// Returns `KdubError::TailsFlash` if `sgdisk` fails.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn fix_gpt_backup_header(device_path: &Path) -> Result<(), KdubError> {
    debug!(
        ?device_path,
        "relocating GPT backup header to end of device"
    );
    let output = Command::new("sudo")
        .args(["sgdisk", "-e"])
        .arg(device_path)
        .output()
        .map_err(|e| KdubError::TailsFlash(format!("failed to run sgdisk -e: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(KdubError::TailsFlash(format!(
            "sgdisk -e (fix GPT backup header) failed: {stderr}"
        )));
    }

    debug!("GPT backup header relocated");
    Ok(())
}

/// Write an ISO image to a block device with progress reporting.
///
/// Opens the image for reading and the device for raw writing, then copies
/// data in 1 MB chunks. On macOS, converts `/dev/diskN` to `/dev/rdiskN`
/// for raw device speed. Tries a direct write first; if permission is denied,
/// falls back to `sudo dd` which prompts for the user's password.
///
/// # Errors
///
/// Returns `KdubError::TailsFlash` if the image or device cannot be opened,
/// a write fails, or permissions are insufficient.
pub fn write_image_to_device(
    image_path: &Path,
    device_path: &Path,
    progress_callback: Option<&dyn Fn(u64, u64)>,
) -> Result<(), KdubError> {
    let total_size = fs::metadata(image_path)
        .map_err(|e| KdubError::TailsFlash(format!("cannot read image file: {e}")))?
        .len();

    // On macOS, use the raw device (/dev/rdiskN) for better write performance.
    let actual_device = resolve_raw_device(device_path);
    debug!(
        device = %actual_device.display(),
        image = %image_path.display(),
        total_size,
        "starting image write"
    );

    // Try direct write first (works if already root or has capabilities).
    // Fall back to sudo dd if permission denied.
    match open_device_for_writing(&actual_device) {
        Ok(writer) => {
            write_image_direct(image_path, writer, total_size, progress_callback)?;
        }
        Err(ref e) if e.to_string().contains("permission denied") => {
            info!("escalating to sudo for device write");
            write_image_sudo(image_path, &actual_device, total_size, progress_callback)?;
        }
        Err(e) => return Err(e),
    }

    debug!(total_size, "image write complete");
    Ok(())
}

/// Write image data directly to an already-opened device file.
fn write_image_direct(
    image_path: &Path,
    mut writer: fs::File,
    total_size: u64,
    progress_callback: Option<&dyn Fn(u64, u64)>,
) -> Result<(), KdubError> {
    let mut reader = fs::File::open(image_path)
        .map_err(|e| KdubError::TailsFlash(format!("cannot open image file: {e}")))?;

    const CHUNK_SIZE: usize = 1024 * 1024;
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut bytes_written: u64 = 0;

    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| KdubError::TailsFlash(format!("read error: {e}")))?;
        if n == 0 {
            break;
        }

        writer
            .write_all(&buf[..n])
            .map_err(|e| KdubError::TailsFlash(format!("write error: {e}")))?;

        bytes_written += n as u64;
        if let Some(cb) = &progress_callback {
            cb(bytes_written, total_size);
        }
    }

    writer
        .flush()
        .map_err(|e| KdubError::TailsFlash(format!("flush error: {e}")))?;
    writer
        .sync_all()
        .map_err(|e| KdubError::TailsFlash(format!("fsync error: {e}")))?;

    Ok(())
}

/// Write image to device via `sudo dd`, escalating privileges only for the write.
///
/// All stdio is inherited so `sudo` can prompt for a password and `dd`'s
/// `status=progress` output goes directly to the user's terminal.
/// The custom progress callback is not used in this path — dd's native
/// progress display is shown instead.
fn write_image_sudo(
    image_path: &Path,
    device_path: &Path,
    _total_size: u64,
    _progress_callback: Option<&dyn Fn(u64, u64)>,
) -> Result<(), KdubError> {
    let status = Command::new("sudo")
        .args([
            "dd",
            &format!("if={}", image_path.display()),
            &format!("of={}", device_path.display()),
            "bs=1M",
            "conv=fsync",
            "status=progress",
        ])
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| KdubError::TailsFlash(format!("failed to run sudo dd: {e}")))?;

    if !status.success() {
        return Err(KdubError::TailsFlash(format!(
            "sudo dd failed with exit code {}",
            status.code().unwrap_or(-1)
        )));
    }

    Ok(())
}

/// Convert `/dev/diskN` to `/dev/rdiskN` on macOS for raw device access.
///
/// On non-macOS platforms (or if the path does not match the pattern), returns
/// the original path unchanged.
fn resolve_raw_device(device_path: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        let path_str = device_path.to_string_lossy();
        if let Some(suffix) = path_str.strip_prefix("/dev/disk") {
            return PathBuf::from(format!("/dev/rdisk{suffix}"));
        }
    }
    device_path.to_path_buf()
}

/// Open a block device for writing.
///
/// Data integrity is ensured by the `sync_all()` call after writing completes,
/// rather than per-write `O_SYNC`, which would significantly degrade throughput
/// on large image writes.
fn open_device_for_writing(device_path: &Path) -> Result<fs::File, KdubError> {
    fs::OpenOptions::new()
        .write(true)
        .open(device_path)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => KdubError::TailsFlash(format!(
                "permission denied opening {}. Try running with sudo.",
                device_path.display()
            )),
            _ => {
                KdubError::TailsFlash(format!("cannot open device {}: {e}", device_path.display()))
            }
        })
}

/// Format a list of block devices for display.
///
/// Produces a human-readable table with device path, model, size in GB,
/// and mount status for each device. Returns an empty header line if no
/// devices are found.
pub fn format_device_table(devices: &[BlockDevice]) -> String {
    if devices.is_empty() {
        return "No removable devices found.".to_string();
    }

    let mut lines = vec!["Removable devices:".to_string()];

    for dev in devices {
        let size_gb = dev.size_bytes as f64 / 1_000_000_000.0;
        let mount_status = if dev.mount_points.is_empty() {
            "(not mounted)".to_string()
        } else {
            format!("(mounted at {})", dev.mount_points.join(", "))
        };

        lines.push(format!(
            "  {:<12} {:<24} {:>7.1} GB  {}",
            dev.path.display(),
            dev.model,
            size_gb,
            mount_status,
        ));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── lsblk JSON parsing ──────────────────────────────────────────

    /// Fixture: mixed lsblk output with removable, fixed, mounted, and small devices.
    const LSBLK_FIXTURE: &str = r#"{
        "blockdevices": [
            {
                "name": "sda",
                "size": 500107862016,
                "model": "Samsung SSD 860",
                "hotplug": false,
                "mountpoint": null,
                "type": "disk",
                "children": [
                    {"name": "sda1", "size": 500106813440, "model": null, "hotplug": false, "mountpoint": "/", "type": "part"}
                ]
            },
            {
                "name": "sdb",
                "size": 15938355200,
                "model": "Flash Drive     ",
                "hotplug": true,
                "mountpoint": null,
                "type": "disk"
            },
            {
                "name": "sdc",
                "size": 32015679488,
                "model": "SanDisk Ultra",
                "hotplug": true,
                "mountpoint": null,
                "type": "disk",
                "children": [
                    {"name": "sdc1", "size": 32015679488, "model": null, "hotplug": true, "mountpoint": "/mnt/usb", "type": "part"}
                ]
            },
            {
                "name": "sdd",
                "size": 4000000000,
                "model": "Tiny USB",
                "hotplug": true,
                "mountpoint": null,
                "type": "disk"
            },
            {
                "name": "sr0",
                "size": 1073741312,
                "model": "DVD-RW",
                "hotplug": true,
                "mountpoint": null,
                "type": "rom"
            }
        ]
    }"#;

    #[test]
    fn parse_lsblk_filters_removable_disks() {
        let devices = parse_lsblk_json(LSBLK_FIXTURE).unwrap();
        // sda: not hotplug -> excluded
        // sdb: hotplug, disk, 15.9 GB -> included
        // sdc: hotplug, disk, 32 GB -> included
        // sdd: hotplug, disk, 4 GB -> excluded (too small)
        // sr0: hotplug, rom (not disk) -> excluded
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn parse_lsblk_extracts_device_paths() {
        let devices = parse_lsblk_json(LSBLK_FIXTURE).unwrap();
        assert_eq!(devices[0].path, PathBuf::from("/dev/sdb"));
        assert_eq!(devices[1].path, PathBuf::from("/dev/sdc"));
    }

    #[test]
    fn parse_lsblk_trims_model_whitespace() {
        let devices = parse_lsblk_json(LSBLK_FIXTURE).unwrap();
        assert_eq!(devices[0].model, "Flash Drive");
    }

    #[test]
    fn parse_lsblk_collects_child_mount_points() {
        let devices = parse_lsblk_json(LSBLK_FIXTURE).unwrap();
        // sdb has no children/mountpoints
        assert!(devices[0].mount_points.is_empty());
        // sdc has child sdc1 mounted at /mnt/usb
        assert_eq!(devices[1].mount_points, vec!["/mnt/usb"]);
    }

    #[test]
    fn parse_lsblk_size_as_integer() {
        let devices = parse_lsblk_json(LSBLK_FIXTURE).unwrap();
        assert_eq!(devices[0].size_bytes, 15938355200);
        assert_eq!(devices[1].size_bytes, 32015679488);
    }

    #[test]
    fn parse_lsblk_all_devices_marked_removable() {
        let devices = parse_lsblk_json(LSBLK_FIXTURE).unwrap();
        for dev in &devices {
            assert!(dev.removable);
        }
    }

    #[test]
    fn parse_lsblk_hotplug_as_string() {
        let json = r#"{
            "blockdevices": [
                {"name": "sdb", "size": 16000000000, "model": "USB Stick", "hotplug": "1", "mountpoint": null, "type": "disk"}
            ]
        }"#;
        let devices = parse_lsblk_json(json).unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn parse_lsblk_hotplug_as_number() {
        let json = r#"{
            "blockdevices": [
                {"name": "sdb", "size": 16000000000, "model": "USB Stick", "hotplug": 1, "mountpoint": null, "type": "disk"}
            ]
        }"#;
        let devices = parse_lsblk_json(json).unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[test]
    fn parse_lsblk_size_as_string() {
        let json = r#"{
            "blockdevices": [
                {"name": "sdb", "size": "16000000000", "model": "USB Stick", "hotplug": true, "mountpoint": null, "type": "disk"}
            ]
        }"#;
        let devices = parse_lsblk_json(json).unwrap();
        assert_eq!(devices[0].size_bytes, 16000000000);
    }

    #[test]
    fn parse_lsblk_invalid_json() {
        let result = parse_lsblk_json("not json");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid lsblk JSON"), "got: {err}");
    }

    #[test]
    fn parse_lsblk_missing_blockdevices() {
        let result = parse_lsblk_json(r#"{"other": []}"#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("blockdevices"), "got: {err}");
    }

    #[test]
    fn parse_lsblk_empty_blockdevices() {
        let devices = parse_lsblk_json(r#"{"blockdevices": []}"#).unwrap();
        assert!(devices.is_empty());
    }

    #[test]
    fn parse_lsblk_nested_luks_mount_detected() {
        // Real-world scenario: Tails USB with encrypted persistence auto-mounted.
        // sdd → sdd1 (Tails boot, unmounted) → sdd2 → luks-xxx → /media/bram/TailsData
        let json = r#"{
            "blockdevices": [
                {
                    "name": "sdd",
                    "size": 128320801792,
                    "model": "Flash Drive",
                    "hotplug": true,
                    "mountpoint": null,
                    "type": "disk",
                    "children": [
                        {
                            "name": "sdd1",
                            "size": 8587951616,
                            "model": null,
                            "hotplug": true,
                            "mountpoint": null,
                            "type": "part"
                        },
                        {
                            "name": "sdd2",
                            "size": 119730601984,
                            "model": null,
                            "hotplug": true,
                            "mountpoint": null,
                            "type": "part",
                            "children": [
                                {
                                    "name": "luks-d0844220-33fb-405c-a323-5213b5957f05",
                                    "size": 119713824768,
                                    "model": null,
                                    "hotplug": false,
                                    "mountpoint": "/media/bram/TailsData",
                                    "type": "crypt"
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let devices = parse_lsblk_json(json).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mount_points, vec!["/media/bram/TailsData"]);
        // Unmount commands must be in correct order: umount first, then close LUKS.
        assert_eq!(
            devices[0].unmount_commands,
            vec![
                "sudo umount /media/bram/TailsData",
                "sudo cryptsetup close luks-d0844220-33fb-405c-a323-5213b5957f05",
            ]
        );
    }

    #[test]
    fn parse_lsblk_deeply_nested_mounts_detected() {
        // Pathological case: disk → part → LUKS → LVM → mount
        let json = r#"{
            "blockdevices": [
                {
                    "name": "sde",
                    "size": 64000000000,
                    "model": "Deep USB",
                    "hotplug": true,
                    "mountpoint": null,
                    "type": "disk",
                    "children": [
                        {
                            "name": "sde1",
                            "size": 64000000000,
                            "mountpoint": null,
                            "type": "part",
                            "children": [
                                {
                                    "name": "luks-abc",
                                    "size": 64000000000,
                                    "mountpoint": null,
                                    "type": "crypt",
                                    "children": [
                                        {
                                            "name": "vg-data",
                                            "size": 64000000000,
                                            "mountpoint": "/mnt/data",
                                            "type": "lvm"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let devices = parse_lsblk_json(json).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mount_points, vec!["/mnt/data"]);
        // LVM mount is unmounted, then LUKS container is closed.
        assert_eq!(
            devices[0].unmount_commands,
            vec!["sudo umount /mnt/data", "sudo cryptsetup close luks-abc",]
        );
    }

    #[test]
    fn parse_lsblk_multiple_nested_mounts_all_collected() {
        // Multiple partitions with mounts at different nesting levels
        let json = r#"{
            "blockdevices": [
                {
                    "name": "sdf",
                    "size": 64000000000,
                    "model": "Multi USB",
                    "hotplug": true,
                    "mountpoint": null,
                    "type": "disk",
                    "children": [
                        {
                            "name": "sdf1",
                            "size": 8000000000,
                            "mountpoint": "/mnt/boot",
                            "type": "part"
                        },
                        {
                            "name": "sdf2",
                            "size": 56000000000,
                            "mountpoint": null,
                            "type": "part",
                            "children": [
                                {
                                    "name": "luks-xyz",
                                    "size": 56000000000,
                                    "mountpoint": "/mnt/encrypted",
                                    "type": "crypt"
                                }
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let devices = parse_lsblk_json(json).unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mount_points, vec!["/mnt/boot", "/mnt/encrypted"]);
        // Direct partition mount + LUKS mount → umount both, close the LUKS.
        assert_eq!(
            devices[0].unmount_commands,
            vec![
                "sudo umount /mnt/boot",
                "sudo umount /mnt/encrypted",
                "sudo cryptsetup close luks-xyz",
            ]
        );
    }

    // ── diskutil plist parsing ──────────────────────────────────────

    #[test]
    fn parse_diskutil_list_extracts_identifiers() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AllDisksAndPartitions</key>
    <array>
        <dict>
            <key>DeviceIdentifier</key>
            <string>disk0</string>
            <key>Size</key>
            <integer>500107862016</integer>
        </dict>
        <dict>
            <key>DeviceIdentifier</key>
            <string>disk2</string>
            <key>Size</key>
            <integer>15938355200</integer>
        </dict>
    </array>
</dict>
</plist>"#;

        let ids = parse_diskutil_list(plist_data).unwrap();
        assert_eq!(ids, vec!["disk0", "disk2"]);
    }

    #[test]
    fn parse_diskutil_list_empty_array() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>AllDisksAndPartitions</key>
    <array/>
</dict>
</plist>"#;

        let ids = parse_diskutil_list(plist_data).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn parse_diskutil_list_missing_key() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>SomeOtherKey</key>
    <array/>
</dict>
</plist>"#;

        let result = parse_diskutil_list(plist_data);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("AllDisksAndPartitions"), "got: {err}");
    }

    #[test]
    fn parse_diskutil_list_invalid_plist() {
        let result = parse_diskutil_list(b"not a plist");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid diskutil list plist"), "got: {err}");
    }

    #[test]
    fn parse_diskutil_info_removable_device() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceNode</key>
    <string>/dev/disk2</string>
    <key>MediaName</key>
    <string>Samsung Flash Drive</string>
    <key>Size</key>
    <integer>15938355200</integer>
    <key>Removable</key>
    <true/>
    <key>MountPoint</key>
    <string></string>
</dict>
</plist>"#;

        let dev = parse_diskutil_info(plist_data).unwrap();
        assert_eq!(dev.path, PathBuf::from("/dev/disk2"));
        assert_eq!(dev.model, "Samsung Flash Drive");
        assert_eq!(dev.size_bytes, 15938355200);
        assert!(dev.removable);
        assert!(dev.mount_points.is_empty());
    }

    #[test]
    fn parse_diskutil_info_mounted_device() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceNode</key>
    <string>/dev/disk3</string>
    <key>MediaName</key>
    <string>SanDisk Ultra</string>
    <key>Size</key>
    <integer>32015679488</integer>
    <key>Removable</key>
    <true/>
    <key>MountPoint</key>
    <string>/Volumes/SANDISK</string>
</dict>
</plist>"#;

        let dev = parse_diskutil_info(plist_data).unwrap();
        assert_eq!(dev.mount_points, vec!["/Volumes/SANDISK"]);
    }

    #[test]
    fn parse_diskutil_info_non_removable() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceNode</key>
    <string>/dev/disk0</string>
    <key>MediaName</key>
    <string>APPLE SSD</string>
    <key>Size</key>
    <integer>500107862016</integer>
    <key>Removable</key>
    <false/>
</dict>
</plist>"#;

        let dev = parse_diskutil_info(plist_data).unwrap();
        assert!(!dev.removable);
    }

    #[test]
    fn parse_diskutil_info_removable_media_key() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceNode</key>
    <string>/dev/disk4</string>
    <key>MediaName</key>
    <string>Generic USB</string>
    <key>Size</key>
    <integer>16000000000</integer>
    <key>RemovableMedia</key>
    <true/>
</dict>
</plist>"#;

        let dev = parse_diskutil_info(plist_data).unwrap();
        assert!(dev.removable);
    }

    #[test]
    fn parse_diskutil_info_total_size_fallback() {
        let plist_data = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>DeviceNode</key>
    <string>/dev/disk5</string>
    <key>MediaName</key>
    <string>USB Key</string>
    <key>TotalSize</key>
    <integer>16000000000</integer>
    <key>Removable</key>
    <true/>
</dict>
</plist>"#;

        let dev = parse_diskutil_info(plist_data).unwrap();
        assert_eq!(dev.size_bytes, 16000000000);
    }

    #[test]
    fn parse_diskutil_info_invalid_plist() {
        let result = parse_diskutil_info(b"not a plist");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid diskutil info plist"), "got: {err}");
    }

    // ── validate_flash_target ───────────────────────────────────────

    #[test]
    fn validate_flash_target_accepts_good_device() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sdb"),
            model: "Flash Drive".into(),
            size_bytes: 16_000_000_000,
            removable: true,
            mount_points: vec![],
            unmount_commands: vec![],
        };
        assert!(validate_flash_target(&dev).is_ok());
    }

    #[test]
    fn validate_flash_target_rejects_non_removable() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sda"),
            model: "Samsung SSD".into(),
            size_bytes: 500_000_000_000,
            removable: false,
            mount_points: vec![],
            unmount_commands: vec![],
        };
        let err = validate_flash_target(&dev).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not a removable device"), "got: {msg}");
        assert!(msg.contains("/dev/sda"), "got: {msg}");
    }

    #[test]
    fn validate_flash_target_rejects_mounted() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sdc"),
            model: "SanDisk Ultra".into(),
            size_bytes: 32_000_000_000,
            removable: true,
            mount_points: vec!["/mnt/usb".into(), "/media/user/drive".into()],
            unmount_commands: vec![
                "sudo umount /mnt/usb".into(),
                "sudo umount /media/user/drive".into(),
            ],
        };
        let err = validate_flash_target(&dev).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mounted filesystems"), "got: {msg}");
        assert!(
            msg.contains("sudo umount"),
            "should show umount command, got: {msg}"
        );
        assert!(msg.contains("/mnt/usb"), "got: {msg}");
        assert!(msg.contains("/media/user/drive"), "got: {msg}");
    }

    #[test]
    fn validate_flash_target_rejects_too_small() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sdd"),
            model: "Tiny USB".into(),
            size_bytes: 4_000_000_000,
            removable: true,
            mount_points: vec![],
            unmount_commands: vec![],
        };
        let err = validate_flash_target(&dev).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("too small"), "got: {msg}");
        assert!(msg.contains("4.0 GB"), "got: {msg}");
        assert!(msg.contains("minimum 8 GB"), "got: {msg}");
    }

    #[test]
    fn validate_flash_target_exact_minimum_size() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sde"),
            model: "Exact 8GB".into(),
            size_bytes: defaults::TAILS_MIN_USB_SIZE_BYTES,
            removable: true,
            mount_points: vec![],
            unmount_commands: vec![],
        };
        assert!(validate_flash_target(&dev).is_ok());
    }

    #[test]
    fn validate_flash_target_checks_removable_first() {
        // Device is non-removable AND mounted AND too small.
        // Should report the non-removable error (checked first).
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sda"),
            model: "Multi-fail".into(),
            size_bytes: 1_000_000_000,
            removable: false,
            mount_points: vec!["/".into()],
            unmount_commands: vec!["sudo umount /".into()],
        };
        let err = validate_flash_target(&dev).unwrap_err();
        assert!(
            err.to_string().contains("not a removable device"),
            "should fail on removable check first"
        );
    }

    #[test]
    fn validate_flash_target_mounted_empty_unmount_commands_falls_back_to_mount_points() {
        // When unmount_commands is empty but mount_points is populated,
        // validate_flash_target should generate fallback umount commands from mount_points.
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sdb"),
            model: "Flash Drive".into(),
            size_bytes: 16_000_000_000,
            removable: true,
            mount_points: vec!["/mnt/tails".into()],
            unmount_commands: vec![], // empty — triggers fallback path
        };
        let err = validate_flash_target(&dev).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("mounted filesystems"), "got: {msg}");
        // Fallback generates "sudo umount <mountpoint>" from mount_points.
        assert!(
            msg.contains("sudo umount /mnt/tails"),
            "expected fallback umount command from mount_points, got: {msg}"
        );
    }

    // ── format_device_table ─────────────────────────────────────────

    #[test]
    fn format_device_table_empty() {
        let output = format_device_table(&[]);
        assert_eq!(output, "No removable devices found.");
    }

    #[test]
    fn format_device_table_snapshot() {
        let devices = vec![
            BlockDevice {
                path: PathBuf::from("/dev/sdb"),
                model: "Samsung Flash Drive".into(),
                size_bytes: 14_900_000_000,
                removable: true,
                mount_points: vec![],
                unmount_commands: vec![],
            },
            BlockDevice {
                path: PathBuf::from("/dev/sdc"),
                model: "SanDisk Ultra".into(),
                size_bytes: 29_800_000_000,
                removable: true,
                mount_points: vec!["/mnt/usb".into()],
                unmount_commands: vec!["sudo umount /mnt/usb".into()],
            },
        ];

        let output = format_device_table(&devices);
        insta::assert_snapshot!(output);
    }

    #[test]
    fn format_device_table_single_device() {
        let devices = vec![BlockDevice {
            path: PathBuf::from("/dev/sdb"),
            model: "USB Stick".into(),
            size_bytes: 16_000_000_000,
            removable: true,
            mount_points: vec![],
            unmount_commands: vec![],
        }];

        let output = format_device_table(&devices);
        assert!(output.starts_with("Removable devices:"));
        assert!(output.contains("/dev/sdb"));
        assert!(output.contains("USB Stick"));
        assert!(output.contains("16.0 GB"));
        assert!(output.contains("(not mounted)"));
    }

    #[test]
    fn format_device_table_multiple_mount_points() {
        let devices = vec![BlockDevice {
            path: PathBuf::from("/dev/sdc"),
            model: "Multi Mount".into(),
            size_bytes: 32_000_000_000,
            removable: true,
            mount_points: vec!["/mnt/a".into(), "/mnt/b".into()],
            unmount_commands: vec!["sudo umount /mnt/a".into(), "sudo umount /mnt/b".into()],
        }];

        let output = format_device_table(&devices);
        assert!(output.contains("(mounted at /mnt/a, /mnt/b)"));
    }

    // ── write_image_to_device ───────────────────────────────────────

    #[test]
    fn write_image_to_device_copies_data() {
        let dir = tempfile::tempdir().unwrap();
        let image_path = dir.path().join("test.img");
        let device_path = dir.path().join("fake_device");

        // Write a test image.
        let test_data = vec![0xABu8; 4 * 1024 * 1024]; // 4 MB
        fs::write(&image_path, &test_data).unwrap();

        // Create the device file before opening it (devices must exist).
        fs::write(&device_path, b"").unwrap();

        // Write to a regular file as a stand-in for a device.
        let result = write_image_to_device(&image_path, &device_path, None);
        assert!(result.is_ok(), "write should succeed: {result:?}");

        // Verify the copy is identical.
        let written = fs::read(&device_path).unwrap();
        assert_eq!(written.len(), test_data.len());
        assert_eq!(written, test_data);
    }

    #[test]
    fn write_image_to_device_reports_progress() {
        let dir = tempfile::tempdir().unwrap();
        let image_path = dir.path().join("test.img");
        let device_path = dir.path().join("fake_device");

        // 3 MB image: will produce multiple progress callbacks with 1 MB chunks.
        let test_data = vec![0xCDu8; 3 * 1024 * 1024];
        fs::write(&image_path, &test_data).unwrap();

        // Create the device file before opening it (devices must exist).
        fs::write(&device_path, b"").unwrap();

        let progress_count = std::sync::atomic::AtomicU32::new(0);
        let last_total = std::sync::atomic::AtomicU64::new(0);

        let result = write_image_to_device(
            &image_path,
            &device_path,
            Some(&|_written, total| {
                progress_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                last_total.store(total, std::sync::atomic::Ordering::Relaxed);
            }),
        );

        assert!(result.is_ok());
        let count = progress_count.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            count >= 3,
            "expected at least 3 progress callbacks, got {count}"
        );
        let total = last_total.load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(total, test_data.len() as u64);
    }

    #[test]
    fn write_image_to_device_nonexistent_image() {
        let dir = tempfile::tempdir().unwrap();
        let result = write_image_to_device(
            &dir.path().join("nonexistent.img"),
            &dir.path().join("device"),
            None,
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot read image file"), "got: {err}");
    }

    // ── resolve_raw_device ──────────────────────────────────────────

    #[test]
    fn resolve_raw_device_non_disk_path_passthrough() {
        // /dev/sdb doesn't match /dev/disk*, so it should passthrough on all platforms.
        let path = PathBuf::from("/dev/sdb");
        let result = resolve_raw_device(&path);
        assert_eq!(result, path);
    }

    #[test]
    fn resolve_raw_device_macos_disk_path() {
        // /dev/disk2 should become /dev/rdisk2 on macOS, passthrough elsewhere.
        let path = PathBuf::from("/dev/disk2");
        let result = resolve_raw_device(&path);
        if cfg!(target_os = "macos") {
            assert_eq!(result, PathBuf::from("/dev/rdisk2"));
        } else {
            assert_eq!(result, path);
        }
    }

    // ── BlockDevice clone and serialize ─────────────────────────────

    #[test]
    fn block_device_clone() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sdb"),
            model: "Test".into(),
            size_bytes: 16_000_000_000,
            removable: true,
            mount_points: vec!["/mnt/usb".into()],
            unmount_commands: vec!["sudo umount /mnt/usb".into()],
        };
        let cloned = dev.clone();
        assert_eq!(cloned.path, dev.path);
        assert_eq!(cloned.model, dev.model);
        assert_eq!(cloned.size_bytes, dev.size_bytes);
        assert_eq!(cloned.removable, dev.removable);
        assert_eq!(cloned.mount_points, dev.mount_points);
    }

    #[test]
    fn block_device_debug() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sdb"),
            model: "Test".into(),
            size_bytes: 16_000_000_000,
            removable: true,
            mount_points: vec![],
            unmount_commands: vec![],
        };
        let debug = format!("{dev:?}");
        assert!(debug.contains("BlockDevice"));
        assert!(debug.contains("sdb"));
    }

    #[test]
    fn block_device_serialize() {
        let dev = BlockDevice {
            path: PathBuf::from("/dev/sdb"),
            model: "Flash Drive".into(),
            size_bytes: 16_000_000_000,
            removable: true,
            mount_points: vec![],
            unmount_commands: vec![],
        };
        let json = serde_json::to_string(&dev).unwrap();
        assert!(json.contains("Flash Drive"));
        assert!(json.contains("16000000000"));
    }

    // ── MockBlockDeviceOps ──────────────────────────────────────────

    #[test]
    fn mock_block_device_ops_returns_devices() {
        let mut mock = MockBlockDeviceOps::new();
        mock.expect_list_removable_devices().returning(|| {
            Ok(vec![BlockDevice {
                path: PathBuf::from("/dev/sdb"),
                model: "Mock USB".into(),
                size_bytes: 16_000_000_000,
                removable: true,
                mount_points: vec![],
                unmount_commands: vec![],
            }])
        });

        let devices = mock.list_removable_devices().unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].model, "Mock USB");
    }

    #[test]
    fn mock_block_device_ops_returns_error() {
        let mut mock = MockBlockDeviceOps::new();
        mock.expect_list_removable_devices()
            .returning(|| Err(KdubError::TailsFlash("mock error".into())));

        let result = mock.list_removable_devices();
        assert!(result.is_err());
    }

    #[test]
    fn mock_block_device_ops_returns_empty() {
        let mut mock = MockBlockDeviceOps::new();
        mock.expect_list_removable_devices()
            .returning(|| Ok(vec![]));

        let devices = mock.list_removable_devices().unwrap();
        assert!(devices.is_empty());
    }

    // ── find_cached_iso integration ─────────────────────────────────

    #[test]
    fn find_cached_iso_from_flash_module() {
        use crate::tails_download::find_cached_iso;

        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("tails-amd64-7.5.img");
        fs::write(&img_path, b"fake img").unwrap();

        let found = find_cached_iso(dir.path());
        assert_eq!(found, Some(img_path));
    }
}
