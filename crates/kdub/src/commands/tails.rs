use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::cli::{GlobalOpts, TailsCommand, TailsDownloadArgs, TailsFlashArgs, TailsPersistArgs};
#[cfg(target_os = "linux")]
use crate::secret_input;
use indicatif::{ProgressBar, ProgressStyle};
use kdub_lib::error::KdubError;
use kdub_lib::tails_download;
use kdub_lib::tails_flash::{self, BlockDeviceOps, format_device_table, validate_flash_target};
#[cfg(target_os = "linux")]
use kdub_lib::types::Passphrase;
#[cfg(target_os = "linux")]
use rand::rngs::OsRng;

use super::CmdResult;

pub fn run(cmd: &TailsCommand, global: &GlobalOpts) -> CmdResult {
    match cmd {
        TailsCommand::Download(args) => run_download(args, global),
        TailsCommand::Flash(args) => run_flash(args, global),
        TailsCommand::Persist(args) => run_persist(args, global),
    }
}

/// Download and verify the latest Tails ISO image.
///
/// Shows a bytes-style progress bar unless `--quiet` is set.
/// After download, prints the cached path, version, and an
/// Apple Silicon warning on macOS ARM64.
fn run_download(args: &TailsDownloadArgs, global: &GlobalOpts) -> CmdResult {
    // 1. Create progress bar (hidden if quiet)
    let pb = if global.quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(0);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .expect("valid progress bar template")
                .progress_chars("#>-"),
        );
        pb
    };

    // 2. Download with progress callback
    let pb_ref = &pb;
    let (path, release) = tails_download::download_tails_iso(
        args.force,
        global.quiet,
        Some(&|bytes_written, total| {
            pb_ref.set_length(total);
            pb_ref.set_position(bytes_written);
        }),
    )?;
    pb.finish_and_clear();

    // 3. Print result
    println!("Tails {} downloaded to {}", release.version, path.display());

    // 4. macOS ARM64 warning
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    eprintln!("\n{}", tails_download::MACOS_ARM64_WARNING);

    Ok(())
}

/// Normalize a device path for comparison against discovered devices.
///
/// On macOS, strips the `r` prefix from `/dev/rdiskN` paths so they match
/// the canonical `/dev/diskN` form returned by device discovery.
fn normalize_device_path(path: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        let path_str = path.to_string_lossy();
        if let Some(suffix) = path_str.strip_prefix("/dev/rdisk") {
            return PathBuf::from(format!("/dev/disk{suffix}"));
        }
    }
    path.to_path_buf()
}

/// Write a verified Tails image to a USB device.
///
/// Discovers removable devices, prompts for device selection,
/// validates the target, then writes the image with a progress bar.
fn run_flash(args: &TailsFlashArgs, global: &GlobalOpts) -> CmdResult {
    // 1. Find cached ISO
    let cache_dir = tails_download::resolve_cache_dir()?;
    let iso_path = tails_download::find_cached_iso(&cache_dir).ok_or_else(|| {
        KdubError::TailsFlash("No Tails image found. Run 'kdub tails download' first.".into())
    })?;

    // 2. Create platform-appropriate BlockDeviceOps
    #[cfg(target_os = "linux")]
    let block_ops = tails_flash::LinuxBlockDeviceOps;
    #[cfg(target_os = "macos")]
    let block_ops = tails_flash::MacOSBlockDeviceOps;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return Err(KdubError::TailsFlash(
        "USB flashing is only supported on Linux and macOS".into(),
    ));

    // 3. Discover removable devices
    let devices = block_ops.list_removable_devices()?;
    if devices.is_empty() {
        return Err(KdubError::TailsFlash(
            "No removable devices found. Insert a USB drive and try again.".into(),
        ));
    }

    // 4. Reject early if all devices have mounted filesystems
    let all_mounted = devices.iter().all(|d| !d.mount_points.is_empty());
    if all_mounted {
        let table = format_device_table(&devices);
        println!("{table}");
        println!();
        let cmds: Vec<&str> = devices
            .iter()
            .flat_map(|d| d.unmount_commands.iter())
            .map(|s| s.as_str())
            .collect();
        return Err(KdubError::TailsFlash(format!(
            "All removable devices have mounted filesystems.\n\
             Run these commands, then re-run kdub tails flash:\n\n  {}",
            cmds.join("\n  ")
        )));
    }

    // 5. Display device table
    let table = format_device_table(&devices);
    println!("{table}");
    println!();

    // 5. Resolve device path
    let device_path: PathBuf = if let Some(ref dev) = args.device {
        // --device provided: validate it exists in the device list
        let normalized_dev = normalize_device_path(dev);
        let device = devices
            .iter()
            .find(|d| d.path == normalized_dev)
            .ok_or_else(|| {
                KdubError::TailsFlash(format!(
                    "{} is not in the list of removable devices",
                    dev.display()
                ))
            })?;
        validate_flash_target(device)?;
        dev.clone()
    } else {
        // Interactive: prompt for device path
        print!("Enter device path to flash (e.g. /dev/sdX or /dev/diskN): ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().lock().read_line(&mut input)?;
        let typed_path = PathBuf::from(input.trim());

        let normalized_path = normalize_device_path(&typed_path);
        let device = devices
            .iter()
            .find(|d| d.path == normalized_path)
            .ok_or_else(|| {
                KdubError::TailsFlash(format!(
                    "{} is not in the list of removable devices",
                    typed_path.display()
                ))
            })?;
        validate_flash_target(device)?;
        typed_path
    };

    // 6. Confirmation (unless --yes)
    if !args.yes {
        println!(
            "WARNING: All data on {} will be overwritten.",
            device_path.display()
        );
        print!("Type the full device path to confirm: ");
        io::stdout().flush()?;
        let mut confirm = String::new();
        io::stdin().lock().read_line(&mut confirm)?;
        if confirm.trim() != device_path.to_string_lossy() {
            return Err(KdubError::TailsFlash(
                "device path mismatch — aborting".into(),
            ));
        }
    }

    // 7. Write image with progress bar
    let iso_size = std::fs::metadata(&iso_path)?.len();
    let pb = if global.quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(iso_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .expect("valid progress bar template")
                .progress_chars("#>-"),
        );
        pb
    };

    let pb_ref = &pb;
    tails_flash::write_image_to_device(
        &iso_path,
        &device_path,
        Some(&|written, total| {
            pb_ref.set_length(total);
            pb_ref.set_position(written);
        }),
    )?;
    pb.finish_and_clear();

    // 8. Print next-step guidance
    println!("Tails written to {}.", device_path.display());
    println!(
        "Run 'kdub tails persist --device {}' next.",
        device_path.display()
    );

    Ok(())
}

/// Create encrypted persistent storage on a Tails USB.
///
/// Linux-only. Resolves the LUKS passphrase through the standard
/// input chain (flag > stdin > env > interactive), optionally
/// downloads a cross-arch binary, then delegates to
/// `create_persistent_storage`.
#[cfg(target_os = "linux")]
fn run_persist(args: &TailsPersistArgs, global: &GlobalOpts) -> CmdResult {
    // 1. Resolve passphrase using the standard input chain
    let passphrase = if let Some(ref p) = args.passphrase {
        p.parse::<Passphrase>()
            .map_err(|e| KdubError::TailsPersist(e.to_string()))?
    } else if args.passphrase_stdin {
        // Use resolve_secret which handles stdin reading
        secret_input::resolve_secret::<Passphrase>(
            None,
            true,
            "KDUB_PASSPHRASE",
            "LUKS passphrase",
            global.batch,
        )
        .map_err(|e| KdubError::TailsPersist(e.to_string()))?
    } else if let Ok(env_val) = std::env::var("KDUB_PASSPHRASE") {
        if !env_val.is_empty() {
            env_val
                .parse::<Passphrase>()
                .map_err(|e| KdubError::TailsPersist(e.to_string()))?
        } else {
            resolve_passphrase_interactive(global.batch)?
        }
    } else {
        resolve_passphrase_interactive(global.batch)?
    };

    // 2. Resolve kdub binary source
    let current_arch = std::env::consts::ARCH;
    let current_version = env!("CARGO_PKG_VERSION");
    let binary_source = kdub_lib::tails::resolve_kdub_binary_source(current_arch, current_version)?;

    let kdub_binary_path = if let Some(download_url) = binary_source {
        tails_download::download_and_verify_kdub_binary(
            &download_url,
            kdub_lib::defaults::ZIPSIGN_PUBLIC_KEY,
            global.quiet,
        )?
    } else {
        // Same arch: use current binary.
        std::env::current_exe()
            .map_err(|e| KdubError::TailsPersist(format!("cannot find current binary: {e}")))?
    };

    // 3. Determine device
    let device = args
        .device
        .clone()
        .ok_or_else(|| KdubError::TailsPersist("--device is required for persist".into()))?;

    // 4. Create persistent storage
    let opts = kdub_lib::tails_persist::PersistOptions {
        device: device.clone(),
        passphrase,
        skip_preseed: args.skip_preseed,
        kdub_binary_path,
        quiet: global.quiet,
    };

    let deps = kdub_lib::tails_persist::LinuxTailsSystemDeps;
    kdub_lib::tails_persist::create_persistent_storage(&deps, &opts)?;

    // 5. Print summary
    println!("Persistent storage created on {}.", device.display());
    println!("Boot from USB → unlock persistence → kdub doctor → kdub key create");

    Ok(())
}

/// Stub for non-Linux platforms: persistent storage requires Linux.
#[cfg(not(target_os = "linux"))]
fn run_persist(_args: &TailsPersistArgs, _global: &GlobalOpts) -> CmdResult {
    Err(KdubError::TailsUnsupported(
        concat!(
            "Persistent storage requires Linux (cryptsetup/parted).\n",
            "Options:\n",
            "  - Boot from the USB and configure persistence via Tails Welcome Screen\n",
            "  - Run this command from a Linux machine or VM\n",
            "  - See: https://github.com/bramswenson/kdub/issues/7 (VM guide)",
        )
        .into(),
    ))
}

/// Resolve LUKS passphrase interactively.
///
/// Offers auto-generation with a prominent recording banner, following
/// the same pattern as `card setup` PIN display. Falls back to manual
/// entry with confirmation if the user declines.
#[cfg(target_os = "linux")]
fn resolve_passphrase_interactive(batch: bool) -> Result<Passphrase, KdubError> {
    if batch {
        return Err(KdubError::TailsPersist(
            "batch mode requires passphrase via --passphrase, --passphrase-stdin, or KDUB_PASSPHRASE"
                .into(),
        ));
    }

    let generate = dialoguer::Confirm::new()
        .with_prompt("Auto-generate a strong LUKS passphrase?")
        .default(true)
        .interact()
        .map_err(|e| KdubError::TailsPersist(e.to_string()))?;

    if generate {
        let pp = Passphrase::generate(&mut OsRng);
        eprintln!();
        eprintln!("==============================================");
        eprintln!("  LUKS PASSPHRASE - RECORD THIS NOW");
        eprintln!("==============================================");
        eprintln!();
        eprintln!("  {}", pp.expose_secret());
        eprintln!();
        eprintln!("==============================================");
        eprintln!();
        Ok(pp)
    } else {
        let input = dialoguer::Password::new()
            .with_prompt("Enter LUKS passphrase")
            .with_confirmation("Confirm passphrase", "Passphrases don't match")
            .interact()
            .map_err(|e| KdubError::TailsPersist(e.to_string()))?;
        input
            .parse::<Passphrase>()
            .map_err(|e| KdubError::TailsPersist(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn normalize_device_path_linux_passthrough() {
        let path = PathBuf::from("/dev/sdb");
        assert_eq!(normalize_device_path(&path), PathBuf::from("/dev/sdb"));
    }

    #[test]
    fn normalize_device_path_disk_passthrough() {
        let path = PathBuf::from("/dev/disk2");
        assert_eq!(normalize_device_path(&path), PathBuf::from("/dev/disk2"));
    }

    #[test]
    fn normalize_device_path_rdisk_on_macos() {
        let path = PathBuf::from("/dev/rdisk2");
        let result = normalize_device_path(&path);
        if cfg!(target_os = "macos") {
            assert_eq!(result, PathBuf::from("/dev/disk2"));
        } else {
            assert_eq!(result, PathBuf::from("/dev/rdisk2"));
        }
    }
}
