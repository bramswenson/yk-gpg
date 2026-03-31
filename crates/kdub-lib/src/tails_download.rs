//! Tails ISO download, parsing, and verification.
//!
//! Provides types and functions for parsing Tails release metadata from
//! `latest.json`, downloading ISO images with progress reporting and
//! local caching, verifying SHA256 checksums of downloaded images, and
//! verifying detached PGP signatures against the Tails signing key.

use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::defaults;
use crate::error::KdubError;

/// Warning text shown on macOS ARM64 after downloading Tails.
///
/// Tails images are x86_64 only and cannot boot on Apple Silicon Macs.
/// This message is displayed to inform the user they need an x86_64 machine
/// or a virtual machine to use the downloaded image.
pub const MACOS_ARM64_WARNING: &str = concat!(
    "Note: This Tails image is x86_64 only. It cannot boot on Apple Silicon Macs.\n",
    "You'll need an x86_64 PC to boot from the USB, or use a virtual machine.",
);

/// Parsed Tails release metadata from `latest.json`.
///
/// Contains all the information needed to download and verify a Tails
/// USB image: version string, download URL, signature URL, expected
/// SHA256 checksum, and file size in bytes.
#[derive(Debug, Clone)]
pub struct TailsRelease {
    /// Tails release version (e.g. "7.5").
    pub version: String,
    /// Direct download URL for the `.img` file.
    pub img_url: String,
    /// URL for the detached PGP signature of the `.img` file.
    pub sig_url: String,
    /// Expected SHA256 hex digest of the `.img` file.
    pub sha256: String,
    /// Expected file size in bytes.
    pub size: u64,
}

/// Parse the Tails release metadata JSON from `latest.json`.
///
/// Extracts the USB image (`type: "img"`) entry from the `installations`
/// array. Constructs the signature URL using the tails.net/torrents/files host and the version from the parsed metadata, independent of the image download URL.
///
/// # Errors
///
/// Returns `KdubError::TailsDownload` if the JSON is malformed, missing
/// required fields, or contains no USB image installation path.
pub fn parse_latest_json(json: &str) -> Result<TailsRelease, KdubError> {
    let root: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| KdubError::TailsDownload(format!("invalid JSON: {e}")))?;

    let installations = root
        .get("installations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| KdubError::TailsDownload("missing 'installations' array".into()))?;

    let install = installations
        .first()
        .ok_or_else(|| KdubError::TailsDownload("empty 'installations' array".into()))?;

    let version = install
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KdubError::TailsDownload("missing 'version' field".into()))?
        .to_string();

    let paths = install
        .get("installation-paths")
        .and_then(|v| v.as_array())
        .ok_or_else(|| KdubError::TailsDownload("missing 'installation-paths' array".into()))?;

    // Find the "img" installation path (USB image).
    let img_path = paths
        .iter()
        .find(|p| p.get("type").and_then(|t| t.as_str()) == Some("img"))
        .ok_or_else(|| KdubError::TailsDownload("no 'img' type in installation-paths".into()))?;

    let target_file = img_path
        .get("target-files")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| KdubError::TailsDownload("missing 'target-files' array".into()))?;

    let img_url = target_file
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KdubError::TailsDownload("missing 'url' in target-files".into()))?
        .to_string();

    let sha256 = target_file
        .get("sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| KdubError::TailsDownload("missing 'sha256' in target-files".into()))?
        .to_string();

    let size = target_file
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| KdubError::TailsDownload("missing 'size' in target-files".into()))?;

    // Derive the signature URL: same base path but on the tails.net torrents host.
    // Pattern: https://tails.net/torrents/files/tails-amd64-{version}.img.sig
    let sig_url = format!("https://tails.net/torrents/files/tails-amd64-{version}.img.sig");

    Ok(TailsRelease {
        version,
        img_url,
        sig_url,
        sha256,
        size,
    })
}

/// Verify a file's SHA256 checksum against an expected hex digest.
///
/// Reads the file at `path`, computes SHA256, and compares the lowercase
/// hex digest to `expected` (case-insensitive).
///
/// # Errors
///
/// Returns `KdubError::Io` if the file cannot be read, or
/// `KdubError::TailsDownload` if the checksum does not match.
pub fn verify_iso_sha256(path: &Path, expected: &str) -> Result<(), KdubError> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024]; // 64 KB chunks

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    let actual = hex::encode(hasher.finalize());
    let expected_lower = expected.to_lowercase();

    if actual != expected_lower {
        return Err(KdubError::TailsDownload(format!(
            "SHA256 mismatch: expected {expected_lower}, got {actual}"
        )));
    }

    Ok(())
}

/// Verify a detached PGP signature over ISO/IMG data.
///
/// Parses the signing key and detached signature from armored PGP format,
/// optionally checks the key fingerprint against `expected_fingerprint`,
/// and verifies the signature over `iso_bytes`.
///
/// # Arguments
///
/// * `iso_bytes` - The raw data that was signed.
/// * `sig_bytes` - The armored detached PGP signature.
/// * `signing_key_bytes` - The armored PGP public key of the signer.
/// * `expected_fingerprint` - If `Some`, the key's fingerprint must match
///   this uppercase hex string. Pass `None` to skip the fingerprint check.
///
/// # Errors
///
/// Returns `KdubError::TailsDownload` if the key or signature cannot be
/// parsed, the fingerprint does not match, or signature verification fails.
pub fn verify_iso_signature(
    iso_bytes: &[u8],
    sig_bytes: &[u8],
    signing_key_bytes: &[u8],
    expected_fingerprint: Option<&str>,
) -> Result<(), KdubError> {
    // Parse the signing public key.
    let (public_key, _) =
        SignedPublicKey::from_armor_single(std::io::Cursor::new(signing_key_bytes))
            .map_err(|e| KdubError::TailsDownload(format!("failed to parse signing key: {e}")))?;

    // Check fingerprint if expected.
    if let Some(expected_fp) = expected_fingerprint {
        let actual_fp = hex::encode_upper(public_key.fingerprint().as_bytes());
        if actual_fp != expected_fp.to_uppercase() {
            return Err(KdubError::TailsDownload(format!(
                "signing key fingerprint mismatch: expected {expected_fp}, got {actual_fp}"
            )));
        }
    }

    // Parse the detached signature.
    let (sig, _) = DetachedSignature::from_armor_single(std::io::Cursor::new(sig_bytes))
        .map_err(|e| KdubError::TailsDownload(format!("failed to parse signature: {e}")))?;

    // Try verification against the primary key first, then each subkey.
    // Tails signs ISOs with a signing subkey, not the primary key. rPGP's
    // VerifyingKey impl for SignedPublicKey only checks the primary key,
    // so we must also try each subkey explicitly.
    let mut last_err = sig.verify(&public_key, iso_bytes).err();

    if last_err.is_some() {
        for subkey in &public_key.public_subkeys {
            match sig.verify(subkey, iso_bytes) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
    } else {
        return Ok(());
    }

    Err(KdubError::TailsDownload(format!(
        "signature verification failed: {}",
        last_err.expect("at least one verification attempt was made")
    )))
}

/// Resolve the cache directory for Tails downloads.
///
/// Returns `~/.cache/kdub/tails/`, creating it (and parents) if needed.
/// Uses `directories::BaseDirs` to locate the platform cache directory.
///
/// # Errors
///
/// Returns `KdubError::TailsDownload` if the home directory cannot be
/// determined, or `KdubError::Io` if directory creation fails.
pub fn resolve_cache_dir() -> Result<PathBuf, KdubError> {
    let base = directories::BaseDirs::new()
        .ok_or_else(|| KdubError::TailsDownload("could not determine home directory".into()))?;

    let cache_dir = base.cache_dir().join("kdub").join("tails");
    fs::create_dir_all(&cache_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700))?;
    }

    Ok(cache_dir)
}

/// Build an HTTP agent, optionally routing through a SOCKS proxy.
///
/// Reads the `KDUB_TOR_PROXY` environment variable. If set to a non-empty
/// value (e.g., `socks5h://127.0.0.1:9050`), the agent routes all traffic
/// through the specified SOCKS proxy. The `socks5h://` scheme ensures DNS
/// resolution also goes through the proxy to prevent DNS leaks.
///
/// # Errors
///
/// Returns `KdubError::TailsDownload` if the proxy URL is invalid.
pub fn build_http_agent() -> Result<ureq::Agent, KdubError> {
    let proxy_url = std::env::var("KDUB_TOR_PROXY").unwrap_or_default();

    if proxy_url.is_empty() {
        debug!("building HTTP agent without proxy");
        Ok(ureq::Agent::new_with_defaults())
    } else {
        debug!(proxy = %proxy_url, "building HTTP agent with SOCKS proxy");
        let proxy = ureq::Proxy::new(&proxy_url)
            .map_err(|e| KdubError::TailsDownload(format!("invalid tor proxy: {e}")))?;
        Ok(ureq::Agent::config_builder()
            .proxy(Some(proxy))
            .build()
            .new_agent())
    }
}

/// Download and verify the latest Tails ISO.
///
/// Fetches Tails release metadata, checks the local cache, and downloads
/// the ISO image if needed. The download is verified with both SHA256
/// checksum and PGP signature against the Tails signing key.
///
/// Returns the path to the verified, cached ISO image and its release
/// metadata.
///
/// # Arguments
///
/// * `force` - If `true`, re-download even if a valid cached copy exists.
/// * `quiet` - If `true`, suppress informational output (progress callback
///   is still invoked).
/// * `progress_callback` - Optional callback invoked periodically during
///   download with `(bytes_written, total_size)`.
///
/// # Errors
///
/// Returns `KdubError::TailsDownload` on network errors, verification
/// failures, or if the signing key fingerprint does not match the
/// expected value.
pub fn download_tails_iso(
    force: bool,
    quiet: bool,
    progress_callback: Option<&dyn Fn(u64, u64)>,
) -> Result<(PathBuf, TailsRelease), KdubError> {
    // 1. Build HTTP agent (with SOCKS proxy if KDUB_TOR_PROXY is set).
    let agent = build_http_agent()?;

    // 2. Fetch latest.json and parse release metadata.
    info!("fetching Tails release metadata");
    let mut response = agent
        .get(defaults::TAILS_LATEST_JSON_URL)
        .call()
        .map_err(|e| KdubError::TailsDownload(format!("failed to fetch latest.json: {e}")))?;

    let json = response
        .body_mut()
        .read_to_string()
        .map_err(|e| KdubError::TailsDownload(format!("failed to read latest.json body: {e}")))?;

    let release = parse_latest_json(&json)?;
    debug!(version = %release.version, url = %release.img_url, "parsed release metadata");

    // 3. Resolve cache directory.
    let cache_dir = resolve_cache_dir()?;
    let img_filename = format!("tails-amd64-{}.img", release.version);
    let img_path = cache_dir.join(&img_filename);

    // 4. Check cache: if file exists AND SHA256 matches, return early.
    if !force && img_path.exists() {
        debug!(path = %img_path.display(), "checking cached ISO");
        if verify_iso_sha256(&img_path, &release.sha256).is_ok() {
            if !quiet {
                info!(version = %release.version, "already downloaded and verified");
            }
            return Ok((img_path, release));
        }
        warn!("cached ISO failed SHA256 check, re-downloading");
    }

    // 5. Download ISO to temp file with progress.
    let part_path = cache_dir.join(format!("{img_filename}.part"));
    info!(url = %release.img_url, "downloading Tails ISO");

    let mut iso_response = agent
        .get(&release.img_url)
        .call()
        .map_err(|e| KdubError::TailsDownload(format!("failed to download ISO: {e}")))?;

    let total_size = iso_response.body().content_length().unwrap_or(release.size);

    {
        let mut file = fs::File::create(&part_path)?;
        let mut reader = iso_response.body_mut().as_reader();
        let mut buf = [0u8; 64 * 1024]; // 64 KB chunks
        let mut bytes_written: u64 = 0;

        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| KdubError::TailsDownload(format!("download read error: {e}")))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            bytes_written += n as u64;

            if let Some(cb) = &progress_callback {
                cb(bytes_written, total_size);
            }
        }
        file.flush()?;
        debug!(bytes = bytes_written, "ISO download complete");
    }

    // 6. Download detached signature file.
    info!(url = %release.sig_url, "downloading detached signature");
    let mut sig_response = agent
        .get(&release.sig_url)
        .call()
        .map_err(|e| KdubError::TailsDownload(format!("failed to download signature: {e}")))?;

    let sig_bytes = sig_response
        .body_mut()
        .with_config()
        .limit(64 * 1024) // PGP detached signature is under 1 KB
        .read_to_vec()
        .map_err(|e| KdubError::TailsDownload(format!("failed to read signature body: {e}")))?;

    // 7. Verify downloads (SHA256 first — cheaper — then PGP).
    // Wrap verification + rename so .part file is cleaned up on any failure.
    let verify_result = (|| -> Result<(), KdubError> {
        let iso_file = fs::File::open(&part_path)?;
        // SAFETY: The file lives in the user's private cache directory (0o700
        // permissions set by `resolve_cache_dir`). No external process is expected
        // to modify the file during the mapped lifetime. The file was written and
        // flushed by this process in the download loop above, and no other file
        // descriptor to this path is open.
        let iso_mmap = unsafe { memmap2::Mmap::map(&iso_file) }.map_err(|e| {
            KdubError::TailsDownload(format!("failed to memory-map ISO for verification: {e}"))
        })?;

        // 7a. Verify SHA256 matches latest.json checksum (cheap, do first).
        info!("verifying SHA256 checksum");
        let computed = hex::encode(Sha256::digest(&iso_mmap));
        let expected_lower = release.sha256.to_lowercase();
        if computed != expected_lower {
            return Err(KdubError::TailsDownload(format!(
                "SHA256 mismatch: expected {expected_lower}, got {computed}"
            )));
        }

        // 7b. Verify detached PGP signature on ISO (uses embedded signing key).
        info!("verifying PGP signature");
        verify_iso_signature(
            &iso_mmap,
            &sig_bytes,
            defaults::TAILS_SIGNING_KEY,
            Some(defaults::TAILS_SIGNING_KEY_FINGERPRINT),
        )?;

        // 7c. Rename .img.part to .img (atomic on same filesystem).
        drop(iso_mmap);
        drop(iso_file);
        fs::rename(&part_path, &img_path)?;
        debug!(path = %img_path.display(), "renamed part file to final path");

        Ok(())
    })();

    if verify_result.is_err()
        && let Err(e) = fs::remove_file(&part_path)
    {
        debug!(error = %e, "failed to clean up partial download");
    }
    verify_result?;

    // 12. Clean up old cached versions.
    cleanup_old_versions(&cache_dir, &img_filename);

    if !quiet {
        info!(version = %release.version, path = %img_path.display(), "download complete and verified");
    }

    // 13. Return path + release info.
    Ok((img_path, release))
}

/// Remove old Tails IMG files from the cache directory.
///
/// Deletes any `tails-amd64-*.img` file in `cache_dir` that does not
/// match `keep_filename`. Errors during deletion are logged at debug
/// level but do not fail the overall operation.
fn cleanup_old_versions(cache_dir: &Path, keep_filename: &str) {
    let entries = match fs::read_dir(cache_dir) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, "could not read cache dir for cleanup");
            return;
        }
    };

    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("tails-amd64-")
            && name_str.ends_with(".img")
            && *name_str != *keep_filename
        {
            debug!(file = %name_str, "removing old cached version");
            if let Err(e) = fs::remove_file(entry.path()) {
                debug!(error = %e, file = %name_str, "failed to remove old cached version");
            }
        }
    }
}

/// Find the most recent `tails-amd64-*.img` file in a cache directory.
///
/// Scans `cache_dir` for files matching the Tails IMG naming pattern
/// and returns the one with the most recent modification time, or `None`
/// if no matching files exist.
pub fn find_cached_iso(cache_dir: &Path) -> Option<PathBuf> {
    let entries = match fs::read_dir(cache_dir) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, path = ?cache_dir, "cannot read cache directory for ISO lookup");
            return None;
        }
    };

    entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            name_str.starts_with("tails-amd64-") && name_str.ends_with(".img")
        })
        .max_by_key(|entry| {
            entry
                .metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
        })
        .map(|entry| entry.path())
}

/// Maximum expected size for a kdub CLI binary archive (50 MB).
const MAX_BINARY_ARCHIVE_SIZE: u64 = 50 * 1024 * 1024;

/// Download, verify, and extract a signed kdub binary archive for cross-architecture use.
///
/// For aarch64 hosts preparing Tails persistence, downloads the x86_64 kdub
/// binary from the given GitHub release URL, verifies its zipsign ed25519ph
/// signature, extracts the `kdub` binary, and sets executable permissions.
///
/// The binary is cached in the kdub cache directory as `kdub-linux-amd64`.
/// The archive is automatically cleaned up after extraction or on verification failure.
///
/// # Errors
///
/// Returns `KdubError::TailsPersist` for download, verification, or extraction failures.
pub fn download_and_verify_kdub_binary(
    download_url: &str,
    public_key: [u8; 32],
    quiet: bool,
) -> Result<PathBuf, KdubError> {
    let cache_dir = resolve_cache_dir()?;
    let archive_path = cache_dir.join("kdub-linux-amd64.tar.gz");
    let target_path = cache_dir.join("kdub-linux-amd64");

    // 1. Download the signed tar.gz archive.
    if !quiet {
        eprintln!("Downloading x86_64 kdub binary for Tails...");
    }
    info!(url = %download_url, "downloading signed kdub archive");
    let agent = build_http_agent()?;
    let response = agent
        .get(download_url)
        .call()
        .map_err(|e| KdubError::TailsPersist(format!("failed to download kdub archive: {e}")))?;

    let mut file = fs::File::create(&archive_path)?;
    let mut body = response.into_body();
    let mut reader = body.as_reader().take(MAX_BINARY_ARCHIVE_SIZE);
    let bytes_copied = std::io::copy(&mut reader, &mut file)?;
    drop(file);
    if bytes_copied >= MAX_BINARY_ARCHIVE_SIZE {
        if let Err(e) = fs::remove_file(&archive_path) {
            warn!(error = %e, path = %archive_path.display(), "failed to clean up oversized archive");
        }
        return Err(KdubError::TailsPersist(format!(
            "archive exceeds maximum expected size ({} MB)",
            MAX_BINARY_ARCHIVE_SIZE / (1024 * 1024)
        )));
    }
    debug!(path = %archive_path.display(), bytes = bytes_copied, "archive downloaded");

    // 2. Verify the zipsign ed25519ph signature embedded in the archive.
    if !quiet {
        eprintln!("Verifying binary signature...");
    }
    info!("verifying zipsign signature");
    let keys = zipsign_api::verify::collect_keys([Ok(public_key)])
        .map_err(|e| KdubError::TailsPersist(format!("invalid signing key: {e}")))?;
    let mut archive_file = fs::File::open(&archive_path)?;
    zipsign_api::verify::verify_tar(&mut archive_file, &keys, None).map_err(|e| {
        if let Err(rm_err) = fs::remove_file(&archive_path) {
            warn!(error = %rm_err, path = %archive_path.display(), "failed to clean up archive after verification failure");
        }
        KdubError::TailsPersist(format!("kdub binary signature verification failed: {e}"))
    })?;
    debug!("signature verification passed");

    // 3. Extract the kdub binary from the verified archive.
    debug!("extracting kdub binary from archive");
    let archive_file = fs::File::open(&archive_path)?;
    let gz = flate2::read::GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(gz);
    let mut found = false;
    for entry in archive
        .entries()
        .map_err(|e| KdubError::TailsPersist(format!("failed to read archive: {e}")))?
    {
        let mut entry = entry
            .map_err(|e| KdubError::TailsPersist(format!("failed to read archive entry: {e}")))?;
        let is_kdub = entry
            .path()
            .ok()
            .is_some_and(|p| p.file_name() == Some(std::ffi::OsStr::new("kdub")));
        if is_kdub {
            entry.unpack(&target_path).map_err(|e| {
                KdubError::TailsPersist(format!("failed to extract kdub binary: {e}"))
            })?;
            debug!(path = %target_path.display(), "kdub binary extracted");
            found = true;
            break;
        }
    }
    if !found {
        if let Err(e) = fs::remove_file(&archive_path) {
            warn!(error = %e, path = %archive_path.display(), "failed to clean up archive after extraction failure");
        }
        return Err(KdubError::TailsPersist(
            "kdub binary not found in archive".into(),
        ));
    }

    // 4. Clean up archive and set executable permissions.
    if let Err(e) = fs::remove_file(&archive_path) {
        debug!(error = %e, path = %archive_path.display(), "failed to clean up archive after successful extraction");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target_path, fs::Permissions::from_mode(0o755))?;
    }

    Ok(target_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fingerprint of the test fixture signing key.
    const TEST_FINGERPRINT: &str = "0C76990839169079C5B60AAEFAFE79FB89205B26";

    /// Minimal valid latest.json matching the real Tails format.
    const FIXTURE_JSON: &str = r#"{
        "build_target": "amd64",
        "channel": "stable",
        "installations": [
            {
                "installation-paths": [
                    {
                        "target-files": [
                            {
                                "sha256": "c805de0c57b7b8bdec67d41e3432aca5a12ebae44a51cc320a7dc602a83005d0",
                                "size": 2041577472,
                                "url": "https://download.tails.net/tails/stable/tails-amd64-7.5/tails-amd64-7.5.img"
                            }
                        ],
                        "type": "img"
                    },
                    {
                        "target-files": [
                            {
                                "sha256": "3aa15d0cd26a812270ae2904abcdb18960ee5d7edbfd933116db946068f7c085",
                                "size": 2031644672,
                                "url": "https://download.tails.net/tails/stable/tails-amd64-7.5/tails-amd64-7.5.iso"
                            }
                        ],
                        "type": "iso"
                    }
                ],
                "version": "7.5"
            }
        ],
        "product-name": "Tails"
    }"#;

    #[test]
    fn parse_latest_json_valid() {
        let release = parse_latest_json(FIXTURE_JSON).unwrap();
        assert_eq!(release.version, "7.5");
        assert_eq!(
            release.img_url,
            "https://download.tails.net/tails/stable/tails-amd64-7.5/tails-amd64-7.5.img"
        );
        assert_eq!(
            release.sig_url,
            "https://tails.net/torrents/files/tails-amd64-7.5.img.sig"
        );
        assert_eq!(
            release.sha256,
            "c805de0c57b7b8bdec67d41e3432aca5a12ebae44a51cc320a7dc602a83005d0"
        );
        assert_eq!(release.size, 2041577472);
    }

    #[test]
    fn parse_latest_json_invalid_json() {
        let result = parse_latest_json("not json");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid JSON"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_missing_installations() {
        let result = parse_latest_json(r#"{"product-name": "Tails"}"#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("installations"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_empty_installations() {
        let result = parse_latest_json(r#"{"installations": []}"#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_no_img_type() {
        let json = r#"{
            "installations": [{
                "version": "7.5",
                "installation-paths": [{
                    "target-files": [{"sha256": "abc", "size": 100, "url": "https://example.com/file.iso"}],
                    "type": "iso"
                }]
            }]
        }"#;
        let result = parse_latest_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("img"), "got: {err}");
    }

    #[test]
    fn verify_sha256_correct() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("testfile.bin");
        let content = b"known test content for sha256";
        fs::write(&file_path, content).unwrap();

        let expected = hex::encode(Sha256::digest(content));
        let result = verify_iso_sha256(&file_path, &expected);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_sha256_correct_uppercase() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("testfile.bin");
        let content = b"known test content for sha256";
        fs::write(&file_path, content).unwrap();

        let expected = hex::encode_upper(Sha256::digest(content));
        let result = verify_iso_sha256(&file_path, &expected);
        assert!(result.is_ok());
    }

    #[test]
    fn verify_sha256_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("empty.bin");
        fs::write(&file_path, b"").unwrap();
        let expected = hex::encode(Sha256::digest(b""));
        assert!(verify_iso_sha256(&file_path, &expected).is_ok());
    }

    #[test]
    fn verify_sha256_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("testfile.bin");
        fs::write(&file_path, b"actual content").unwrap();

        let wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        let result = verify_iso_sha256(&file_path, wrong_hash);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("SHA256 mismatch"), "got: {err}");
    }

    #[test]
    fn verify_sha256_missing_file() {
        let result = verify_iso_sha256(Path::new("/nonexistent/file"), "abc");
        assert!(result.is_err());
    }

    #[test]
    fn verify_signature_valid() {
        let key_bytes = include_bytes!("../tests/fixtures/test_tails_signer.asc");
        let data = include_bytes!("../tests/fixtures/test_iso.bin");
        let sig = include_bytes!("../tests/fixtures/test_iso.bin.sig");

        let result = verify_iso_signature(data, sig, key_bytes, Some(TEST_FINGERPRINT));
        assert!(result.is_ok(), "signature verification should succeed");
    }

    #[test]
    fn verify_signature_valid_no_fingerprint_check() {
        let key_bytes = include_bytes!("../tests/fixtures/test_tails_signer.asc");
        let data = include_bytes!("../tests/fixtures/test_iso.bin");
        let sig = include_bytes!("../tests/fixtures/test_iso.bin.sig");

        let result = verify_iso_signature(data, sig, key_bytes, None);
        assert!(
            result.is_ok(),
            "verification without fingerprint check should succeed"
        );
    }

    #[test]
    fn verify_signature_wrong_data() {
        let key_bytes = include_bytes!("../tests/fixtures/test_tails_signer.asc");
        let sig = include_bytes!("../tests/fixtures/test_iso.bin.sig");
        let wrong_data = b"this is not the original content";

        let result = verify_iso_signature(wrong_data, sig, key_bytes, Some(TEST_FINGERPRINT));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("signature verification failed"), "got: {err}");
    }

    #[test]
    fn verify_signature_wrong_fingerprint() {
        let key_bytes = include_bytes!("../tests/fixtures/test_tails_signer.asc");
        let data = include_bytes!("../tests/fixtures/test_iso.bin");
        let sig = include_bytes!("../tests/fixtures/test_iso.bin.sig");
        let wrong_fp = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let result = verify_iso_signature(data, sig, key_bytes, Some(wrong_fp));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("fingerprint mismatch"), "got: {err}");
    }

    #[test]
    fn verify_signature_bad_key() {
        let data = include_bytes!("../tests/fixtures/test_iso.bin");
        let sig = include_bytes!("../tests/fixtures/test_iso.bin.sig");

        let result = verify_iso_signature(data, sig, b"not a PGP key", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to parse signing key"), "got: {err}");
    }

    #[test]
    fn verify_signature_bad_sig() {
        let key_bytes = include_bytes!("../tests/fixtures/test_tails_signer.asc");
        let data = include_bytes!("../tests/fixtures/test_iso.bin");

        let result = verify_iso_signature(data, b"not a PGP sig", key_bytes, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to parse signature"), "got: {err}");
    }

    #[test]
    fn verify_signature_wrong_data_with_subkeys() {
        // The embedded Tails key has subkeys. Verification against wrong data
        // should fail for the primary key AND all subkeys, returning an error.
        // This exercises the subkey fallback loop's error path.
        let key_bytes = defaults::TAILS_SIGNING_KEY;
        let sig = include_bytes!("../tests/fixtures/test_iso.bin.sig");
        let wrong_data = b"this data was not signed by any Tails key";

        let result = verify_iso_signature(wrong_data, sig, key_bytes, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("signature verification failed"),
            "should report verification failure after trying all subkeys, got: {err}"
        );
    }

    /// Verify the embedded production Tails signing key parses correctly,
    /// has the expected primary fingerprint, and contains signing-capable
    /// subkeys. This catches key truncation or bad minimization that would
    /// break ISO verification at runtime.
    #[test]
    fn embedded_tails_signing_key_has_signing_subkeys() {
        use pgp::types::KeyDetails;

        let key_bytes = defaults::TAILS_SIGNING_KEY;
        let (public_key, _) = SignedPublicKey::from_armor_single(std::io::Cursor::new(key_bytes))
            .expect("embedded Tails signing key should parse");

        // Primary key fingerprint matches the hardcoded constant.
        let fp = hex::encode_upper(public_key.fingerprint().as_bytes());
        assert_eq!(
            fp,
            defaults::TAILS_SIGNING_KEY_FINGERPRINT,
            "embedded key fingerprint should match TAILS_SIGNING_KEY_FINGERPRINT"
        );

        // Key must have subkeys. A key with 0 subkeys means it was
        // over-minimized and can't verify ISO signatures (which are
        // made by subkeys, not the primary key).
        assert!(
            !public_key.public_subkeys.is_empty(),
            "embedded key must have subkeys for signature verification; \
             got 0 subkeys — key may have been over-minimized"
        );

        // The subkey that signs current Tails releases (as of 2026-03).
        // If Tails rotates to a new subkey, update this constant.
        // The subkeys-exist assertion above still catches truncation regardless.
        let current_signing_subkey_fp = "A013A001BEDF1AFADF0B0B3AE26AE7BE8FA5B8D1";
        let subkey_fps: Vec<String> = public_key
            .public_subkeys
            .iter()
            .map(|sk| hex::encode_upper(sk.fingerprint().as_bytes()))
            .collect();
        assert!(
            subkey_fps.iter().any(|f| f == current_signing_subkey_fp),
            "embedded key should contain current signing subkey {current_signing_subkey_fp}; \
             found subkeys: {subkey_fps:?}"
        );
    }

    #[test]
    fn parse_latest_json_missing_version() {
        let json = r#"{
            "installations": [{
                "installation-paths": [{
                    "target-files": [{"sha256": "abc", "size": 100, "url": "https://example.com/file.img"}],
                    "type": "img"
                }]
            }]
        }"#;
        let result = parse_latest_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("version"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_missing_target_files() {
        let json = r#"{
            "installations": [{
                "version": "7.5",
                "installation-paths": [{
                    "type": "img"
                }]
            }]
        }"#;
        let result = parse_latest_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("target-files"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_missing_url() {
        let json = r#"{
            "installations": [{
                "version": "7.5",
                "installation-paths": [{
                    "target-files": [{"sha256": "abc", "size": 100}],
                    "type": "img"
                }]
            }]
        }"#;
        let result = parse_latest_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("url"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_missing_sha256() {
        let json = r#"{
            "installations": [{
                "version": "7.5",
                "installation-paths": [{
                    "target-files": [{"url": "https://example.com/tails.img", "size": 100}],
                    "type": "img"
                }]
            }]
        }"#;
        let result = parse_latest_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("sha256"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_missing_size() {
        let json = r#"{
            "installations": [{
                "version": "7.5",
                "installation-paths": [{
                    "target-files": [{"url": "https://example.com/tails.img", "sha256": "abc"}],
                    "type": "img"
                }]
            }]
        }"#;
        let result = parse_latest_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("size"), "got: {err}");
    }

    #[test]
    fn parse_latest_json_missing_installation_paths() {
        let json = r#"{
            "installations": [{
                "version": "7.5"
            }]
        }"#;
        let result = parse_latest_json(json);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("installation-paths"), "got: {err}");
    }

    #[test]
    fn find_cached_iso_none_when_empty() {
        let dir = tempfile::tempdir().unwrap();
        let result = find_cached_iso(dir.path());
        assert!(result.is_none());
    }

    #[test]
    fn find_cached_iso_finds_matching_file() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("tails-amd64-7.5.img");
        fs::write(&img_path, b"fake iso").unwrap();

        let result = find_cached_iso(dir.path());
        assert!(result.is_some());
        assert_eq!(result.unwrap(), img_path);
    }

    #[test]
    fn find_cached_iso_ignores_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("README.txt"), b"not an iso").unwrap();
        fs::write(dir.path().join("tails-amd64-7.5.img.part"), b"partial").unwrap();

        let result = find_cached_iso(dir.path());
        assert!(result.is_none());
    }

    #[test]
    fn find_cached_iso_nonexistent_dir_returns_none() {
        let result = find_cached_iso(std::path::Path::new(
            "/nonexistent/path/that/does/not/exist",
        ));
        assert!(result.is_none());
    }

    #[test]
    fn find_cached_iso_none_when_nonexistent() {
        let result = find_cached_iso(Path::new("/nonexistent/cache/dir"));
        assert!(result.is_none());
    }

    #[test]
    fn find_cached_iso_finds_img() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("tails-amd64-7.5.img");
        fs::write(&img_path, b"fake img").unwrap();

        let result = find_cached_iso(dir.path());
        assert_eq!(result, Some(img_path));
    }

    #[test]
    fn find_cached_iso_ignores_non_img() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("tails-amd64-7.5.iso"), b"iso").unwrap();
        fs::write(dir.path().join("something-else.img"), b"other").unwrap();
        fs::write(dir.path().join("readme.txt"), b"text").unwrap();

        let result = find_cached_iso(dir.path());
        assert!(result.is_none());
    }

    #[test]
    fn find_cached_iso_returns_most_recent() {
        let dir = tempfile::tempdir().unwrap();

        let old_path = dir.path().join("tails-amd64-7.4.img");
        fs::write(&old_path, b"old img").unwrap();

        // Small delay to ensure different modification times.
        std::thread::sleep(std::time::Duration::from_millis(50));

        let new_path = dir.path().join("tails-amd64-7.5.img");
        fs::write(&new_path, b"new img").unwrap();

        let result = find_cached_iso(dir.path());
        assert_eq!(result, Some(new_path));
    }

    #[test]
    fn resolve_cache_dir_creates_directory() {
        // This test uses the real home directory, so just verify
        // it returns a path ending in kdub/tails.
        let cache_dir = resolve_cache_dir().unwrap();
        assert!(cache_dir.ends_with("kdub/tails"));
        assert!(cache_dir.exists());
    }

    #[test]
    fn tails_release_clone() {
        let release = parse_latest_json(FIXTURE_JSON).unwrap();
        let cloned = release.clone();
        assert_eq!(cloned.version, release.version);
        assert_eq!(cloned.img_url, release.img_url);
        assert_eq!(cloned.sig_url, release.sig_url);
        assert_eq!(cloned.sha256, release.sha256);
        assert_eq!(cloned.size, release.size);
    }

    #[test]
    fn tails_release_debug() {
        let release = parse_latest_json(FIXTURE_JSON).unwrap();
        let debug = format!("{release:?}");
        assert!(debug.contains("TailsRelease"));
        assert!(debug.contains("7.5"));
    }

    #[test]
    fn build_http_agent_no_proxy() {
        // Ensure KDUB_TOR_PROXY is not set for this test.
        // SAFETY: nextest runs each test in its own process, so mutating env vars is safe.
        unsafe { std::env::remove_var("KDUB_TOR_PROXY") };
        let agent = build_http_agent();
        assert!(agent.is_ok(), "should build agent without proxy");
    }

    #[test]
    fn build_http_agent_with_proxy() {
        // SAFETY: nextest runs each test in its own process, so mutating env vars is safe.
        unsafe { std::env::set_var("KDUB_TOR_PROXY", "socks5h://127.0.0.1:9050") };
        let agent = build_http_agent();
        assert!(agent.is_ok(), "should build agent with proxy config");
        unsafe { std::env::remove_var("KDUB_TOR_PROXY") };
    }

    #[test]
    fn build_http_agent_empty_proxy() {
        // SAFETY: nextest runs each test in its own process, so mutating env vars is safe.
        unsafe { std::env::set_var("KDUB_TOR_PROXY", "") };
        let agent = build_http_agent();
        assert!(
            agent.is_ok(),
            "should build agent when proxy is empty string"
        );
        unsafe { std::env::remove_var("KDUB_TOR_PROXY") };
    }

    #[test]
    fn cleanup_old_versions_removes_stale() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("tails-amd64-7.4.img");
        let current = dir.path().join("tails-amd64-7.5.img");
        let unrelated = dir.path().join("notes.txt");

        fs::write(&old, b"old").unwrap();
        fs::write(&current, b"current").unwrap();
        fs::write(&unrelated, b"notes").unwrap();

        cleanup_old_versions(dir.path(), "tails-amd64-7.5.img");

        assert!(!old.exists(), "old version should be removed");
        assert!(current.exists(), "current version should be kept");
        assert!(unrelated.exists(), "unrelated files should be kept");
    }

    #[test]
    fn cleanup_old_versions_no_crash_on_missing_dir() {
        // Should not panic when the directory does not exist.
        cleanup_old_versions(Path::new("/nonexistent/cache/dir"), "keep.img");
    }

    #[test]
    fn macos_arm64_warning_snapshot() {
        insta::assert_snapshot!(MACOS_ARM64_WARNING);
    }

    #[test]
    fn cache_hit_path_skips_download() {
        let dir = tempfile::tempdir().unwrap();
        let img_path = dir.path().join("tails-amd64-7.5.img");
        let content = b"simulated tails image content for cache hit test";
        fs::write(&img_path, content).unwrap();

        let expected_hash = hex::encode(Sha256::digest(content));

        // find_cached_iso should locate the file.
        let found = find_cached_iso(dir.path());
        assert_eq!(found, Some(img_path.clone()));

        // verify_iso_sha256 should pass with the correct hash.
        let result = verify_iso_sha256(&img_path, &expected_hash);
        assert!(
            result.is_ok(),
            "cache-hit verification should pass: {result:?}"
        );
    }

    #[test]
    #[ignore] // requires network
    fn tails_download_fetches_latest_json() {
        let agent = build_http_agent().unwrap();
        let mut response = agent
            .get(crate::defaults::TAILS_LATEST_JSON_URL)
            .call()
            .unwrap();
        let body = response.body_mut().read_to_string().unwrap();
        let release = parse_latest_json(&body).unwrap();
        assert!(!release.version.is_empty());
        assert!(release.img_url.starts_with("https://"));
        assert!(!release.sha256.is_empty());
    }
}
