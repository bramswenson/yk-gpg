use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::KdubError;
use crate::types::Fingerprint;

/// Metadata for a managed OpenPGP identity, persisted as JSON.
///
/// Stored at `$DATA_DIR/identities/<fingerprint>.json` (mode 0600).
/// This is the single source of truth for identity lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityMetadata {
    /// User ID string, e.g. "Name <email>"
    pub identity: String,
    /// V4 primary key fingerprint (validated 20-byte / 40-hex-char value).
    pub fingerprint: Fingerprint,
    /// Key algorithm: "ed25519" or "rsa4096"
    pub key_type: String,
    /// When the key was created
    pub created: DateTime<Utc>,
    /// When the key was last backed up
    pub backed_up: Option<DateTime<Utc>>,
    /// When subkeys were last renewed (expiration extended)
    pub renewed: Option<DateTime<Utc>>,
    /// When subkeys were last rotated (new subkeys generated)
    pub rotated: Option<DateTime<Utc>>,
    /// Serial number of the smart card holding the subkeys
    pub card_serial: Option<String>,
    /// When subkeys were provisioned to a smart card
    pub provisioned: Option<DateTime<Utc>>,
}

impl IdentityMetadata {
    /// Save metadata to `$DATA_DIR/identities/<fingerprint>.json`.
    ///
    /// Creates the `identities/` subdirectory if it doesn't exist.
    /// File permissions are set to 0600.
    pub fn save(&self, data_dir: &Path) -> Result<(), KdubError> {
        let dir = data_dir.join("identities");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", self.fingerprint));
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| KdubError::Config(format!("failed to serialize identity: {e}")))?;
        fs::write(&path, &json)?;
        set_file_permissions(&path, 0o600)?;
        Ok(())
    }

    /// Load metadata for a specific fingerprint from `$DATA_DIR/identities/`.
    pub fn load(data_dir: &Path, fingerprint: &Fingerprint) -> Result<Self, KdubError> {
        let path = data_dir
            .join("identities")
            .join(format!("{fingerprint}.json"));
        let json = fs::read_to_string(&path)?;
        let meta: Self = serde_json::from_str(&json)
            .map_err(|e| KdubError::Config(format!("failed to parse identity metadata: {e}")))?;
        Ok(meta)
    }

    /// Load all identity metadata files from `$DATA_DIR/identities/`.
    ///
    /// Returns an empty vec if the directory doesn't exist.
    /// Skips files that fail to parse (logs a warning).
    pub fn load_all(data_dir: &Path) -> Result<Vec<Self>, KdubError> {
        let dir = data_dir.join("identities");
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut identities = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match fs::read_to_string(&path) {
                Ok(json) => match serde_json::from_str::<Self>(&json) {
                    Ok(meta) => identities.push(meta),
                    Err(e) => {
                        tracing::warn!("skipping {}: {e}", path.display());
                    }
                },
                Err(e) => {
                    tracing::warn!("skipping {}: {e}", path.display());
                }
            }
        }
        Ok(identities)
    }
}

/// Find an identity by query string (fingerprint, key ID, name, or email).
///
/// Search order:
/// 1. Exact fingerprint match (case-insensitive)
/// 2. Fingerprint prefix match (at least 8 chars)
/// 3. Key ID match (with or without 0x prefix)
/// 4. Substring match on identity string (name or email)
///
/// Returns an error if zero or more than one identity matches.
pub fn find_identity(data_dir: &Path, query: &str) -> Result<IdentityMetadata, KdubError> {
    let all = IdentityMetadata::load_all(data_dir)?;
    if all.is_empty() {
        return Err(KdubError::KeyNotFound(format!(
            "no managed identities found in {}",
            data_dir.display()
        )));
    }

    let query_normalized = query.trim();
    let query_upper = query_normalized.to_ascii_uppercase();
    let query_hex = query_upper.strip_prefix("0X").unwrap_or(&query_upper);

    // 1. Exact fingerprint match (case-insensitive)
    let exact: Vec<_> = all
        .iter()
        .filter(|m| m.fingerprint.to_string() == query_hex)
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0].clone());
    }

    // 2. Fingerprint prefix match (at least 8 hex chars)
    if query_hex.len() >= 8 && query_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let prefix_matches: Vec<_> = all
            .iter()
            .filter(|m| m.fingerprint.to_string().starts_with(query_hex))
            .collect();
        if prefix_matches.len() == 1 {
            return Ok(prefix_matches[0].clone());
        }
        if prefix_matches.len() > 1 {
            return Err(KdubError::AmbiguousIdentity(format!(
                "fingerprint prefix '{query_normalized}' matches {} identities",
                prefix_matches.len()
            )));
        }
    }

    // 3. Key ID match (last 16 hex chars of fingerprint, with or without 0x prefix)
    if query_hex.len() >= 8 && query_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        let keyid_matches: Vec<_> = all
            .iter()
            .filter(|m| m.fingerprint.to_string().ends_with(query_hex))
            .collect();
        if keyid_matches.len() == 1 {
            return Ok(keyid_matches[0].clone());
        }
        if keyid_matches.len() > 1 {
            return Err(KdubError::AmbiguousIdentity(format!(
                "key ID '{query_normalized}' matches {} identities",
                keyid_matches.len()
            )));
        }
    }

    // 4. Substring match on identity string (name or email)
    let query_lower = query_normalized.to_lowercase();
    let name_matches: Vec<_> = all
        .iter()
        .filter(|m| m.identity.to_lowercase().contains(&query_lower))
        .collect();
    if name_matches.len() == 1 {
        return Ok(name_matches[0].clone());
    }
    if name_matches.len() > 1 {
        return Err(KdubError::AmbiguousIdentity(format!(
            "'{query_normalized}' matches {} identities",
            name_matches.len()
        )));
    }

    Err(KdubError::KeyNotFound(format!(
        "no identity found matching '{query_normalized}'"
    )))
}

/// Set Unix file permissions (mode).
fn set_file_permissions(path: &Path, mode: u32) -> Result<(), KdubError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata(fingerprint: &str) -> IdentityMetadata {
        IdentityMetadata {
            identity: "Test User <test@example.com>".to_string(),
            fingerprint: fingerprint.parse::<Fingerprint>().unwrap(),
            key_type: "ed25519".to_string(),
            created: Utc::now(),
            backed_up: None,
            renewed: None,
            rotated: None,
            card_serial: None,
            provisioned: None,
        }
    }

    #[test]
    fn test_metadata_save_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let fp_str = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        let fp: Fingerprint = fp_str.parse().unwrap();
        let meta = sample_metadata(fp_str);
        meta.save(data_dir).unwrap();

        let loaded = IdentityMetadata::load(data_dir, &fp).unwrap();
        assert_eq!(meta.identity, loaded.identity);
        assert_eq!(meta.fingerprint.to_string(), loaded.fingerprint.to_string());
        assert_eq!(meta.key_type, loaded.key_type);
    }

    #[test]
    fn test_metadata_save_creates_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join("nonexistent");

        let meta = sample_metadata("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        meta.save(&data_dir).unwrap();

        assert!(data_dir.join("identities").exists());
    }

    #[test]
    fn test_metadata_save_file_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let fp = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        let meta = sample_metadata(fp);
        meta.save(data_dir).unwrap();

        let path = data_dir.join("identities").join(format!("{fp}.json"));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn test_metadata_load_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        // Valid fingerprint format but no file exists
        let fp: Fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap();
        let result = IdentityMetadata::load(tmp.path(), &fp);
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_load_all() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let meta1 = sample_metadata("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        let meta2 = sample_metadata("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
        meta1.save(data_dir).unwrap();
        meta2.save(data_dir).unwrap();

        let all = IdentityMetadata::load_all(data_dir).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_metadata_load_all_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let all = IdentityMetadata::load_all(tmp.path()).unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn test_metadata_load_all_skips_non_json() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let meta = sample_metadata("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
        meta.save(data_dir).unwrap();

        // Create a non-JSON file in identities dir
        fs::write(data_dir.join("identities").join("readme.txt"), "not json").unwrap();

        let all = IdentityMetadata::load_all(data_dir).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_find_identity_by_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let fp = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        let meta = IdentityMetadata {
            identity: "Alice Smith <alice@example.com>".to_string(),
            ..sample_metadata(fp)
        };
        meta.save(data_dir).unwrap();

        let found = find_identity(data_dir, fp).unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);

        // Case-insensitive
        let found = find_identity(data_dir, &fp.to_lowercase()).unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);
    }

    #[test]
    fn test_find_identity_by_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let fp = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        let meta = IdentityMetadata {
            identity: "Alice Smith <alice@example.com>".to_string(),
            ..sample_metadata(fp)
        };
        meta.save(data_dir).unwrap();

        let found = find_identity(data_dir, "D3B9C00B").unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);

        // With 0x prefix
        let found = find_identity(data_dir, "0xD3B9C00B").unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);
    }

    #[test]
    fn test_find_identity_by_name() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let fp = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        let meta = IdentityMetadata {
            identity: "Alice Smith <alice@example.com>".to_string(),
            ..sample_metadata(fp)
        };
        meta.save(data_dir).unwrap();

        let found = find_identity(data_dir, "Alice Smith").unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);

        // Email match
        let found = find_identity(data_dir, "alice@example.com").unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);

        // Case-insensitive
        let found = find_identity(data_dir, "alice smith").unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);
    }

    #[test]
    fn test_find_identity_ambiguous() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let meta1 = IdentityMetadata {
            identity: "Alice Smith <alice@example.com>".to_string(),
            ..sample_metadata("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        };
        let meta2 = IdentityMetadata {
            identity: "Alice Jones <alice@other.com>".to_string(),
            ..sample_metadata("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        };
        meta1.save(data_dir).unwrap();
        meta2.save(data_dir).unwrap();

        let result = find_identity(data_dir, "Alice");
        assert!(result.is_err());
        match result.unwrap_err() {
            KdubError::AmbiguousIdentity(msg) => {
                assert!(msg.contains("2 identities"), "got: {msg}");
            }
            other => panic!("expected AmbiguousIdentity, got: {other}"),
        }
    }

    #[test]
    fn test_find_identity_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let meta = sample_metadata("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        meta.save(data_dir).unwrap();

        let result = find_identity(data_dir, "nonexistent");
        assert!(result.is_err());
        match result.unwrap_err() {
            KdubError::KeyNotFound(msg) => {
                assert!(msg.contains("nonexistent"), "got: {msg}");
            }
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn test_find_identity_empty_store() {
        let tmp = tempfile::tempdir().unwrap();
        let result = find_identity(tmp.path(), "anything");
        assert!(result.is_err());
        match result.unwrap_err() {
            KdubError::KeyNotFound(msg) => {
                assert!(msg.contains("no managed identities"), "got: {msg}");
            }
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn test_find_identity_by_key_id_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let fp = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        let meta = IdentityMetadata {
            identity: "Alice Smith <alice@example.com>".to_string(),
            ..sample_metadata(fp)
        };
        meta.save(data_dir).unwrap();

        // Last 16 chars (key ID)
        let found = find_identity(data_dir, "0630571A396BC2A7").unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);

        // With 0x prefix
        let found = find_identity(data_dir, "0x0630571A396BC2A7").unwrap();
        assert_eq!(found.fingerprint.to_string(), fp);
    }

    #[test]
    fn test_metadata_serialization_format() {
        let meta = sample_metadata("D3B9C00B365DC5B752A6554A0630571A396BC2A7");
        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("\"identity\""));
        assert!(json.contains("\"fingerprint\""));
        assert!(json.contains("\"key_type\""));
        assert!(json.contains("\"created\""));
    }
}
