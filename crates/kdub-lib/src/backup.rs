use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use pgp::composed::{Deserializable, SignedPublicKey};

use crate::error::KdubError;
use crate::identity::IdentityMetadata;
use crate::keygen::SignedSecretKey;
use crate::types::Fingerprint;

/// Run a key backup: export all key files to `$DATA_DIR/backups/$FINGERPRINT/`.
///
/// Creates five files:
/// - `certify-key.asc` — armored secret certify (primary) key
/// - `subkeys.asc` — armored secret subkeys (full secret key export)
/// - `public-key.asc` — armored public key
/// - `ownertrust.txt` — GPG ownertrust format for import compatibility
/// - `revocation-cert.asc` — revocation certificate (primary public key + revocation signature)
///
/// All files mode 0600, backup directory mode 0700.
///
/// `passphrase` is needed to unlock the primary key for signing the revocation certificate.
/// If `None`, the revocation cert falls back to a placeholder with instructions.
///
/// Returns a list of action strings describing what was created.
pub fn run_backup(
    data_dir: &Path,
    fingerprint: &Fingerprint,
    key: &SignedSecretKey,
    passphrase: Option<&str>,
) -> Result<Vec<String>, KdubError> {
    let backup_dir = data_dir.join("backups").join(fingerprint.to_string());
    fs::create_dir_all(&backup_dir)?;
    set_dir_permissions(&backup_dir, 0o700)?;

    let mut actions = Vec::new();

    // 1. certify-key.asc — full armored secret key (contains certify primary + subkeys)
    let certify_armored = key
        .to_armored_string(Default::default())
        .map_err(|e| KdubError::Backup(format!("failed to export certify key: {e}")))?;
    let certify_path = backup_dir.join("certify-key.asc");
    fs::write(&certify_path, &certify_armored)?;
    set_file_permissions(&certify_path, 0o600)?;
    actions.push(format!("Created {}", certify_path.display()));

    // 2. subkeys.asc — armored secret key (same full export; rPGP does not support
    //    exporting subkeys separately without the primary key, so we export the full
    //    key bundle which contains all subkeys)
    let subkeys_path = backup_dir.join("subkeys.asc");
    fs::write(&subkeys_path, &certify_armored)?;
    set_file_permissions(&subkeys_path, 0o600)?;
    actions.push(format!("Created {}", subkeys_path.display()));

    // 3. public-key.asc — armored public key
    let public_key: SignedPublicKey = key.to_public_key();
    let public_armored = public_key
        .to_armored_string(Default::default())
        .map_err(|e| KdubError::Backup(format!("failed to export public key: {e}")))?;
    let public_path = backup_dir.join("public-key.asc");
    fs::write(&public_path, &public_armored)?;
    set_file_permissions(&public_path, 0o600)?;
    actions.push(format!("Created {}", public_path.display()));

    // 4. ownertrust.txt — GPG ownertrust format (ultimate trust)
    let ownertrust_content = format!("{fingerprint}:6:\n"); // fingerprint Display is uppercase hex
    let ownertrust_path = backup_dir.join("ownertrust.txt");
    fs::write(&ownertrust_path, &ownertrust_content)?;
    set_file_permissions(&ownertrust_path, 0o600)?;
    actions.push(format!("Created {}", ownertrust_path.display()));

    // 5. revocation-cert.asc — revocation certificate
    let revocation_path = backup_dir.join("revocation-cert.asc");
    match generate_revocation_cert(key, passphrase) {
        Ok(revocation_armored) => {
            fs::write(&revocation_path, &revocation_armored)?;
            set_file_permissions(&revocation_path, 0o600)?;
            actions.push(format!("Created {}", revocation_path.display()));
        }
        Err(e) => {
            // Fallback: write a placeholder explaining the failure
            let revocation_content = format!(
                "# Revocation certificate generation failed: {e}\n\
                 # To generate a revocation certificate manually, use:\n\
                 #   gpg --gen-revoke {fingerprint}\n"
            );
            fs::write(&revocation_path, &revocation_content)?;
            set_file_permissions(&revocation_path, 0o600)?;
            actions.push(format!(
                "Created {} (placeholder — generation failed: {e})",
                revocation_path.display()
            ));
        }
    }

    Ok(actions)
}

/// Generate a revocation certificate for a `SignedSecretKey`.
///
/// The revocation cert is: the primary public key packet + a KeyRevocation signature,
/// armored as a PGP PUBLIC KEY BLOCK. This follows GPG's format.
fn generate_revocation_cert(
    key: &SignedSecretKey,
    passphrase: Option<&str>,
) -> Result<String, KdubError> {
    use pgp::packet::{RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData};
    use pgp::types::{KeyDetails, Password, Timestamp};

    let mut rng = rand::rngs::OsRng;

    // Build a KeyRevocation signature config
    let mut sig_config =
        SignatureConfig::from_key(&mut rng, &key.primary_key, SignatureType::KeyRevocation)
            .map_err(|e| {
                KdubError::Backup(format!("failed to create revocation signature config: {e}"))
            })?;

    // Add required hashed subpackets
    sig_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .map_err(|e| KdubError::Backup(format!("failed to create timestamp subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            key.primary_key.fingerprint(),
        ))
        .map_err(|e| KdubError::Backup(format!("failed to create fingerprint subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::RevocationReason(
            RevocationCode::NoReason,
            "Revocation certificate generated at key creation time.".into(),
        ))
        .map_err(|e| KdubError::Backup(format!("failed to create reason subpacket: {e}")))?,
    ];

    // Add unhashed issuer key ID for v4 compatibility
    sig_config.unhashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerKeyId(key.primary_key.legacy_key_id()))
            .map_err(|e| KdubError::Backup(format!("failed to create key ID subpacket: {e}")))?,
    ];

    // Build the password
    let key_pw: Password = passphrase.map(Into::into).unwrap_or_else(Password::empty);

    // Sign the revocation
    let revocation_sig = sig_config
        .sign_key(
            &key.primary_key,
            &key_pw,
            &key.primary_key.public_key().clone(),
        )
        .map_err(|e| KdubError::Backup(format!("failed to sign revocation: {e}")))?;

    // Build the revocation cert as: public key + revocation signature
    // This matches GPG's revocation certificate format
    use pgp::composed::SignedKeyDetails;
    let revocation_key_details = SignedKeyDetails::new(
        vec![revocation_sig], // revocation_signatures
        vec![],               // direct_signatures
        vec![],               // users (empty for revocation cert)
        vec![],               // user_attributes
    );

    let revocation_pub = SignedPublicKey::new(
        key.primary_key.public_key().clone(),
        revocation_key_details,
        vec![], // no subkeys
    );

    let armored = revocation_pub
        .to_armored_string(Default::default())
        .map_err(|e| KdubError::Backup(format!("failed to armor revocation cert: {e}")))?;

    Ok(armored)
}

/// Run a key restore: read from `$DATA_DIR/backups/$FINGERPRINT/` and
/// save key material to `$DATA_DIR/identities/$FINGERPRINT.key`.
///
/// Returns a list of action strings describing what was restored.
pub fn run_restore(data_dir: &Path, fingerprint: &Fingerprint) -> Result<Vec<String>, KdubError> {
    let backup_dir = data_dir.join("backups").join(fingerprint.to_string());
    if !backup_dir.exists() {
        return Err(KdubError::BackupNotFound(fingerprint.clone()));
    }

    let mut actions = Vec::new();

    // 1. Read and parse certify-key.asc
    let certify_path = backup_dir.join("certify-key.asc");
    if !certify_path.exists() {
        return Err(KdubError::Backup(format!(
            "certify-key.asc not found in backup directory: {}",
            backup_dir.display()
        )));
    }
    let certify_armored = fs::read_to_string(&certify_path)?;

    // Verify the armored key parses successfully
    let (parsed_key, _) =
        SignedSecretKey::from_armor_single(std::io::Cursor::new(&certify_armored))
            .map_err(|e| KdubError::Backup(format!("failed to parse certify-key.asc: {e}")))?;

    // Verify fingerprint matches
    let parsed_fp = crate::keygen::extract_fingerprint(&parsed_key);
    if parsed_fp != *fingerprint {
        return Err(KdubError::Backup(format!(
            "fingerprint mismatch: backup dir says {fingerprint} but key has {parsed_fp}"
        )));
    }

    // 2. Save key material to identity store
    let identities_dir = data_dir.join("identities");
    fs::create_dir_all(&identities_dir)?;

    let fp_str = fingerprint.to_string();
    let key_path = identities_dir.join(format!("{fp_str}.key"));
    fs::write(&key_path, &certify_armored)?;
    set_file_permissions(&key_path, 0o600)?;
    actions.push(format!("Restored key to {}", key_path.display()));

    // 3. Update or create metadata
    let metadata_path = identities_dir.join(format!("{fp_str}.json"));
    if metadata_path.exists() {
        // Update existing metadata — preserve the existing backed_up timestamp
        let meta = IdentityMetadata::load(data_dir, fingerprint)?;
        meta.save(data_dir)?;
        actions.push(format!("Updated metadata: {}", metadata_path.display()));
    } else {
        // Create minimal metadata from the key
        let identity = extract_primary_userid(&parsed_key);
        let key_type = detect_key_type(&parsed_key);

        let meta = IdentityMetadata {
            identity,
            fingerprint: fingerprint.clone(),
            key_type,
            created: chrono::Utc::now(),
            backed_up: Some(chrono::Utc::now()),
            renewed: None,
            rotated: None,
            card_serial: None,
            provisioned: None,
        };
        meta.save(data_dir)?;
        actions.push(format!("Created metadata: {}", metadata_path.display()));
    }

    Ok(actions)
}

/// Load a `SignedSecretKey` from the identity store (`$DATA_DIR/identities/$FINGERPRINT.key`).
pub fn load_key_from_store(
    data_dir: &Path,
    fingerprint: &Fingerprint,
) -> Result<SignedSecretKey, KdubError> {
    let fp_str = fingerprint.to_string();
    let key_path = data_dir.join("identities").join(format!("{fp_str}.key"));
    if !key_path.exists() {
        return Err(KdubError::KeyNotFound(fp_str));
    }
    let armored = fs::read_to_string(&key_path)?;
    let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(&armored))
        .map_err(|e| KdubError::Backup(format!("failed to parse key file: {e}")))?;
    Ok(key)
}

/// Save a `SignedSecretKey` to the identity store (`$DATA_DIR/identities/$FINGERPRINT.key`).
pub fn save_key_to_store(
    data_dir: &Path,
    fingerprint: &Fingerprint,
    key: &SignedSecretKey,
) -> Result<(), KdubError> {
    let identities_dir = data_dir.join("identities");
    fs::create_dir_all(&identities_dir)?;

    let armored = key
        .to_armored_string(Default::default())
        .map_err(|e| KdubError::Backup(format!("failed to export key: {e}")))?;
    let key_path = identities_dir.join(format!("{}.key", fingerprint));
    fs::write(&key_path, &armored)?;
    set_file_permissions(&key_path, 0o600)?;
    Ok(())
}

/// Extract the primary user ID from a `SignedSecretKey`.
fn extract_primary_userid(key: &SignedSecretKey) -> String {
    key.details
        .users
        .first()
        .map(|u| String::from_utf8_lossy(u.id.id()).to_string())
        .unwrap_or_else(|| "<unknown>".to_string())
}

/// Detect the key type from a `SignedSecretKey`.
fn detect_key_type(key: &SignedSecretKey) -> String {
    use pgp::crypto::public_key::PublicKeyAlgorithm;
    use pgp::types::KeyDetails;

    match key.algorithm() {
        PublicKeyAlgorithm::EdDSALegacy | PublicKeyAlgorithm::Ed25519 => "ed25519".to_string(),
        PublicKeyAlgorithm::RSA => "rsa4096".to_string(),
        other => format!("{other:?}"),
    }
}

/// Set Unix directory permissions (mode).
fn set_dir_permissions(path: &Path, mode: u32) -> Result<(), KdubError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Set Unix file permissions (mode).
fn set_file_permissions(path: &Path, mode: u32) -> Result<(), KdubError> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;

    fn generate_test_key() -> (SignedSecretKey, Fingerprint) {
        use pgp::composed::Deserializable;
        let armored = include_str!("../tests/fixtures/test_key.asc");
        let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored))
            .expect("fixture key should parse");
        let fp = crate::keygen::extract_fingerprint(&key);
        (key, fp)
    }

    #[test]
    fn test_backup_creates_all_files() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        let actions = run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();
        assert_eq!(actions.len(), 5);

        let backup_dir = data_dir.join("backups").join(fp.to_string());
        assert!(backup_dir.join("certify-key.asc").exists());
        assert!(backup_dir.join("subkeys.asc").exists());
        assert!(backup_dir.join("public-key.asc").exists());
        assert!(backup_dir.join("ownertrust.txt").exists());
        assert!(backup_dir.join("revocation-cert.asc").exists());
    }

    #[test]
    fn test_backup_file_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        let backup_dir = data_dir.join("backups").join(fp.to_string());

        // Check directory is 0700
        let dir_mode = fs::metadata(&backup_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "backup dir should be mode 0700");

        // Check all files are 0600
        for name in &[
            "certify-key.asc",
            "subkeys.asc",
            "public-key.asc",
            "ownertrust.txt",
            "revocation-cert.asc",
        ] {
            let path = backup_dir.join(name);
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} should be mode 0600");
        }
    }

    #[test]
    fn test_backup_public_key_content() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        let public_key_content = fs::read_to_string(
            data_dir
                .join("backups")
                .join(fp.to_string())
                .join("public-key.asc"),
        )
        .unwrap();
        assert!(
            public_key_content.contains("BEGIN PGP PUBLIC KEY BLOCK"),
            "public-key.asc should contain PGP public key header"
        );
        assert!(
            !public_key_content.contains("BEGIN PGP PRIVATE KEY BLOCK"),
            "public-key.asc should NOT contain private key header"
        );
    }

    #[test]
    fn test_backup_certify_key_content() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        let certify_content = fs::read_to_string(
            data_dir
                .join("backups")
                .join(fp.to_string())
                .join("certify-key.asc"),
        )
        .unwrap();
        assert!(
            certify_content.contains("BEGIN PGP PRIVATE KEY BLOCK"),
            "certify-key.asc should contain PGP private key header"
        );
    }

    #[test]
    fn test_backup_ownertrust_format() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        let ownertrust_content = fs::read_to_string(
            data_dir
                .join("backups")
                .join(fp.to_string())
                .join("ownertrust.txt"),
        )
        .unwrap();
        let expected = format!("{fp}:6:\n");
        assert_eq!(
            ownertrust_content, expected,
            "ownertrust should be FINGERPRINT:6:"
        );
    }

    #[test]
    fn test_revocation_cert_is_valid_pgp() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        let revocation_content = fs::read_to_string(
            data_dir
                .join("backups")
                .join(fp.to_string())
                .join("revocation-cert.asc"),
        )
        .unwrap();

        // Should be a valid armored PGP public key block
        assert!(
            revocation_content.contains("BEGIN PGP PUBLIC KEY BLOCK"),
            "revocation cert should be an armored PGP public key block"
        );

        // Should be parseable as a SignedPublicKey
        let (parsed, _) =
            SignedPublicKey::from_armor_single(std::io::Cursor::new(&revocation_content)).unwrap();

        // The parsed key should have a revocation signature
        assert!(
            !parsed.details.revocation_signatures.is_empty(),
            "revocation cert should contain a revocation signature"
        );
    }

    #[test]
    fn test_backup_restore_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Save metadata first (simulating key create)
        let metadata = IdentityMetadata {
            identity: "Backup Test <backup@example.com>".to_string(),
            fingerprint: fp.clone(),
            key_type: "ed25519".to_string(),
            created: chrono::Utc::now(),
            backed_up: None,
            renewed: None,
            rotated: None,
            card_serial: None,
            provisioned: None,
        };
        metadata.save(data_dir).unwrap();

        // Backup
        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        // Delete the key file from identities (if any)
        let key_path = data_dir.join("identities").join(format!("{fp}.key"));
        if key_path.exists() {
            fs::remove_file(&key_path).unwrap();
        }

        // Restore
        let restore_actions = run_restore(data_dir, &fp).unwrap();
        assert!(!restore_actions.is_empty());

        // Verify key file was restored
        assert!(key_path.exists(), "key file should be restored");

        // Verify the restored key parses
        let restored_key = load_key_from_store(data_dir, &fp).unwrap();
        let restored_fp = keygen::extract_fingerprint(&restored_key);
        assert_eq!(restored_fp, fp, "restored key fingerprint should match");

        // Verify metadata was updated
        let loaded_meta = IdentityMetadata::load(data_dir, &fp).unwrap();
        assert!(
            loaded_meta.backed_up.is_none(),
            "backed_up timestamp should be preserved as-is (None)"
        );
    }

    #[test]
    fn test_restore_missing_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let fp_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let fp: Fingerprint = fp_str.parse().unwrap();
        let result = run_restore(data_dir, &fp);
        assert!(result.is_err());
        match result.unwrap_err() {
            KdubError::BackupNotFound(found_fp) => {
                assert_eq!(found_fp.to_string(), fp_str);
            }
            other => panic!("expected BackupNotFound, got: {other}"),
        }
    }

    #[test]
    fn test_restore_creates_metadata_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Backup without pre-existing metadata
        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        // Restore (no metadata exists)
        let actions = run_restore(data_dir, &fp).unwrap();
        assert!(actions.iter().any(|a| a.contains("Created metadata")));

        // Verify metadata was created
        let meta = IdentityMetadata::load(data_dir, &fp).unwrap();
        assert_eq!(meta.fingerprint, fp);
        assert_eq!(meta.identity, "Test Fixture <fixture@test.example>");
    }

    #[test]
    fn test_save_and_load_key_from_store() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        save_key_to_store(data_dir, &fp, &key).unwrap();
        let loaded = load_key_from_store(data_dir, &fp).unwrap();

        let loaded_fp = keygen::extract_fingerprint(&loaded);
        assert_eq!(loaded_fp, fp);
    }

    #[test]
    fn test_load_key_from_store_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        // Use a valid 40-char fingerprint that has no associated file
        let fp: Fingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap();
        let result = load_key_from_store(tmp.path(), &fp);
        assert!(result.is_err());
        match result.unwrap_err() {
            KdubError::KeyNotFound(fp_str) => {
                assert_eq!(fp_str, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            }
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn test_save_key_file_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        save_key_to_store(data_dir, &fp, &key).unwrap();

        let key_path = data_dir.join("identities").join(format!("{fp}.key"));
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file should be mode 0600");
    }
}
