//! Card provision preparation and finalization logic.
//!
//! The provision flow is split into two library functions:
//!
//! 1. [`prepare_provision`] — validates preconditions (backup exists, key is
//!    not already a stub) and returns a [`ProvisionPlan`] with the key and
//!    metadata. No side effects.
//!
//! 2. [`finalize_provision`] — replaces the local key with a GNU S2K stub
//!    and updates identity metadata with the card serial and provision
//!    timestamp.
//!
//! The command handler calls `prepare_provision`, imports subkeys to the card
//! (via [`CardExecutor`]), then calls `finalize_provision`.
//!
//! **SAFETY:** This is the most safety-critical operation in kdub. After
//! provisioning, secret subkey material exists only on the physical card
//! and in the backup. Getting this wrong means irrecoverable key loss.

use std::path::Path;

use pgp::composed::SignedSecretSubKey;
use pgp::packet::SignatureType;

use crate::backup::{load_key_from_store, save_key_to_store};
use crate::card::KeySlot;
use crate::error::KdubError;
use crate::identity::IdentityMetadata;
use crate::keygen::{SignedSecretKey, extract_fingerprint};
use crate::stub;
use crate::types::{FactoryPin, Fingerprint};

/// Validated provision plan returned by [`prepare_provision`].
///
/// Contains the key, metadata, and fingerprint needed for the provision
/// flow. The command handler uses this to import subkeys to the card,
/// then passes it to [`finalize_provision`].
#[derive(Debug)]
pub struct ProvisionPlan {
    /// The full secret key loaded from the identity store.
    pub key: SignedSecretKey,
    /// Identity metadata for the key.
    pub metadata: IdentityMetadata,
    /// Validated primary key fingerprint.
    pub fingerprint: Fingerprint,
}

/// A subkey matched to its target card slot.
///
/// Returned by [`classify_subkeys`] for the command handler to iterate
/// and import to the card.
#[derive(Debug)]
pub struct SubkeySlot {
    /// The secret subkey to import.
    pub subkey: SignedSecretSubKey,
    /// The card slot this subkey should be imported to.
    pub slot: KeySlot,
    /// Human-readable label for display (e.g. "sign", "encrypt", "auth").
    pub label: &'static str,
}

/// Validate preconditions and prepare a provision plan.
///
/// # Checks performed
///
/// 1. Backup directory `$DATA_DIR/backups/$FINGERPRINT/` must exist.
///    No override, no `--force`. If missing, returns an error instructing
///    the user to run `kdub key backup` first.
/// 2. Key must not already be a GNU S2K stub (already provisioned).
/// 3. Admin PIN must not be the factory default ("12345678").
///
/// # Returns
///
/// A [`ProvisionPlan`] containing the loaded key, metadata, and fingerprint.
pub fn prepare_provision(
    data_dir: &Path,
    fingerprint: &Fingerprint,
    admin_pin_value: &str,
) -> Result<ProvisionPlan, KdubError> {
    // Check 1: backup must exist (CRITICAL — no override)
    let backup_dir = data_dir.join("backups").join(fingerprint.to_string());
    if !backup_dir.exists() {
        return Err(KdubError::Card(
            "Run 'kdub key backup' first \u{2014} this operation is irrecoverable without a backup."
                .to_string(),
        ));
    }

    // Check 2: load key and verify it is not already a stub
    let key = load_key_from_store(data_dir, fingerprint)?;
    if stub::is_stub(&key) {
        let serial = stub::card_serial_from_stub(&key).unwrap_or_else(|| "unknown".to_string());
        return Err(KdubError::Card(format!(
            "key is already provisioned to card serial {serial}. \
             To re-provision, restore from backup first: kdub key restore {fingerprint}"
        )));
    }

    // Check 3: reject factory admin PIN
    if admin_pin_value == FactoryPin::ADMIN {
        return Err(KdubError::Card(
            "Run 'kdub card setup' first to change PINs from factory defaults.".to_string(),
        ));
    }

    // Load metadata
    let metadata = IdentityMetadata::load(data_dir, fingerprint)?;

    let fp_from_key = extract_fingerprint(&key);
    if fp_from_key != *fingerprint {
        return Err(KdubError::Card(format!(
            "fingerprint mismatch: expected {fingerprint}, key has {fp_from_key}"
        )));
    }

    Ok(ProvisionPlan {
        key,
        metadata,
        fingerprint: fingerprint.clone(),
    })
}

/// Classify subkeys by their key flags into card slots.
///
/// Inspects each subkey's binding signature to determine its usage
/// (sign, encrypt, authenticate) and maps it to the corresponding
/// [`KeySlot`].
///
/// Returns an error if any expected slot cannot be matched.
pub fn classify_subkeys(key: &SignedSecretKey) -> Result<Vec<SubkeySlot>, KdubError> {
    let mut slots = Vec::new();

    for subkey in &key.secret_subkeys {
        // Extract key flags from the most recent subkey binding signature
        let key_flags = subkey
            .signatures
            .iter()
            .rev()
            .find(|s| s.typ() == Some(SignatureType::SubkeyBinding))
            .map(|s| s.key_flags())
            .unwrap_or_default();

        let (slot, label) = if key_flags.sign() {
            (KeySlot::Signing, "sign")
        } else if key_flags.encrypt_comms() || key_flags.encrypt_storage() {
            (KeySlot::Decryption, "encrypt")
        } else if key_flags.authentication() {
            (KeySlot::Authentication, "auth")
        } else {
            // Subkey with no recognized flags — skip it
            continue;
        };

        slots.push(SubkeySlot {
            subkey: subkey.clone(),
            slot,
            label,
        });
    }

    if slots.is_empty() {
        return Err(KdubError::Card(
            "no subkeys with recognized key flags (sign, encrypt, auth) found".to_string(),
        ));
    }

    Ok(slots)
}

/// Replace the local key with a GNU S2K stub and update metadata.
///
/// This is the point of no return: after this call, the local key file
/// contains only stubs and the secret material is gone. The card and
/// the backup are the only copies.
///
/// # What happens
///
/// 1. Calls [`stub::stub_key`] to replace secret params with GNU S2K stubs.
/// 2. Saves the stubbed key back to the identity store.
/// 3. Updates [`IdentityMetadata`] with `card_serial` and `provisioned` timestamp.
pub fn finalize_provision(
    data_dir: &Path,
    key: SignedSecretKey,
    fingerprint: &Fingerprint,
    card_serial: &str,
) -> Result<(), KdubError> {
    // Stub the key: primary gets mode 1001, subkeys get mode 1002 with card serial
    let stubbed = stub::stub_key(key, card_serial)?;

    // Verify the stub was created correctly
    if !stub::is_stub(&stubbed) {
        return Err(KdubError::Card(
            "internal error: stubbed key does not pass is_stub() check".to_string(),
        ));
    }

    // Save the stubbed key to the identity store
    save_key_to_store(data_dir, fingerprint, &stubbed)?;

    // Update metadata
    let mut metadata = IdentityMetadata::load(data_dir, fingerprint)?;
    metadata.card_serial = Some(card_serial.to_string());
    metadata.provisioned = Some(chrono::Utc::now());
    metadata.save(data_dir)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::run_backup;

    fn generate_test_key() -> (SignedSecretKey, Fingerprint) {
        use pgp::composed::Deserializable;
        let armored = include_str!("../tests/fixtures/test_key.asc");
        let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored))
            .expect("fixture key should parse");
        let fp = crate::keygen::extract_fingerprint(&key);
        (key, fp)
    }

    /// Create a full test environment: key in identity store, metadata, backup.
    fn setup_test_env(data_dir: &Path) -> (SignedSecretKey, Fingerprint) {
        let (key, fp) = generate_test_key();

        // Save key to identity store
        save_key_to_store(data_dir, &fp, &key).unwrap();

        // Create metadata
        let metadata = IdentityMetadata {
            identity: "Provision Test <provision@example.com>".to_string(),
            fingerprint: fp.clone(),
            key_type: "ed25519".to_string(),
            created: chrono::Utc::now(),
            backed_up: Some(chrono::Utc::now()),
            renewed: None,
            rotated: None,
            card_serial: None,
            provisioned: None,
        };
        metadata.save(data_dir).unwrap();

        // Create backup
        run_backup(data_dir, &fp, &key, Some("testpass123")).unwrap();

        (key, fp)
    }

    #[test]
    fn test_prepare_provision_checks_backup() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Save key and metadata but NO backup
        save_key_to_store(data_dir, &fp, &key).unwrap();
        let metadata = IdentityMetadata {
            identity: "Test <test@example.com>".to_string(),
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

        let result = prepare_provision(data_dir, &fp, "87654321");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("backup"),
            "error should mention backup, got: {err_msg}"
        );
    }

    #[test]
    fn test_prepare_provision_checks_stub() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (_key, fp) = setup_test_env(data_dir);

        // Stub the key (simulate already provisioned)
        let key = load_key_from_store(data_dir, &fp).unwrap();
        let stubbed = stub::stub_key(key, "12345678").unwrap();
        save_key_to_store(data_dir, &fp, &stubbed).unwrap();

        let result = prepare_provision(data_dir, &fp, "87654321");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already provisioned"),
            "error should mention already provisioned, got: {err_msg}"
        );
    }

    #[test]
    fn test_prepare_provision_rejects_factory_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (_key, fp) = setup_test_env(data_dir);

        let result = prepare_provision(data_dir, &fp, FactoryPin::ADMIN);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("factory defaults"),
            "error should mention factory defaults, got: {err_msg}"
        );
    }

    #[test]
    fn test_prepare_provision_success() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (_key, fp) = setup_test_env(data_dir);

        let plan = prepare_provision(data_dir, &fp, "87654321").unwrap();
        assert_eq!(plan.fingerprint, fp);
        assert!(!stub::is_stub(&plan.key));
    }

    #[test]
    fn test_classify_subkeys_finds_all_three() {
        let (key, _fp) = generate_test_key();
        let slots = classify_subkeys(&key).unwrap();
        assert_eq!(slots.len(), 3, "should find sign, encrypt, auth subkeys");

        let labels: Vec<&str> = slots.iter().map(|s| s.label).collect();
        assert!(labels.contains(&"sign"), "should have sign subkey");
        assert!(labels.contains(&"encrypt"), "should have encrypt subkey");
        assert!(labels.contains(&"auth"), "should have auth subkey");
    }

    #[test]
    fn test_classify_subkeys_correct_slots() {
        let (key, _fp) = generate_test_key();
        let slots = classify_subkeys(&key).unwrap();

        for slot in &slots {
            match slot.label {
                "sign" => assert_eq!(slot.slot, KeySlot::Signing),
                "encrypt" => assert_eq!(slot.slot, KeySlot::Decryption),
                "auth" => assert_eq!(slot.slot, KeySlot::Authentication),
                _ => panic!("unexpected label: {}", slot.label),
            }
        }
    }

    #[test]
    fn test_finalize_provision_creates_stub() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = setup_test_env(data_dir);

        finalize_provision(data_dir, key, &fp, "AABBCCDD").unwrap();

        // Verify key is now a stub
        let loaded = load_key_from_store(data_dir, &fp).unwrap();
        assert!(
            stub::is_stub(&loaded),
            "key should be a stub after finalize_provision"
        );

        // Verify card serial is embedded in the stub
        let serial = stub::card_serial_from_stub(&loaded);
        assert_eq!(serial, Some("AABBCCDD".to_string()));
    }

    #[test]
    fn test_finalize_provision_updates_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = setup_test_env(data_dir);

        finalize_provision(data_dir, key, &fp, "AABBCCDD").unwrap();

        let meta = IdentityMetadata::load(data_dir, &fp).unwrap();
        assert_eq!(
            meta.card_serial,
            Some("AABBCCDD".to_string()),
            "card_serial should be set"
        );
        assert!(
            meta.provisioned.is_some(),
            "provisioned timestamp should be set"
        );
    }

    #[test]
    fn test_finalize_provision_preserves_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = setup_test_env(data_dir);

        finalize_provision(data_dir, key, &fp, "AABBCCDD").unwrap();

        // Verify the stubbed key still has the same fingerprint
        let loaded = load_key_from_store(data_dir, &fp).unwrap();
        let loaded_fp = extract_fingerprint(&loaded);
        assert_eq!(
            loaded_fp, fp,
            "fingerprint should be preserved after stubbing"
        );
    }
}
