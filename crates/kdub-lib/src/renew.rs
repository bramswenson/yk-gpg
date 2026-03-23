use std::path::Path;

use pgp::composed::SignedSecretSubKey;
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{Duration as PgpDuration, KeyDetails, KeyVersion, Password, Timestamp};

use crate::backup::{load_key_from_store, save_key_to_store};
use crate::error::KdubError;
use crate::identity::IdentityMetadata;
use crate::keygen::{SignedSecretKey, extract_fingerprint, parse_expiration};
use crate::stub;
use crate::types::{CardSerial, Fingerprint};

/// Renew subkey expiration on a `SignedSecretKey`.
///
/// For each secret subkey, creates a new subkey binding signature with an updated
/// `KeyExpirationTime` subpacket. The new expiration is measured from **now**
/// (not from the subkey's creation time), so the effective expiry date is
/// `now + expiration_duration`.
///
/// If `expiration` is `"never"`, the `KeyExpirationTime` subpacket is omitted,
/// meaning the subkeys will not expire.
///
/// Returns the updated key and a list of action strings describing what was done.
pub fn renew_subkeys(
    key: &SignedSecretKey,
    expiration: &str,
    passphrase: &str,
) -> Result<(SignedSecretKey, Vec<String>), KdubError> {
    let expiry_duration = parse_expiration(expiration)?;
    let key_pw: Password = passphrase.into();
    let mut rng = rand::rngs::OsRng;
    let mut actions = Vec::new();

    let mut renewed_subkeys = Vec::new();
    for subkey in &key.secret_subkeys {
        let new_sig = create_renewed_binding_signature(
            &key.primary_key,
            subkey,
            expiry_duration,
            &key_pw,
            &mut rng,
        )?;

        // Keep the new signature along with any existing ones (append model)
        let mut sigs = subkey.signatures.clone();
        sigs.push(new_sig);

        let renewed = SignedSecretSubKey::new(subkey.key.clone(), sigs);
        renewed_subkeys.push(renewed);

        let subkey_fp = hex::encode_upper(subkey.key.fingerprint().as_bytes());
        let short_fp = &subkey_fp[..16.min(subkey_fp.len())];
        match expiry_duration {
            Some(d) => {
                let days = d.as_secs() / 86400;
                actions.push(format!(
                    "Renewed subkey {short_fp} — expires in {days} days"
                ));
            }
            None => {
                actions.push(format!("Renewed subkey {short_fp} — set to never expire"));
            }
        }
    }

    let renewed_key = SignedSecretKey::new(
        key.primary_key.clone(),
        key.details.clone(),
        key.public_subkeys.clone(),
        renewed_subkeys,
    );

    Ok((renewed_key, actions))
}

/// Create a new subkey binding signature with updated expiration.
///
/// The binding signature includes:
/// - `SignatureCreationTime` (now)
/// - `KeyFlags` (copied from the existing binding signature)
/// - `KeyExpirationTime` (the new duration, or omitted for "never")
/// - `IssuerFingerprint` (primary key fingerprint)
/// - `EmbeddedSignature` (back-signature, if present in the original and needed for signing subkeys)
///
/// The signature is made by the primary key, which must be unlockable with `key_pw`.
fn create_renewed_binding_signature<R: rand::CryptoRng + rand::Rng>(
    primary_key: &pgp::packet::SecretKey,
    subkey: &SignedSecretSubKey,
    expiry_duration: Option<std::time::Duration>,
    key_pw: &Password,
    rng: &mut R,
) -> Result<pgp::packet::Signature, KdubError> {
    // Extract key flags from the most recent existing binding signature
    let key_flags = subkey
        .signatures
        .iter()
        .rev()
        .find(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .map(|s| s.key_flags())
        .unwrap_or_default();

    // Extract embedded signature (back-sig) from existing binding, if present.
    // Signing subkeys require a Primary Key Binding Signature (0x19).
    let embedded_sig = subkey
        .signatures
        .iter()
        .rev()
        .find(|s| s.typ() == Some(SignatureType::SubkeyBinding))
        .and_then(|s| {
            s.config().and_then(|c| {
                c.hashed_subpackets().find_map(|sp| match &sp.data {
                    SubpacketData::EmbeddedSignature(sig) => Some(sig.as_ref().clone()),
                    _ => None,
                })
            })
        });

    // Build the subkey binding signature config
    let mut sig_config =
        SignatureConfig::from_key(&mut *rng, primary_key, SignatureType::SubkeyBinding)
            .map_err(|e| KdubError::Renew(format!("failed to create signature config: {e}")))?;

    // Build hashed subpackets
    let mut hashed = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .map_err(|e| KdubError::Renew(format!("timestamp subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::KeyFlags(key_flags))
            .map_err(|e| KdubError::Renew(format!("key flags subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
            .map_err(|e| KdubError::Renew(format!("fingerprint subpacket: {e}")))?,
    ];

    // Add key expiration time (relative to subkey creation time)
    if let Some(duration) = expiry_duration {
        // KeyExpirationTime is relative to the key creation time, but we want
        // the subkey to expire `duration` from now. So we compute the offset from
        // the subkey's creation time.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| KdubError::Renew(format!("system time error: {e}")))?
            .as_secs();
        let created_secs = u64::from(subkey.key.created_at().as_secs());
        let expire_offset_secs = (now_secs - created_secs) + duration.as_secs();

        let pgp_duration =
            PgpDuration::try_from(std::time::Duration::from_secs(expire_offset_secs))
                .map_err(|e| KdubError::Renew(format!("duration overflow: {e}")))?;

        hashed.push(
            Subpacket::regular(SubpacketData::KeyExpirationTime(pgp_duration))
                .map_err(|e| KdubError::Renew(format!("expiration subpacket: {e}")))?,
        );
    }

    // Add embedded back-signature if the original had one
    if let Some(back_sig) = embedded_sig {
        hashed.push(
            Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(back_sig)))
                .map_err(|e| KdubError::Renew(format!("embedded sig subpacket: {e}")))?,
        );
    }

    sig_config.hashed_subpackets = hashed;

    // Add unhashed issuer key ID for v4 compatibility
    if primary_key.version() <= KeyVersion::V4 {
        sig_config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(primary_key.legacy_key_id()))
                .map_err(|e| KdubError::Renew(format!("key ID subpacket: {e}")))?,
        ];
    }

    // Sign the binding
    let signature = sig_config
        .sign_subkey_binding(
            primary_key,
            primary_key.public_key(),
            key_pw,
            subkey.key.public_key(),
        )
        .map_err(|e| KdubError::Renew(format!("failed to sign subkey binding: {e}")))?;

    Ok(signature)
}

/// Run a full key renewal: load key, renew subkeys, save, update metadata.
///
/// Returns a list of action strings describing what was done.
pub fn run_renew(
    data_dir: &Path,
    fingerprint: &Fingerprint,
    expiration: &str,
    passphrase: &str,
) -> Result<Vec<String>, KdubError> {
    // Load key
    let key = load_key_from_store(data_dir, fingerprint)?;

    // Refuse to operate on stub keys (key material on smart card)
    if stub::is_stub(&key) {
        let serial = CardSerial::from_stub(stub::card_serial_from_stub(&key));
        return Err(KdubError::KeyOnCard(serial));
    }

    // Verify fingerprint matches
    let key_fp = extract_fingerprint(&key);
    if key_fp != *fingerprint {
        return Err(KdubError::Renew(format!(
            "fingerprint mismatch: expected {fingerprint}, got {key_fp}"
        )));
    }

    // Renew subkeys
    let (renewed_key, actions) = renew_subkeys(&key, expiration, passphrase)?;

    // Verify the renewed key bindings are valid
    renewed_key
        .verify_bindings()
        .map_err(|e| KdubError::Renew(format!("renewed key failed binding verification: {e}")))?;

    // Save updated key
    save_key_to_store(data_dir, fingerprint, &renewed_key)?;

    // Update metadata
    let mut metadata = IdentityMetadata::load(data_dir, fingerprint)?;
    metadata.renewed = Some(chrono::Utc::now());
    metadata.save(data_dir)?;

    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_key() -> (SignedSecretKey, Fingerprint) {
        use pgp::composed::Deserializable;
        let armored = include_str!("../tests/fixtures/test_key.asc");
        let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored))
            .expect("fixture key should parse");
        let fp = crate::keygen::extract_fingerprint(&key);
        (key, fp)
    }

    #[test]
    fn test_renew_updates_expiration() {
        let (key, _fp) = generate_test_key();

        // Original key has 3 subkeys with 2y expiration set at generation time
        assert_eq!(key.secret_subkeys.len(), 3);

        // Renew with 3y expiration
        let (renewed, actions) = renew_subkeys(&key, "3y", "testpass123").unwrap();

        // All 3 subkeys should have been renewed
        assert_eq!(actions.len(), 3);
        for action in &actions {
            assert!(
                action.contains("expires in"),
                "action should mention expiration: {action}"
            );
        }

        // Verify the renewed key has valid bindings
        renewed.verify_bindings().unwrap();

        // Each subkey should now have at least 2 signatures (original + renewal)
        for subkey in &renewed.secret_subkeys {
            assert!(
                subkey.signatures.len() >= 2,
                "subkey should have at least 2 signatures after renewal"
            );

            // The newest signature should have a KeyExpirationTime subpacket
            let newest_sig = subkey.signatures.last().unwrap();
            let has_expiration = newest_sig
                .config()
                .map(|c| {
                    c.hashed_subpackets()
                        .any(|sp| matches!(sp.data, SubpacketData::KeyExpirationTime(_)))
                })
                .unwrap_or(false);
            assert!(
                has_expiration,
                "renewed subkey binding should have KeyExpirationTime"
            );
        }
    }

    #[test]
    fn test_renew_with_never_expiration() {
        let (key, _fp) = generate_test_key();

        let (renewed, actions) = renew_subkeys(&key, "never", "testpass123").unwrap();

        assert_eq!(actions.len(), 3);
        for action in &actions {
            assert!(
                action.contains("never expire"),
                "action should mention never expire: {action}"
            );
        }

        renewed.verify_bindings().unwrap();

        // The newest binding signature should NOT have a KeyExpirationTime
        for subkey in &renewed.secret_subkeys {
            let newest_sig = subkey.signatures.last().unwrap();
            let has_expiration = newest_sig
                .config()
                .map(|c| {
                    c.hashed_subpackets()
                        .any(|sp| matches!(sp.data, SubpacketData::KeyExpirationTime(_)))
                })
                .unwrap_or(false);
            assert!(
                !has_expiration,
                "renewed subkey with 'never' should not have KeyExpirationTime"
            );
        }
    }

    #[test]
    fn test_renew_preserves_key_flags() {
        let (key, _fp) = generate_test_key();

        // Collect original key flags
        let original_flags: Vec<_> = key
            .secret_subkeys
            .iter()
            .map(|sk| {
                sk.signatures
                    .iter()
                    .find(|s| s.typ() == Some(SignatureType::SubkeyBinding))
                    .map(|s| s.key_flags())
                    .unwrap_or_default()
            })
            .collect();

        let (renewed, _) = renew_subkeys(&key, "1y", "testpass123").unwrap();

        // Verify key flags are preserved
        for (i, subkey) in renewed.secret_subkeys.iter().enumerate() {
            let renewed_flags = subkey.signatures.last().unwrap().key_flags();
            assert_eq!(
                renewed_flags, original_flags[i],
                "key flags should be preserved for subkey {i}"
            );
        }
    }

    #[test]
    fn test_renew_wrong_passphrase() {
        let (key, _fp) = generate_test_key();

        let result = renew_subkeys(&key, "2y", "wrongpassphrase");
        assert!(result.is_err(), "wrong passphrase should fail");
    }

    #[test]
    fn test_renew_invalid_expiration() {
        let (key, _fp) = generate_test_key();

        let result = renew_subkeys(&key, "2w", "testpass123");
        assert!(result.is_err(), "invalid expiration format should fail");
    }

    #[test]
    fn test_run_renew_full_workflow() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Set up identity store
        let metadata = IdentityMetadata {
            identity: "Renew Test <renew@example.com>".to_string(),
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
        save_key_to_store(data_dir, &fp, &key).unwrap();

        // Run renewal
        let actions = run_renew(data_dir, &fp, "2y", "testpass123").unwrap();
        assert_eq!(actions.len(), 3);

        // Verify metadata was updated
        let updated_meta = IdentityMetadata::load(data_dir, &fp).unwrap();
        assert!(
            updated_meta.renewed.is_some(),
            "renewed timestamp should be set"
        );

        // Verify saved key loads and has valid bindings
        let reloaded = load_key_from_store(data_dir, &fp).unwrap();
        reloaded.verify_bindings().unwrap();
    }

    #[test]
    fn test_renew_refuses_stubbed_key() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Stub the key (simulates card provision)
        let stubbed = crate::stub::stub_key(key.clone(), "DEADBEEF").unwrap();

        // Set up identity store with stubbed key
        let metadata = IdentityMetadata {
            identity: "Renew Test <renew@example.com>".to_string(),
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
        save_key_to_store(data_dir, &fp, &stubbed).unwrap();

        // Attempt renewal — should fail with KeyOnCard
        let result = run_renew(data_dir, &fp, "2y", "testpass123");
        assert!(result.is_err(), "renew should refuse stubbed key");

        let err = result.unwrap_err();
        match &err {
            KdubError::KeyOnCard(serial) => {
                assert!(
                    serial.to_string().contains("DEADBEEF"),
                    "error should contain card serial, got: {serial}"
                );
            }
            other => panic!("expected KeyOnCard error, got: {other}"),
        }
        assert_eq!(err.exit_code(), 4, "KeyOnCard should have exit code 4");
    }
}
