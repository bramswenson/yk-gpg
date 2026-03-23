use std::path::Path;

use pgp::composed::{KeyType as PgpKeyType, SignedSecretSubKey};
use pgp::packet::{
    PubKeyInner, RevocationCode, SignatureConfig, SignatureType, Subpacket, SubpacketData,
};
use pgp::types::{KeyDetails, KeyVersion, Password, Timestamp};

use crate::backup::{load_key_from_store, save_key_to_store};
use crate::error::KdubError;
use crate::identity::IdentityMetadata;
use crate::keygen::{SignedSecretKey, extract_fingerprint, parse_expiration};
use crate::stub;
use crate::types::{CardSerial, Fingerprint, KeyType};

/// Rotate subkeys on a `SignedSecretKey`.
///
/// Generates 3 new subkeys (sign, encrypt, authenticate) under the existing
/// primary key. If `revoke_old` is true, creates SubkeyRevocation signatures
/// for all existing subkeys.
///
/// Returns the updated key and a list of action strings describing what was done.
pub fn rotate_subkeys(
    key: &SignedSecretKey,
    key_type: KeyType,
    expiration: &str,
    passphrase: &str,
    revoke_old: bool,
) -> Result<(SignedSecretKey, Vec<String>), KdubError> {
    let _expiry_duration = parse_expiration(expiration)?;
    let key_pw: Password = passphrase.into();
    let mut rng = rand::rngs::OsRng;
    let mut actions = Vec::new();

    // Map our KeyType to rPGP key types
    let (sign_type, encrypt_type, auth_type) = match key_type {
        KeyType::Ed25519 => (PgpKeyType::Ed25519, PgpKeyType::X25519, PgpKeyType::Ed25519),
        KeyType::Rsa4096 => (
            PgpKeyType::Rsa(4096),
            PgpKeyType::Rsa(4096),
            PgpKeyType::Rsa(4096),
        ),
    };

    // Start with existing subkeys, potentially adding revocation signatures
    let mut all_subkeys: Vec<SignedSecretSubKey> = Vec::new();

    if revoke_old {
        // Revoke each existing subkey
        for subkey in &key.secret_subkeys {
            let revocation_sig =
                create_subkey_revocation(&key.primary_key, subkey, &key_pw, &mut rng)?;

            let mut sigs = subkey.signatures.clone();
            sigs.push(revocation_sig);

            let revoked = SignedSecretSubKey::new(subkey.key.clone(), sigs);
            all_subkeys.push(revoked);

            let subkey_fp = hex::encode_upper(subkey.key.fingerprint().as_bytes());
            let short_fp = &subkey_fp[..16.min(subkey_fp.len())];
            actions.push(format!("Revoked old subkey {short_fp}"));
        }
    } else {
        // Keep existing subkeys as-is
        all_subkeys.extend(key.secret_subkeys.clone());
    }

    // Generate 3 new subkeys
    let subkey_specs = [
        ("sign", sign_type, true, false, false),
        ("encrypt", encrypt_type, false, true, false),
        ("auth", auth_type, false, false, true),
    ];

    for (label, pgp_key_type, can_sign, _can_encrypt, can_auth) in &subkey_specs {
        let new_subkey = generate_and_bind_subkey(
            &key.primary_key,
            pgp_key_type,
            *can_sign,
            *_can_encrypt,
            *can_auth,
            &key_pw,
            &mut rng,
        )?;

        let subkey_fp = hex::encode_upper(new_subkey.key.fingerprint().as_bytes());
        let short_fp = &subkey_fp[..16.min(subkey_fp.len())];
        actions.push(format!(
            "Created new {label} subkey {short_fp} ({key_type})"
        ));

        all_subkeys.push(new_subkey);
    }

    // Reassemble the key with all subkeys
    let rotated_key = SignedSecretKey::new(
        key.primary_key.clone(),
        key.details.clone(),
        key.public_subkeys.clone(),
        all_subkeys,
    );

    Ok((rotated_key, actions))
}

/// Generate a new subkey and create a binding signature.
///
/// Generates fresh key material, creates the `SecretSubkey` packet, produces
/// an embedded back-signature for signing-capable subkeys, and creates the
/// SubkeyBinding signature from the primary key.
fn generate_and_bind_subkey<R: rand::CryptoRng + rand::Rng>(
    primary_key: &pgp::packet::SecretKey,
    pgp_key_type: &PgpKeyType,
    can_sign: bool,
    can_encrypt: bool,
    can_auth: bool,
    key_pw: &Password,
    rng: &mut R,
) -> Result<SignedSecretSubKey, KdubError> {
    // Generate key pair
    let (public_params, secret_params) = pgp_key_type
        .generate(&mut *rng)
        .map_err(|e| KdubError::Rotate(format!("failed to generate subkey material: {e}")))?;

    // Create the public subkey inner structure
    let pub_key_inner = PubKeyInner::new(
        primary_key.version(),
        pgp_key_type.to_alg(),
        Timestamp::now(),
        None, // expiration
        public_params,
    )
    .map_err(|e| KdubError::Rotate(format!("failed to create subkey inner: {e}")))?;

    let pub_subkey = pgp::packet::PublicSubkey::from_inner(pub_key_inner)
        .map_err(|e| KdubError::Rotate(format!("failed to create public subkey: {e}")))?;

    let secret_subkey = pgp::packet::SecretSubkey::new(pub_subkey, secret_params)
        .map_err(|e| KdubError::Rotate(format!("failed to create secret subkey: {e}")))?;

    // For signing-capable subkeys, produce an embedded back-signature
    let embedded = if can_sign {
        let backsig = secret_subkey
            .sign_primary_key_binding(
                &mut *rng,
                &primary_key.public_key(),
                &"".into(), // subkey has no passphrase
            )
            .map_err(|e| KdubError::Rotate(format!("failed to create back-signature: {e}")))?;
        Some(backsig)
    } else {
        None
    };

    // Build key flags
    let mut keyflags = pgp::packet::KeyFlags::default();
    keyflags.set_sign(can_sign);
    if can_encrypt {
        keyflags.set_encrypt_comms(true);
        keyflags.set_encrypt_storage(true);
    }
    keyflags.set_authentication(can_auth);

    // Create subkey binding signature (0x18) from the primary key
    let binding_sig = secret_subkey
        .sign(
            &mut *rng,
            primary_key,
            primary_key.public_key(),
            key_pw,
            keyflags,
            embedded,
        )
        .map_err(|e| KdubError::Rotate(format!("failed to sign subkey binding: {e}")))?;

    Ok(SignedSecretSubKey::new(secret_subkey, vec![binding_sig]))
}

/// Create a SubkeyRevocation signature (type 0x28) for an existing subkey.
///
/// The revocation signature is made by the primary key and signals that
/// the subkey should no longer be used.
fn create_subkey_revocation<R: rand::CryptoRng + rand::Rng>(
    primary_key: &pgp::packet::SecretKey,
    subkey: &SignedSecretSubKey,
    key_pw: &Password,
    rng: &mut R,
) -> Result<pgp::packet::Signature, KdubError> {
    let mut sig_config =
        SignatureConfig::from_key(&mut *rng, primary_key, SignatureType::SubkeyRevocation)
            .map_err(|e| KdubError::Rotate(format!("failed to create revocation config: {e}")))?;

    sig_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))
            .map_err(|e| KdubError::Rotate(format!("timestamp subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_key.fingerprint()))
            .map_err(|e| KdubError::Rotate(format!("fingerprint subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::RevocationReason(
            RevocationCode::KeySuperseded,
            "Subkey superseded by key rotation.".into(),
        ))
        .map_err(|e| KdubError::Rotate(format!("revocation reason subpacket: {e}")))?,
    ];

    // Add unhashed issuer key ID for v4 compatibility
    if primary_key.version() <= KeyVersion::V4 {
        sig_config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(primary_key.legacy_key_id()))
                .map_err(|e| KdubError::Rotate(format!("key ID subpacket: {e}")))?,
        ];
    }

    // SubkeyRevocation uses the same hash structure as SubkeyBinding:
    // hash(primary_key || subkey)
    let signature = sig_config
        .sign_subkey_binding(
            primary_key,
            primary_key.public_key(),
            key_pw,
            subkey.key.public_key(),
        )
        .map_err(|e| KdubError::Rotate(format!("failed to sign subkey revocation: {e}")))?;

    Ok(signature)
}

/// Run a full key rotation: load key, generate new subkeys, save, update metadata.
///
/// Returns a list of action strings describing what was done.
pub fn run_rotate(
    data_dir: &Path,
    fingerprint: &Fingerprint,
    key_type: KeyType,
    expiration: &str,
    passphrase: &str,
    revoke_old: bool,
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
        return Err(KdubError::Rotate(format!(
            "fingerprint mismatch: expected {fingerprint}, got {key_fp}"
        )));
    }

    // Rotate subkeys
    let (rotated_key, actions) =
        rotate_subkeys(&key, key_type, expiration, passphrase, revoke_old)?;

    // Verify the rotated key bindings are valid
    rotated_key
        .verify_bindings()
        .map_err(|e| KdubError::Rotate(format!("rotated key failed binding verification: {e}")))?;

    // Save updated key
    save_key_to_store(data_dir, fingerprint, &rotated_key)?;

    // Update metadata
    let mut metadata = IdentityMetadata::load(data_dir, fingerprint)?;
    metadata.rotated = Some(chrono::Utc::now());
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
    fn test_rotate_adds_new_subkeys() {
        let (key, _fp) = generate_test_key();

        // Original key has 3 subkeys
        assert_eq!(key.secret_subkeys.len(), 3);

        // Rotate without revoking
        let (rotated, actions) =
            rotate_subkeys(&key, KeyType::Ed25519, "2y", "testpass123", false).unwrap();

        // Should have 6 subkeys: 3 old + 3 new
        assert_eq!(
            rotated.secret_subkeys.len(),
            6,
            "rotated key should have 6 subkeys (3 old + 3 new)"
        );

        // Should report 3 new subkey actions
        assert_eq!(actions.len(), 3);
        for action in &actions {
            assert!(
                action.contains("Created new"),
                "action should mention creation: {action}"
            );
        }

        // Verify key bindings are valid
        rotated.verify_bindings().unwrap();
    }

    #[test]
    fn test_rotate_with_revoke_old() {
        let (key, _fp) = generate_test_key();

        // Rotate with revocation
        let (rotated, actions) =
            rotate_subkeys(&key, KeyType::Ed25519, "2y", "testpass123", true).unwrap();

        // Should have 6 subkeys: 3 old (revoked) + 3 new
        assert_eq!(
            rotated.secret_subkeys.len(),
            6,
            "rotated key should have 6 subkeys"
        );

        // Actions: 3 revocations + 3 new subkeys = 6
        assert_eq!(actions.len(), 6);

        let revoke_count = actions.iter().filter(|a| a.contains("Revoked")).count();
        let create_count = actions.iter().filter(|a| a.contains("Created")).count();
        assert_eq!(revoke_count, 3, "should have 3 revocation actions");
        assert_eq!(create_count, 3, "should have 3 creation actions");

        // Old subkeys (first 3) should have revocation signatures
        for subkey in &rotated.secret_subkeys[..3] {
            let has_revocation = subkey
                .signatures
                .iter()
                .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation));
            assert!(
                has_revocation,
                "old subkey should have a SubkeyRevocation signature"
            );
        }

        // Verify key bindings are valid
        rotated.verify_bindings().unwrap();
    }

    #[test]
    fn test_rotate_preserves_primary_key() {
        let (key, fp) = generate_test_key();

        let (rotated, _actions) =
            rotate_subkeys(&key, KeyType::Ed25519, "2y", "testpass123", false).unwrap();

        // Fingerprint should be the same
        let rotated_fp = extract_fingerprint(&rotated);
        assert_eq!(
            rotated_fp, fp,
            "primary key fingerprint should not change after rotation"
        );
    }

    #[test]
    fn test_rotate_wrong_passphrase() {
        let (key, _fp) = generate_test_key();

        let result = rotate_subkeys(&key, KeyType::Ed25519, "2y", "wrongpassphrase", false);
        assert!(result.is_err(), "wrong passphrase should fail");
    }

    #[test]
    fn test_rotate_invalid_expiration() {
        let (key, _fp) = generate_test_key();

        let result = rotate_subkeys(&key, KeyType::Ed25519, "2w", "testpass123", false);
        assert!(result.is_err(), "invalid expiration format should fail");
    }

    #[test]
    fn test_run_rotate_full_workflow() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Set up identity store
        let metadata = IdentityMetadata {
            identity: "Rotate Test <rotate@example.com>".to_string(),
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

        // Run rotation
        let actions =
            run_rotate(data_dir, &fp, KeyType::Ed25519, "2y", "testpass123", false).unwrap();
        assert_eq!(actions.len(), 3);

        // Verify metadata was updated
        let updated_meta = IdentityMetadata::load(data_dir, &fp).unwrap();
        assert!(
            updated_meta.rotated.is_some(),
            "rotated timestamp should be set"
        );

        // Verify saved key loads and has valid bindings
        let reloaded = load_key_from_store(data_dir, &fp).unwrap();
        reloaded.verify_bindings().unwrap();
        assert_eq!(
            reloaded.secret_subkeys.len(),
            6,
            "reloaded key should have 6 subkeys"
        );
    }

    #[test]
    fn test_run_rotate_with_revoke_old() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Set up identity store
        let metadata = IdentityMetadata {
            identity: "Rotate Test <rotate@example.com>".to_string(),
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

        // Run rotation with revocation
        let actions =
            run_rotate(data_dir, &fp, KeyType::Ed25519, "2y", "testpass123", true).unwrap();

        // 3 revocations + 3 new = 6
        assert_eq!(actions.len(), 6);

        // Verify metadata was updated
        let updated_meta = IdentityMetadata::load(data_dir, &fp).unwrap();
        assert!(updated_meta.rotated.is_some());

        // Verify saved key
        let reloaded = load_key_from_store(data_dir, &fp).unwrap();
        reloaded.verify_bindings().unwrap();
    }

    #[test]
    fn test_rotate_refuses_stubbed_key() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let (key, fp) = generate_test_key();

        // Stub the key (simulates card provision)
        let stubbed = crate::stub::stub_key(key.clone(), "CAFEBABE").unwrap();

        // Set up identity store with stubbed key
        let metadata = IdentityMetadata {
            identity: "Rotate Test <rotate@example.com>".to_string(),
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

        // Attempt rotation — should fail with KeyOnCard
        let result = run_rotate(data_dir, &fp, KeyType::Ed25519, "2y", "testpass123", false);
        assert!(result.is_err(), "rotate should refuse stubbed key");

        let err = result.unwrap_err();
        match &err {
            KdubError::KeyOnCard(serial) => {
                assert!(
                    serial.to_string().contains("CAFEBABE"),
                    "error should contain card serial, got: {serial}"
                );
            }
            other => panic!("expected KeyOnCard error, got: {other}"),
        }
        assert_eq!(err.exit_code(), 4, "KeyOnCard should have exit code 4");
    }
}
