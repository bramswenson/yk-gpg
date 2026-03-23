use pgp::composed::{EncryptionCaps, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::composed::{KeyType as PgpKeyType, SecretKeyParams};
use pgp::types::KeyDetails;
use rand::{CryptoRng, Rng};

use crate::error::KdubError;
use crate::types::{KeyType, Passphrase};

/// Result of key generation: the signed secret key.
pub type SignedSecretKey = pgp::composed::SignedSecretKey;

/// Generate an OpenPGP key with certify-only primary and 3 subkeys (sign, encrypt, auth).
///
/// Expiration is applied to all subkeys via `KeyExpirationTime` binding signatures
/// after key generation. If `expiration` is `"never"`, no expiration is set.
///
/// # Arguments
/// * `identity` - User ID string, e.g. "Name <email>"
/// * `key_type` - Algorithm selection (Ed25519 or Rsa4096)
/// * `expiration` - Subkey expiration duration string (e.g. "2y", "1y", "6m", "90d", "never")
/// * `passphrase` - Passphrase to protect the primary key
/// * `rng` - Cryptographic RNG (injectable for deterministic testing)
pub fn generate_key<R: Rng + CryptoRng>(
    identity: &str,
    key_type: KeyType,
    expiration: &str,
    passphrase: &Passphrase,
    rng: R,
) -> Result<SignedSecretKey, KdubError> {
    // Validate expiration format early
    let expiry_duration = parse_expiration(expiration)?;

    // Map our KeyType to rPGP key types
    let (primary_type, sign_type, encrypt_type, auth_type) = match key_type {
        KeyType::Ed25519 => (
            PgpKeyType::Ed25519,
            PgpKeyType::Ed25519,
            PgpKeyType::X25519,
            PgpKeyType::Ed25519,
        ),
        KeyType::Rsa4096 => (
            PgpKeyType::Rsa(4096),
            PgpKeyType::Rsa(4096),
            PgpKeyType::Rsa(4096),
            PgpKeyType::Rsa(4096),
        ),
    };

    // Build primary key: certify-only, no expiration
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(primary_type)
        .primary_user_id(identity.to_string())
        .can_certify(true)
        .can_sign(false)
        .can_authenticate(false)
        .passphrase(Some(passphrase.expose_secret().to_string()));

    // Sign subkey: sign-only
    let sign_subkey = SubkeyParamsBuilder::default()
        .key_type(sign_type)
        .can_sign(true)
        .can_authenticate(false)
        .build()
        .map_err(|e| KdubError::KeyGen(format!("failed to build sign subkey: {e}")))?;

    // Encrypt subkey: encrypt-only
    let encrypt_subkey = SubkeyParamsBuilder::default()
        .key_type(encrypt_type)
        .can_sign(false)
        .can_encrypt(EncryptionCaps::All)
        .can_authenticate(false)
        .build()
        .map_err(|e| KdubError::KeyGen(format!("failed to build encrypt subkey: {e}")))?;

    // Auth subkey: authenticate-only
    let auth_subkey = SubkeyParamsBuilder::default()
        .key_type(auth_type)
        .can_sign(false)
        .can_authenticate(true)
        .build()
        .map_err(|e| KdubError::KeyGen(format!("failed to build auth subkey: {e}")))?;

    key_params
        .subkey(sign_subkey)
        .subkey(encrypt_subkey)
        .subkey(auth_subkey);

    let secret_key_params: SecretKeyParams = key_params
        .build()
        .map_err(|e| KdubError::KeyGen(format!("failed to build key params: {e}")))?;

    // Generate the signed key (pgp 0.19 returns SignedSecretKey directly)
    let signed_key = secret_key_params
        .generate(rng)
        .map_err(|e| KdubError::KeyGen(format!("key generation failed: {e}")))?;

    // Apply subkey expiration via binding signatures (unless "never")
    if expiry_duration.is_some() {
        let (key_with_expiry, _actions) =
            crate::renew::renew_subkeys(&signed_key, expiration, passphrase.expose_secret())
                .map_err(|e| {
                    KdubError::KeyGen(format!("failed to apply subkey expiration: {e}"))
                })?;
        Ok(key_with_expiry)
    } else {
        Ok(signed_key)
    }
}

/// Extract the [`Fingerprint`] from a `SignedSecretKey`.
///
/// Parses the raw bytes from the key into a [`crate::types::Fingerprint`].
/// Panics (via `.expect`) only if rPGP returns a fingerprint that is not
/// 20 bytes — which is an invariant violation in the library itself.
pub fn extract_fingerprint(key: &SignedSecretKey) -> crate::types::Fingerprint {
    let fp = key.fingerprint();
    let hex_str = hex::encode_upper(fp.as_bytes());
    hex_str
        .parse::<crate::types::Fingerprint>()
        .expect("rPGP fingerprint is always a valid 20-byte / 40-char hex fingerprint")
}

/// Export a `SignedSecretKey` as an armored PGP private key string.
pub fn export_armored_secret(key: &SignedSecretKey) -> Result<String, KdubError> {
    key.to_armored_string(Default::default())
        .map_err(|e| KdubError::KeyGen(format!("failed to export armored key: {e}")))
}

/// Parse an expiration duration string into an `Option<Duration>`.
///
/// Supported formats: "2y", "1y", "6m", "90d", "never"
/// Returns `None` for "never" (no expiration).
///
/// Used by `generate_key` to apply expiration at creation time and by
/// `renew_subkeys` to update expiration via binding signatures.
pub fn parse_expiration(s: &str) -> Result<Option<std::time::Duration>, KdubError> {
    let s = s.trim().to_lowercase();
    if s == "never" {
        return Ok(None);
    }

    let (num_str, unit) = if let Some(n) = s.strip_suffix('y') {
        (n, 'y')
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 'm')
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 'd')
    } else {
        return Err(KdubError::KeyGen(format!(
            "invalid expiration format: {s} (expected e.g. 2y, 6m, 90d, never)"
        )));
    };

    let num: u64 = num_str
        .parse()
        .map_err(|e| KdubError::KeyGen(format!("invalid expiration number in '{s}': {e}")))?;

    let seconds = match unit {
        'y' => num * 365 * 24 * 3600,
        'm' => num * 30 * 24 * 3600,
        'd' => num * 24 * 3600,
        _ => unreachable!(),
    };

    Ok(Some(std::time::Duration::from_secs(seconds)))
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rstest::rstest;

    use super::*;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[rstest]
    #[case("2y", Some(2 * 365 * 24 * 3600))]
    #[case("6m", Some(6 * 30 * 24 * 3600))]
    #[case("90d", Some(90 * 24 * 3600))]
    #[case("never", None)]
    fn parse_expiration_valid(#[case] input: &str, #[case] expected_secs: Option<u64>) {
        let result = parse_expiration(input).unwrap();
        assert_eq!(result.map(|d| d.as_secs()), expected_secs);
    }

    #[rstest]
    #[case("2w")]
    #[case("abc")]
    #[case("")]
    fn parse_expiration_invalid(#[case] input: &str) {
        assert!(parse_expiration(input).is_err());
    }

    #[test]
    fn test_generate_ed25519_key() {
        let rng = test_rng();
        let pp: Passphrase = "testpassphrase123".parse().unwrap();
        let key = generate_key(
            "Test User <test@example.com>",
            KeyType::Ed25519,
            "2y",
            &pp,
            rng,
        )
        .unwrap();

        // Verify 3 secret subkeys
        assert_eq!(
            key.secret_subkeys.len(),
            3,
            "ed25519 key should have 3 subkeys (sign, encrypt, auth)"
        );

        // Verify fingerprint extraction
        let fp = extract_fingerprint(&key);
        assert_eq!(
            fp.to_string().len(),
            40,
            "V4 fingerprint should be 40 hex chars"
        );

        // Verify armored export
        let armored = export_armored_secret(&key).unwrap();
        assert!(armored.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    }

    #[test]
    fn test_generate_rsa4096_key() {
        // RSA key generation is slow, use a smaller test
        let rng = test_rng();
        let pp: Passphrase = "rsapassphrase".parse().unwrap();
        let key = generate_key(
            "RSA User <rsa@example.com>",
            KeyType::Rsa4096,
            "1y",
            &pp,
            rng,
        )
        .unwrap();

        assert_eq!(
            key.secret_subkeys.len(),
            3,
            "rsa4096 key should have 3 subkeys (sign, encrypt, auth)"
        );

        let fp = extract_fingerprint(&key);
        assert_eq!(fp.to_string().len(), 40);
    }

    #[test]
    fn test_key_has_correct_identity() {
        let rng = test_rng();
        let identity = "Identity Test <identity@example.com>";
        let pp: Passphrase = "pass123".parse().unwrap();
        let key = generate_key(identity, KeyType::Ed25519, "2y", &pp, rng).unwrap();

        // Check that the primary user ID is in the signed key details
        let uid_packets = &key.details.users;
        assert!(
            !uid_packets.is_empty(),
            "key should have at least one user ID"
        );

        // The first user ID should match our identity
        let uid_str = uid_packets[0].id.id();
        assert_eq!(uid_str, identity.as_bytes());
    }

    #[test]
    fn test_generate_key_never_expiration() {
        let rng = test_rng();
        let pp: Passphrase = "pass1234".parse().unwrap();
        let key = generate_key(
            "NoExpiry <noexpiry@example.com>",
            KeyType::Ed25519,
            "never",
            &pp,
            rng,
        )
        .unwrap();

        assert_eq!(key.secret_subkeys.len(), 3);
    }

    #[test]
    fn test_generated_key_with_expiration_has_key_expiration_time() {
        use pgp::packet::SubpacketData;

        let rng = test_rng();
        let pp: Passphrase = "testpass".parse().unwrap();
        let key = generate_key(
            "Expiry Test <expiry@example.com>",
            KeyType::Ed25519,
            "2y",
            &pp,
            rng,
        )
        .unwrap();

        assert_eq!(key.secret_subkeys.len(), 3);

        // Every subkey should have a binding signature with KeyExpirationTime
        for (i, subkey) in key.secret_subkeys.iter().enumerate() {
            let has_expiration = subkey.signatures.iter().any(|sig| {
                sig.config()
                    .map(|c| {
                        c.hashed_subpackets()
                            .any(|sp| matches!(sp.data, SubpacketData::KeyExpirationTime(_)))
                    })
                    .unwrap_or(false)
            });
            assert!(
                has_expiration,
                "subkey {i} should have KeyExpirationTime subpacket"
            );
        }

        // Verify bindings are valid
        key.verify_bindings().unwrap();
    }

    #[test]
    fn test_generated_key_with_never_has_no_key_expiration_time() {
        use pgp::packet::SubpacketData;

        let rng = test_rng();
        let pp: Passphrase = "testpass".parse().unwrap();
        let key = generate_key(
            "NoExpiry2 <noexpiry2@example.com>",
            KeyType::Ed25519,
            "never",
            &pp,
            rng,
        )
        .unwrap();

        assert_eq!(key.secret_subkeys.len(), 3);

        // No subkey should have a KeyExpirationTime subpacket
        for (i, subkey) in key.secret_subkeys.iter().enumerate() {
            let has_expiration = subkey.signatures.iter().any(|sig| {
                sig.config()
                    .map(|c| {
                        c.hashed_subpackets()
                            .any(|sp| matches!(sp.data, SubpacketData::KeyExpirationTime(_)))
                    })
                    .unwrap_or(false)
            });
            assert!(
                !has_expiration,
                "subkey {i} should NOT have KeyExpirationTime for 'never' expiration"
            );
        }

        key.verify_bindings().unwrap();
    }

    #[test]
    fn test_generated_key_expiration_duration_is_correct() {
        use pgp::packet::SubpacketData;

        let rng = test_rng();
        let pp: Passphrase = "testpass".parse().unwrap();
        let key = generate_key(
            "Duration Test <duration@example.com>",
            KeyType::Ed25519,
            "2y",
            &pp,
            rng,
        )
        .unwrap();

        let expected_secs = 2 * 365 * 24 * 3600_u64;

        for (i, subkey) in key.secret_subkeys.iter().enumerate() {
            // Find the KeyExpirationTime from the binding signature
            let expiration_secs = subkey
                .signatures
                .iter()
                .find_map(|sig| {
                    sig.config().and_then(|c| {
                        c.hashed_subpackets().find_map(|sp| match &sp.data {
                            SubpacketData::KeyExpirationTime(d) => {
                                Some(std::time::Duration::from(*d).as_secs())
                            }
                            _ => None,
                        })
                    })
                })
                .unwrap_or_else(|| panic!("subkey {i} should have KeyExpirationTime"));

            // KeyExpirationTime is relative to key creation. Since the key was just
            // created, the offset should be close to the requested duration.
            // Allow 60 seconds tolerance for test execution time.
            let diff = expiration_secs.abs_diff(expected_secs);
            assert!(
                diff < 60,
                "subkey {i}: expiration offset {expiration_secs}s should be within 60s of {expected_secs}s (diff={diff}s)"
            );
        }
    }
}
