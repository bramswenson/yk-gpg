use pgp::composed::{EncryptionCaps, SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::composed::{KeyType as PgpKeyType, SecretKeyParams};
use pgp::types::KeyDetails;
use rand::{CryptoRng, Rng};

use crate::error::KdubError;
use crate::types::KeyType;

/// Result of key generation: the signed secret key.
pub type SignedSecretKey = pgp::composed::SignedSecretKey;

/// Generate an OpenPGP key with certify-only primary and 3 subkeys (sign, encrypt, auth).
///
/// # Arguments
/// * `identity` - User ID string, e.g. "Name <email>"
/// * `key_type` - Algorithm selection (Ed25519 or Rsa4096)
/// * `expiration` - Subkey expiration duration string (e.g. "2y", "1y", "6m", "90d", "never").
///   NOTE: pgp 0.19 no longer supports setting expiration at key-generation time.
///   Expiration should be set later via binding signatures or gpg --edit-key.
///   This parameter is parsed and validated but not applied to the generated key.
/// * `passphrase` - Passphrase to protect the primary key
/// * `rng` - Cryptographic RNG (injectable for deterministic testing)
pub fn generate_key<R: Rng + CryptoRng>(
    identity: &str,
    key_type: KeyType,
    expiration: &str,
    passphrase: &str,
    rng: R,
) -> Result<SignedSecretKey, KdubError> {
    // Validate expiration format (even though pgp 0.19 doesn't use it at keygen time)
    let _expiry_duration = parse_expiration(expiration)?;

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
        .passphrase(Some(passphrase.to_string()));

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

    Ok(signed_key)
}

/// Extract the hex-encoded fingerprint from a `SignedSecretKey`.
pub fn extract_fingerprint(key: &SignedSecretKey) -> String {
    let fp = key.fingerprint();
    hex::encode_upper(fp.as_bytes())
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
/// NOTE: pgp 0.19 removed expiration from the key builder. This function
/// is retained for input validation and used by the renew command to set
/// expiration via binding signatures.
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

    use super::*;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn test_parse_expiration_2y() {
        let d = parse_expiration("2y").unwrap().unwrap();
        assert_eq!(d.as_secs(), 2 * 365 * 24 * 3600);
    }

    #[test]
    fn test_parse_expiration_6m() {
        let d = parse_expiration("6m").unwrap().unwrap();
        assert_eq!(d.as_secs(), 6 * 30 * 24 * 3600);
    }

    #[test]
    fn test_parse_expiration_90d() {
        let d = parse_expiration("90d").unwrap().unwrap();
        assert_eq!(d.as_secs(), 90 * 24 * 3600);
    }

    #[test]
    fn test_parse_expiration_never() {
        assert!(parse_expiration("never").unwrap().is_none());
    }

    #[test]
    fn test_parse_expiration_invalid() {
        assert!(parse_expiration("2w").is_err());
        assert!(parse_expiration("abc").is_err());
        assert!(parse_expiration("").is_err());
    }

    #[test]
    fn test_generate_ed25519_key() {
        let rng = test_rng();
        let key = generate_key(
            "Test User <test@example.com>",
            KeyType::Ed25519,
            "2y",
            "testpassphrase123",
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
        assert_eq!(fp.len(), 40, "V4 fingerprint should be 40 hex chars");

        // Verify armored export
        let armored = export_armored_secret(&key).unwrap();
        assert!(armored.contains("BEGIN PGP PRIVATE KEY BLOCK"));
    }

    #[test]
    fn test_generate_rsa4096_key() {
        // RSA key generation is slow, use a smaller test
        let rng = test_rng();
        let key = generate_key(
            "RSA User <rsa@example.com>",
            KeyType::Rsa4096,
            "1y",
            "rsapassphrase",
            rng,
        )
        .unwrap();

        assert_eq!(
            key.secret_subkeys.len(),
            3,
            "rsa4096 key should have 3 subkeys (sign, encrypt, auth)"
        );

        let fp = extract_fingerprint(&key);
        assert_eq!(fp.len(), 40);
    }

    #[test]
    fn test_key_has_correct_identity() {
        let rng = test_rng();
        let identity = "Identity Test <identity@example.com>";
        let key = generate_key(identity, KeyType::Ed25519, "2y", "pass123", rng).unwrap();

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
        let key = generate_key(
            "NoExpiry <noexpiry@example.com>",
            KeyType::Ed25519,
            "never",
            "pass",
            rng,
        )
        .unwrap();

        assert_eq!(key.secret_subkeys.len(), 3);
    }
}
