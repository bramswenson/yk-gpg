//! GNU S2K stub creation and detection for GPG compatibility.
//!
//! After `card provision` moves keys to a smart card, the local `.key` file
//! is replaced with a stub that preserves public key parameters but removes
//! secret material.
//!
//! The stub uses S2K specifier type 101 (private/experimental range per
//! RFC 4880):
//!
//! **Mode 1001 ("gnu-dummy")** — secret removed, no card reference:
//! - Bytes: `FF 00 65 00 47 4E 55 01`
//!
//! **Mode 1002 ("gnu-divert-to-card")** — key is on a specific card:
//! - Bytes: `FF 00 65 00 47 4E 55 02 <len> <serial_bytes>`

use pgp::bytes::Bytes;
use pgp::composed::SignedSecretSubKey;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{EncryptedSecretParams, S2kParams, SecretParams, StringToKey};

use crate::error::KdubError;
use crate::keygen::SignedSecretKey;

/// The GNU extension magic bytes: "GNU" in ASCII.
const GNU_MAGIC: &[u8] = b"GNU";

/// GNU S2K mode 1001: secret key material removed (no card reference).
const GNU_MODE_DUMMY: u8 = 1;

/// GNU S2K mode 1002: secret key material on a smart card.
const GNU_MODE_DIVERT_TO_CARD: u8 = 2;

/// S2K type 101 — private/experimental range per RFC 4880.
const GNU_S2K_TYPE: u8 = 101;

/// Check if any subkey in a `SignedSecretKey` is a GNU S2K stub.
///
/// Returns `true` if at least one secret subkey has its secret params
/// replaced with a GNU S2K stub (mode 1001 or 1002).
pub fn is_stub(key: &SignedSecretKey) -> bool {
    key.secret_subkeys.iter().any(is_subkey_stub)
}

/// Check if a specific subkey's secret params are a GNU S2K stub.
///
/// Inspects the S2K parameters of the subkey's secret key material
/// to determine if they match the GNU S2K stub format (type 101,
/// mode 1001 or 1002).
pub fn is_subkey_stub(subkey: &SignedSecretSubKey) -> bool {
    is_secret_params_stub(subkey.key.secret_params())
}

/// Check if a `SecretParams` value is a GNU S2K stub.
fn is_secret_params_stub(params: &SecretParams) -> bool {
    match params {
        SecretParams::Encrypted(enc) => match enc.string_to_key_params() {
            // We check both Cfb and MalleableCfb defensively, even though rPGP typically normalizes MalleableCfb to Cfb during parsing.
            S2kParams::Cfb { s2k, .. } | S2kParams::MalleableCfb { s2k, .. } => {
                is_gnu_s2k_stub(s2k)
            }
            _ => false,
        },
        SecretParams::Plain(_) => false,
    }
}

/// Check if a `StringToKey` value matches the GNU S2K stub pattern.
fn is_gnu_s2k_stub(s2k: &StringToKey) -> bool {
    match s2k {
        StringToKey::Private { typ, unknown } if *typ == GNU_S2K_TYPE => {
            // Expected format: [hash_alg=0x00, 'G', 'N', 'U', mode, ...]
            // The hash algorithm byte (0x00) is consumed as part of the S2K
            // type parsing, so `unknown` starts with: [0x00, 0x47, 0x4E, 0x55, mode, ...]
            if unknown.len() < 5 {
                return false;
            }
            // hash_alg byte is 0x00 (None)
            if unknown[0] != 0x00 {
                return false;
            }
            // Check GNU magic bytes
            if &unknown[1..4] != GNU_MAGIC {
                return false;
            }
            // Mode must be 1 (dummy) or 2 (divert-to-card)
            let mode = unknown[4];
            mode == GNU_MODE_DUMMY || mode == GNU_MODE_DIVERT_TO_CARD
        }
        _ => false,
    }
}

/// Get card serial from a mode 1002 stub.
///
/// Returns `None` if the key has no subkey stubs, if the stubs are mode 1001
/// (no card reference), or if the key is not a stub at all.
pub fn card_serial_from_stub(key: &SignedSecretKey) -> Option<String> {
    for subkey in &key.secret_subkeys {
        if let Some(serial) = card_serial_from_subkey_stub(subkey) {
            return Some(serial);
        }
    }
    None
}

/// Extract card serial from a single subkey's GNU S2K mode 1002 stub.
fn card_serial_from_subkey_stub(subkey: &SignedSecretSubKey) -> Option<String> {
    let params = subkey.key.secret_params();
    let enc = match params {
        SecretParams::Encrypted(enc) => enc,
        SecretParams::Plain(_) => return None,
    };

    let s2k = match enc.string_to_key_params() {
        S2kParams::Cfb { s2k, .. } | S2kParams::MalleableCfb { s2k, .. } => s2k,
        _ => return None,
    };

    match s2k {
        StringToKey::Private { typ, unknown } if *typ == GNU_S2K_TYPE => {
            // Format: [hash=0x00, 'G', 'N', 'U', mode, len, serial_bytes...]
            if unknown.len() < 5 {
                return None;
            }
            if unknown[0] != 0x00 || &unknown[1..4] != GNU_MAGIC {
                return None;
            }
            let mode = unknown[4];
            if mode != GNU_MODE_DIVERT_TO_CARD {
                return None;
            }
            // After mode byte: length byte + serial bytes
            if unknown.len() < 6 {
                return None;
            }
            let serial_len = unknown[5] as usize;
            if unknown.len() < 6 + serial_len {
                return None;
            }
            let serial_bytes = &unknown[6..6 + serial_len];
            Some(hex::encode_upper(serial_bytes))
        }
        _ => None,
    }
}

/// Build the `unknown` bytes for a GNU S2K mode 1001 stub (dummy).
///
/// Format: `[hash=0x00, 'G', 'N', 'U', 0x01]`
fn build_gnu_dummy_unknown() -> Bytes {
    let mut buf = Vec::with_capacity(5);
    buf.push(0x00); // hash algorithm = None
    buf.extend_from_slice(GNU_MAGIC);
    buf.push(GNU_MODE_DUMMY);
    Bytes::from(buf)
}

/// Build the `unknown` bytes for a GNU S2K mode 1002 stub (divert-to-card).
///
/// Format: `[hash=0x00, 'G', 'N', 'U', 0x02, len, serial_bytes...]`
fn build_gnu_divert_unknown(card_serial: &str) -> Result<Bytes, KdubError> {
    let serial_bytes = hex::decode(card_serial)
        .map_err(|e| KdubError::Backup(format!("invalid card serial hex '{card_serial}': {e}")))?;
    if serial_bytes.len() > 255 {
        return Err(KdubError::Backup(
            "card serial too long (max 255 bytes)".to_string(),
        ));
    }

    let mut buf = Vec::with_capacity(6 + serial_bytes.len());
    buf.push(0x00); // hash algorithm = None
    buf.extend_from_slice(GNU_MAGIC);
    buf.push(GNU_MODE_DIVERT_TO_CARD);
    buf.push(serial_bytes.len() as u8);
    buf.extend_from_slice(&serial_bytes);
    Ok(Bytes::from(buf))
}

/// Build an `S2kParams` representing a GNU S2K stub.
///
/// Uses `MalleableCfb` variant so the usage byte serializes as 0xFF (255),
/// matching GPG's format. The cipher is `Plaintext` (0x00) with an empty IV.
fn build_stub_s2k_params(s2k: StringToKey) -> S2kParams {
    S2kParams::MalleableCfb {
        sym_alg: SymmetricKeyAlgorithm::Plaintext,
        s2k,
        iv: Bytes::new(),
    }
}

/// Build `SecretParams` for a GNU S2K stub.
fn build_stub_secret_params(s2k: StringToKey) -> SecretParams {
    let s2k_params = build_stub_s2k_params(s2k);
    // No encrypted data for stubs — the "data" field is empty.
    let enc = EncryptedSecretParams::new(Bytes::new(), s2k_params);
    SecretParams::Encrypted(enc)
}

/// Replace secret key material with GNU S2K stubs.
///
/// The primary key gets mode 1001 (gnu-dummy: secret removed, no card
/// reference). Subkeys get mode 1002 (gnu-divert-to-card) with the
/// provided card serial number.
///
/// The public key parameters (fingerprint, user IDs, signatures) are
/// preserved. Only the secret key material is replaced.
pub fn stub_key(key: SignedSecretKey, card_serial: &str) -> Result<SignedSecretKey, KdubError> {
    // Build stub params for primary key (mode 1001 — no card reference)
    let primary_stub_s2k = StringToKey::Private {
        typ: GNU_S2K_TYPE,
        unknown: build_gnu_dummy_unknown(),
    };
    let primary_stub_params = build_stub_secret_params(primary_stub_s2k);

    // Build stub params for subkeys (mode 1002 — divert to card)
    let subkey_stub_s2k = StringToKey::Private {
        typ: GNU_S2K_TYPE,
        unknown: build_gnu_divert_unknown(card_serial)?,
    };

    // Reconstruct the primary key with stub secret params
    let stubbed_primary =
        pgp::packet::SecretKey::new(key.primary_key.public_key().clone(), primary_stub_params)
            .map_err(|e| KdubError::Backup(format!("failed to create stubbed primary key: {e}")))?;

    // Reconstruct each subkey with stub secret params
    let mut stubbed_subkeys = Vec::with_capacity(key.secret_subkeys.len());
    for subkey in &key.secret_subkeys {
        let subkey_stub_params = build_stub_secret_params(subkey_stub_s2k.clone());
        let stubbed_subkey =
            pgp::packet::SecretSubkey::new(subkey.key.public_key().clone(), subkey_stub_params)
                .map_err(|e| KdubError::Backup(format!("failed to create stubbed subkey: {e}")))?;

        let signed_subkey = SignedSecretSubKey::new(stubbed_subkey, subkey.signatures.clone());
        stubbed_subkeys.push(signed_subkey);
    }

    Ok(SignedSecretKey::new(
        stubbed_primary,
        key.details.clone(),
        key.public_subkeys.clone(),
        stubbed_subkeys,
    ))
}

#[cfg(test)]
mod tests {
    use pgp::composed::Deserializable;

    use super::*;
    use crate::keygen;

    fn generate_test_key() -> (SignedSecretKey, crate::types::Fingerprint) {
        let armored = include_str!("../tests/fixtures/test_key.asc");
        let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored))
            .expect("fixture key should parse");
        let fp = crate::keygen::extract_fingerprint(&key);
        (key, fp)
    }

    #[test]
    fn test_is_stub_on_normal_key() {
        let (key, _fp) = generate_test_key();
        assert!(!is_stub(&key), "normal key should not be detected as stub");
    }

    #[test]
    fn test_stub_key_creates_valid_stub() {
        let (key, _fp) = generate_test_key();
        let stubbed = stub_key(key, "12345678").unwrap();
        assert!(is_stub(&stubbed), "stubbed key should be detected as stub");
    }

    #[test]
    fn test_card_serial_from_stub() {
        let (key, _fp) = generate_test_key();
        let stubbed = stub_key(key, "12345678").unwrap();
        let serial = card_serial_from_stub(&stubbed);
        assert_eq!(
            serial,
            Some("12345678".to_string()),
            "should extract card serial from mode 1002 stub"
        );
    }

    #[test]
    fn test_card_serial_from_mode_1001() {
        let (key, _fp) = generate_test_key();
        // The primary key is mode 1001 (no card serial).
        // Subkeys are mode 1002. So card_serial_from_stub should return the serial.
        // To test mode 1001 specifically, we need a key where all subkeys are also mode 1001.
        // We can test by checking the primary key directly.
        assert!(
            card_serial_from_stub(&key).is_none(),
            "non-stub key should return None for card serial"
        );

        // Build a key with only mode 1001 stubs (no card serial on subkeys)
        let primary_stub_s2k = StringToKey::Private {
            typ: GNU_S2K_TYPE,
            unknown: build_gnu_dummy_unknown(),
        };
        let primary_stub_params = build_stub_secret_params(primary_stub_s2k.clone());

        let stubbed_primary =
            pgp::packet::SecretKey::new(key.primary_key.public_key().clone(), primary_stub_params)
                .unwrap();

        // Rebuild subkeys with mode 1001 instead of 1002
        let mut stubbed_subkeys = Vec::new();
        for subkey in &key.secret_subkeys {
            let subkey_stub_params = build_stub_secret_params(primary_stub_s2k.clone());
            let stubbed_subkey =
                pgp::packet::SecretSubkey::new(subkey.key.public_key().clone(), subkey_stub_params)
                    .unwrap();
            let signed_subkey = SignedSecretSubKey::new(stubbed_subkey, subkey.signatures.clone());
            stubbed_subkeys.push(signed_subkey);
        }

        let mode_1001_key = SignedSecretKey::new(
            stubbed_primary,
            key.details.clone(),
            key.public_subkeys.clone(),
            stubbed_subkeys,
        );

        assert!(
            is_stub(&mode_1001_key),
            "mode 1001 stub should be detected as stub"
        );
        assert!(
            card_serial_from_stub(&mode_1001_key).is_none(),
            "mode 1001 stub should return None for card serial"
        );
    }

    #[test]
    fn test_stub_preserves_public_params() {
        let (key, fp) = generate_test_key();
        let stubbed = stub_key(key, "12345678").unwrap();

        // Fingerprint should be unchanged
        let stubbed_fp = keygen::extract_fingerprint(&stubbed);
        assert_eq!(
            stubbed_fp, fp,
            "stubbed key should preserve the primary fingerprint"
        );

        // Public key export should work
        let public_key = stubbed.to_public_key();
        let armored = public_key
            .to_armored_string(Default::default())
            .expect("should be able to export public key from stubbed key");
        assert!(
            armored.contains("BEGIN PGP PUBLIC KEY BLOCK"),
            "public key export should produce valid armored output"
        );
    }

    #[test]
    fn test_stub_key_roundtrip() {
        let (key, _fp) = generate_test_key();
        let stubbed = stub_key(key, "AABBCCDD").unwrap();

        // Serialize to armored string
        let armored = stubbed
            .to_armored_string(Default::default())
            .expect("should be able to serialize stubbed key");

        // Parse back
        let (parsed, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(&armored))
            .expect("should be able to parse serialized stub key");

        // Should still be detected as stub
        assert!(
            is_stub(&parsed),
            "parsed stubbed key should still be detected as stub"
        );

        // Should still have the card serial
        let serial = card_serial_from_stub(&parsed);
        assert_eq!(
            serial,
            Some("AABBCCDD".to_string()),
            "card serial should survive roundtrip"
        );
    }
}
