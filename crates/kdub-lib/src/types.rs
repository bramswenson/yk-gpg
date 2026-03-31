use std::fmt;
use std::str::FromStr;

use rand::Rng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::defaults::{DEFAULT_PASSPHRASE_LENGTH, PASSPHRASE_ALPHABET};

/// OpenPGP key algorithm selection.
///
/// Determines which cryptographic algorithms are used for the primary key
/// and subkeys. Ed25519 uses modern elliptic curves (Ed25519 for signing,
/// X25519 for encryption). Rsa4096 uses RSA for all operations.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    /// Ed25519 signing + X25519 encryption (modern, recommended for YubiKey 5+)
    #[serde(alias = "Ed25519")]
    Ed25519,
    /// RSA 4096-bit for all operations (compatible with YubiKey 4)
    #[serde(alias = "Rsa4096", alias = "RSA4096", alias = "rsa4096")]
    Rsa4096,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Ed25519 => write!(f, "ed25519"),
            KeyType::Rsa4096 => write!(f, "rsa4096"),
        }
    }
}

impl FromStr for KeyType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(KeyType::Ed25519),
            "rsa4096" => Ok(KeyType::Rsa4096),
            _ => Err(ParseError(format!(
                "unknown key type: {s} (expected 'ed25519' or 'rsa4096')"
            ))),
        }
    }
}

/// Shared error for all `FromStr` implementations.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(pub String);

/// V4 OpenPGP fingerprint (20 bytes / 40 hex characters).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 20]);

impl Fingerprint {
    /// Access the raw 20-byte fingerprint.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl FromStr for Fingerprint {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() != 40 {
            return Err(ParseError(format!(
                "expected 40 hex characters, got {}",
                s.len()
            )));
        }
        let bytes = hex::decode(s).map_err(|e| ParseError(format!("invalid hex: {e}")))?;
        let arr: [u8; 20] = bytes
            .try_into()
            .map_err(|_| ParseError("invalid fingerprint length".into()))?;
        Ok(Fingerprint(arr))
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(self.0))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode_upper(self.0))
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Fingerprint::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// Validated hex key ID, displayed with `0x` prefix.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeyId(String);

impl FromStr for KeyId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let hex_part = s.strip_prefix("0x").unwrap_or(s);
        if hex_part.is_empty() {
            return Err(ParseError("key ID cannot be empty".into()));
        }
        // Validate that the remaining characters are valid hex
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError(format!(
                "invalid hex characters in key ID: {hex_part}"
            )));
        }
        // Store uppercase hex without prefix
        Ok(KeyId(hex_part.to_ascii_uppercase()))
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.0)
    }
}

impl From<KeyId> for String {
    fn from(kid: KeyId) -> String {
        format!("0x{}", kid.0)
    }
}

impl TryFrom<String> for KeyId {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        KeyId::from_str(&s)
    }
}

/// Smart card serial number (hex identifier, normalized to uppercase).
///
/// Wraps a `String` — serials are public identifiers, not secrets. The
/// `FromStr` implementation validates that the value is non-empty hex and
/// normalizes to uppercase on parse.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CardSerial(String);

impl FromStr for CardSerial {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseError("card serial cannot be empty".into()));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ParseError(format!(
                "invalid hex characters in card serial: {s}"
            )));
        }
        Ok(CardSerial(s.to_ascii_uppercase()))
    }
}

impl fmt::Display for CardSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<CardSerial> for String {
    fn from(cs: CardSerial) -> String {
        cs.0
    }
}

impl TryFrom<String> for CardSerial {
    type Error = ParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        CardSerial::from_str(&s)
    }
}

impl CardSerial {
    /// Construct a `CardSerial` from a raw string, bypassing hex validation.
    ///
    /// Use only as a fallback when the serial value cannot be validated as hex
    /// (e.g., when the stub key does not encode a recognizable serial). The
    /// value is stored as-is.
    pub(crate) fn new_raw(s: impl Into<String>) -> Self {
        CardSerial(s.into())
    }

    /// Create a `CardSerial` from a stub extraction result.
    ///
    /// Falls back to `"unknown"` if `serial` is `None`, and uses
    /// [`CardSerial::new_raw`] if the value is not valid hex — so that
    /// non-standard serials embedded in stub keys are not silently dropped.
    pub(crate) fn from_stub(serial: Option<String>) -> Self {
        let serial_str = serial.unwrap_or_else(|| "unknown".to_string());
        serial_str
            .parse::<CardSerial>()
            .unwrap_or_else(|_| CardSerial::new_raw(&serial_str))
    }
}

/// Admin PIN for OpenPGP smart card (exactly 8 numeric digits).
pub struct AdminPin(SecretString);

impl FromStr for AdminPin {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() != 8 {
            return Err(ParseError(format!(
                "admin PIN must be exactly 8 digits, got {}",
                s.len()
            )));
        }
        if !s.chars().all(|c| c.is_ascii_digit()) {
            return Err(ParseError("admin PIN must contain only digits".into()));
        }
        Ok(AdminPin(SecretString::from(s.to_string())))
    }
}

impl AdminPin {
    /// Construct an `AdminPin` directly from a `SecretString`.
    ///
    /// This bypasses the `FromStr` validation path and is intended only for
    /// callers (within the crate) that have already ensured the string is
    /// exactly 8 ASCII digits (e.g., `generate_admin_pin`).
    pub(crate) fn from_secret(s: SecretString) -> Self {
        AdminPin(s)
    }

    /// Expose the secret PIN value.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for AdminPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminPin")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// User PIN for OpenPGP smart card (exactly 6 numeric digits).
pub struct UserPin(SecretString);

impl FromStr for UserPin {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() != 6 {
            return Err(ParseError(format!(
                "user PIN must be exactly 6 digits, got {}",
                s.len()
            )));
        }
        if !s.chars().all(|c| c.is_ascii_digit()) {
            return Err(ParseError("user PIN must contain only digits".into()));
        }
        Ok(UserPin(SecretString::from(s.to_string())))
    }
}

impl UserPin {
    /// Construct a `UserPin` directly from a `SecretString`.
    ///
    /// This bypasses the `FromStr` validation path and is intended only for
    /// callers (within the crate) that have already ensured the string is
    /// exactly 6 ASCII digits (e.g., `generate_user_pin`).
    pub(crate) fn from_secret(s: SecretString) -> Self {
        UserPin(s)
    }

    /// Expose the secret PIN value.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for UserPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserPin")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Sentinel type for factory default PINs.
pub struct FactoryPin;

impl FactoryPin {
    pub const USER: &'static str = "123456";
    pub const ADMIN: &'static str = "12345678";
}

/// Passphrase for certify key operations.
pub struct Passphrase(SecretString);

impl FromStr for Passphrase {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseError("passphrase cannot be empty".into()));
        }
        Ok(Passphrase(SecretString::from(s.to_string())))
    }
}

impl Passphrase {
    /// Generate a random passphrase of `DEFAULT_PASSPHRASE_LENGTH` characters
    /// from the `PASSPHRASE_ALPHABET`.
    pub fn generate(rng: &mut impl rand::RngCore) -> Self {
        let mut buf = String::with_capacity(DEFAULT_PASSPHRASE_LENGTH);
        let alphabet_len = PASSPHRASE_ALPHABET.len();
        for _ in 0..DEFAULT_PASSPHRASE_LENGTH {
            let idx = rng.gen_range(0..alphabet_len);
            buf.push(PASSPHRASE_ALPHABET[idx] as char);
        }
        Passphrase(SecretString::from(buf))
    }

    /// Expose the secret passphrase value.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Passphrase")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// GitHub API token for key publishing.
pub struct GithubToken(SecretString);

impl FromStr for GithubToken {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseError("GitHub token cannot be empty".into()));
        }
        Ok(GithubToken(SecretString::from(s.to_string())))
    }
}

impl GithubToken {
    /// Expose the secret token value.
    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for GithubToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubToken")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use rstest::rstest;

    use super::*;

    // ---- Fingerprint tests ----

    #[rstest]
    #[case("D3B9C00B365DC5B752A6554A0630571A396BC2A7", true)]
    #[case("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", false)] // invalid hex
    #[case("D3B9 C00B 365D C5B7 52A6 554A 0630 571A 396B C2A7", false)] // spaces
    #[case("D3B9C00B365DC5B7", false)] // wrong length
    fn fingerprint_validation(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(input.parse::<Fingerprint>().is_ok(), valid);
    }

    #[test]
    fn fingerprint_case_normalization() {
        let lower = "d3b9c00b365dc5b752a6554a0630571a396bc2a7";
        let fp: Fingerprint = lower.parse().unwrap();
        assert_eq!(fp.to_string(), "D3B9C00B365DC5B752A6554A0630571A396BC2A7");
    }

    #[test]
    fn fingerprint_valid_hex_roundtrip() {
        let hex_str = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        let fp: Fingerprint = hex_str.parse().unwrap();
        assert_eq!(fp.to_string(), hex_str);
        assert_eq!(fp.as_bytes().len(), 20);
    }

    #[test]
    fn fingerprint_invalid_hex_error_message() {
        let result = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".parse::<Fingerprint>();
        assert!(result.unwrap_err().to_string().contains("invalid hex"));
    }

    #[test]
    fn fingerprint_wrong_length_error_message() {
        let result = "D3B9C00B365DC5B7".parse::<Fingerprint>();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected 40 hex characters")
        );
    }

    #[test]
    fn fingerprint_serializes_to_hex_string() {
        let fp: Fingerprint = "D3B9C00B365DC5B752A6554A0630571A396BC2A7".parse().unwrap();
        let json = serde_json::to_string(&fp).unwrap();
        assert_eq!(json, r#""D3B9C00B365DC5B752A6554A0630571A396BC2A7""#);
    }

    #[test]
    fn fingerprint_deserializes_from_hex_string() {
        let json = r#""D3B9C00B365DC5B752A6554A0630571A396BC2A7""#;
        let fp: Fingerprint = serde_json::from_str(json).unwrap();
        assert_eq!(fp.to_string(), "D3B9C00B365DC5B752A6554A0630571A396BC2A7");
    }

    // ---- KeyId tests ----

    #[rstest]
    #[case("0x0630571A396BC2A7", true)]
    #[case("0630571A396BC2A7", true)]
    #[case("0xGGGG", false)] // invalid hex
    #[case("0x", false)] // empty
    fn keyid_validation(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(input.parse::<KeyId>().is_ok(), valid);
    }

    #[test]
    fn keyid_display_includes_prefix() {
        let kid: KeyId = "0630571A396BC2A7".parse().unwrap();
        assert_eq!(kid.to_string(), "0x0630571A396BC2A7");
    }

    #[test]
    fn keyid_invalid_hex_error_message() {
        let result = "0xGGGG".parse::<KeyId>();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid hex characters")
        );
    }

    // ---- AdminPin tests ----

    #[rstest]
    #[case("12345678", true)]
    #[case("1234567", false)] // too short
    #[case("123456789", false)] // too long
    #[case("1234567a", false)] // non-numeric
    fn admin_pin_validation(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(input.parse::<AdminPin>().is_ok(), valid);
    }

    #[test]
    fn admin_pin_expose_secret() {
        let pin: AdminPin = "12345678".parse().unwrap();
        assert_eq!(pin.expose_secret(), "12345678");
    }

    // ---- UserPin tests ----

    #[rstest]
    #[case("123456", true)]
    #[case("12345", false)] // too short
    #[case("1234567", false)] // too long
    #[case("12345a", false)] // non-numeric
    fn user_pin_validation(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(input.parse::<UserPin>().is_ok(), valid);
    }

    #[test]
    fn user_pin_expose_secret() {
        let pin: UserPin = "123456".parse().unwrap();
        assert_eq!(pin.expose_secret(), "123456");
    }

    // ---- FactoryPin tests ----

    #[test]
    fn factory_pin_constants() {
        assert_eq!(FactoryPin::USER, "123456");
        assert_eq!(FactoryPin::ADMIN, "12345678");
    }

    // ---- Passphrase tests ----

    #[test]
    fn passphrase_empty_rejected() {
        let result = "".parse::<Passphrase>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn passphrase_non_empty_accepted() {
        let pp: Passphrase = "my-secret-passphrase".parse().unwrap();
        assert_eq!(pp.expose_secret(), "my-secret-passphrase");
    }

    #[test]
    fn passphrase_generate_length_and_alphabet() {
        let mut rng = StdRng::seed_from_u64(42);
        let pp = Passphrase::generate(&mut rng);
        let secret = pp.expose_secret();
        assert_eq!(secret.len(), DEFAULT_PASSPHRASE_LENGTH);
        for ch in secret.chars() {
            assert!(
                PASSPHRASE_ALPHABET.contains(&(ch as u8)),
                "unexpected character in generated passphrase: {ch}"
            );
        }
    }

    // ---- GithubToken tests ----

    #[test]
    fn github_token_empty_rejected() {
        let result = "".parse::<GithubToken>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn github_token_non_empty_accepted() {
        let tok: GithubToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".parse().unwrap();
        assert_eq!(
            tok.expose_secret(),
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        );
    }

    // ---- CardSerial tests ----

    #[rstest]
    #[case("12345678", true)]
    #[case("deadbeef", true)]
    #[case("", false)] // empty
    #[case("ZZZZZZZZ", false)] // non-hex
    fn card_serial_validation(#[case] input: &str, #[case] valid: bool) {
        assert_eq!(input.parse::<CardSerial>().is_ok(), valid);
    }

    #[test]
    fn card_serial_case_normalization() {
        let serial: CardSerial = "deadbeef".parse().unwrap();
        assert_eq!(serial.to_string(), "DEADBEEF");
    }

    #[test]
    fn card_serial_empty_error_message() {
        let result = "".parse::<CardSerial>();
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn card_serial_non_hex_error_message() {
        let result = "ZZZZZZZZ".parse::<CardSerial>();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid hex characters")
        );
    }

    #[test]
    fn card_serial_serde_roundtrip() {
        let serial: CardSerial = "CAFEBABE".parse().unwrap();
        let json = serde_json::to_string(&serial).unwrap();
        assert_eq!(json, r#""CAFEBABE""#);
        let back: CardSerial = serde_json::from_str(&json).unwrap();
        assert_eq!(back, serial);
    }

    // ---- KeyType tests ----

    #[test]
    fn key_type_parse_ed25519() {
        let kt: KeyType = "ed25519".parse().unwrap();
        assert_eq!(kt, KeyType::Ed25519);
    }

    #[test]
    fn key_type_parse_rsa4096() {
        let kt: KeyType = "rsa4096".parse().unwrap();
        assert_eq!(kt, KeyType::Rsa4096);
    }

    #[test]
    fn key_type_parse_case_insensitive() {
        assert_eq!("Ed25519".parse::<KeyType>().unwrap(), KeyType::Ed25519);
        assert_eq!("ED25519".parse::<KeyType>().unwrap(), KeyType::Ed25519);
        assert_eq!("RSA4096".parse::<KeyType>().unwrap(), KeyType::Rsa4096);
    }

    #[test]
    fn key_type_parse_invalid() {
        let result = "rsa2048".parse::<KeyType>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown key type"));
    }

    #[test]
    fn key_type_display() {
        assert_eq!(KeyType::Ed25519.to_string(), "ed25519");
        assert_eq!(KeyType::Rsa4096.to_string(), "rsa4096");
    }

    // ---- Debug redaction tests ----

    #[test]
    fn admin_pin_debug_redacted() {
        let pin: AdminPin = "12345678".parse().unwrap();
        let debug_str = format!("{pin:?}");
        assert!(debug_str.contains("[REDACTED]"), "got: {debug_str}");
        assert!(
            !debug_str.contains("12345678"),
            "secret leaked: {debug_str}"
        );
    }

    #[test]
    fn user_pin_debug_redacted() {
        let pin: UserPin = "123456".parse().unwrap();
        let debug_str = format!("{pin:?}");
        assert!(debug_str.contains("[REDACTED]"), "got: {debug_str}");
        assert!(!debug_str.contains("123456"), "secret leaked: {debug_str}");
    }

    #[test]
    fn passphrase_debug_redacted() {
        let pp: Passphrase = "supersecret".parse().unwrap();
        let debug_str = format!("{pp:?}");
        assert!(debug_str.contains("[REDACTED]"), "got: {debug_str}");
        assert!(
            !debug_str.contains("supersecret"),
            "secret leaked: {debug_str}"
        );
    }

    #[test]
    fn github_token_debug_redacted() {
        let tok: GithubToken = "ghp_abc123xyz".parse().unwrap();
        let debug_str = format!("{tok:?}");
        assert!(debug_str.contains("[REDACTED]"), "got: {debug_str}");
        assert!(
            !debug_str.contains("ghp_abc123xyz"),
            "secret leaked: {debug_str}"
        );
    }

    #[test]
    fn fingerprint_debug_format() {
        let fp: Fingerprint = "D3B9C00B365DC5B752A6554A0630571A396BC2A7".parse().unwrap();
        let debug_str = format!("{fp:?}");
        assert!(
            debug_str.contains("Fingerprint(D3B9C00B365DC5B752A6554A0630571A396BC2A7)"),
            "got: {debug_str}"
        );
    }

    // ---- CardSerial::from_stub tests ----

    #[test]
    fn card_serial_from_stub_valid_hex() {
        let serial = CardSerial::from_stub(Some("deadbeef".to_string()));
        // Valid hex is normalized to uppercase.
        assert_eq!(serial.to_string(), "DEADBEEF");
    }

    #[test]
    fn card_serial_from_stub_none_returns_unknown() {
        let serial = CardSerial::from_stub(None);
        assert_eq!(serial.to_string(), "unknown");
    }

    #[test]
    fn card_serial_from_stub_non_hex_uses_raw() {
        // Non-hex strings fall back to raw storage without validation.
        let serial = CardSerial::from_stub(Some("not-valid-hex!!".to_string()));
        assert_eq!(serial.to_string(), "not-valid-hex!!");
    }

    // ---- CardSerial::new_raw test ----

    #[test]
    fn card_serial_new_raw_stores_as_is() {
        let serial = CardSerial::new_raw("custom-raw-value");
        assert_eq!(serial.to_string(), "custom-raw-value");
    }

    #[test]
    fn key_type_serde_roundtrip() {
        let kt = KeyType::Ed25519;
        let json = serde_json::to_string(&kt).unwrap();
        assert_eq!(json, r#""ed25519""#);
        let back: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kt);

        let kt = KeyType::Rsa4096;
        let json = serde_json::to_string(&kt).unwrap();
        assert_eq!(json, r#""rsa4096""#);
        let back: KeyType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kt);
    }
}
