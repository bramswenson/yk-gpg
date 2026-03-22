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

    use super::*;

    // ---- Fingerprint tests ----

    #[test]
    fn fingerprint_valid_hex_roundtrip() {
        let hex_str = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        let fp: Fingerprint = hex_str.parse().unwrap();
        assert_eq!(fp.to_string(), hex_str);
        assert_eq!(fp.as_bytes().len(), 20);
    }

    #[test]
    fn fingerprint_case_normalization() {
        let lower = "d3b9c00b365dc5b752a6554a0630571a396bc2a7";
        let fp: Fingerprint = lower.parse().unwrap();
        assert_eq!(fp.to_string(), "D3B9C00B365DC5B752A6554A0630571A396BC2A7");
    }

    #[test]
    fn fingerprint_invalid_hex_rejected() {
        let result = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ".parse::<Fingerprint>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid hex"));
    }

    #[test]
    fn fingerprint_with_spaces_rejected() {
        // GPG displays fingerprints with spaces, e.g. "D3B9 C00B 365D ..."
        let result = "D3B9 C00B 365D C5B7 52A6 554A 0630 571A 396B C2A7".parse::<Fingerprint>();
        assert!(result.is_err());
    }

    #[test]
    fn fingerprint_wrong_length_rejected() {
        let result = "D3B9C00B365DC5B7".parse::<Fingerprint>();
        assert!(result.is_err());
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

    #[test]
    fn keyid_with_prefix() {
        let kid: KeyId = "0x0630571A396BC2A7".parse().unwrap();
        assert_eq!(kid.to_string(), "0x0630571A396BC2A7");
    }

    #[test]
    fn keyid_without_prefix() {
        let kid: KeyId = "0630571A396BC2A7".parse().unwrap();
        assert_eq!(kid.to_string(), "0x0630571A396BC2A7");
    }

    #[test]
    fn keyid_invalid_hex_rejected() {
        let result = "0xGGGG".parse::<KeyId>();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid hex characters")
        );
    }

    #[test]
    fn keyid_empty_rejected() {
        let result = "0x".parse::<KeyId>();
        assert!(result.is_err());
    }

    // ---- AdminPin tests ----

    #[test]
    fn admin_pin_valid_8_digits() {
        let pin: AdminPin = "12345678".parse().unwrap();
        assert_eq!(pin.expose_secret(), "12345678");
    }

    #[test]
    fn admin_pin_too_short() {
        let result = "1234567".parse::<AdminPin>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("8 digits"));
    }

    #[test]
    fn admin_pin_too_long() {
        let result = "123456789".parse::<AdminPin>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("8 digits"));
    }

    #[test]
    fn admin_pin_non_numeric_rejected() {
        let result = "1234567a".parse::<AdminPin>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("only digits"));
    }

    // ---- UserPin tests ----

    #[test]
    fn user_pin_valid_6_digits() {
        let pin: UserPin = "123456".parse().unwrap();
        assert_eq!(pin.expose_secret(), "123456");
    }

    #[test]
    fn user_pin_too_short() {
        let result = "12345".parse::<UserPin>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("6 digits"));
    }

    #[test]
    fn user_pin_too_long() {
        let result = "1234567".parse::<UserPin>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("6 digits"));
    }

    #[test]
    fn user_pin_non_numeric_rejected() {
        let result = "12345a".parse::<UserPin>();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("only digits"));
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
