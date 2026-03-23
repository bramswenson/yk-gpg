//! Smart card abstraction layer for OpenPGP card operations.
//!
//! Provides a mockable [`CardExecutor`] trait and its concrete
//! [`PcscCardExecutor`] implementation using `openpgp-card` and
//! `card-backend-pcsc`.

use serde::Serialize;

use crate::error::KdubError;
use crate::types::{AdminPin, UserPin};

/// Information about a connected OpenPGP smart card.
#[derive(Debug, Clone, Serialize)]
pub struct CardInfo {
    /// Card manufacturer name (e.g. "Yubico").
    pub manufacturer: String,
    /// Card serial number as a hex string.
    pub serial: String,
    /// OpenPGP card application version (e.g. "3.4").
    pub card_version: String,
    /// Current PIN retry counts.
    pub pin_retries: PinRetries,
    /// Signing key slot info, if populated.
    pub signature_key: Option<CardKeyInfo>,
    /// Encryption key slot info, if populated.
    pub encryption_key: Option<CardKeyInfo>,
    /// Authentication key slot info, if populated.
    pub authentication_key: Option<CardKeyInfo>,
    /// Whether KDF (on-card PIN hashing) is enabled.
    pub kdf_enabled: bool,
    /// Touch policy info, if the card supports it.
    pub touch_policy: Option<TouchPolicyInfo>,
}

/// PIN retry counts for user, reset code, and admin PINs.
#[derive(Debug, Clone, Serialize)]
pub struct PinRetries {
    /// Remaining user PIN attempts.
    pub user: u8,
    /// Remaining reset code attempts.
    pub reset: u8,
    /// Remaining admin PIN attempts.
    pub admin: u8,
}

/// Information about a key loaded in a card slot.
#[derive(Debug, Clone, Serialize)]
pub struct CardKeyInfo {
    /// Algorithm description (e.g. "ed25519", "rsa4096").
    pub algorithm: String,
    /// Key fingerprint as a hex string.
    pub fingerprint: String,
}

/// Touch policy configuration for each key slot.
#[derive(Debug, Clone, Serialize)]
pub struct TouchPolicyInfo {
    /// Touch policy for signing operations.
    pub sign: String,
    /// Touch policy for encryption operations.
    pub encrypt: String,
    /// Touch policy for authentication operations.
    pub auth: String,
}

/// Which card key slot to target for import operations.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// Signing key slot.
    Signing,
    /// Decryption key slot.
    Decryption,
    /// Authentication key slot.
    Authentication,
}

impl KeySlot {
    /// Human-readable display name for this card slot.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Signing => "Signing (slot 1)",
            Self::Decryption => "Decryption (slot 2)",
            Self::Authentication => "Authentication (slot 3)",
        }
    }
}

/// Trait for OpenPGP smart card operations.
///
/// This is the mockable boundary for all card interactions. Commands call
/// the trait; tests use `MockCardExecutor` (via mockall), production uses
/// [`PcscCardExecutor`].
#[cfg_attr(test, mockall::automock)]
pub trait CardExecutor {
    /// Read card status and key information.
    fn card_info(&mut self) -> Result<CardInfo, KdubError>;

    /// Enable KDF (on-card PIN hashing) using factory PINs.
    fn enable_kdf(&mut self, admin_pin: &str) -> Result<(), KdubError>;

    /// Change the admin PIN from `current_pin` to `new_pin`.
    fn change_admin_pin(&mut self, current_pin: &str, new_pin: &AdminPin) -> Result<(), KdubError>;

    /// Change the user PIN from `current_pin` to `new_pin`.
    fn change_user_pin(&mut self, current_pin: &str, new_pin: &UserPin) -> Result<(), KdubError>;

    /// Set the cardholder name on the card (ISO 7501-1 format: `Last<<First`).
    fn set_cardholder_name(&mut self, name: &str, admin_pin: &AdminPin) -> Result<(), KdubError>;

    /// Set the public key URL on the card.
    fn set_cardholder_url(&mut self, url: &str, admin_pin: &AdminPin) -> Result<(), KdubError>;

    /// Import a secret subkey into a card slot.
    ///
    /// The `key_data` is the armored secret subkey packet. The concrete
    /// implementation deserializes it and calls the card API. Using raw
    /// bytes here keeps the trait mockable with mockall (no trait objects
    /// in parameters).
    fn import_key(
        &mut self,
        key_data: &[u8],
        slot: KeySlot,
        admin_pin: &AdminPin,
        passphrase: &str,
    ) -> Result<(), KdubError>;

    /// Factory-reset the OpenPGP applet on the card.
    fn factory_reset(&mut self) -> Result<(), KdubError>;

    /// Return the card serial number, if known.
    fn card_serial(&self) -> Option<String>;
}

/// Concrete [`CardExecutor`] backed by PC/SC via `card-backend-pcsc`.
///
/// Each method creates a fresh transaction to the card, performs the
/// operation, and drops the transaction. This avoids holding a long-lived
/// borrow on the card backend.
pub struct PcscCardExecutor {
    /// The opened card backend (owns the pcsc connection).
    backend: openpgp_card::Card<openpgp_card::state::Open>,
    /// Cached card serial number (read on connect).
    serial: Option<String>,
}

impl PcscCardExecutor {
    /// Connect to the first available OpenPGP smart card via PC/SC.
    ///
    /// Returns `Err(KdubError::CardNotFound)` if no card is detected.
    pub fn connect() -> Result<Self, KdubError> {
        let backends = card_backend_pcsc::PcscBackend::card_backends(None)
            .map_err(|e| KdubError::Card(format!("PC/SC context error: {e}")))?;

        let mut last_err = None;
        for backend_result in backends {
            match backend_result {
                Ok(backend) => match openpgp_card::Card::new(backend) {
                    Ok(mut card) => {
                        let serial = {
                            let tx = card
                                .transaction()
                                .map_err(|e| KdubError::Card(format!("card transaction: {e}")))?;
                            let aid = tx
                                .application_identifier()
                                .map_err(|e| KdubError::Card(format!("read AID: {e}")))?;
                            Some(format!("{:08X}", aid.serial()))
                        };
                        return Ok(Self {
                            backend: card,
                            serial,
                        });
                    }
                    Err(e) => {
                        last_err = Some(format!("OpenPGP SELECT failed: {e}"));
                    }
                },
                Err(e) => {
                    last_err = Some(format!("card backend error: {e}"));
                }
            }
        }

        match last_err {
            Some(detail) => Err(KdubError::CardNotFound(detail)),
            None => Err(KdubError::CardNotFound(
                "no smart card detected".to_string(),
            )),
        }
    }

    /// Create a transaction for read operations.
    fn transaction(
        &mut self,
    ) -> Result<openpgp_card::Card<openpgp_card::state::Transaction<'_>>, KdubError> {
        self.backend
            .transaction()
            .map_err(|e| KdubError::Card(format!("card transaction: {e}")))
    }
}

impl CardExecutor for PcscCardExecutor {
    fn card_info(&mut self) -> Result<CardInfo, KdubError> {
        let mut tx = self.transaction()?;

        // Application ID
        let aid = tx
            .application_identifier()
            .map_err(|e| KdubError::Card(format!("read AID: {e}")))?;
        let manufacturer = aid.manufacturer_name().to_string();
        let serial = format!("{:08X}", aid.serial());
        let version = aid.version();
        let card_version = format!("{}.{}", version >> 8, version & 0xFF);

        // PIN retries
        let pw_status = tx
            .pw_status_bytes()
            .map_err(|e| KdubError::Card(format!("read PW status: {e}")))?;
        let pin_retries = PinRetries {
            user: pw_status.err_count_pw1(),
            reset: pw_status.err_count_rc(),
            admin: pw_status.err_count_pw3(),
        };

        // Key fingerprints
        let fps = tx
            .fingerprints()
            .map_err(|e| KdubError::Card(format!("read fingerprints: {e}")))?;

        let sig_fp = fps.signature().map(|f| f.to_string());
        let enc_fp = fps.decryption().map(|f| f.to_string());
        let auth_fp = fps.authentication().map(|f| f.to_string());

        // Algorithm attributes
        let sig_algo = tx
            .algorithm_attributes(openpgp_card::ocard::KeyType::Signing)
            .ok()
            .map(|a| format!("{a}"));
        let enc_algo = tx
            .algorithm_attributes(openpgp_card::ocard::KeyType::Decryption)
            .ok()
            .map(|a| format!("{a}"));
        let auth_algo = tx
            .algorithm_attributes(openpgp_card::ocard::KeyType::Authentication)
            .ok()
            .map(|a| format!("{a}"));

        let signature_key = sig_fp.map(|fp| CardKeyInfo {
            algorithm: sig_algo.unwrap_or_default(),
            fingerprint: fp,
        });
        let encryption_key = enc_fp.map(|fp| CardKeyInfo {
            algorithm: enc_algo.unwrap_or_default(),
            fingerprint: fp,
        });
        let authentication_key = auth_fp.map(|fp| CardKeyInfo {
            algorithm: auth_algo.unwrap_or_default(),
            fingerprint: fp,
        });

        // KDF: check the actual algorithm byte.
        // kdf_do() returns Ok(KdfDo) if the KDF DO exists on the card.
        // A KDF DO with kdf_algo=0x00 means "not used" — PINs are passed raw.
        // True KDF (algo=0x03, iterated-salted S2K) hashes PINs on the card.
        // We report kdf_enabled=true only when algo != 0x00.
        let kdf_enabled = match tx.kdf_do() {
            Ok(kdf_do) => kdf_do.kdf_algo() != 0x00,
            Err(_) => false,
        };

        // Touch policy (UIF)
        let touch_policy = Self::read_touch_policy(&mut tx);

        Ok(CardInfo {
            manufacturer,
            serial,
            card_version,
            pin_retries,
            signature_key,
            encryption_key,
            authentication_key,
            kdf_enabled,
            touch_policy,
        })
    }

    fn enable_kdf(&mut self, admin_pin: &str) -> Result<(), KdubError> {
        use std::convert::TryFrom;

        let mut tx = self.transaction()?;
        let pin = secrecy::SecretString::from(admin_pin.to_string());

        let mut admin = tx
            .to_admin_card(pin)
            .map_err(|e| KdubError::Card(format!("admin auth for KDF: {e}")))?;

        // Construct a "KDF none" DO: kdf_algo = 0x00 means "not used".
        // This sets the KDF DO to acknowledge the feature without actually
        // hashing PINs on the card. Full iterated-salted-S2K setup is
        // handled at the command level in Phase E.4 (card setup).
        let kdf_none_bytes: &[u8] = &[0x81, 0x01, 0x00];
        let kdf_do = openpgp_card::ocard::data::KdfDo::try_from(kdf_none_bytes)
            .map_err(|e| KdubError::Card(format!("construct KDF DO: {e}")))?;

        admin
            .as_transaction()
            .card()
            .set_kdf_do(&kdf_do)
            .map_err(|e| KdubError::Card(format!("enable KDF: {e}")))
    }

    fn change_admin_pin(&mut self, current_pin: &str, new_pin: &AdminPin) -> Result<(), KdubError> {
        let mut tx = self.transaction()?;
        let old = secrecy::SecretString::from(current_pin.to_string());
        let new = secrecy::SecretString::from(new_pin.expose_secret().to_string());
        tx.change_admin_pin(old, new)
            .map_err(|e| KdubError::Card(format!("change admin PIN: {e}")))
    }

    fn change_user_pin(&mut self, current_pin: &str, new_pin: &UserPin) -> Result<(), KdubError> {
        let mut tx = self.transaction()?;
        let old = secrecy::SecretString::from(current_pin.to_string());
        let new = secrecy::SecretString::from(new_pin.expose_secret().to_string());
        tx.change_user_pin(old, new)
            .map_err(|e| KdubError::Card(format!("change user PIN: {e}")))
    }

    fn set_cardholder_name(&mut self, name: &str, admin_pin: &AdminPin) -> Result<(), KdubError> {
        let mut tx = self.transaction()?;
        let pin = secrecy::SecretString::from(admin_pin.expose_secret().to_string());
        let mut admin = tx
            .to_admin_card(pin)
            .map_err(|e| KdubError::Card(format!("admin auth for name: {e}")))?;
        admin
            .set_cardholder_name(name)
            .map_err(|e| KdubError::Card(format!("set cardholder name: {e}")))
    }

    fn set_cardholder_url(&mut self, url: &str, admin_pin: &AdminPin) -> Result<(), KdubError> {
        let mut tx = self.transaction()?;
        let pin = secrecy::SecretString::from(admin_pin.expose_secret().to_string());
        let mut admin = tx
            .to_admin_card(pin)
            .map_err(|e| KdubError::Card(format!("admin auth for URL: {e}")))?;
        admin
            .set_url(url)
            .map_err(|e| KdubError::Card(format!("set cardholder URL: {e}")))
    }

    fn import_key(
        &mut self,
        _key_data: &[u8],
        slot: KeySlot,
        _admin_pin: &AdminPin,
        _passphrase: &str,
    ) -> Result<(), KdubError> {
        // Trait method exists for mockability with mockall. Production callers
        // should use PcscCardExecutor::import_subkey directly, which accepts
        // rPGP SecretSubkey types. This method is intentionally unimplemented
        // because reconstructing a SecretSubkey from raw bytes is not feasible.
        Err(KdubError::Card(format!(
            "use PcscCardExecutor::import_subkey for slot {slot:?} (byte-based import not supported)"
        )))
    }

    fn factory_reset(&mut self) -> Result<(), KdubError> {
        let mut tx = self.transaction()?;
        tx.factory_reset()
            .map_err(|e| KdubError::Card(format!("factory reset: {e}")))
    }

    fn card_serial(&self) -> Option<String> {
        self.serial.clone()
    }
}

impl PcscCardExecutor {
    /// Import a secret subkey directly into a card slot.
    ///
    /// This is the concrete method that callers should use instead of the
    /// trait's byte-based `import_key`. It accepts the rPGP `SecretSubkey`
    /// type directly, avoiding packet serialization round-trips.
    pub fn import_subkey(
        &mut self,
        subkey: pgp::packet::SecretSubkey,
        slot: KeySlot,
        admin_pin: &AdminPin,
        passphrase: &str,
    ) -> Result<(), KdubError> {
        let mut uploadable = openpgp_card_rpgp::UploadableKey::from(subkey);

        // Unlock the key if it's password-protected
        if uploadable.is_locked() {
            uploadable
                .try_unlock(passphrase)
                .map_err(|e| KdubError::Card(format!("unlock subkey: {e}")))?;
        }

        let key_type = match slot {
            KeySlot::Signing => openpgp_card::ocard::KeyType::Signing,
            KeySlot::Decryption => openpgp_card::ocard::KeyType::Decryption,
            KeySlot::Authentication => openpgp_card::ocard::KeyType::Authentication,
        };

        let mut tx = self.transaction()?;
        let pin = secrecy::SecretString::from(admin_pin.expose_secret().to_string());
        let mut admin = tx
            .to_admin_card(pin)
            .map_err(|e| KdubError::Card(format!("admin auth for import: {e}")))?;

        admin
            .import_key(Box::new(uploadable), key_type)
            .map_err(|e| KdubError::Card(format!("import key to slot {slot:?}: {e}")))
    }

    /// Read touch policy from card UIF data objects.
    fn read_touch_policy(
        tx: &mut openpgp_card::Card<openpgp_card::state::Transaction<'_>>,
    ) -> Option<TouchPolicyInfo> {
        let sign = tx
            .user_interaction_flag(openpgp_card::ocard::KeyType::Signing)
            .ok()
            .flatten();
        let encrypt = tx
            .user_interaction_flag(openpgp_card::ocard::KeyType::Decryption)
            .ok()
            .flatten();
        let auth = tx
            .user_interaction_flag(openpgp_card::ocard::KeyType::Authentication)
            .ok()
            .flatten();

        // If none of the slots support UIF, return None
        if sign.is_none() && encrypt.is_none() && auth.is_none() {
            return None;
        }

        Some(TouchPolicyInfo {
            sign: sign
                .map(|u| format!("{}", u.touch_policy()))
                .unwrap_or_else(|| "n/a".to_string()),
            encrypt: encrypt
                .map(|u| format!("{}", u.touch_policy()))
                .unwrap_or_else(|| "n/a".to_string()),
            auth: auth
                .map(|u| format!("{}", u.touch_policy()))
                .unwrap_or_else(|| "n/a".to_string()),
        })
    }
}

/// Check that stdin is a TTY.
///
/// Card-modifying operations (setup, provision, reset, touch) require
/// interactive confirmation. This function ensures we are running in an
/// interactive terminal before proceeding.
pub fn require_tty() -> Result<(), KdubError> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        return Err(KdubError::Card(
            "card operations require interactive confirmation (stdin must be a TTY)".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_card_info() {
        let mut mock = MockCardExecutor::new();
        mock.expect_card_info().times(1).returning(|| {
            Ok(CardInfo {
                manufacturer: "Yubico".to_string(),
                serial: "12345678".to_string(),
                card_version: "3.4".to_string(),
                pin_retries: PinRetries {
                    user: 3,
                    reset: 0,
                    admin: 3,
                },
                signature_key: Some(CardKeyInfo {
                    algorithm: "ed25519".to_string(),
                    fingerprint: "AABB".to_string(),
                }),
                encryption_key: Some(CardKeyInfo {
                    algorithm: "cv25519".to_string(),
                    fingerprint: "CCDD".to_string(),
                }),
                authentication_key: None,
                kdf_enabled: true,
                touch_policy: Some(TouchPolicyInfo {
                    sign: "on".to_string(),
                    encrypt: "on".to_string(),
                    auth: "off".to_string(),
                }),
            })
        });

        let info = mock.card_info().unwrap();
        assert_eq!(info.manufacturer, "Yubico");
        assert_eq!(info.serial, "12345678");
        assert_eq!(info.card_version, "3.4");
        assert_eq!(info.pin_retries.user, 3);
        assert_eq!(info.pin_retries.admin, 3);
        assert!(info.signature_key.is_some());
        assert!(info.encryption_key.is_some());
        assert!(info.authentication_key.is_none());
        assert!(info.kdf_enabled);
        assert!(info.touch_policy.is_some());
    }

    #[test]
    fn test_mock_card_info_empty_card() {
        let mut mock = MockCardExecutor::new();
        mock.expect_card_info().times(1).returning(|| {
            Ok(CardInfo {
                manufacturer: "GnuPG e.V.".to_string(),
                serial: "00000000".to_string(),
                card_version: "2.0".to_string(),
                pin_retries: PinRetries {
                    user: 3,
                    reset: 3,
                    admin: 3,
                },
                signature_key: None,
                encryption_key: None,
                authentication_key: None,
                kdf_enabled: false,
                touch_policy: None,
            })
        });

        let info = mock.card_info().unwrap();
        assert_eq!(info.manufacturer, "GnuPG e.V.");
        assert!(info.signature_key.is_none());
        assert!(!info.kdf_enabled);
        assert!(info.touch_policy.is_none());
    }

    #[test]
    fn test_mock_enable_kdf() {
        let mut mock = MockCardExecutor::new();
        mock.expect_enable_kdf()
            .withf(|pin: &str| pin == "12345678")
            .times(1)
            .returning(|_| Ok(()));

        mock.enable_kdf("12345678").unwrap();
    }

    #[test]
    fn test_mock_change_admin_pin() {
        let mut mock = MockCardExecutor::new();
        mock.expect_change_admin_pin()
            .times(1)
            .returning(|_, _| Ok(()));

        let new_pin: AdminPin = "87654321".parse().unwrap();
        mock.change_admin_pin("12345678", &new_pin).unwrap();
    }

    #[test]
    fn test_mock_change_user_pin() {
        let mut mock = MockCardExecutor::new();
        mock.expect_change_user_pin()
            .times(1)
            .returning(|_, _| Ok(()));

        let new_pin: UserPin = "654321".parse().unwrap();
        mock.change_user_pin("123456", &new_pin).unwrap();
    }

    #[test]
    fn test_mock_set_cardholder_name() {
        let mut mock = MockCardExecutor::new();
        mock.expect_set_cardholder_name()
            .withf(|name: &str, _pin: &AdminPin| name == "Smith<<Alice")
            .times(1)
            .returning(|_, _| Ok(()));

        let pin: AdminPin = "87654321".parse().unwrap();
        mock.set_cardholder_name("Smith<<Alice", &pin).unwrap();
    }

    #[test]
    fn test_mock_set_cardholder_url() {
        let mut mock = MockCardExecutor::new();
        mock.expect_set_cardholder_url()
            .withf(|url: &str, _pin: &AdminPin| url == "https://example.com/key.asc")
            .times(1)
            .returning(|_, _| Ok(()));

        let pin: AdminPin = "87654321".parse().unwrap();
        mock.set_cardholder_url("https://example.com/key.asc", &pin)
            .unwrap();
    }

    #[test]
    fn test_mock_import_key_signing() {
        let mut mock = MockCardExecutor::new();
        mock.expect_import_key()
            .withf(
                |_data: &[u8], slot: &KeySlot, _pin: &AdminPin, _pass: &str| {
                    *slot == KeySlot::Signing
                },
            )
            .times(1)
            .returning(|_, _, _, _| Ok(()));

        let pin: AdminPin = "87654321".parse().unwrap();
        mock.import_key(b"fake-key-data", KeySlot::Signing, &pin, "passphrase")
            .unwrap();
    }

    #[test]
    fn test_mock_import_key_all_slots() {
        let mut mock = MockCardExecutor::new();
        mock.expect_import_key()
            .times(3)
            .returning(|_, _, _, _| Ok(()));

        let pin: AdminPin = "87654321".parse().unwrap();
        mock.import_key(b"sign", KeySlot::Signing, &pin, "pass")
            .unwrap();
        mock.import_key(b"enc", KeySlot::Decryption, &pin, "pass")
            .unwrap();
        mock.import_key(b"auth", KeySlot::Authentication, &pin, "pass")
            .unwrap();
    }

    #[test]
    fn test_mock_factory_reset() {
        let mut mock = MockCardExecutor::new();
        mock.expect_factory_reset().times(1).returning(|| Ok(()));

        mock.factory_reset().unwrap();
    }

    #[test]
    fn test_mock_card_serial() {
        let mut mock = MockCardExecutor::new();
        mock.expect_card_serial()
            .times(1)
            .returning(|| Some("12345678".to_string()));

        assert_eq!(mock.card_serial(), Some("12345678".to_string()));
    }

    #[test]
    fn test_mock_card_serial_none() {
        let mut mock = MockCardExecutor::new();
        mock.expect_card_serial().times(1).returning(|| None);

        assert_eq!(mock.card_serial(), None);
    }

    #[test]
    fn test_mock_card_info_error() {
        let mut mock = MockCardExecutor::new();
        mock.expect_card_info()
            .times(1)
            .returning(|| Err(KdubError::CardNotFound("no card".to_string())));

        let result = mock.card_info();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KdubError::CardNotFound(_)));
    }

    #[test]
    fn test_key_slot_debug() {
        assert_eq!(format!("{:?}", KeySlot::Signing), "Signing");
        assert_eq!(format!("{:?}", KeySlot::Decryption), "Decryption");
        assert_eq!(format!("{:?}", KeySlot::Authentication), "Authentication");
    }

    #[test]
    fn test_key_slot_equality() {
        assert_eq!(KeySlot::Signing, KeySlot::Signing);
        assert_ne!(KeySlot::Signing, KeySlot::Decryption);
        assert_ne!(KeySlot::Decryption, KeySlot::Authentication);
    }

    #[test]
    fn test_require_tty_compiles() {
        // We cannot reliably test require_tty() in CI since stdin may
        // or may not be a TTY depending on the test runner. This test
        // verifies the function exists, compiles, and returns a Result.
        let _result: Result<(), KdubError> = require_tty();
    }

    #[test]
    fn test_card_info_clone() {
        let info = CardInfo {
            manufacturer: "Test".to_string(),
            serial: "AABBCCDD".to_string(),
            card_version: "3.4".to_string(),
            pin_retries: PinRetries {
                user: 3,
                reset: 0,
                admin: 3,
            },
            signature_key: None,
            encryption_key: None,
            authentication_key: None,
            kdf_enabled: false,
            touch_policy: None,
        };
        let cloned = info.clone();
        assert_eq!(cloned.serial, "AABBCCDD");
        assert_eq!(cloned.manufacturer, "Test");
    }

    #[test]
    fn test_pin_retries_clone() {
        let retries = PinRetries {
            user: 3,
            reset: 0,
            admin: 3,
        };
        let cloned = retries.clone();
        assert_eq!(cloned.user, 3);
        assert_eq!(cloned.reset, 0);
        assert_eq!(cloned.admin, 3);
    }

    #[test]
    fn test_card_key_info_clone() {
        let key_info = CardKeyInfo {
            algorithm: "ed25519".to_string(),
            fingerprint: "AABB".to_string(),
        };
        let cloned = key_info.clone();
        assert_eq!(cloned.algorithm, "ed25519");
        assert_eq!(cloned.fingerprint, "AABB");
    }

    #[test]
    fn test_touch_policy_info_clone() {
        let policy = TouchPolicyInfo {
            sign: "on".to_string(),
            encrypt: "off".to_string(),
            auth: "cached".to_string(),
        };
        let cloned = policy.clone();
        assert_eq!(cloned.sign, "on");
        assert_eq!(cloned.encrypt, "off");
        assert_eq!(cloned.auth, "cached");
    }
}
