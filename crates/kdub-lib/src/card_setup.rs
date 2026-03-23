//! Card setup logic: PIN changes, KDF enablement, and cardholder metadata.
//!
//! Implements the core setup flow for OpenPGP smart cards. The command handler
//! is responsible for all interactive I/O (confirmation prompts, PIN display);
//! this module performs the card operations in the correct order:
//!
//! 1. Enable KDF (while PINs are still at factory defaults)
//! 2. Change admin PIN
//! 3. Change user PIN
//! 4. Set cardholder name (if provided)
//! 5. Set cardholder URL (if provided)

use rand::RngCore;
use secrecy::SecretString;

use crate::card::CardExecutor;
use crate::error::KdubError;
use crate::types::{AdminPin, FactoryPin, UserPin};

/// Options for [`run_card_setup`].
///
/// The command handler resolves CLI flags and environment variables into
/// this struct before calling the library function.
pub struct CardSetupOptions {
    /// Trust that the card has factory default PINs.
    pub factory_pins: bool,
    /// Current admin PIN (if not using factory PINs).
    pub current_admin_pin: Option<AdminPin>,
    /// Current user PIN (if not using factory PINs and user PIN change is desired).
    ///
    /// When `factory_pins=false`:
    /// - `Some(pin)`: use this as the current user PIN for `change_user_pin`
    /// - `None`: skip user PIN change entirely (matches original bash behavior)
    pub current_user_pin: Option<UserPin>,
    /// New admin PIN to set. If `None`, one is generated.
    pub new_admin_pin: Option<AdminPin>,
    /// New user PIN to set. If `None`, one is generated.
    pub new_user_pin: Option<UserPin>,
    /// Skip KDF (on-card PIN hashing) setup.
    pub skip_kdf: bool,
    /// Identity string for cardholder name (e.g. `"Alice Smith <alice@example.com>"`).
    pub identity: Option<String>,
    /// Public key URL to store on the card.
    pub url: Option<String>,
}

/// Result of a successful card setup operation.
///
/// Contains the PINs that were set (generated or provided) so the command
/// handler can display them to the user exactly once.
#[derive(Debug)]
pub struct CardSetupResult {
    /// The new admin PIN that was set on the card.
    pub admin_pin: AdminPin,
    /// The new user PIN that was set on the card, or `None` if the user PIN
    /// change was skipped (i.e. `factory_pins=false` and no `current_user_pin`
    /// was provided). Callers must not display a PIN when this is `None`.
    pub new_user_pin: Option<UserPin>,
    /// Whether KDF was enabled.
    pub kdf_enabled: bool,
    /// Cardholder name that was set, if any (ISO 7501-1 format).
    pub cardholder_name: Option<String>,
    /// URL that was set on the card, if any.
    pub cardholder_url: Option<String>,
}

/// Generate a numeric PIN string of the given length using the provided RNG.
///
/// Each digit is independently sampled from 0–9. This is an internal helper;
/// callers should use [`generate_admin_pin`] or [`generate_user_pin`] instead.
fn generate_pin_digits(rng: &mut impl RngCore, length: usize) -> String {
    use rand::Rng;
    (0..length)
        .map(|_| (rng.gen_range(0..10u8) + b'0') as char)
        .collect()
}

/// Generate a random 8-digit admin PIN.
///
/// Returns a validated [`AdminPin`] ready for use in card operations.
/// The generated PIN always satisfies the 8-digit numeric constraint imposed
/// by [`AdminPin::from_str`].
pub fn generate_admin_pin(rng: &mut impl RngCore) -> AdminPin {
    let s = generate_pin_digits(rng, 8);
    // generate_pin_digits(_, 8) always produces exactly 8 ASCII digits —
    // the invariant required by AdminPin — so we construct directly.
    AdminPin::from_secret(SecretString::from(s))
}

/// Generate a random 6-digit user PIN.
///
/// Returns a validated [`UserPin`] ready for use in card operations.
/// The generated PIN always satisfies the 6-digit numeric constraint imposed
/// by [`UserPin::from_str`].
pub fn generate_user_pin(rng: &mut impl RngCore) -> UserPin {
    let s = generate_pin_digits(rng, 6);
    // generate_pin_digits(_, 6) always produces exactly 6 ASCII digits —
    // the invariant required by UserPin — so we construct directly.
    UserPin::from_secret(SecretString::from(s))
}

/// Parse an identity string like `"Alice Smith <alice@example.com>"` into
/// ISO 7501-1 cardholder name format: `Last<<First`.
///
/// Heuristic: splits on the last space before `<` to get first/last name.
/// If parsing fails, returns the full name part as-is (no `<<` separator).
pub fn identity_to_cardholder_name(identity: &str) -> String {
    // Strip email part: everything from first '<' onwards
    let name_part = identity.split('<').next().unwrap_or(identity).trim();

    if name_part.is_empty() {
        return String::new();
    }

    // Split into first name(s) and last name
    // Convention: last token is surname, everything before is given name(s)
    let parts: Vec<&str> = name_part.split_whitespace().collect();
    if parts.len() == 1 {
        // Single name — use as surname
        return parts[0].to_string();
    }

    let last = parts.last().unwrap_or(&"");
    let first = parts[..parts.len() - 1].join(" ");
    format!("{last}<<{first}")
}

/// Execute the card setup sequence.
///
/// Operations are performed in a specific order to maintain card integrity:
/// 1. Enable KDF while PINs are at factory defaults (if applicable)
/// 2. Change admin PIN
/// 3. Change user PIN
/// 4. Set cardholder metadata (requires new admin PIN)
///
/// # Errors
///
/// Returns `KdubError::Card` if any card operation fails, or
/// `KdubError::InvalidPin` if provided PINs fail validation.
pub fn run_card_setup(
    executor: &mut dyn CardExecutor,
    opts: &CardSetupOptions,
    rng: &mut impl RngCore,
) -> Result<CardSetupResult, KdubError> {
    // Determine the current admin PIN
    let current_admin = if opts.factory_pins {
        FactoryPin::ADMIN.to_string()
    } else {
        match &opts.current_admin_pin {
            Some(pin) => pin.expose_secret().to_string(),
            None => {
                return Err(KdubError::Card(
                    "current admin PIN required (use --factory-pins or --admin-pin)".to_string(),
                ));
            }
        }
    };

    // Determine if we should change the user PIN, and what current value to use.
    // - factory_pins=true: use factory user PIN (always change)
    // - factory_pins=false, current_user_pin=Some(pin): use provided PIN (change)
    // - factory_pins=false, current_user_pin=None: skip user PIN change (bash behavior)
    let current_user: Option<String> = if opts.factory_pins {
        Some(FactoryPin::USER.to_string())
    } else {
        opts.current_user_pin
            .as_ref()
            .map(|pin| pin.expose_secret().to_string())
    };

    // Generate or use provided PINs
    let new_admin: AdminPin = match &opts.new_admin_pin {
        Some(pin) => {
            // Clone by parsing the exposed secret
            pin.expose_secret()
                .parse()
                .map_err(|e: crate::types::ParseError| KdubError::InvalidPin(e.to_string()))?
        }
        None => generate_admin_pin(rng),
    };

    let new_user: UserPin = match &opts.new_user_pin {
        Some(pin) => pin
            .expose_secret()
            .parse()
            .map_err(|e: crate::types::ParseError| KdubError::InvalidPin(e.to_string()))?,
        None => generate_user_pin(rng),
    };

    // Step 1: Enable KDF (must happen while PINs are at factory defaults)
    //
    // KDF must be enabled before PIN change while factory PINs are known.
    // When real KDF (algo=0x03, iterated-salted S2K) is implemented, the
    // openpgp-card library handles PIN hashing transparently — callers
    // still pass plaintext PINs, and the library hashes them before
    // sending to the card.
    //
    // Note: enable_kdf() currently writes kdf_algo=0x00 ("not used"), so
    // kdf_enabled is always false from run_card_setup. The card_info() function
    // checks the actual algo byte to determine true KDF enablement.
    let kdf_enabled = if !opts.skip_kdf && opts.factory_pins {
        match executor.enable_kdf(&current_admin) {
            Ok(()) => {
                // enable_kdf() writes kdf_algo=0x00 (placeholder, not real KDF).
                // Report false: KDF is not actually hashing PINs yet.
                false
            }
            Err(e) => {
                tracing::warn!("KDF setup failed (card may not support it): {e}");
                false
            }
        }
    } else {
        false
    };

    // Step 2: Change admin PIN
    executor.change_admin_pin(&current_admin, &new_admin)?;

    // Step 3: Change user PIN (only if we have the current user PIN)
    let user_pin_changed = if let Some(ref cur_user) = current_user {
        executor.change_user_pin(cur_user, &new_user)?;
        true
    } else {
        tracing::info!("skipping user PIN change: no current user PIN provided");
        false
    };

    // Step 4: Set cardholder name
    let cardholder_name = if let Some(identity) = &opts.identity {
        let name = identity_to_cardholder_name(identity);
        if !name.is_empty() {
            executor.set_cardholder_name(&name, &new_admin)?;
            Some(name)
        } else {
            None
        }
    } else {
        None
    };

    // Step 5: Set cardholder URL
    let cardholder_url = if let Some(url) = &opts.url {
        executor.set_cardholder_url(url, &new_admin)?;
        Some(url.clone())
    } else {
        None
    };

    Ok(CardSetupResult {
        admin_pin: new_admin,
        new_user_pin: if user_pin_changed {
            Some(new_user)
        } else {
            None
        },
        kdf_enabled,
        cardholder_name,
        cardholder_url,
    })
}

#[cfg(test)]
mod tests {
    use mockall::predicate;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    use super::*;
    use crate::card::MockCardExecutor;

    /// Helper: build default factory-pin options for tests.
    fn factory_opts() -> CardSetupOptions {
        CardSetupOptions {
            factory_pins: true,
            current_admin_pin: None,
            current_user_pin: None,
            new_admin_pin: None,
            new_user_pin: None,
            skip_kdf: false,
            identity: None,
            url: None,
        }
    }

    #[test]
    fn test_generate_admin_pin_length_and_digits() {
        let mut rng = StdRng::seed_from_u64(42);
        let pin = generate_admin_pin(&mut rng);
        let secret = pin.expose_secret();
        assert_eq!(secret.len(), 8);
        assert!(secret.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_user_pin_length_and_digits() {
        let mut rng = StdRng::seed_from_u64(42);
        let pin = generate_user_pin(&mut rng);
        let secret = pin.expose_secret();
        assert_eq!(secret.len(), 6);
        assert!(secret.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_admin_pin_different_seeds_different_pins() {
        let mut rng1 = StdRng::seed_from_u64(1);
        let mut rng2 = StdRng::seed_from_u64(2);
        let pin1 = generate_admin_pin(&mut rng1);
        let pin2 = generate_admin_pin(&mut rng2);
        assert_ne!(pin1.expose_secret(), pin2.expose_secret());
    }

    #[test]
    fn test_identity_to_cardholder_name_full() {
        let name = identity_to_cardholder_name("Alice Smith <alice@example.com>");
        assert_eq!(name, "Smith<<Alice");
    }

    #[test]
    fn test_identity_to_cardholder_name_multiple_first_names() {
        let name = identity_to_cardholder_name("Alice Jane Smith <alice@example.com>");
        assert_eq!(name, "Smith<<Alice Jane");
    }

    #[test]
    fn test_identity_to_cardholder_name_single() {
        let name = identity_to_cardholder_name("Alice");
        assert_eq!(name, "Alice");
    }

    #[test]
    fn test_identity_to_cardholder_name_no_email() {
        let name = identity_to_cardholder_name("Alice Smith");
        assert_eq!(name, "Smith<<Alice");
    }

    #[test]
    fn test_identity_to_cardholder_name_empty() {
        let name = identity_to_cardholder_name("");
        assert_eq!(name, "");
    }

    #[test]
    fn test_identity_to_cardholder_name_only_email() {
        let name = identity_to_cardholder_name("<alice@example.com>");
        assert_eq!(name, "");
    }

    #[test]
    fn test_setup_kdf_before_pin_change() {
        // Verify that enable_kdf is called BEFORE change_admin_pin
        let mut mock = MockCardExecutor::new();
        let mut seq = mockall::Sequence::new();

        // KDF must be called first (with factory admin PIN)
        mock.expect_enable_kdf()
            .with(predicate::eq(FactoryPin::ADMIN))
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(()));

        // Then admin PIN change
        mock.expect_change_admin_pin()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));

        // Then user PIN change
        mock.expect_change_user_pin()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = factory_opts();
        let result = run_card_setup(&mut mock, &opts, &mut rng);
        assert!(result.is_ok());
        let result = result.unwrap();
        // enable_kdf() writes kdf_algo=0x00 (placeholder), so kdf_enabled is false
        assert!(!result.kdf_enabled);
    }

    #[test]
    fn test_setup_skip_kdf() {
        let mut mock = MockCardExecutor::new();

        // KDF should NOT be called
        mock.expect_enable_kdf().times(0);

        mock.expect_change_admin_pin()
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_change_user_pin()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let mut opts = factory_opts();
        opts.skip_kdf = true;

        let result = run_card_setup(&mut mock, &opts, &mut rng);
        assert!(result.is_ok());
        assert!(!result.unwrap().kdf_enabled);
    }

    #[test]
    fn test_setup_generates_pins() {
        let mut mock = MockCardExecutor::new();

        mock.expect_enable_kdf().returning(|_| Ok(()));
        mock.expect_change_admin_pin()
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_change_user_pin()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = factory_opts();

        let result = run_card_setup(&mut mock, &opts, &mut rng).unwrap();

        // Generated admin PIN is 8 digits
        let admin = result.admin_pin.expose_secret();
        assert_eq!(admin.len(), 8);
        assert!(admin.chars().all(|c| c.is_ascii_digit()));

        // Generated user PIN is 6 digits (was changed, so Some)
        let user = result.new_user_pin.as_ref().unwrap().expose_secret();
        assert_eq!(user.len(), 6);
        assert!(user.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_setup_with_provided_pins() {
        let mut mock = MockCardExecutor::new();

        mock.expect_enable_kdf().returning(|_| Ok(()));
        mock.expect_change_admin_pin()
            .withf(|current, new| current == FactoryPin::ADMIN && new.expose_secret() == "87654321")
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_change_user_pin()
            .withf(|current, new| current == FactoryPin::USER && new.expose_secret() == "654321")
            .times(1)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = CardSetupOptions {
            factory_pins: true,
            current_admin_pin: None,
            current_user_pin: None,
            new_admin_pin: Some("87654321".parse().unwrap()),
            new_user_pin: Some("654321".parse().unwrap()),
            skip_kdf: false,
            identity: None,
            url: None,
        };

        let result = run_card_setup(&mut mock, &opts, &mut rng).unwrap();
        assert_eq!(result.admin_pin.expose_secret(), "87654321");
        assert_eq!(
            result.new_user_pin.as_ref().unwrap().expose_secret(),
            "654321"
        );
    }

    #[test]
    fn test_setup_with_identity_sets_cardholder_name() {
        let mut mock = MockCardExecutor::new();

        mock.expect_enable_kdf().returning(|_| Ok(()));
        mock.expect_change_admin_pin().returning(|_, _| Ok(()));
        mock.expect_change_user_pin().returning(|_, _| Ok(()));
        mock.expect_set_cardholder_name()
            .withf(|name: &str, _pin| name == "Smith<<Alice")
            .times(1)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = CardSetupOptions {
            factory_pins: true,
            current_admin_pin: None,
            current_user_pin: None,
            new_admin_pin: None,
            new_user_pin: None,
            skip_kdf: false,
            identity: Some("Alice Smith <alice@example.com>".to_string()),
            url: None,
        };

        let result = run_card_setup(&mut mock, &opts, &mut rng).unwrap();
        assert_eq!(result.cardholder_name.as_deref(), Some("Smith<<Alice"));
    }

    #[test]
    fn test_setup_with_url_sets_cardholder_url() {
        let mut mock = MockCardExecutor::new();

        mock.expect_enable_kdf().returning(|_| Ok(()));
        mock.expect_change_admin_pin().returning(|_, _| Ok(()));
        mock.expect_change_user_pin().returning(|_, _| Ok(()));
        mock.expect_set_cardholder_url()
            .withf(|url: &str, _pin| url == "https://example.com/key.asc")
            .times(1)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = CardSetupOptions {
            factory_pins: true,
            current_admin_pin: None,
            current_user_pin: None,
            new_admin_pin: None,
            new_user_pin: None,
            skip_kdf: false,
            identity: None,
            url: Some("https://example.com/key.asc".to_string()),
        };

        let result = run_card_setup(&mut mock, &opts, &mut rng).unwrap();
        assert_eq!(
            result.cardholder_url.as_deref(),
            Some("https://example.com/key.asc")
        );
    }

    #[test]
    fn test_setup_no_factory_pins_no_admin_pin_errors() {
        let mut mock = MockCardExecutor::new();
        let mut rng = StdRng::seed_from_u64(42);
        let opts = CardSetupOptions {
            factory_pins: false,
            current_admin_pin: None,
            current_user_pin: None,
            new_admin_pin: None,
            new_user_pin: None,
            skip_kdf: false,
            identity: None,
            url: None,
        };

        let result = run_card_setup(&mut mock, &opts, &mut rng);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("admin PIN required"), "got: {err}");
    }

    #[test]
    fn test_setup_kdf_failure_continues() {
        // If KDF fails (card doesn't support it), setup should continue
        let mut mock = MockCardExecutor::new();

        mock.expect_enable_kdf()
            .times(1)
            .returning(|_| Err(KdubError::Card("KDF not supported".to_string())));

        mock.expect_change_admin_pin()
            .times(1)
            .returning(|_, _| Ok(()));
        mock.expect_change_user_pin()
            .times(1)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = factory_opts();

        let result = run_card_setup(&mut mock, &opts, &mut rng).unwrap();
        assert!(!result.kdf_enabled);
    }

    #[test]
    fn test_setup_admin_pin_change_failure_is_error() {
        let mut mock = MockCardExecutor::new();

        mock.expect_enable_kdf().returning(|_| Ok(()));
        mock.expect_change_admin_pin()
            .times(1)
            .returning(|_, _| Err(KdubError::Card("PIN change failed".to_string())));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = factory_opts();

        let result = run_card_setup(&mut mock, &opts, &mut rng);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("PIN change failed")
        );
    }

    #[test]
    fn test_setup_user_pin_change_failure_is_error() {
        let mut mock = MockCardExecutor::new();

        mock.expect_enable_kdf().returning(|_| Ok(()));
        mock.expect_change_admin_pin().returning(|_, _| Ok(()));
        mock.expect_change_user_pin()
            .times(1)
            .returning(|_, _| Err(KdubError::Card("user PIN failed".to_string())));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = factory_opts();

        let result = run_card_setup(&mut mock, &opts, &mut rng);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("user PIN failed"));
    }

    #[test]
    fn test_setup_full_flow_with_all_options() {
        let mut mock = MockCardExecutor::new();
        let mut seq = mockall::Sequence::new();

        mock.expect_enable_kdf()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_| Ok(()));
        mock.expect_change_admin_pin()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));
        mock.expect_change_user_pin()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));
        mock.expect_set_cardholder_name()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));
        mock.expect_set_cardholder_url()
            .times(1)
            .in_sequence(&mut seq)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = CardSetupOptions {
            factory_pins: true,
            current_admin_pin: None,
            current_user_pin: None,
            new_admin_pin: Some("87654321".parse().unwrap()),
            new_user_pin: Some("654321".parse().unwrap()),
            skip_kdf: false,
            identity: Some("Alice Smith <alice@example.com>".to_string()),
            url: Some("https://example.com/key.asc".to_string()),
        };

        let result = run_card_setup(&mut mock, &opts, &mut rng).unwrap();
        // enable_kdf() writes kdf_algo=0x00 (placeholder), so kdf_enabled is false
        assert!(!result.kdf_enabled);
        assert_eq!(result.admin_pin.expose_secret(), "87654321");
        assert_eq!(
            result.new_user_pin.as_ref().unwrap().expose_secret(),
            "654321"
        );
        assert_eq!(result.cardholder_name.as_deref(), Some("Smith<<Alice"));
        assert_eq!(
            result.cardholder_url.as_deref(),
            Some("https://example.com/key.asc")
        );
    }

    #[test]
    fn test_non_factory_with_current_user_pin_changes_user_pin() {
        // When factory_pins=false and current_user_pin=Some(...), user PIN change is performed.
        let mut mock = MockCardExecutor::new();

        // KDF should NOT be called (not factory_pins)
        mock.expect_enable_kdf().times(0);

        let current_admin_str = "87654321";
        let current_user_str = "654321";
        let new_admin_str = "11223344";
        let new_user_str = "998877";

        mock.expect_change_admin_pin()
            .withf(move |current, _new| current == current_admin_str)
            .times(1)
            .returning(|_, _| Ok(()));

        mock.expect_change_user_pin()
            .withf(move |current, new| {
                current == current_user_str && new.expose_secret() == new_user_str
            })
            .times(1)
            .returning(|_, _| Ok(()));

        let mut rng = StdRng::seed_from_u64(42);
        let opts = CardSetupOptions {
            factory_pins: false,
            current_admin_pin: Some("87654321".parse().unwrap()),
            current_user_pin: Some("654321".parse().unwrap()),
            new_admin_pin: Some(new_admin_str.parse().unwrap()),
            new_user_pin: Some(new_user_str.parse().unwrap()),
            skip_kdf: false,
            identity: None,
            url: None,
        };

        let result = run_card_setup(&mut mock, &opts, &mut rng);
        assert!(result.is_ok(), "expected ok, got: {:?}", result);
        let result = result.unwrap();
        assert_eq!(result.admin_pin.expose_secret(), new_admin_str);
        assert_eq!(
            result.new_user_pin.as_ref().unwrap().expose_secret(),
            new_user_str
        );
    }

    #[test]
    fn test_non_factory_without_current_user_pin_skips_user_pin_change() {
        // When factory_pins=false and current_user_pin=None, user PIN change is skipped.
        let mut mock = MockCardExecutor::new();

        // KDF should NOT be called (not factory_pins)
        mock.expect_enable_kdf().times(0);

        mock.expect_change_admin_pin()
            .times(1)
            .returning(|_, _| Ok(()));

        // change_user_pin must NOT be called
        mock.expect_change_user_pin().times(0);

        let mut rng = StdRng::seed_from_u64(42);
        let opts = CardSetupOptions {
            factory_pins: false,
            current_admin_pin: Some("87654321".parse().unwrap()),
            current_user_pin: None,
            new_admin_pin: Some("11223344".parse().unwrap()),
            new_user_pin: Some("998877".parse().unwrap()),
            skip_kdf: false,
            identity: None,
            url: None,
        };

        let result = run_card_setup(&mut mock, &opts, &mut rng);
        assert!(
            result.is_ok(),
            "expected ok (user PIN skipped), got: {:?}",
            result
        );
        // new_user_pin must be None because the PIN was never set on the card
        assert!(
            result.unwrap().new_user_pin.is_none(),
            "new_user_pin should be None when user PIN change was skipped"
        );
    }
}
