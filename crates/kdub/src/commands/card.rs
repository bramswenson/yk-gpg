use std::io::{self, Write};

use kdub_lib::card::{
    CardExecutor, CardInfo, CardKeyInfo, PcscCardExecutor, TouchPolicyInfo, require_tty,
};
use kdub_lib::card_provision;
use kdub_lib::card_reset;
use kdub_lib::card_setup::{self, CardSetupOptions};
use kdub_lib::error::KdubError;
use kdub_lib::types::{AdminPin, Fingerprint, Passphrase, UserPin};
use kdub_lib::ykman::{RealYkmanExecutor, YkmanExecutor, YubiKeyInfo, ykman_info};
use rand::rngs::OsRng;
use serde::Serialize;

use crate::cli::{
    CardCommand, CardInfoArgs, CardProvisionArgs, CardResetArgs, CardSetupArgs, CardTouchArgs,
    GlobalOpts,
};
use crate::secret_input;

use super::{CmdResult, normalize_key_id, resolve_data_dir};

pub fn run(cmd: &CardCommand, global: &GlobalOpts) -> CmdResult {
    match cmd {
        CardCommand::Info(args) => run_info(args, global),
        CardCommand::Setup(args) => run_setup(args, global),
        CardCommand::Provision(args) => run_provision(args, global),
        CardCommand::Reset(args) => run_reset(args, global),
        CardCommand::Touch(args) => run_touch(args, global),
    }
}

/// Run the `card setup` command.
///
/// SAFETY-CRITICAL: configures PINs and KDF on the smart card.
/// - Rejects `--batch` mode (always interactive)
/// - Requires TTY for confirmation prompts
/// - Shows summary before proceeding
/// - Requires typing `yes` to confirm
/// - Displays new PINs exactly once
/// - Requires PIN recording acknowledgment
fn run_setup(args: &CardSetupArgs, global: &GlobalOpts) -> CmdResult {
    // Safety check 1: reject batch mode
    if global.batch {
        return Err(KdubError::Card(
            "card setup requires interactive confirmation -- --batch is not supported".to_string(),
        ));
    }

    // Safety check 2: require TTY
    require_tty()?;

    // Connect to card
    let mut executor = PcscCardExecutor::connect().map_err(|e| match e {
        KdubError::CardNotFound(_) => KdubError::CardNotFound(
            "no smart card detected\n  Ensure your YubiKey or OpenPGP card is inserted".to_string(),
        ),
        other => other,
    })?;

    // Read current card info for the summary
    let info = executor.card_info()?;

    // Resolve current admin PIN
    let current_admin_pin = if args.factory_pins {
        None // run_card_setup handles factory PINs internally
    } else if let Some(ref pin_str) = args.admin_pin {
        Some(
            pin_str
                .parse::<AdminPin>()
                .map_err(|e| KdubError::InvalidPin(format!("--admin-pin: {e}")))?,
        )
    } else {
        return Err(KdubError::Card(
            "specify --factory-pins if the card has default PINs, or provide --admin-pin"
                .to_string(),
        ));
    };

    // Resolve current user PIN (only relevant when not using factory PINs)
    let current_user_pin = if args.factory_pins {
        None // factory_pins path uses FactoryPin::USER internally
    } else {
        args.current_user_pin
            .as_ref()
            .map(|s| {
                s.parse::<UserPin>()
                    .map_err(|e| KdubError::InvalidPin(format!("--current-user-pin: {e}")))
            })
            .transpose()?
    };

    // Resolve new PINs (validate if provided via flag or stdin, otherwise will be generated)
    let new_admin_pin = if args.new_admin_pin_stdin {
        Some(secret_input::resolve_secret::<AdminPin>(
            None,
            true,
            "KDUB_NEW_ADMIN_PIN",
            "New admin PIN (8 numeric digits)",
            false,
        )?)
    } else {
        args.new_admin_pin
            .as_ref()
            .map(|s| {
                s.parse::<AdminPin>()
                    .map_err(|e| KdubError::InvalidPin(format!("--new-admin-pin: {e}")))
            })
            .transpose()?
    };

    let new_user_pin = if args.new_user_pin_stdin {
        Some(secret_input::resolve_secret::<UserPin>(
            None,
            true,
            "KDUB_NEW_USER_PIN",
            "New user PIN (6 numeric digits)",
            false,
        )?)
    } else {
        args.new_user_pin
            .as_ref()
            .map(|s| {
                s.parse::<UserPin>()
                    .map_err(|e| KdubError::InvalidPin(format!("--new-user-pin: {e}")))
            })
            .transpose()?
    };

    // Show setup summary
    println!();
    println!("Card setup summary:");
    println!(
        "  Card:          {} (serial: {})",
        info.manufacturer, info.serial
    );
    println!(
        "  KDF:           {}",
        if args.skip_kdf {
            "skip"
        } else if args.factory_pins {
            "enable (if supported)"
        } else {
            "skip (requires factory PINs)"
        }
    );
    println!(
        "  Admin PIN:     {}",
        if new_admin_pin.is_some() {
            "set to provided value"
        } else {
            "generate random (8 digits)"
        }
    );
    println!(
        "  User PIN:      {}",
        if !args.factory_pins && args.current_user_pin.is_none() {
            "skip (no --current-user-pin provided)"
        } else if new_user_pin.is_some() {
            "set to provided value"
        } else {
            "generate random (6 digits)"
        }
    );
    if let Some(ref identity) = args.identity {
        let name = card_setup::identity_to_cardholder_name(identity);
        println!("  Cardholder:    {name}");
    }
    if let Some(ref url) = args.url {
        println!("  Public key URL: {url}");
    }
    println!();

    // Safety check 3: require typing 'yes' to proceed
    if !confirm_with_yes("Type 'yes' to proceed with card setup: ")? {
        return Err(KdubError::Card("setup cancelled by user".to_string()));
    }

    // Build options and run setup
    let opts = CardSetupOptions {
        factory_pins: args.factory_pins,
        current_admin_pin,
        current_user_pin,
        new_admin_pin,
        new_user_pin,
        skip_kdf: args.skip_kdf,
        identity: args.identity.clone(),
        url: args.url.clone(),
    };

    let mut rng = OsRng;
    let result = card_setup::run_card_setup(&mut executor, &opts, &mut rng)?;

    // Display new PINs in bordered banner
    println!();
    println!("============================================================");
    println!("  IMPORTANT: Record these PINs before continuing!");
    println!("  They will not be displayed again.");
    println!("============================================================");
    println!();
    println!("  Admin PIN:  {}", result.admin_pin.expose_secret());
    if let Some(ref user_pin) = result.new_user_pin {
        println!("  User PIN:   {}", user_pin.expose_secret());
    } else {
        println!("  User PIN:   (unchanged)");
    }
    println!();
    if result.kdf_enabled {
        println!("  KDF:        enabled");
    }
    if let Some(ref name) = result.cardholder_name {
        println!("  Cardholder: {name}");
    }
    if let Some(ref url) = result.cardholder_url {
        println!("  URL:        {url}");
    }
    println!();
    println!("============================================================");
    println!();

    // Safety check 4: confirm PINs recorded
    if !confirm_with_yes("Have you recorded the PINs above? Type 'yes' to confirm: ")? {
        // PINs are already set on the card — warn the user
        eprintln!("warning: PINs have already been changed on the card.");
        eprintln!("         If you did not record them, you may need to factory reset.");
    }

    println!();
    println!("Card setup complete.");

    Ok(())
}

/// Run the `card provision` command.
///
/// SAFETY-CRITICAL: transfers subkeys to the smart card and replaces the
/// local key with a GNU S2K stub. After this, secret subkey material exists
/// ONLY on the card and in the backup.
///
/// Safety checks:
/// - Rejects `--batch` mode (always interactive)
/// - Requires TTY for confirmation prompts
/// - Mandatory backup check (no override, no `--force`)
/// - Rejects factory admin PIN ("12345678")
/// - Shows summary before proceeding
/// - Requires typing `yes` to confirm
fn run_provision(args: &CardProvisionArgs, global: &GlobalOpts) -> CmdResult {
    // Safety check 1: reject batch mode
    if global.batch {
        return Err(KdubError::Card(
            "card provision requires interactive confirmation -- --batch is not supported"
                .to_string(),
        ));
    }

    // Safety check 2: require TTY
    require_tty()?;

    // Resolve data directory
    let data_dir = resolve_data_dir(global)?;

    // Normalize the key_id: strip 0x prefix, uppercase, then parse to Fingerprint
    let fp_str = normalize_key_id(&args.key_id)?;
    let fingerprint: Fingerprint = fp_str
        .parse()
        .map_err(|e| KdubError::InvalidFingerprint(format!("{fp_str}: {e}")))?;

    // Resolve admin PIN (stdin flags cannot be combined)
    secret_input::check_stdin_conflicts(&[
        ("--admin-pin-stdin", args.admin_pin_stdin),
        ("--passphrase-stdin", args.passphrase_stdin),
    ])?;

    let admin_pin = secret_input::resolve_secret::<AdminPin>(
        args.admin_pin.as_deref(),
        args.admin_pin_stdin,
        "KDUB_ADMIN_PIN",
        "Card admin PIN",
        global.batch,
    )?;

    // Resolve passphrase
    let passphrase = secret_input::resolve_secret::<Passphrase>(
        args.passphrase.as_deref(),
        args.passphrase_stdin,
        "KDUB_PASSPHRASE",
        "Certify key passphrase",
        global.batch,
    )?;

    // Safety check 3-5: prepare provision (checks backup, stub, factory PIN)
    // expose_secret() as late as possible — immediately in the function call
    let plan =
        card_provision::prepare_provision(&data_dir, &fingerprint, admin_pin.expose_secret())?;

    // Classify subkeys into card slots
    let subkey_slots = card_provision::classify_subkeys(&plan.key)?;

    // Connect to card
    let mut executor = PcscCardExecutor::connect().map_err(|e| match e {
        KdubError::CardNotFound(_) => KdubError::CardNotFound(
            "no smart card detected\n  Ensure your YubiKey or OpenPGP card is inserted".to_string(),
        ),
        other => other,
    })?;

    let card_info = executor.card_info()?;

    // Safety check 6: show summary
    println!();
    println!("Card provision summary:");
    println!("  Key:         {}", plan.metadata.identity);
    println!("  Fingerprint: {}", plan.fingerprint);
    println!("  Key type:    {}", plan.metadata.key_type);
    println!(
        "  Card:        {} (serial: {})",
        card_info.manufacturer, card_info.serial
    );
    println!("  Slots to write:");
    for slot in &subkey_slots {
        let slot_name = slot.slot.display_name();
        println!(
            "    [{}] -> {}",
            slot.label.to_uppercase().chars().next().unwrap_or('?'),
            slot_name
        );
    }
    println!();
    println!("WARNING: After provisioning, secret subkey material will exist");
    println!("ONLY on this card and in your backup. This is irrecoverable");
    println!("without a backup.");
    println!();

    // Safety check 7: require typing 'yes' to confirm
    if !confirm_with_yes("Type 'yes' to proceed with card provision: ")? {
        return Err(KdubError::Card("provision cancelled by user".to_string()));
    }

    // Import each subkey to the card
    for slot in &subkey_slots {
        if !global.quiet {
            print!("  Importing {} key to card... ", slot.label);
            io::stdout().flush()?;
        }

        // Use the concrete PcscCardExecutor::import_subkey method directly
        // expose_secret() as late as possible — in the same expression as the call
        executor.import_subkey(
            slot.subkey.key.clone(),
            slot.slot,
            &admin_pin,
            passphrase.expose_secret(),
        )?;

        if !global.quiet {
            println!("ok");
        }
    }

    // Verify import by reading card status
    let post_info = executor.card_info()?;
    let all_populated = post_info.signature_key.is_some()
        && post_info.encryption_key.is_some()
        && post_info.authentication_key.is_some();

    if !all_populated {
        eprintln!("warning: not all card slots are populated after import");
        eprintln!(
            "  signature:      {}",
            if post_info.signature_key.is_some() {
                "ok"
            } else {
                "EMPTY"
            }
        );
        eprintln!(
            "  encryption:     {}",
            if post_info.encryption_key.is_some() {
                "ok"
            } else {
                "EMPTY"
            }
        );
        eprintln!(
            "  authentication: {}",
            if post_info.authentication_key.is_some() {
                "ok"
            } else {
                "EMPTY"
            }
        );
        return Err(KdubError::Card(
            "aborting provision: not all card slots were populated after import. \
             The local key has NOT been modified. Check card status and retry."
                .to_string(),
        ));
    }

    // Finalize: stub local key and update metadata
    if !global.quiet {
        print!("  Replacing local key with card stub... ");
        io::stdout().flush()?;
    }

    card_provision::finalize_provision(&data_dir, plan.key, &plan.fingerprint, &card_info.serial)?;

    if !global.quiet {
        println!("ok");
    }

    // Display results
    println!();
    println!("Provision complete.");
    println!("  Key:    {}", plan.metadata.identity);
    println!(
        "  Card:   {} (serial: {})",
        card_info.manufacturer, card_info.serial
    );
    println!();
    println!("Subkeys are now on the card. GPG will show them as ssb>");
    println!("Signing, decryption, and authentication require the physical card.");

    Ok(())
}

/// Run the `card reset` command.
///
/// SAFETY-CRITICAL: this is the MOST DESTRUCTIVE command in kdub.
/// It factory-resets the OpenPGP applet, erasing ALL keys and PINs.
///
/// Safety checks:
/// - Rejects `--batch` mode (always interactive)
/// - Requires TTY for confirmation prompts
/// - Shows current card status (serial, loaded keys) as a warning
/// - Requires typing the exact card serial number to confirm (NOT "yes")
/// - Serial mismatch aborts immediately
fn run_reset(_args: &CardResetArgs, global: &GlobalOpts) -> CmdResult {
    // Safety check 1: reject batch mode
    if global.batch {
        return Err(KdubError::Card(
            "card reset requires interactive confirmation -- --batch is not supported".to_string(),
        ));
    }

    // Safety check 2: require TTY
    require_tty()?;

    // Connect to card
    let mut executor = PcscCardExecutor::connect().map_err(|e| match e {
        KdubError::CardNotFound(_) => KdubError::CardNotFound(
            "no smart card detected\n  Ensure your YubiKey or OpenPGP card is inserted".to_string(),
        ),
        other => other,
    })?;

    // Read current card info for the warning display
    let info = executor.card_info()?;
    let serial = info.serial.clone();

    // Display warning with current card status
    println!();
    println!("WARNING: This will factory reset the OpenPGP applet on your card.");
    println!();
    println!("Card serial: {serial}");
    println!("Keys on card:");

    if let Some(key) = &info.signature_key {
        let fp_short = shorten_fingerprint(&key.fingerprint);
        println!("  Signature key: {} [S] {fp_short}", key.algorithm);
    } else {
        println!("  Signature key: (none)");
    }

    if let Some(key) = &info.encryption_key {
        let fp_short = shorten_fingerprint(&key.fingerprint);
        println!("  Encrypt key:   {} [E] {fp_short}", key.algorithm);
    } else {
        println!("  Encrypt key:   (none)");
    }

    if let Some(key) = &info.authentication_key {
        let fp_short = shorten_fingerprint(&key.fingerprint);
        println!("  Auth key:      {} [A] {fp_short}", key.algorithm);
    } else {
        println!("  Auth key:      (none)");
    }

    println!();
    println!("All keys and PINs on this card will be ERASED.");
    println!("Other YubiKey applets (FIDO2, OTP, etc.) are NOT affected.");
    println!();

    // Safety check 3: require typing the exact serial number
    print!("Type '{serial}' to confirm factory reset: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !card_reset::validate_serial_confirmation(&serial, &input) {
        return Err(KdubError::Card(format!(
            "serial number mismatch: expected '{}', got '{}'",
            serial,
            input.trim()
        )));
    }

    // Perform factory reset
    executor.factory_reset()?;

    println!();
    println!("Factory reset complete.");
    println!("PINs restored to defaults: user=123456, admin=12345678");

    Ok(())
}

/// Run the `card touch` command.
///
/// Configures YubiKey touch policy for all three OpenPGP operations
/// (sign, decrypt, authenticate) via `ykman`.
///
/// Safety checks:
/// - Rejects `--batch` mode (always interactive)
/// - Requires TTY for confirmation prompts
/// - Requires `ykman` to be installed
/// - Reversible policies (`on`, `off`, `cached`): simple `y/N` confirmation
/// - Irreversible policies (`fixed`, `cached-fixed`): require typing `yes`
fn run_touch(args: &CardTouchArgs, global: &GlobalOpts) -> CmdResult {
    // Safety check 1: reject batch mode
    if global.batch {
        return Err(KdubError::Card(
            "card touch requires interactive confirmation -- --batch is not supported".to_string(),
        ));
    }

    // Safety check 2: require TTY
    require_tty()?;

    // Safety check 3: require ykman
    let ykman = RealYkmanExecutor;
    if !ykman.is_available() {
        return Err(KdubError::MissingDependency(
            "ykman (yubikey-manager) is required for touch policy configuration".to_string(),
        ));
    }

    let policy = args.policy.to_string();
    let is_irreversible = args.policy.is_irreversible();

    // Show what will happen
    println!(
        "Setting touch policy to '{}' for all OpenPGP operations.",
        policy
    );

    if is_irreversible {
        println!();
        println!(
            "WARNING: '{}' policy CANNOT be changed without factory reset.",
            policy
        );
        println!();

        // Safety check 4: require typing 'yes' for irreversible policies
        if !confirm_with_yes("Type 'yes' to proceed: ")? {
            return Err(KdubError::Cancelled);
        }
    } else {
        // Simple y/N confirmation for reversible policies
        print!("Proceed? [y/N] ");
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !matches!(input.trim(), "y" | "Y") {
            return Err(KdubError::Cancelled);
        }
    }

    // Resolve admin PIN
    let admin_pin = secret_input::resolve_secret::<AdminPin>(
        args.admin_pin.as_deref(),
        args.admin_pin_stdin,
        "KDUB_ADMIN_PIN",
        "Card admin PIN",
        global.batch,
    )?;

    // Set touch policy for all three operations
    let ops = [("sig", "sign"), ("dec", "decrypt"), ("aut", "authenticate")];

    for (op_code, op_name) in &ops {
        if !global.quiet {
            print!("  Setting {} touch policy to '{}'... ", op_name, policy);
            io::stdout().flush()?;
        }

        ykman.set_touch_policy(op_code, &policy, &admin_pin)?;

        if !global.quiet {
            println!("ok");
        }
    }

    println!();
    println!(
        "Touch policy set to '{}' for all OpenPGP operations.",
        policy
    );

    Ok(())
}

/// Prompt for confirmation by requiring the user to type `yes`.
///
/// Returns `true` if the user typed exactly `yes`, `false` otherwise.
/// Uses raw stdin/stdout instead of `dialoguer::Confirm` because we need
/// the full word `yes`, not just `y/N`.
fn confirm_with_yes(prompt: &str) -> Result<bool, KdubError> {
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim() == "yes")
}

/// Run the `card info` command.
///
/// Read-only — no TTY check, no confirmation needed.
fn run_info(args: &CardInfoArgs, global: &GlobalOpts) -> CmdResult {
    let mut executor = PcscCardExecutor::connect().map_err(|e| match e {
        KdubError::CardNotFound(_) => KdubError::CardNotFound(
            "no smart card detected\n  Ensure your YubiKey or OpenPGP card is inserted".to_string(),
        ),
        other => other,
    })?;

    let info = executor.card_info()?;
    let yubikey = ykman_info();

    if args.json {
        let output = CardInfoJson::from_parts(&info, yubikey.as_ref());
        let json = serde_json::to_string_pretty(&output)
            .map_err(|e| KdubError::Card(format!("JSON serialization error: {e}")))?;
        println!("{json}");
    } else if !global.quiet {
        print_card_info(&info, yubikey.as_ref());
    }

    Ok(())
}

/// JSON output structure matching the README `card info --json` schema.
///
/// Wraps [`CardInfo`] and optional [`YubiKeyInfo`] into the documented
/// top-level `{ "card": {...}, "yubikey": {...} }` structure.
#[derive(Debug, Serialize)]
struct CardInfoJson {
    card: CardJsonBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    yubikey: Option<YubiKeyInfo>,
}

/// The `"card"` object in the JSON output.
#[derive(Debug, Serialize)]
struct CardJsonBody {
    manufacturer: String,
    serial: String,
    version: String,
    pin_retries: PinRetriesJson,
    keys: KeysJson,
    kdf: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    touch_policy: Option<TouchPolicyJson>,
}

/// PIN retry counts in the JSON output.
#[derive(Debug, Serialize)]
struct PinRetriesJson {
    user: u8,
    reset: u8,
    admin: u8,
}

/// Key slots in the JSON output.
#[derive(Debug, Serialize)]
struct KeysJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<KeySlotJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<KeySlotJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication: Option<KeySlotJson>,
}

/// A single key slot in the JSON output.
#[derive(Debug, Serialize)]
struct KeySlotJson {
    algorithm: String,
    fingerprint: String,
}

/// Touch policy in the JSON output.
#[derive(Debug, Serialize)]
struct TouchPolicyJson {
    sign: String,
    encrypt: String,
    auth: String,
}

impl CardInfoJson {
    /// Build the JSON output from a [`CardInfo`] and optional [`YubiKeyInfo`].
    fn from_parts(info: &CardInfo, yubikey: Option<&YubiKeyInfo>) -> Self {
        let card = CardJsonBody {
            manufacturer: info.manufacturer.clone(),
            serial: info.serial.clone(),
            version: info.card_version.clone(),
            pin_retries: PinRetriesJson {
                user: info.pin_retries.user,
                reset: info.pin_retries.reset,
                admin: info.pin_retries.admin,
            },
            keys: KeysJson {
                signature: info.signature_key.as_ref().map(key_slot_json),
                encryption: info.encryption_key.as_ref().map(key_slot_json),
                authentication: info.authentication_key.as_ref().map(key_slot_json),
            },
            kdf: info.kdf_enabled,
            touch_policy: info.touch_policy.as_ref().map(touch_policy_json),
        };

        Self {
            card,
            yubikey: yubikey.cloned(),
        }
    }
}

/// Convert a [`CardKeyInfo`] to its JSON representation.
fn key_slot_json(key: &CardKeyInfo) -> KeySlotJson {
    KeySlotJson {
        algorithm: key.algorithm.clone(),
        fingerprint: key.fingerprint.clone(),
    }
}

/// Convert a [`TouchPolicyInfo`] to its JSON representation.
fn touch_policy_json(policy: &TouchPolicyInfo) -> TouchPolicyJson {
    TouchPolicyJson {
        sign: policy.sign.clone(),
        encrypt: policy.encrypt.clone(),
        auth: policy.auth.clone(),
    }
}

/// Print card info in human-readable format matching the README spec.
fn print_card_info(info: &CardInfo, yubikey: Option<&YubiKeyInfo>) {
    println!("OpenPGP Card:");
    println!("  Manufacturer:  {}", info.manufacturer);
    println!("  Serial:        {}", info.serial);
    println!("  Version:       {}", info.card_version);
    println!(
        "  PIN retries:   {} / {} / {} (user / reset / admin)",
        info.pin_retries.user, info.pin_retries.reset, info.pin_retries.admin
    );

    if let Some(key) = &info.signature_key {
        let fp_short = shorten_fingerprint(&key.fingerprint);
        println!("  Signature key: {} [S] {fp_short}", key.algorithm);
    } else {
        println!("  Signature key: (none)");
    }

    if let Some(key) = &info.encryption_key {
        let fp_short = shorten_fingerprint(&key.fingerprint);
        println!("  Encrypt key:   {} [E] {fp_short}", key.algorithm);
    } else {
        println!("  Encrypt key:   (none)");
    }

    if let Some(key) = &info.authentication_key {
        let fp_short = shorten_fingerprint(&key.fingerprint);
        println!("  Auth key:      {} [A] {fp_short}", key.algorithm);
    } else {
        println!("  Auth key:      (none)");
    }

    println!(
        "  KDF:           {}",
        if info.kdf_enabled {
            "enabled"
        } else {
            "disabled"
        }
    );

    if let Some(tp) = &info.touch_policy {
        println!(
            "  Touch policy:  sign={}, encrypt={}, auth={}",
            tp.sign, tp.encrypt, tp.auth
        );
    }

    if let Some(yk) = yubikey {
        println!();
        println!("YubiKey:");
        println!("  Model:         {}", yk.model);
        println!("  Firmware:      {}", yk.firmware);
        println!("  Serial:        {}", yk.serial);
        println!("  Best key type: {}", yk.best_key_type);
    }
}

/// Shorten a fingerprint for display: show first 4 and last 3 hex chars.
///
/// If the fingerprint is short enough already, return it unchanged.
fn shorten_fingerprint(fp: &str) -> String {
    if fp.len() <= 10 {
        return fp.to_string();
    }
    format!("{}...{}", &fp[..4], &fp[fp.len() - 3..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use kdub_lib::card::PinRetries;

    fn sample_card_info() -> CardInfo {
        CardInfo {
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
                fingerprint: "D3B9C00B365DC5B752A6554A0630571A396BC2A7".to_string(),
            }),
            encryption_key: Some(CardKeyInfo {
                algorithm: "cv25519".to_string(),
                fingerprint: "D3B9C00B365DC5B752A6554A0630571A396BC2A7".to_string(),
            }),
            authentication_key: Some(CardKeyInfo {
                algorithm: "ed25519".to_string(),
                fingerprint: "D3B9C00B365DC5B752A6554A0630571A396BC2A7".to_string(),
            }),
            kdf_enabled: true,
            touch_policy: Some(TouchPolicyInfo {
                sign: "on".to_string(),
                encrypt: "on".to_string(),
                auth: "on".to_string(),
            }),
        }
    }

    fn sample_yubikey_info() -> YubiKeyInfo {
        YubiKeyInfo {
            model: "YubiKey 5 NFC".to_string(),
            firmware: "5.4.3".to_string(),
            serial: "12345678".to_string(),
            best_key_type: "ed25519".to_string(),
        }
    }

    #[test]
    fn test_shorten_fingerprint_long() {
        let fp = "D3B9C00B365DC5B752A6554A0630571A396BC2A7";
        assert_eq!(shorten_fingerprint(fp), "D3B9...2A7");
    }

    #[test]
    fn test_shorten_fingerprint_short() {
        assert_eq!(shorten_fingerprint("AABB"), "AABB");
        assert_eq!(shorten_fingerprint("AABBCCDDEE"), "AABBCCDDEE");
    }

    #[test]
    fn test_card_info_json_full() {
        let info = sample_card_info();
        let yk = sample_yubikey_info();
        let json_obj = CardInfoJson::from_parts(&info, Some(&yk));

        let json_str = serde_json::to_string_pretty(&json_obj).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        // Card fields
        assert_eq!(parsed["card"]["manufacturer"], "Yubico");
        assert_eq!(parsed["card"]["serial"], "12345678");
        assert_eq!(parsed["card"]["version"], "3.4");
        assert_eq!(parsed["card"]["pin_retries"]["user"], 3);
        assert_eq!(parsed["card"]["pin_retries"]["reset"], 0);
        assert_eq!(parsed["card"]["pin_retries"]["admin"], 3);
        assert_eq!(parsed["card"]["kdf"], true);
        assert_eq!(parsed["card"]["keys"]["signature"]["algorithm"], "ed25519");
        assert_eq!(parsed["card"]["touch_policy"]["sign"], "on");

        // YubiKey fields
        assert_eq!(parsed["yubikey"]["model"], "YubiKey 5 NFC");
        assert_eq!(parsed["yubikey"]["firmware"], "5.4.3");
        assert_eq!(parsed["yubikey"]["serial"], "12345678");
        assert_eq!(parsed["yubikey"]["best_key_type"], "ed25519");
    }

    #[test]
    fn test_card_info_json_no_yubikey() {
        let info = sample_card_info();
        let json_obj = CardInfoJson::from_parts(&info, None);

        let json_str = serde_json::to_string_pretty(&json_obj).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert!(parsed["card"].is_object());
        assert!(parsed["yubikey"].is_null());
    }

    #[test]
    fn test_card_info_json_empty_card() {
        let info = CardInfo {
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
        };

        let json_obj = CardInfoJson::from_parts(&info, None);
        let json_str = serde_json::to_string_pretty(&json_obj).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["card"]["manufacturer"], "GnuPG e.V.");
        assert_eq!(parsed["card"]["kdf"], false);
        // Empty slots should be null/absent
        assert!(parsed["card"]["keys"]["signature"].is_null());
        assert!(parsed["card"]["keys"]["encryption"].is_null());
        assert!(parsed["card"]["keys"]["authentication"].is_null());
        assert!(parsed["card"]["touch_policy"].is_null());
    }

    #[test]
    fn test_key_slot_json_conversion() {
        let key = CardKeyInfo {
            algorithm: "ed25519".to_string(),
            fingerprint: "AABBCCDD".to_string(),
        };
        let slot = key_slot_json(&key);
        assert_eq!(slot.algorithm, "ed25519");
        assert_eq!(slot.fingerprint, "AABBCCDD");
    }

    #[test]
    fn test_touch_policy_json_conversion() {
        let policy = TouchPolicyInfo {
            sign: "on".to_string(),
            encrypt: "off".to_string(),
            auth: "cached".to_string(),
        };
        let json = touch_policy_json(&policy);
        assert_eq!(json.sign, "on");
        assert_eq!(json.encrypt, "off");
        assert_eq!(json.auth, "cached");
    }
}
