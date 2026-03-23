use kdub_lib::backup;
use kdub_lib::error::KdubError;
use kdub_lib::identity::IdentityMetadata;
use kdub_lib::keygen;
use kdub_lib::publish;
use kdub_lib::types::{Fingerprint, GithubToken, KeyType, Passphrase};

use crate::cli::{
    GlobalOpts, KeyBackupArgs, KeyCommand, KeyCreateArgs, KeyListArgs, KeyPublishArgs,
    KeyRenewArgs, KeyRestoreArgs, KeyRotateArgs,
};
use crate::secret_input;

use super::{CmdResult, normalize_key_id, resolve_data_dir};

pub fn run(cmd: &KeyCommand, global: &GlobalOpts) -> CmdResult {
    match cmd {
        KeyCommand::Create(args) => run_create(args, global),
        KeyCommand::List(args) => run_list(args, global),
        KeyCommand::Backup(args) => run_backup(args, global),
        KeyCommand::Restore(args) => run_restore(args, global),
        KeyCommand::Renew(args) => run_renew(args, global),
        KeyCommand::Rotate(args) => run_rotate(args, global),
        KeyCommand::Publish(args) => run_publish(args, global),
    }
}

fn run_create(args: &KeyCreateArgs, global: &GlobalOpts) -> CmdResult {
    let batch = global.batch;

    // 1. Resolve key type: --key-type flag > ykman detection > KDUB_KEY_TYPE env > config > Ed25519
    let key_type = resolve_key_type(args, global)?;

    // 2. Resolve passphrase
    let (passphrase, passphrase_generated) = resolve_passphrase(args, batch)?;

    // 3. Resolve data directory
    let data_dir = resolve_data_dir(global)?;

    // 4. Generate key
    let rng = rand::rngs::OsRng;
    let signed_key =
        keygen::generate_key(&args.identity, key_type, &args.expiration, &passphrase, rng)?;

    // 5. Extract fingerprint
    let fingerprint = keygen::extract_fingerprint(&signed_key);

    // 6. Save identity metadata
    let metadata = IdentityMetadata {
        identity: args.identity.clone(),
        fingerprint: fingerprint.clone(),
        key_type: key_type.to_string(),
        created: chrono::Utc::now(),
        backed_up: None,
        renewed: None,
        rotated: None,
        card_serial: None,
        provisioned: None,
    };
    metadata.save(&data_dir)?;

    // 7. Save key material to identity store for subsequent backup/restore
    backup::save_key_to_store(&data_dir, &fingerprint, &signed_key)?;

    // 8. Display results
    if !global.quiet {
        println!("Key created successfully!");
        println!("  Identity:    {}", args.identity);
        println!("  Fingerprint: {fingerprint}");
        println!("  Key type:    {key_type}");
        println!("  Expiration:  {}", args.expiration);

        if passphrase_generated {
            println!();
            println!(
                "  Passphrase:  {} (SAVE THIS — shown only once!)",
                passphrase.expose_secret()
            );
        }

        if !batch {
            println!();
            println!("Run 'kdub key backup {fingerprint}' to create an offline backup.");
        }
    }

    Ok(())
}

fn run_list(args: &KeyListArgs, global: &GlobalOpts) -> CmdResult {
    let data_dir = resolve_data_dir(global)?;
    let mut identities = IdentityMetadata::load_all(&data_dir)?;

    // Sort by creation date (oldest first) for stable output
    identities.sort_by_key(|m| m.created);

    if args.json {
        let json = serde_json::to_string_pretty(&identities)
            .map_err(|e| KdubError::Config(format!("failed to serialize identities: {e}")))?;
        println!("{json}");
    } else if !global.quiet {
        if identities.is_empty() {
            println!("No managed identities.");
        } else {
            println!("Managed identities:");
            println!();
            for meta in &identities {
                println!("  {}", meta.identity);
                println!("    Fingerprint: {}", meta.fingerprint);
                println!("    Key type:    {}", meta.key_type);
                println!("    Created:     {}", meta.created.format("%Y-%m-%d"));
                if let Some(ref backed_up) = meta.backed_up {
                    println!("    Backed up:   {}", backed_up.format("%Y-%m-%d"));
                }
                if let Some(ref renewed) = meta.renewed {
                    println!("    Renewed:     {}", renewed.format("%Y-%m-%d"));
                }
                if let Some(ref rotated) = meta.rotated {
                    println!("    Rotated:     {}", rotated.format("%Y-%m-%d"));
                }
                if let Some(ref serial) = meta.card_serial {
                    println!("    Card:        {serial}");
                }
                println!();
            }
        }
    }

    Ok(())
}

/// Resolve key type with fallback chain:
/// --key-type flag > ykman detection > KDUB_KEY_TYPE env > config > Ed25519
fn resolve_key_type(args: &KeyCreateArgs, global: &GlobalOpts) -> Result<KeyType, KdubError> {
    // 1. CLI flag
    if let Some(ref kt_str) = args.key_type {
        return kt_str
            .parse::<KeyType>()
            .map_err(|e| KdubError::UsageError(e.to_string()));
    }

    // 2. YubiKey auto-detection
    if let Some(kt) = kdub_lib::ykman::detect_key_type() {
        return Ok(kt);
    }

    // 3. KDUB_KEY_TYPE env var
    if let Ok(kt_str) = std::env::var("KDUB_KEY_TYPE")
        && !kt_str.is_empty()
    {
        return kt_str
            .parse::<KeyType>()
            .map_err(|e| KdubError::Config(e.to_string()));
    }

    // 4. Config file
    let config = load_config(global)?;
    if let Ok(kt) = config.key.key_type.parse::<KeyType>() {
        return Ok(kt);
    }

    // 5. Default
    Ok(KeyType::Ed25519)
}

/// Resolve passphrase with batch/interactive handling.
///
/// Returns (passphrase, was_generated).
fn resolve_passphrase(args: &KeyCreateArgs, batch: bool) -> Result<(Passphrase, bool), KdubError> {
    // Check for stdin conflicts
    secret_input::check_stdin_conflicts(&[("--passphrase-stdin", args.passphrase_stdin)])?;

    // Determine whether explicit input was provided (flag, stdin, or env var)
    let has_explicit_input = args.passphrase.is_some()
        || args.passphrase_stdin
        || !std::env::var("KDUB_PASSPHRASE")
            .unwrap_or_default()
            .is_empty();

    if has_explicit_input {
        // Explicit input: resolve it and propagate ALL errors (including IO/Ctrl+C)
        let pp = secret_input::resolve_secret::<Passphrase>(
            args.passphrase.as_deref(),
            args.passphrase_stdin,
            "KDUB_PASSPHRASE",
            "Enter passphrase for certify key",
            batch,
        )?;
        return Ok((pp, false));
    }

    // No explicit input provided
    if batch {
        // Batch mode requires passphrase from flag/stdin/env
        return Err(KdubError::Config(
            "batch mode requires --passphrase, --passphrase-stdin, or KDUB_PASSPHRASE".to_string(),
        ));
    }

    // Interactive mode, no explicit input: try interactive prompt.
    // Only auto-generate if dialoguer is not available (NotImplemented).
    // Do NOT auto-generate on IO errors (Ctrl+C, broken pipe) — those are real failures.
    match secret_input::resolve_secret::<Passphrase>(
        None,
        false,
        "KDUB_PASSPHRASE",
        "Enter passphrase for certify key",
        false,
    ) {
        Ok(pp) => Ok((pp, false)),
        Err(KdubError::NotImplemented(_)) => {
            // Dialoguer not available (non-TTY env without explicit input):
            // auto-generate a secure passphrase and display it once.
            let pp = Passphrase::generate(&mut rand::rngs::OsRng);
            Ok((pp, true))
        }
        Err(e) => {
            // Real IO error (Ctrl+C, broken pipe, etc.) — propagate
            Err(e)
        }
    }
}

/// Load config (convenience wrapper).
fn load_config(global: &GlobalOpts) -> Result<kdub_lib::config::KdubConfig, KdubError> {
    kdub_lib::config::KdubConfig::load(global.config.as_deref())
}

fn run_backup(args: &KeyBackupArgs, global: &GlobalOpts) -> CmdResult {
    let data_dir = resolve_data_dir(global)?;

    // Normalize the key_id: strip 0x prefix, uppercase, then parse to Fingerprint
    let fp_str = normalize_key_id(&args.key_id)?;
    let fingerprint: Fingerprint = fp_str
        .parse()
        .map_err(|e| KdubError::InvalidFingerprint(format!("{fp_str}: {e}")))?;

    // Verify identity metadata exists
    let _metadata = IdentityMetadata::load(&data_dir, &fingerprint).map_err(|_| {
        KdubError::KeyNotFound(format!(
            "no identity found for {fingerprint} in {}",
            data_dir.display()
        ))
    })?;

    // Load key from identity store
    let key = backup::load_key_from_store(&data_dir, &fingerprint)?;

    // Resolve passphrase (optional: backup works without it, but a real revocation
    // cert requires the certify key to be unlocked with the passphrase).
    secret_input::check_stdin_conflicts(&[("--passphrase-stdin", args.passphrase_stdin)])?;
    let passphrase = secret_input::resolve_secret::<Passphrase>(
        args.passphrase.as_deref(),
        args.passphrase_stdin,
        "KDUB_PASSPHRASE",
        "Enter passphrase for certify key (optional, press Enter to skip)",
        global.batch,
    )
    .ok();

    // Run backup
    let actions = backup::run_backup(
        &data_dir,
        &fingerprint,
        &key,
        passphrase.as_ref().map(|p| p.expose_secret()),
    )?;

    // Update metadata with backup timestamp
    let mut metadata = IdentityMetadata::load(&data_dir, &fingerprint)?;
    metadata.backed_up = Some(chrono::Utc::now());
    metadata.save(&data_dir)?;

    // Display results
    if !global.quiet {
        let backup_dir = data_dir.join("backups").join(fingerprint.to_string());
        println!("Backed up to {}", backup_dir.display());
        for action in &actions {
            println!("  {action}");
        }
    }

    Ok(())
}

fn run_restore(args: &KeyRestoreArgs, global: &GlobalOpts) -> CmdResult {
    let data_dir = resolve_data_dir(global)?;

    // Parse and validate the fingerprint
    let fp_str = args.fingerprint.trim().to_ascii_uppercase();
    let fingerprint: Fingerprint = fp_str
        .parse()
        .map_err(|e| KdubError::InvalidFingerprint(format!("{fp_str}: {e}")))?;

    // Run restore
    let actions = backup::run_restore(&data_dir, &fingerprint)?;

    // Display results
    if !global.quiet {
        println!("Restored key {fingerprint}");
        for action in &actions {
            println!("  {action}");
        }
    }

    Ok(())
}

fn run_renew(args: &KeyRenewArgs, global: &GlobalOpts) -> CmdResult {
    let batch = global.batch;

    let data_dir = resolve_data_dir(global)?;

    // Resolve identity
    let metadata = kdub_lib::identity::find_identity(&data_dir, &args.identity)?;

    // Resolve passphrase
    secret_input::check_stdin_conflicts(&[("--passphrase-stdin", args.passphrase_stdin)])?;
    let passphrase = secret_input::resolve_secret::<Passphrase>(
        args.passphrase.as_deref(),
        args.passphrase_stdin,
        "KDUB_PASSPHRASE",
        "Enter passphrase for certify key",
        batch,
    )
    .map_err(|e| match e {
        KdubError::NotImplemented(_) if batch => KdubError::Config(
            "batch mode requires --passphrase, --passphrase-stdin, or KDUB_PASSPHRASE".to_string(),
        ),
        other => other,
    })?;

    let fingerprint = metadata.fingerprint.clone();

    // Run renewal
    let actions = kdub_lib::renew::run_renew(
        &data_dir,
        &fingerprint,
        &args.expiration,
        passphrase.expose_secret(),
    )?;

    // Display results
    if !global.quiet {
        println!("Key renewed successfully!");
        println!("  Identity:    {}", metadata.identity);
        println!("  Fingerprint: {fingerprint}");
        println!("  Expiration:  {}", args.expiration);
        println!();
        for action in &actions {
            println!("  {action}");
        }

        if !batch {
            println!();
            println!("Run 'kdub key backup {fingerprint}' to update your offline backup.",);
        }
    }

    Ok(())
}

fn run_rotate(args: &KeyRotateArgs, global: &GlobalOpts) -> CmdResult {
    let batch = global.batch;

    let data_dir = resolve_data_dir(global)?;

    // Resolve identity
    let metadata = kdub_lib::identity::find_identity(&data_dir, &args.identity)?;

    // Resolve key type: --key-type flag > existing key type from metadata
    let key_type = if let Some(ref kt_str) = args.key_type {
        kt_str
            .parse::<KeyType>()
            .map_err(|e| KdubError::UsageError(e.to_string()))?
    } else {
        metadata.key_type.parse::<KeyType>().map_err(|e| {
            KdubError::Config(format!(
                "corrupted metadata: invalid key_type '{}': {e}",
                metadata.key_type
            ))
        })?
    };

    // Resolve passphrase
    secret_input::check_stdin_conflicts(&[("--passphrase-stdin", args.passphrase_stdin)])?;
    let passphrase = secret_input::resolve_secret::<Passphrase>(
        args.passphrase.as_deref(),
        args.passphrase_stdin,
        "KDUB_PASSPHRASE",
        "Enter passphrase for certify key",
        batch,
    )
    .map_err(|e| match e {
        KdubError::NotImplemented(_) if batch => KdubError::Config(
            "batch mode requires --passphrase, --passphrase-stdin, or KDUB_PASSPHRASE".to_string(),
        ),
        other => other,
    })?;

    let fingerprint = metadata.fingerprint.clone();

    // Run rotation
    let actions = kdub_lib::rotate::run_rotate(
        &data_dir,
        &fingerprint,
        key_type,
        &args.expiration,
        passphrase.expose_secret(),
        args.revoke_old,
    )?;

    // Display results
    if !global.quiet {
        println!("Key rotated successfully!");
        println!("  Identity:    {}", metadata.identity);
        println!("  Fingerprint: {fingerprint}");
        println!("  Key type:    {key_type}");
        if args.revoke_old {
            println!("  Old subkeys: revoked");
        }
        println!();
        for action in &actions {
            println!("  {action}");
        }

        if !batch {
            println!();
            println!(
                "Run 'kdub card provision {fingerprint}' to transfer new subkeys to your smart card.",
            );
            println!("Run 'kdub key backup {fingerprint}' to update your offline backup.",);
        }
    }

    Ok(())
}

fn run_publish(args: &KeyPublishArgs, global: &GlobalOpts) -> CmdResult {
    let batch = global.batch;

    let data_dir = resolve_data_dir(global)?;
    let config = load_config(global)?;

    // Normalize the key_id, then parse to Fingerprint
    let fp_str = normalize_key_id(&args.key_id)?;
    let fingerprint: Fingerprint = fp_str
        .parse()
        .map_err(|e| KdubError::InvalidFingerprint(format!("{fp_str}: {e}")))?;

    // Verify identity metadata exists
    let metadata = IdentityMetadata::load(&data_dir, &fingerprint).map_err(|_| {
        KdubError::KeyNotFound(format!(
            "no identity found for {fingerprint} in {}",
            data_dir.display()
        ))
    })?;

    // Load and export the public key
    let armored_pubkey = publish::export_armored_pubkey(&data_dir, &fingerprint)?;

    // Determine which destinations to publish to
    let do_keyserver = args.keyserver || args.all;
    let do_github = args.github || args.all;
    let do_wkd = args.wkd.is_some();
    let do_file = args.file.is_some();

    // In batch mode, at least one destination is required
    if batch && !do_keyserver && !do_github && !do_wkd && !do_file {
        return Err(KdubError::Publish(
            "at least one destination flag is required (--keyserver, --github, --wkd, --file, --all)"
                .to_string(),
        ));
    }

    // If no destination flags specified in interactive mode, that's also an error
    if !do_keyserver && !do_github && !do_wkd && !do_file {
        return Err(KdubError::Publish(
            "at least one destination flag is required (--keyserver, --github, --wkd, --file, --all)"
                .to_string(),
        ));
    }

    let mut actions = Vec::new();

    // Create HTTP agent (shared for keyserver + github)
    let agent = if do_keyserver || do_github {
        Some(publish::make_http_agent(&config)?)
    } else {
        None
    };

    // 1. Keyserver
    if do_keyserver {
        let result = publish::publish_to_keyserver(
            agent.as_ref().unwrap(),
            &config.network.keyserver,
            &armored_pubkey,
        )?;
        actions.push(result);
    }

    // 2. GitHub
    if do_github {
        // Resolve GitHub token from env var and parse immediately into GithubToken
        let token_env_name = &config.publish.github_token_env;
        let token: Option<GithubToken> = std::env::var(token_env_name)
            .ok()
            .filter(|t| !t.is_empty())
            .map(|t| t.parse::<GithubToken>())
            .transpose()
            .map_err(|e| KdubError::Publish(format!("invalid GitHub token: {e}")))?;

        match token {
            Some(ref token) => {
                let result =
                    publish::publish_to_github(agent.as_ref().unwrap(), token, &armored_pubkey)?;
                actions.push(result);
            }
            None => {
                if args.all {
                    // --all: skip GitHub silently if no token available
                    if !global.quiet {
                        println!("  Skipped GitHub (no {token_env_name} environment variable set)");
                    }
                } else {
                    // --github explicitly requested: fail
                    return Err(KdubError::Publish(format!(
                        "GitHub token required: set {token_env_name} environment variable"
                    )));
                }
            }
        }
    }

    // 3. WKD
    if let Some(ref wkd_path) = args.wkd {
        let public_key = publish::load_public_key(&data_dir, &fingerprint)?;
        let email = publish::extract_email_from_key(&public_key).ok_or_else(|| {
            KdubError::Publish(format!(
                "cannot determine email from identity '{}' for WKD export",
                metadata.identity
            ))
        })?;
        let result = publish::publish_to_wkd(wkd_path, &email, &public_key)?;
        actions.push(result);
    }

    // 4. File
    if let Some(ref file_path) = args.file {
        let result = publish::publish_to_file(file_path, &armored_pubkey)?;
        actions.push(result);
    }

    // Display results
    if !global.quiet {
        println!("Published key {fingerprint}");
        for action in &actions {
            println!("  {action}");
        }
    }

    Ok(())
}
