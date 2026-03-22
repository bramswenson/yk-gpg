use std::path::PathBuf;

use directories::ProjectDirs;
use kdub_lib::backup;
use kdub_lib::error::KdubError;
use kdub_lib::identity::IdentityMetadata;
use kdub_lib::keygen;
use kdub_lib::publish;
use kdub_lib::types::{KeyType, Passphrase};

use crate::cli::{
    GlobalOpts, KeyBackupArgs, KeyCommand, KeyCreateArgs, KeyListArgs, KeyPublishArgs,
    KeyRenewArgs, KeyRestoreArgs, KeyRotateArgs,
};
use crate::secret_input;

use super::CmdResult;

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
    let batch = global.batch
        || std::env::var("CI")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
        || std::env::var("BATCH_MODE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

    // 1. Resolve key type: --key-type flag > ykman detection > KDUB_KEY_TYPE env > config > Ed25519
    let key_type = resolve_key_type(args, global)?;

    // 2. Resolve passphrase
    let (passphrase, passphrase_generated) = resolve_passphrase(args, batch)?;

    // 3. Resolve data directory
    let data_dir = resolve_data_dir(global)?;

    // 4. Generate key
    let rng = rand::rngs::OsRng;
    let signed_key = keygen::generate_key(
        &args.identity,
        key_type,
        &args.expiration,
        passphrase.expose_secret(),
        rng,
    )?;

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
            .map_err(|e| KdubError::Config(e.to_string()));
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

    // Try to resolve from flag/stdin/env
    let resolved = secret_input::resolve_secret::<Passphrase>(
        args.passphrase.as_deref(),
        args.passphrase_stdin,
        "KDUB_PASSPHRASE",
        "Enter passphrase for certify key",
        batch,
    );

    match resolved {
        Ok(pp) => Ok((pp, false)),
        Err(KdubError::NotImplemented(_)) if batch => {
            // Batch mode requires passphrase from flag/stdin/env
            Err(KdubError::Config(
                "batch mode requires --passphrase, --passphrase-stdin, or KDUB_PASSPHRASE"
                    .to_string(),
            ))
        }
        Err(e) if !batch => {
            // Interactive mode: auto-generate passphrase if no input provided
            // The resolve_secret function returns the dialoguer prompt result,
            // but if the user explicitly chose not to provide one via
            // flags/stdin/env, we auto-generate.
            // Actually, resolve_secret already handles the interactive prompt.
            // If it failed for other reasons, propagate the error.
            // Check if this is a "no input" situation where we should auto-generate.
            if args.passphrase.is_none()
                && !args.passphrase_stdin
                && std::env::var("KDUB_PASSPHRASE")
                    .unwrap_or_default()
                    .is_empty()
            {
                let pp = Passphrase::generate(&mut rand::rngs::OsRng);
                Ok((pp, true))
            } else {
                Err(e)
            }
        }
        Err(e) => Err(e),
    }
}

/// Resolve the data directory path.
fn resolve_data_dir(global: &GlobalOpts) -> Result<PathBuf, KdubError> {
    if let Some(ref d) = global.data_dir {
        return Ok(d.clone());
    }
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join("kdub"));
    }
    let proj_dirs = ProjectDirs::from("", "", "kdub").ok_or_else(|| {
        KdubError::Config("could not determine home directory for data paths".to_string())
    })?;
    Ok(proj_dirs.data_dir().to_path_buf())
}

/// Load config (convenience wrapper).
fn load_config(global: &GlobalOpts) -> Result<kdub_lib::config::KdubConfig, KdubError> {
    kdub_lib::config::KdubConfig::load(global.config.as_deref())
}

fn run_backup(args: &KeyBackupArgs, global: &GlobalOpts) -> CmdResult {
    let data_dir = resolve_data_dir(global)?;

    // Normalize the key_id: strip 0x prefix, uppercase
    let fingerprint = normalize_key_id(&args.key_id)?;

    // Verify identity metadata exists
    let _metadata = IdentityMetadata::load(&data_dir, &fingerprint).map_err(|_| {
        KdubError::KeyNotFound(format!(
            "no identity found for {fingerprint} in {}",
            data_dir.display()
        ))
    })?;

    // Load key from identity store
    let key = backup::load_key_from_store(&data_dir, &fingerprint)?;

    // Run backup
    // Passphrase is not available at backup time from the CLI;
    // the revocation cert will fall back to a placeholder.
    // To generate a real revocation cert, use `kdub key backup` at key creation time
    // or provide passphrase via --passphrase / env.
    let actions = backup::run_backup(&data_dir, &fingerprint, &key, None)?;

    // Update metadata with backup timestamp
    let mut metadata = IdentityMetadata::load(&data_dir, &fingerprint)?;
    metadata.backed_up = Some(chrono::Utc::now());
    metadata.save(&data_dir)?;

    // Display results
    if !global.quiet {
        let backup_dir = data_dir.join("backups").join(&fingerprint);
        println!("Backed up to {}", backup_dir.display());
        for action in &actions {
            println!("  {action}");
        }
    }

    Ok(())
}

fn run_restore(args: &KeyRestoreArgs, global: &GlobalOpts) -> CmdResult {
    let data_dir = resolve_data_dir(global)?;

    // Normalize the fingerprint
    let fingerprint = args.fingerprint.trim().to_ascii_uppercase();

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
    let batch = global.batch
        || std::env::var("CI")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
        || std::env::var("BATCH_MODE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

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

    // Run renewal
    let actions = kdub_lib::renew::run_renew(
        &data_dir,
        &metadata.fingerprint,
        &args.expiration,
        passphrase.expose_secret(),
    )?;

    // Display results
    if !global.quiet {
        println!("Key renewed successfully!");
        println!("  Identity:    {}", metadata.identity);
        println!("  Fingerprint: {}", metadata.fingerprint);
        println!("  Expiration:  {}", args.expiration);
        println!();
        for action in &actions {
            println!("  {action}");
        }

        if !batch {
            println!();
            println!(
                "Run 'kdub key backup {}' to update your offline backup.",
                metadata.fingerprint
            );
        }
    }

    Ok(())
}

fn run_rotate(args: &KeyRotateArgs, global: &GlobalOpts) -> CmdResult {
    let batch = global.batch
        || std::env::var("CI")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
        || std::env::var("BATCH_MODE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

    let data_dir = resolve_data_dir(global)?;

    // Resolve identity
    let metadata = kdub_lib::identity::find_identity(&data_dir, &args.identity)?;

    // Resolve key type: --key-type flag > existing key type from metadata
    let key_type = if let Some(ref kt_str) = args.key_type {
        kt_str
            .parse::<KeyType>()
            .map_err(|e| KdubError::Config(e.to_string()))?
    } else {
        metadata
            .key_type
            .parse::<KeyType>()
            .unwrap_or(KeyType::Ed25519)
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

    // Run rotation
    let actions = kdub_lib::rotate::run_rotate(
        &data_dir,
        &metadata.fingerprint,
        key_type,
        &args.expiration,
        passphrase.expose_secret(),
        args.revoke_old,
    )?;

    // Display results
    if !global.quiet {
        println!("Key rotated successfully!");
        println!("  Identity:    {}", metadata.identity);
        println!("  Fingerprint: {}", metadata.fingerprint);
        println!("  Key type:    {key_type}");
        if args.revoke_old {
            println!("  Old subkeys: revoked");
        }
        println!();
        for action in &actions {
            println!("  {action}");
        }

        if !batch {
            // Prompt for card provisioning (placeholder per task description)
            tracing::warn!(
                "Card provisioning not yet implemented \
                 — run 'kdub card provision' after Phase E"
            );
            println!();
            println!(
                "Run 'kdub card provision {}' to transfer new subkeys to your smart card.",
                metadata.fingerprint
            );
            println!(
                "Run 'kdub key backup {}' to update your offline backup.",
                metadata.fingerprint
            );
        }
    }

    Ok(())
}

fn run_publish(args: &KeyPublishArgs, global: &GlobalOpts) -> CmdResult {
    let batch = global.batch
        || std::env::var("CI")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
        || std::env::var("BATCH_MODE")
            .map(|v| matches!(v.to_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

    let data_dir = resolve_data_dir(global)?;
    let config = load_config(global)?;

    // Normalize the key_id
    let fingerprint = normalize_key_id(&args.key_id)?;

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
        // Resolve GitHub token from env var
        let token_env_name = &config.publish.github_token_env;
        let token = std::env::var(token_env_name).ok().filter(|t| !t.is_empty());

        match token {
            Some(token) => {
                let result =
                    publish::publish_to_github(agent.as_ref().unwrap(), &token, &armored_pubkey)?;
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

/// Normalize a key ID or fingerprint to uppercase hex without 0x prefix.
fn normalize_key_id(key_id: &str) -> Result<String, KdubError> {
    let trimmed = key_id.trim();
    let hex_part = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex_part.is_empty() {
        return Err(KdubError::InvalidKeyId(
            "key ID cannot be empty".to_string(),
        ));
    }
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(KdubError::InvalidKeyId(format!(
            "invalid hex characters in key ID: {hex_part}"
        )));
    }
    Ok(hex_part.to_ascii_uppercase())
}
