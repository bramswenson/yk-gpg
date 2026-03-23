use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "kdub",
    version,
    about = "Cross-platform OpenPGP key lifecycle management with smart card support",
    long_about = "Cross-platform OpenPGP key lifecycle management with smart card support.\n\n\
        kdub creates and manages OpenPGP keys, provisions them to YubiKey or \
        other OpenPGP smart cards, and handles the full key lifecycle — backup, \
        renewal, rotation, and publishing.\n\n\
        Based on drduh/YubiKey-Guide. Designed for use with Tails OS on an \
        air-gapped machine for maximum security.",
    after_long_help = "\
\x1b[1mQuick start:\x1b[0m
  kdub init                              Set up directories and config
  kdub doctor                            Verify system readiness
  kdub key create \"Name <email>\"         Create an OpenPGP identity
  kdub key backup 0xKEYID                Back up keys (do this BEFORE provisioning)
  kdub card setup                        Configure smart card PINs
  kdub card provision 0xKEYID            Move keys to smart card

\x1b[1mKey lifecycle:\x1b[0m
  kdub key renew \"Name\"                  Extend subkey expiration
  kdub key rotate \"Name\" --revoke-old    Rotate to new subkeys
  kdub key publish 0xKEYID --keyserver   Publish to keys.openpgp.org
  kdub key publish 0xKEYID --github      Upload to GitHub

\x1b[1mRecommended setup:\x1b[0m
  For key generation and smart card provisioning, use Tails OS on an
  air-gapped machine with an encrypted USB for long-term backup:

    1. Download and verify Tails:  https://tails.net/install/
    2. Boot Tails, set up encrypted persistent storage
    3. Download kdub into persistent storage
    4. Disable networking → create keys → provision to YubiKey
    5. Store the Tails USB as your encrypted offline backup

  Automated Tails setup is planned: https://github.com/bramswenson/kdub/issues/3

\x1b[1mMore info:\x1b[0m
  https://github.com/bramswenson/kdub
  https://github.com/drduh/YubiKey-Guide"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args)]
pub struct GlobalOpts {
    /// Non-interactive mode; fail instead of prompting.
    /// Also enabled by: BATCH_MODE=true or CI=true
    #[arg(long, global = true)]
    pub batch: bool,

    /// Verbose output (repeat for debug: -vv)
    #[arg(long, short = 'v', action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Suppress informational output
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Config file path
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Data directory (identities, backups)
    #[arg(long, global = true, env = "KDUB_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Disable colored output
    #[arg(long, global = true, env = "NO_COLOR")]
    pub no_color: bool,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize directories and configuration
    Init(InitArgs),
    /// Check system dependencies
    Doctor(DoctorArgs),
    /// Print version information
    Version,
    /// Generate shell completions
    Completions(CompletionsArgs),
    /// Key management operations
    Key {
        #[command(subcommand)]
        cmd: KeyCommand,
    },
    /// Smart card operations
    Card {
        #[command(subcommand)]
        cmd: CardCommand,
    },
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct InitArgs {
    /// Overwrite existing config files
    #[arg(long)]
    pub force: bool,
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct DoctorArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

// ---------------------------------------------------------------------------
// completions
// ---------------------------------------------------------------------------

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: ShellType,
}

#[derive(Clone, ValueEnum)]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
}

// ---------------------------------------------------------------------------
// key subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum KeyCommand {
    /// Create a new OpenPGP identity
    Create(KeyCreateArgs),
    /// List all managed identities
    List(KeyListArgs),
    /// Export keys and revocation certificate
    Backup(KeyBackupArgs),
    /// Import keys from a previous backup
    Restore(KeyRestoreArgs),
    /// Extend expiration of existing subkeys
    Renew(KeyRenewArgs),
    /// Generate new subkeys (full key rotation)
    Rotate(KeyRotateArgs),
    /// Publish public key to one or more destinations
    Publish(KeyPublishArgs),
}

#[derive(Args)]
pub struct KeyCreateArgs {
    /// User ID string: "Name <email>"
    pub identity: String,

    /// Key algorithm: ed25519 or rsa4096 (auto-detects from connected YubiKey)
    #[arg(long)]
    pub key_type: Option<String>,

    /// Subkey expiration: 1y, 2y, 6m, 90d, never
    #[arg(long, default_value = "2y")]
    pub expiration: String,

    /// Certify key passphrase (visible in process listings)
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Read passphrase from stdin (one line). Preferred for scripts
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[derive(Args)]
pub struct KeyListArgs {
    /// Output as JSON array
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct KeyBackupArgs {
    /// Key ID or fingerprint
    pub key_id: String,

    /// Certify key passphrase (visible in process listings)
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Read passphrase from stdin (one line)
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[derive(Args)]
pub struct KeyRestoreArgs {
    /// Fingerprint matching backup directory name
    pub fingerprint: String,

    /// Certify key passphrase (visible in process listings)
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Read passphrase from stdin (one line)
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[derive(Args)]
pub struct KeyRenewArgs {
    /// Identity name, email, or key ID
    pub identity: String,

    /// New expiration from today: 1y, 2y, 6m, 90d, never
    #[arg(long, default_value = "2y")]
    pub expiration: String,

    /// Certify key passphrase (visible in process listings)
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Read passphrase from stdin (one line)
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[derive(Args)]
pub struct KeyRotateArgs {
    /// Identity name, email, or key ID
    pub identity: String,

    /// Algorithm for new subkeys
    #[arg(long)]
    pub key_type: Option<String>,

    /// New subkey expiration: 1y, 2y, 6m, 90d, never
    #[arg(long, default_value = "2y")]
    pub expiration: String,

    /// Certify key passphrase (visible in process listings)
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Read passphrase from stdin (one line)
    #[arg(long)]
    pub passphrase_stdin: bool,

    /// Revoke old subkeys
    #[arg(long)]
    pub revoke_old: bool,
}

#[derive(Args)]
pub struct KeyPublishArgs {
    /// Key ID or fingerprint
    pub key_id: String,

    /// Upload to keys.openpgp.org
    #[arg(long)]
    pub keyserver: bool,

    /// Upload to GitHub (requires GITHUB_TOKEN)
    #[arg(long)]
    pub github: bool,

    /// Export for Web Key Directory at webroot path
    #[arg(long)]
    pub wkd: Option<PathBuf>,

    /// Export armored public key to file
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Publish to all enabled destinations
    #[arg(long)]
    pub all: bool,
}

// ---------------------------------------------------------------------------
// card subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand)]
pub enum CardCommand {
    /// Display OpenPGP smart card status
    Info(CardInfoArgs),
    /// Configure smart card PINs, KDF, and metadata
    Setup(CardSetupArgs),
    /// Transfer subkeys to smart card
    Provision(CardProvisionArgs),
    /// Factory reset the OpenPGP applet
    Reset(CardResetArgs),
    /// Configure YubiKey touch policy
    Touch(CardTouchArgs),
}

#[derive(Args)]
pub struct CardInfoArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args)]
pub struct CardSetupArgs {
    /// GPG identity to extract name/email for card fields
    #[arg(long)]
    pub identity: Option<String>,

    /// Public key URL to store on card
    #[arg(long)]
    pub url: Option<String>,

    /// Current admin PIN (visible in process listings)
    #[arg(long)]
    pub admin_pin: Option<String>,

    /// Read admin PIN from stdin (one line)
    #[arg(long)]
    pub admin_pin_stdin: bool,

    /// New admin PIN (8 numeric digits)
    #[arg(long)]
    pub new_admin_pin: Option<String>,

    /// Read new admin PIN from stdin (one line)
    #[arg(long)]
    pub new_admin_pin_stdin: bool,

    /// Current user PIN (only used when not using factory PINs)
    /// When provided with --factory-pins absent, changes the user PIN from this value.
    /// When absent and --factory-pins is not set, user PIN change is skipped.
    #[arg(long, env = "KDUB_CURRENT_USER_PIN")]
    pub current_user_pin: Option<String>,

    /// New user PIN (6 numeric digits)
    #[arg(long)]
    pub new_user_pin: Option<String>,

    /// Read new user PIN from stdin (one line)
    #[arg(long)]
    pub new_user_pin_stdin: bool,

    /// Skip KDF (PIN hashing) setup
    #[arg(long)]
    pub skip_kdf: bool,

    /// Card has factory default PINs (123456 / 12345678)
    #[arg(long)]
    pub factory_pins: bool,
}

#[derive(Args)]
pub struct CardProvisionArgs {
    /// Key ID or fingerprint to provision
    pub key_id: String,

    /// Card admin PIN (visible in process listings)
    #[arg(long)]
    pub admin_pin: Option<String>,

    /// Read admin PIN from stdin (one line)
    #[arg(long)]
    pub admin_pin_stdin: bool,

    /// Certify key passphrase (visible in process listings)
    #[arg(long)]
    pub passphrase: Option<String>,

    /// Read passphrase from stdin (one line)
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[derive(Args)]
pub struct CardResetArgs {}

#[derive(Args)]
pub struct CardTouchArgs {
    /// YubiKey admin PIN (visible in process listings)
    #[arg(long)]
    pub admin_pin: Option<String>,

    /// Read admin PIN from stdin (one line)
    #[arg(long)]
    pub admin_pin_stdin: bool,

    /// Touch policy: on, off, fixed, cached, cached-fixed
    #[arg(long, default_value = "on")]
    pub policy: TouchPolicy,
}

#[derive(Clone, ValueEnum)]
pub enum TouchPolicy {
    /// Touch required; can be changed later
    On,
    /// No touch required
    Off,
    /// Touch required; cannot be changed without reset
    Fixed,
    /// Touch required; cached for 15 seconds
    Cached,
    /// Cached touch; cannot be changed without reset
    CachedFixed,
}

impl std::fmt::Display for TouchPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TouchPolicy::On => write!(f, "on"),
            TouchPolicy::Off => write!(f, "off"),
            TouchPolicy::Fixed => write!(f, "fixed"),
            TouchPolicy::Cached => write!(f, "cached"),
            TouchPolicy::CachedFixed => write!(f, "cached-fixed"),
        }
    }
}

impl TouchPolicy {
    /// Whether this policy is irreversible (cannot be changed without factory reset).
    pub fn is_irreversible(&self) -> bool {
        matches!(self, TouchPolicy::Fixed | TouchPolicy::CachedFixed)
    }
}
