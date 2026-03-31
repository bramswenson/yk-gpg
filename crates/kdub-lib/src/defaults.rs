/// Ed25519 public key for verifying signed release archives (kdub binary and self-updates).
/// Generated with `zipsign gen-key` — the corresponding private key
/// is stored as a GitHub Actions secret and never committed to the repo.
pub const ZIPSIGN_PUBLIC_KEY: [u8; 32] = *include_bytes!("../zipsign-public.key");

/// Default PGP key expiration interval.
///
/// Two years balances security (short enough to limit exposure if a key is
/// compromised) with usability (long enough to avoid frequent renewals for
/// keys stored on hardware tokens that auto-extend).
pub const DEFAULT_EXPIRATION: &str = "2y";

/// Default PGP key algorithm.
///
/// Ed25519 is chosen for its small key size, fast operations, and excellent
/// support in modern OpenPGP implementations including rPGP and GnuPG.
pub const DEFAULT_KEY_TYPE: &str = "ed25519";

/// Length of auto-generated LUKS/PGP passphrases in characters.
///
/// 24 characters from the `PASSPHRASE_ALPHABET` (28 symbols) yields
/// approximately 128 bits of entropy — sufficient for a high-value secret
/// stored on a hardware-encrypted volume.
pub const DEFAULT_PASSPHRASE_LENGTH: usize = 24;

/// Alphabet used for auto-generated passphrases.
///
/// Deliberately excludes visually ambiguous characters so passphrases can be
/// read aloud or transcribed without errors:
/// - `I` and `1` (easily confused in many fonts)
/// - `O` and `0` (easily confused in many fonts)
/// - `S` and `5` (easily confused when handwritten)
/// - `B` and `8` (easily confused when handwritten)
pub const PASSPHRASE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRTVWXYZ234679";

/// Default YubiKey touch policy for signing operations.
///
/// `"on"` requires a physical button press for every cryptographic operation,
/// preventing silent use of the key even if the card is stolen with the PIN.
pub const DEFAULT_TOUCH_POLICY: &str = "on";

/// Default OpenPGP keyserver URL.
///
/// keys.openpgp.org is preferred over the SKS pool because it requires
/// e-mail verification before publishing UIDs, reducing spam and harvesting
/// of e-mail addresses from the keyserver network.
pub const DEFAULT_KEYSERVER: &str = "hkps://keys.openpgp.org";

/// Name of the environment variable used to supply a GitHub personal access token.
///
/// Standard name used by GitHub CLI (`gh`) and many CI systems, so users
/// rarely need to set a separate variable.
pub const DEFAULT_GITHUB_TOKEN_ENV: &str = "GITHUB_TOKEN";

/// Fingerprint of the Tails project PGP signing key used to verify ISO downloads.
///
/// Published at https://tails.net/tails-signing.key and on public keyservers.
/// Cross-check any embedded key against this fingerprint before trusting it.
pub const TAILS_SIGNING_KEY_FINGERPRINT: &str = "A490D0F4D311A4153E2BB7CADBB802B258ACD84F";

/// URL of the Tails latest-release JSON endpoint.
///
/// Returns a JSON object with the current stable version and download URLs
/// for the amd64 ISO and its detached PGP signature. Format is defined by
/// the Tails project and may change between major Tails versions.
pub const TAILS_LATEST_JSON_URL: &str =
    "https://tails.net/install/v2/Tails/amd64/stable/latest.json";

/// Tails project PGP signing key for ISO verification.
/// Embedded to avoid network dependency on a trust anchor.
/// Source: https://tails.net/tails-signing.key
/// Fingerprint: A490D0F4D311A4153E2BB7CADBB802B258ACD84F (expires 2027-01-13)
pub const TAILS_SIGNING_KEY: &[u8] = include_bytes!("../tails-signing.key");

/// Standard mount point for the Tails unlocked persistent volume.
///
/// Tails mounts the LUKS-encrypted TailsData partition here after the user
/// unlocks it at the Welcome Screen. Dotfiles and other persisted data live
/// under this path.
pub const TAILS_PERSISTENCE_MOUNT: &str = "/live/persistence/TailsData_unlocked";

/// Minimum USB drive size accepted for Tails installation (8 GB in bytes).
///
/// The Tails ISO itself is ~1.5 GB; 8 GB ensures enough room for the image,
/// the persistent storage partition, and future Tails upgrades.
pub const TAILS_MIN_USB_SIZE_BYTES: u64 = 8_000_000_000;

/// Paths and mount options written to `persistence.conf` on the Tails volume.
///
/// Each entry is `(destination, options)` and becomes one tab-separated line
/// in the file. Only the core features that kdub can fully pre-seed are
/// included. Other features (cups, NetworkManager, apt, etc.) are left for
/// the user to enable via the Persistent Storage UI in Tails, which populates
/// the required configuration files that kdub cannot create from outside Tails.
pub const TAILS_PERSISTENCE_CONF_ENTRIES: &[(&str, &str)] = &[
    ("/home/amnesia", "source=dotfiles,link"),
    ("/home/amnesia/.gnupg", "source=gnupg"),
    ("/home/amnesia/Persistent", "source=Persistent"),
];

/// Target size for Tails system partition (partition 1) after resize.
///
/// Tails resizes partition 1 from the ISO's ~1.9 GiB to 8 GiB on first boot
/// for overlay/temp space. We replicate this resize during `kdub tails persist`
/// so Tails doesn't report a partitioning error.
pub const TAILS_PARTITION1_SIZE: &str = "8GiB";

/// Device mapper name used for the LUKS container during persistence setup.
///
/// Chosen to be clearly identifiable in `dmsetup ls` output and to avoid
/// collisions with Tails' own mapper names (which use `TailsData`).
pub const TAILS_LUKS_MAPPER_NAME: &str = "kdub-tails-persist";

/// GPT partition label applied to the persistence partition.
///
/// Tails itself uses `TailsData` as the label it looks for when unlocking
/// persistent storage at boot, so this label must match that expectation.
pub const TAILS_PARTITION_LABEL: &str = "TailsData";

/// GPT partition type GUID for the Tails persistent storage partition.
///
/// This is the Tails-specific GUID that Tails uses to identify its persistence
/// partition during the boot unlock sequence. Using any other GUID (e.g. the
/// generic Linux data GUID) will cause Tails to ignore the partition.
pub const TAILS_PARTITION_TYPE_GUID: &str = "8DA63339-0007-60C0-C436-083AC8230908";
