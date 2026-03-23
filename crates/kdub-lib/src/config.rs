use std::path::Path;

use serde::Deserialize;

use crate::defaults::{
    DEFAULT_EXPIRATION, DEFAULT_GITHUB_TOKEN_ENV, DEFAULT_KEY_TYPE, DEFAULT_KEYSERVER,
    DEFAULT_TOUCH_POLICY,
};
use crate::error::KdubError;

// Embedded GPG configuration templates (compile-time).
/// Hardened gpg.conf based on drduh/config best practices.
pub const GPG_CONF: &str = include_str!("config/gpg.conf");

/// dirmngr.conf with Tor SOCKS proxy for keyserver traffic.
pub const DIRMNGR_CONF: &str = include_str!("config/dirmngr.conf");

// --- Default value functions for serde ---

fn default_key_type() -> String {
    DEFAULT_KEY_TYPE.to_string()
}

fn default_expiration() -> String {
    DEFAULT_EXPIRATION.to_string()
}

fn default_touch_policy() -> String {
    DEFAULT_TOUCH_POLICY.to_string()
}

fn default_keyserver() -> String {
    DEFAULT_KEYSERVER.to_string()
}

fn default_github_token_env() -> String {
    DEFAULT_GITHUB_TOKEN_ENV.to_string()
}

// --- Config structs ---

/// Top-level kdub configuration, loaded from `config.toml`.
#[derive(Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KdubConfig {
    #[serde(default)]
    pub key: KeyConfig,
    #[serde(default)]
    pub card: CardConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub publish: PublishConfig,
}

/// Key generation defaults.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KeyConfig {
    /// Key algorithm: "ed25519" or "rsa4096".
    #[serde(rename = "type", default = "default_key_type")]
    pub key_type: String,
    /// Subkey expiration duration: "1y", "2y", "6m", "90d", "never".
    #[serde(default = "default_expiration")]
    pub expiration: String,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            key_type: default_key_type(),
            expiration: default_expiration(),
        }
    }
}

/// Smart card configuration.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CardConfig {
    /// Touch policy: "on", "off", "fixed", "cached", "cached-fixed".
    #[serde(default = "default_touch_policy")]
    pub touch_policy: String,
}

impl Default for CardConfig {
    fn default() -> Self {
        Self {
            touch_policy: default_touch_policy(),
        }
    }
}

/// Network configuration for keyserver and proxy.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// SOCKS5 proxy for Tor routing (e.g., "socks5h://127.0.0.1:9050").
    #[serde(default)]
    pub tor_proxy: String,
    /// Keyserver URL.
    #[serde(default = "default_keyserver")]
    pub keyserver: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            tor_proxy: String::new(),
            keyserver: default_keyserver(),
        }
    }
}

/// Publishing configuration.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PublishConfig {
    /// Name of the environment variable holding the GitHub API token.
    #[serde(default = "default_github_token_env")]
    pub github_token_env: String,
}

impl Default for PublishConfig {
    fn default() -> Self {
        Self {
            github_token_env: default_github_token_env(),
        }
    }
}

// --- Config loading ---

impl KdubConfig {
    /// Load configuration with precedence: env vars > TOML file > compiled defaults.
    ///
    /// If `path` is `None` or the file does not exist, compiled defaults are used.
    /// `KDUB_*` environment variables always override file values.
    pub fn load(path: Option<&Path>) -> Result<Self, KdubError> {
        // 1. Start with compiled defaults
        let mut config = KdubConfig::default();

        // 2. Overlay TOML file if present
        if let Some(p) = path
            && p.exists()
        {
            let content =
                std::fs::read_to_string(p).map_err(|e| KdubError::Config(e.to_string()))?;
            config = toml::from_str(&content)
                .map_err(|e| KdubError::Config(format!("invalid config: {e}")))?;
        }

        // 3. Overlay KDUB_* env vars
        if let Ok(v) = std::env::var("KDUB_KEY_TYPE") {
            config.key.key_type = v;
        }
        if let Ok(v) = std::env::var("KDUB_EXPIRATION") {
            config.key.expiration = v;
        }
        if let Ok(v) = std::env::var("KDUB_TOR_PROXY") {
            config.network.tor_proxy = v;
        }
        if let Ok(v) = std::env::var("KDUB_KEYSERVER") {
            config.network.keyserver = v;
        }

        Ok(config)
    }
}

// --- Runtime-generated configs ---

/// Generate platform-specific `gpg-agent.conf` content.
///
/// Pinentry path varies by platform:
/// - tails: `/usr/bin/pinentry-gnome3`
/// - macos (Homebrew ARM): `/opt/homebrew/bin/pinentry-mac`
/// - macos (Homebrew Intel): `/usr/local/bin/pinentry-mac`
/// - linux: `/usr/bin/pinentry-curses`
pub fn generate_gpg_agent_conf(platform: &str) -> String {
    let pinentry_program = match platform {
        "tails" => "/usr/bin/pinentry-gnome3",
        "macos" => {
            // Prefer ARM Homebrew path, fall back to Intel, then curses
            if Path::new("/opt/homebrew/bin/pinentry-mac").exists() {
                "/opt/homebrew/bin/pinentry-mac"
            } else if Path::new("/usr/local/bin/pinentry-mac").exists() {
                "/usr/local/bin/pinentry-mac"
            } else {
                "/usr/bin/pinentry-curses"
            }
        }
        _ => "/usr/bin/pinentry-curses",
    };

    format!(
        "enable-ssh-support\n\
         pinentry-program {pinentry_program}\n\
         default-cache-ttl 60\n\
         max-cache-ttl 120\n\
         allow-loopback-pinentry\n"
    )
}

/// Generate platform-specific `scdaemon.conf` content.
///
/// macOS needs the PCSC driver path; Linux only needs `disable-ccid`.
pub fn generate_scdaemon_conf(platform: &str) -> String {
    if platform == "macos" {
        "disable-ccid\n\
         pcsc-driver /System/Library/Frameworks/PCSC.framework/PCSC\n"
            .to_string()
    } else {
        "disable-ccid\n".to_string()
    }
}

/// Generate default `config.toml` content for `kdub init`.
pub fn default_config_toml() -> String {
    format!(
        "\
# Key generation defaults
[key]
type = \"{key_type}\"           # \"ed25519\" or \"rsa4096\"
expiration = \"{expiration}\"          # Duration: \"1y\", \"2y\", \"6m\", \"90d\", \"never\"

# Smart card defaults
[card]
touch_policy = \"{touch_policy}\"        # \"on\", \"off\", \"fixed\", \"cached\", \"cached-fixed\"

# Network
[network]
tor_proxy = \"\"             # e.g., \"socks5h://127.0.0.1:9050\"
keyserver = \"{keyserver}\"

# Publishing
[publish]
github_token_env = \"{github_token_env}\"   # Env var name containing GitHub token
",
        key_type = DEFAULT_KEY_TYPE,
        expiration = DEFAULT_EXPIRATION,
        touch_policy = DEFAULT_TOUCH_POLICY,
        keyserver = DEFAULT_KEYSERVER,
        github_token_env = DEFAULT_GITHUB_TOKEN_ENV,
    )
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn test_default_config() {
        let config = KdubConfig::default();
        assert_eq!(config.key.key_type, "ed25519");
        assert_eq!(config.key.expiration, "2y");
        assert_eq!(config.card.touch_policy, "on");
        assert_eq!(config.network.tor_proxy, "");
        assert_eq!(config.network.keyserver, "hkps://keys.openpgp.org");
        assert_eq!(config.publish.github_token_env, "GITHUB_TOKEN");
    }

    #[test]
    fn test_load_valid_toml() {
        let toml_content = r#"
[key]
type = "rsa4096"
expiration = "1y"

[card]
touch_policy = "fixed"

[network]
tor_proxy = "socks5h://127.0.0.1:9050"
keyserver = "hkps://keyserver.ubuntu.com"

[publish]
github_token_env = "GH_TOKEN"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, toml_content).unwrap();

        let config = KdubConfig::load(Some(&path)).unwrap();
        assert_eq!(config.key.key_type, "rsa4096");
        assert_eq!(config.key.expiration, "1y");
        assert_eq!(config.card.touch_policy, "fixed");
        assert_eq!(config.network.tor_proxy, "socks5h://127.0.0.1:9050");
        assert_eq!(config.network.keyserver, "hkps://keyserver.ubuntu.com");
        assert_eq!(config.publish.github_token_env, "GH_TOKEN");
    }

    #[test]
    fn test_load_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "this is not valid toml [[[").unwrap();

        let result = KdubConfig::load(Some(&path));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, KdubError::Config(_)));
        assert!(err.to_string().contains("invalid config"));
    }

    #[test]
    fn test_load_missing_file() {
        let path = Path::new("/nonexistent/path/config.toml");
        let config = KdubConfig::load(Some(path)).unwrap();
        // Should return defaults when file doesn't exist
        assert_eq!(config, KdubConfig::default());
    }

    #[test]
    fn test_load_none_path() {
        let config = KdubConfig::load(None).unwrap();
        assert_eq!(config, KdubConfig::default());
    }

    #[test]
    fn test_unknown_fields_rejected() {
        let toml_content = r#"
[key]
type = "ed25519"
unknown_field = "bad"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, toml_content).unwrap();

        let result = KdubConfig::load(Some(&path));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, KdubError::Config(_)));
    }

    #[test]
    fn test_unknown_top_level_section_rejected() {
        let toml_content = r#"
[bogus]
foo = "bar"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, toml_content).unwrap();

        let result = KdubConfig::load(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn test_env_var_overlay() {
        // Write a TOML file with specific values
        let toml_content = r#"
[key]
type = "rsa4096"
expiration = "1y"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, toml_content).unwrap();

        // Set env var to override
        // SAFETY: test-only, single-threaded test execution
        unsafe { std::env::set_var("KDUB_KEY_TYPE", "ed25519") };
        let config = KdubConfig::load(Some(&path)).unwrap();
        // Env var should win over file
        assert_eq!(config.key.key_type, "ed25519");
        // File value should still be used for non-overridden fields
        assert_eq!(config.key.expiration, "1y");
        unsafe { std::env::remove_var("KDUB_KEY_TYPE") };
    }

    #[test]
    fn test_env_var_overlay_tor_proxy() {
        // SAFETY: test-only, single-threaded test execution
        unsafe { std::env::set_var("KDUB_TOR_PROXY", "socks5h://localhost:9050") };
        let config = KdubConfig::load(None).unwrap();
        assert_eq!(config.network.tor_proxy, "socks5h://localhost:9050");
        unsafe { std::env::remove_var("KDUB_TOR_PROXY") };
    }

    #[test]
    fn test_partial_config() {
        // Only [key] section — other sections should get defaults
        let toml_content = r#"
[key]
type = "rsa4096"
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, toml_content).unwrap();

        let config = KdubConfig::load(Some(&path)).unwrap();
        assert_eq!(config.key.key_type, "rsa4096");
        assert_eq!(config.key.expiration, "2y"); // default
        assert_eq!(config.card.touch_policy, "on"); // default
        assert_eq!(config.network.keyserver, "hkps://keys.openpgp.org"); // default
        assert_eq!(config.publish.github_token_env, "GITHUB_TOKEN"); // default
    }

    #[test]
    fn test_embedded_gpg_conf() {
        assert!(GPG_CONF.contains("personal-cipher-preferences AES256 AES192 AES"));
        assert!(GPG_CONF.contains("cert-digest-algo SHA512"));
        assert!(GPG_CONF.contains("throw-keyids"));
        assert!(GPG_CONF.contains("require-cross-certification"));
    }

    #[test]
    fn test_embedded_dirmngr_conf() {
        assert!(DIRMNGR_CONF.contains("keyserver hkps://keys.openpgp.org"));
        assert!(DIRMNGR_CONF.contains("http-proxy socks5h://127.0.0.1:9050"));
        assert!(DIRMNGR_CONF.contains("honor-http-proxy"));
    }

    #[test]
    fn test_generate_gpg_agent_conf_linux() {
        let conf = generate_gpg_agent_conf("linux");
        assert!(conf.contains("enable-ssh-support"));
        assert!(conf.contains("pinentry-program /usr/bin/pinentry-curses"));
        assert!(conf.contains("default-cache-ttl 60"));
        assert!(conf.contains("max-cache-ttl 120"));
        assert!(conf.contains("allow-loopback-pinentry"));
    }

    #[test]
    fn test_generate_gpg_agent_conf_tails() {
        let conf = generate_gpg_agent_conf("tails");
        assert!(conf.contains("pinentry-program /usr/bin/pinentry-gnome3"));
    }

    #[test]
    fn test_generate_scdaemon_conf_linux() {
        let conf = generate_scdaemon_conf("linux");
        assert!(conf.contains("disable-ccid"));
        assert!(!conf.contains("pcsc-driver"));
    }

    #[test]
    fn test_generate_scdaemon_conf_macos() {
        let conf = generate_scdaemon_conf("macos");
        assert!(conf.contains("disable-ccid"));
        assert!(conf.contains("pcsc-driver /System/Library/Frameworks/PCSC.framework/PCSC"));
    }

    #[test]
    fn test_default_config_toml() {
        let toml_str = default_config_toml();
        // The generated default TOML should parse back into default config
        let config: KdubConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(config.key.key_type, DEFAULT_KEY_TYPE);
        assert_eq!(config.key.expiration, DEFAULT_EXPIRATION);
        assert_eq!(config.card.touch_policy, DEFAULT_TOUCH_POLICY);
        assert_eq!(config.network.tor_proxy, "");
        assert_eq!(config.network.keyserver, DEFAULT_KEYSERVER);
        assert_eq!(config.publish.github_token_env, DEFAULT_GITHUB_TOKEN_ENV);
    }

    #[test]
    fn test_default_config_toml_roundtrip() {
        // Generate → parse → compare to defaults
        let toml_str = default_config_toml();
        let parsed: KdubConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed, KdubConfig::default());
    }

    #[test]
    fn test_empty_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Write an empty file — all sections should get defaults
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"").unwrap();

        let config = KdubConfig::load(Some(&path)).unwrap();
        assert_eq!(config, KdubConfig::default());
    }
}
