use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use pgp::composed::SignedPublicKey;
use pgp::ser::Serialize as PgpSerialize;

use crate::config::KdubConfig;
use crate::error::KdubError;
use crate::types::{Fingerprint, GithubToken};
use crate::wkd;

/// Export the armored public key from a secret key stored in the identity store.
///
/// Loads the key from `$DATA_DIR/identities/<fingerprint>.key`, extracts the
/// public key, and returns the armored string.
pub fn export_armored_pubkey(
    data_dir: &Path,
    fingerprint: &Fingerprint,
) -> Result<String, KdubError> {
    let key = crate::backup::load_key_from_store(data_dir, fingerprint)?;
    let public_key: SignedPublicKey = key.to_public_key();
    public_key
        .to_armored_string(Default::default())
        .map_err(|e| KdubError::Publish(format!("failed to export public key: {e}")))
}

/// Export the `SignedPublicKey` from a secret key stored in the identity store.
///
/// Loads the key from `$DATA_DIR/identities/<fingerprint>.key` and returns the
/// public key object (needed for WKD binary export).
pub fn load_public_key(
    data_dir: &Path,
    fingerprint: &Fingerprint,
) -> Result<SignedPublicKey, KdubError> {
    let key = crate::backup::load_key_from_store(data_dir, fingerprint)?;
    Ok(key.to_public_key())
}

/// Create an HTTP agent, optionally configured with a SOCKS proxy for Tor routing.
///
/// If `config.network.tor_proxy` is non-empty, the agent routes all traffic through
/// the specified SOCKS proxy (e.g., `socks5h://127.0.0.1:9050`).
pub fn make_http_agent(config: &KdubConfig) -> Result<ureq::Agent, KdubError> {
    let agent = if !config.network.tor_proxy.is_empty() {
        let proxy = ureq::Proxy::new(&config.network.tor_proxy)
            .map_err(|e| KdubError::Publish(format!("invalid tor proxy: {e}")))?;
        ureq::Agent::config_builder()
            .proxy(Some(proxy))
            .build()
            .new_agent()
    } else {
        ureq::Agent::new_with_defaults()
    };
    Ok(agent)
}

/// Publish an armored public key to a keyserver via HKP.
///
/// Sends a `POST` to `{keyserver_url}/pks/add` with the URL-encoded armored key
/// as `application/x-www-form-urlencoded` body.
pub fn publish_to_keyserver(
    agent: &ureq::Agent,
    keyserver_url: &str,
    armored_pubkey: &str,
) -> Result<String, KdubError> {
    // Build the HKP URL: strip hkps:// -> https://, hkp:// -> http://
    let url = keyserver_url_to_https(keyserver_url);
    let post_url = format!("{url}/pks/add");

    let encoded_key = urlencoding::encode(armored_pubkey);
    let body = format!("keytext={encoded_key}");

    agent
        .post(&post_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|e| KdubError::Publish(format!("keyserver upload failed: {e}")))?;

    Ok(format!("Published to keyserver: {url}"))
}

/// Publish an armored public key to GitHub's GPG keys API.
///
/// Requires a valid GitHub personal access token with `write:gpg_key` scope.
/// The token is accepted as `&GithubToken` to ensure it is never stored in a
/// plain `String` beyond the point of capture.
pub fn publish_to_github(
    agent: &ureq::Agent,
    token: &GithubToken,
    armored_pubkey: &str,
) -> Result<String, KdubError> {
    let body = serde_json::json!({
        "armored_public_key": armored_pubkey,
    });

    let version = env!("CARGO_PKG_VERSION");
    let token_str = token.expose_secret();

    agent
        .post("https://api.github.com/user/gpg_keys")
        .header("authorization", &format!("Bearer {token_str}"))
        .header("accept", "application/vnd.github+json")
        .header("user-agent", &format!("kdub/{version}"))
        .header("content-type", "application/json")
        .send(body.to_string().as_bytes())
        .map_err(|e| KdubError::Publish(format!("GitHub upload failed: {e}")))?;

    Ok("Published to GitHub GPG keys".to_string())
}

/// Export a public key to the Web Key Directory structure.
///
/// Creates `<webroot>/.well-known/openpgpkey/<domain>/hu/<hash>` containing
/// the binary (non-armored) public key.
///
/// The email is extracted from the first User ID of the public key.
pub fn publish_to_wkd(
    webroot: &Path,
    email: &str,
    public_key: &SignedPublicKey,
) -> Result<String, KdubError> {
    let (hash, domain) = wkd::wkd_hash(email)
        .ok_or_else(|| KdubError::Publish(format!("invalid email: {email}")))?;

    let wkd_dir = webroot
        .join(".well-known")
        .join("openpgpkey")
        .join(&domain)
        .join("hu");

    fs::create_dir_all(&wkd_dir)?;

    let key_path = wkd_dir.join(&hash);

    // Write binary (non-armored) public key
    let key_bytes = public_key
        .to_bytes()
        .map_err(|e| KdubError::Publish(format!("failed to serialize public key: {e}")))?;
    fs::write(&key_path, &key_bytes)?;

    // Also create the policy file if it doesn't exist
    let policy_path = webroot
        .join(".well-known")
        .join("openpgpkey")
        .join(&domain)
        .join("policy");
    if !policy_path.exists() {
        fs::write(&policy_path, "")?;
    }

    Ok(format!("Published to WKD: {}", key_path.display()))
}

/// Export armored public key to a file.
///
/// Writes the armored public key string to the specified path with mode 0644.
pub fn publish_to_file(path: &Path, armored_pubkey: &str) -> Result<String, KdubError> {
    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, armored_pubkey)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;

    Ok(format!("Published to file: {}", path.display()))
}

/// Convert an HKP-scheme URL to HTTPS.
///
/// `hkps://keys.openpgp.org` -> `https://keys.openpgp.org`
/// `hkp://keys.openpgp.org` -> `http://keys.openpgp.org`
/// Already-HTTPS URLs are returned as-is.
fn keyserver_url_to_https(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("hkps://") {
        format!("https://{rest}")
    } else if let Some(rest) = url.strip_prefix("hkp://") {
        format!("http://{rest}")
    } else {
        url.to_string()
    }
}

/// Extract the primary email address from a public key's User ID.
///
/// Parses the `"Name <email>"` format and returns the email portion.
/// Returns `None` if no User ID exists or the format doesn't contain `<email>`.
pub fn extract_email_from_key(public_key: &SignedPublicKey) -> Option<String> {
    let uid = public_key.details.users.first()?;
    let uid_str = String::from_utf8_lossy(uid.id.id()).to_string();

    // Parse "Name <email>" format
    if let Some(start) = uid_str.find('<')
        && let Some(end) = uid_str.find('>')
        && start < end
    {
        return Some(uid_str[start + 1..end].to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen::SignedSecretKey;

    fn generate_test_key() -> (SignedSecretKey, crate::types::Fingerprint) {
        use pgp::composed::Deserializable;
        let armored = include_str!("../tests/fixtures/test_key.asc");
        let (key, _) = SignedSecretKey::from_armor_single(std::io::Cursor::new(armored))
            .expect("fixture key should parse");
        let fp = crate::keygen::extract_fingerprint(&key);
        (key, fp)
    }

    #[test]
    fn test_make_http_agent_no_proxy() {
        let config = KdubConfig::default();
        let agent = make_http_agent(&config);
        assert!(agent.is_ok(), "should create agent without proxy");
    }

    #[test]
    fn test_make_http_agent_with_proxy() {
        let mut config = KdubConfig::default();
        config.network.tor_proxy = "socks5h://127.0.0.1:9050".to_string();
        let agent = make_http_agent(&config);
        assert!(agent.is_ok(), "should create agent with proxy config");
    }

    #[test]
    fn test_make_http_agent_with_proxy_string() {
        // ureq accepts proxy URLs at construction time; verify the agent builds
        // successfully with a well-formed SOCKS5 proxy string.
        let mut config = KdubConfig::default();
        config.network.tor_proxy = "socks5h://192.168.1.1:1080".to_string();
        let agent = make_http_agent(&config);
        assert!(agent.is_ok(), "should create agent with valid proxy URL");
    }

    #[test]
    fn test_keyserver_url_to_https_hkps() {
        assert_eq!(
            keyserver_url_to_https("hkps://keys.openpgp.org"),
            "https://keys.openpgp.org"
        );
    }

    #[test]
    fn test_keyserver_url_to_https_hkp() {
        assert_eq!(
            keyserver_url_to_https("hkp://keys.openpgp.org"),
            "http://keys.openpgp.org"
        );
    }

    #[test]
    fn test_keyserver_url_to_https_already_https() {
        assert_eq!(
            keyserver_url_to_https("https://keys.openpgp.org"),
            "https://keys.openpgp.org"
        );
    }

    #[test]
    fn test_publish_to_file() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("pubkey.asc");
        let armored =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";

        let result = publish_to_file(&file_path, armored);
        assert!(result.is_ok());

        let content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, armored);

        // Check permissions
        let mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn test_publish_to_file_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let file_path = tmp.path().join("subdir").join("nested").join("pubkey.asc");
        let armored =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\ntest\n-----END PGP PUBLIC KEY BLOCK-----";

        let result = publish_to_file(&file_path, armored);
        assert!(result.is_ok());
        assert!(file_path.exists());
    }

    #[test]
    fn test_publish_to_wkd() {
        use pgp::composed::Deserializable;

        let (key, _fp) = generate_test_key();
        let public_key: SignedPublicKey = key.to_public_key();
        let tmp = tempfile::tempdir().unwrap();

        let result = publish_to_wkd(tmp.path(), "fixture@test.example", &public_key);
        assert!(result.is_ok(), "WKD publish should succeed: {result:?}");

        // Verify the WKD file was created
        let (hash, domain) = wkd::wkd_hash("fixture@test.example").unwrap();
        let wkd_path = tmp
            .path()
            .join(".well-known")
            .join("openpgpkey")
            .join(&domain)
            .join("hu")
            .join(&hash);
        assert!(wkd_path.exists(), "WKD key file should exist");

        // Verify the file contains a valid public key
        let key_bytes = fs::read(&wkd_path).unwrap();
        let parsed = SignedPublicKey::from_bytes(&key_bytes[..]);
        assert!(parsed.is_ok(), "WKD file should contain valid PGP key");

        // Verify policy file was created
        let policy_path = tmp
            .path()
            .join(".well-known")
            .join("openpgpkey")
            .join(&domain)
            .join("policy");
        assert!(policy_path.exists(), "WKD policy file should exist");
    }

    #[test]
    fn test_publish_to_wkd_invalid_email() {
        let (key, _fp) = generate_test_key();
        let public_key: SignedPublicKey = key.to_public_key();
        let tmp = tempfile::tempdir().unwrap();

        let result = publish_to_wkd(tmp.path(), "not-an-email", &public_key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KdubError::Publish(_)));
    }

    #[test]
    fn test_extract_email_from_key() {
        let (key, _fp) = generate_test_key();
        let public_key: SignedPublicKey = key.to_public_key();
        let email = extract_email_from_key(&public_key);
        assert_eq!(email, Some("fixture@test.example".to_string()));
    }
}
