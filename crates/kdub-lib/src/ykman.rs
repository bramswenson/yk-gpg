use std::process::Command;

use serde::Serialize;

use crate::error::KdubError;
use crate::types::{AdminPin, KeyType};

/// YubiKey-specific information parsed from `ykman info` output.
///
/// Contains hardware details not available through the OpenPGP card
/// interface alone.
#[derive(Debug, Clone, Serialize)]
pub struct YubiKeyInfo {
    /// Device model (e.g. "YubiKey 5 NFC").
    pub model: String,
    /// Firmware version string (e.g. "5.4.3").
    pub firmware: String,
    /// Device serial number.
    pub serial: String,
    /// Best key type supported by this firmware version.
    pub best_key_type: String,
}

/// Abstraction over `ykman` CLI for YubiKey vendor-specific operations.
///
/// Touch policy is a YubiKey extension beyond the OpenPGP card standard,
/// so it goes through `ykman` rather than [`CardExecutor`].
#[cfg_attr(test, mockall::automock)]
pub trait YkmanExecutor {
    /// Set the touch policy for a single OpenPGP operation.
    ///
    /// `op` is one of `"sig"`, `"dec"`, or `"aut"`.
    /// `policy` is the ykman policy string (e.g. `"on"`, `"off"`, `"fixed"`,
    /// `"cached"`, `"cached-fixed"`).
    fn set_touch_policy(
        &self,
        op: &str,
        policy: &str,
        admin_pin: &AdminPin,
    ) -> Result<(), KdubError>;

    /// Check whether `ykman` is available on this system.
    fn is_available(&self) -> bool;
}

/// Concrete [`YkmanExecutor`] that shells out to the real `ykman` binary.
pub struct RealYkmanExecutor;

impl YkmanExecutor for RealYkmanExecutor {
    fn set_touch_policy(
        &self,
        op: &str,
        policy: &str,
        admin_pin: &AdminPin,
    ) -> Result<(), KdubError> {
        let output = Command::new("ykman")
            .args([
                "openpgp",
                "keys",
                "set-touch",
                op,
                policy,
                "--admin-pin",
                admin_pin.expose_secret(),
                "--force",
            ])
            .output()
            .map_err(|e| KdubError::Card(format!("failed to run ykman: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(KdubError::Card(format!(
                "ykman set-touch {op} {policy} failed: {stderr}"
            )));
        }
        Ok(())
    }

    fn is_available(&self) -> bool {
        Command::new("ykman")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Query YubiKey details via `ykman info`.
///
/// Returns `None` if `ykman` is not installed, not in PATH, or no
/// YubiKey is connected.
pub fn ykman_info() -> Option<YubiKeyInfo> {
    let output = Command::new("ykman").arg("info").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_ykman_info(&stdout)
}

/// Parse `ykman info` output into a [`YubiKeyInfo`].
fn parse_ykman_info(output: &str) -> Option<YubiKeyInfo> {
    let model = parse_field(output, "device type")?;
    let firmware_tuple = parse_firmware_version(output)?;
    let firmware = format!(
        "{}.{}.{}",
        firmware_tuple.0, firmware_tuple.1, firmware_tuple.2
    );
    let serial = parse_field(output, "serial number")?;
    let best_key_type = best_key_type_for_firmware(firmware_tuple);

    Some(YubiKeyInfo {
        model,
        firmware,
        serial,
        best_key_type: format!("{best_key_type}"),
    })
}

/// Parse a "Key: Value" field from ykman output (case-insensitive key match).
fn parse_field(output: &str, field_name: &str) -> Option<String> {
    for line in output.lines() {
        if line.to_lowercase().contains(&format!("{field_name}:")) {
            return line.split(':').nth(1).map(|v| v.trim().to_string());
        }
    }
    None
}

/// Auto-detect the best key type for the connected YubiKey.
///
/// Shells out to `ykman info` and parses the firmware version:
/// - YubiKey 5+ (firmware >= 5.2.3): Ed25519
/// - YubiKey 4: Rsa4096
/// - Returns `None` if `ykman` is not found or no YubiKey is connected.
///
/// This is a temporary shim that will be replaced by native card
/// detection in Phase E.
pub fn detect_key_type() -> Option<KeyType> {
    let output = Command::new("ykman").arg("info").output().ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let firmware = parse_firmware_version(&stdout)?;

    Some(best_key_type_for_firmware(firmware))
}

/// Parse firmware version from `ykman info` output.
///
/// Looks for a line like "Firmware version: 5.2.4"
fn parse_firmware_version(ykman_output: &str) -> Option<(u32, u32, u32)> {
    for line in ykman_output.lines() {
        let line_lower = line.to_lowercase();
        if line_lower.contains("firmware version:") {
            let version_str = line.split(':').nth(1)?.trim();
            let parts: Vec<&str> = version_str.split('.').collect();
            if parts.len() >= 3 {
                let major = parts[0].parse().ok()?;
                let minor = parts[1].parse().ok()?;
                let patch = parts[2].parse().ok()?;
                return Some((major, minor, patch));
            }
        }
    }
    None
}

/// Determine the best key type based on firmware version.
///
/// YubiKey 5 firmware >= 5.2.3 supports Ed25519.
/// Older versions fall back to RSA 4096.
fn best_key_type_for_firmware((major, minor, patch): (u32, u32, u32)) -> KeyType {
    if major > 5 || (major == 5 && (minor > 2 || (minor == 2 && patch >= 3))) {
        KeyType::Ed25519
    } else {
        KeyType::Rsa4096
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_firmware_yk5() {
        let output = "\
Device type: YubiKey 5 NFC
Serial number: 12345678
Firmware version: 5.2.4
Form factor: Keychain (USB-A)
";
        let fw = parse_firmware_version(output).unwrap();
        assert_eq!(fw, (5, 2, 4));
    }

    #[test]
    fn test_parse_firmware_yk4() {
        let output = "\
Device type: YubiKey 4
Serial number: 87654321
Firmware version: 4.3.7
";
        let fw = parse_firmware_version(output).unwrap();
        assert_eq!(fw, (4, 3, 7));
    }

    #[test]
    fn test_parse_firmware_missing() {
        let output = "No YubiKey detected\n";
        assert!(parse_firmware_version(output).is_none());
    }

    #[test]
    fn test_best_key_type_yk5_new() {
        assert_eq!(best_key_type_for_firmware((5, 2, 3)), KeyType::Ed25519);
        assert_eq!(best_key_type_for_firmware((5, 2, 4)), KeyType::Ed25519);
        assert_eq!(best_key_type_for_firmware((5, 4, 0)), KeyType::Ed25519);
        assert_eq!(best_key_type_for_firmware((6, 0, 0)), KeyType::Ed25519);
    }

    #[test]
    fn test_best_key_type_yk5_old() {
        assert_eq!(best_key_type_for_firmware((5, 2, 2)), KeyType::Rsa4096);
        assert_eq!(best_key_type_for_firmware((5, 1, 0)), KeyType::Rsa4096);
    }

    #[test]
    fn test_best_key_type_yk4() {
        assert_eq!(best_key_type_for_firmware((4, 3, 7)), KeyType::Rsa4096);
        assert_eq!(best_key_type_for_firmware((4, 0, 0)), KeyType::Rsa4096);
    }

    #[test]
    fn test_parse_ykman_info_yk5() {
        let output = "\
Device type: YubiKey 5 NFC
Serial number: 12345678
Firmware version: 5.4.3
Form factor: Keychain (USB-A)
";
        let info = parse_ykman_info(output).unwrap();
        assert_eq!(info.model, "YubiKey 5 NFC");
        assert_eq!(info.firmware, "5.4.3");
        assert_eq!(info.serial, "12345678");
        assert_eq!(info.best_key_type, "ed25519");
    }

    #[test]
    fn test_parse_ykman_info_yk4() {
        let output = "\
Device type: YubiKey 4
Serial number: 87654321
Firmware version: 4.3.7
Form factor: Keychain (USB-A)
";
        let info = parse_ykman_info(output).unwrap();
        assert_eq!(info.model, "YubiKey 4");
        assert_eq!(info.firmware, "4.3.7");
        assert_eq!(info.serial, "87654321");
        assert_eq!(info.best_key_type, "rsa4096");
    }

    #[test]
    fn test_parse_ykman_info_missing_field() {
        let output = "Firmware version: 5.4.3\nSerial number: 12345678\n";
        assert!(parse_ykman_info(output).is_none());
    }

    #[test]
    fn test_parse_field_found() {
        let output = "Device type: YubiKey 5 NFC\nOther: stuff\n";
        assert_eq!(
            parse_field(output, "device type"),
            Some("YubiKey 5 NFC".to_string())
        );
    }

    #[test]
    fn test_parse_field_not_found() {
        let output = "Other: stuff\n";
        assert!(parse_field(output, "device type").is_none());
    }

    // ---- YkmanExecutor mock tests ----

    #[test]
    fn test_set_touch_policy_all_ops() {
        let pin: AdminPin = "12345678".parse().unwrap();
        let mut mock = MockYkmanExecutor::new();

        // Expect set_touch_policy called once for each of sig, dec, aut
        mock.expect_set_touch_policy()
            .withf(|op, policy, _| op == "sig" && policy == "on")
            .times(1)
            .returning(|_, _, _| Ok(()));
        mock.expect_set_touch_policy()
            .withf(|op, policy, _| op == "dec" && policy == "on")
            .times(1)
            .returning(|_, _, _| Ok(()));
        mock.expect_set_touch_policy()
            .withf(|op, policy, _| op == "aut" && policy == "on")
            .times(1)
            .returning(|_, _, _| Ok(()));

        for op in &["sig", "dec", "aut"] {
            mock.set_touch_policy(op, "on", &pin).unwrap();
        }
    }

    #[test]
    fn test_set_touch_policy_cached_fixed() {
        let pin: AdminPin = "87654321".parse().unwrap();
        let mut mock = MockYkmanExecutor::new();

        mock.expect_set_touch_policy()
            .withf(|_, policy, _| policy == "cached-fixed")
            .times(3)
            .returning(|_, _, _| Ok(()));

        for op in &["sig", "dec", "aut"] {
            mock.set_touch_policy(op, "cached-fixed", &pin).unwrap();
        }
    }

    #[test]
    fn test_set_touch_policy_error() {
        let pin: AdminPin = "12345678".parse().unwrap();
        let mut mock = MockYkmanExecutor::new();

        mock.expect_set_touch_policy()
            .times(1)
            .returning(|_, _, _| {
                Err(KdubError::Card(
                    "ykman set-touch sig on failed: error".to_string(),
                ))
            });

        let result = mock.set_touch_policy("sig", "on", &pin);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ykman set-touch"));
    }

    #[test]
    fn test_ykman_not_available() {
        let mut mock = MockYkmanExecutor::new();
        mock.expect_is_available().times(1).returning(|| false);
        assert!(!mock.is_available());
    }

    #[test]
    fn test_ykman_available() {
        let mut mock = MockYkmanExecutor::new();
        mock.expect_is_available().times(1).returning(|| true);
        assert!(mock.is_available());
    }
}
