//! Card reset validation logic.
//!
//! The `card reset` command is the most destructive operation in kdub.
//! It factory-resets the OpenPGP applet, erasing all keys and PINs.
//! This module provides the serial-number confirmation validation
//! used by the command handler.

/// Validate that the user-typed serial number matches the card serial.
///
/// The confirmation requires an exact match (after trimming whitespace).
/// This prevents wrong-card accidents by forcing the user to type the
/// specific serial number of the card being reset.
pub fn validate_serial_confirmation(expected: &str, input: &str) -> bool {
    expected == input.trim()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_serial_exact_match() {
        assert!(validate_serial_confirmation("12345678", "12345678"));
    }

    #[test]
    fn test_validate_serial_with_trailing_newline() {
        assert!(validate_serial_confirmation("12345678", "12345678\n"));
    }

    #[test]
    fn test_validate_serial_with_whitespace() {
        assert!(validate_serial_confirmation("12345678", "  12345678  "));
    }

    #[test]
    fn test_validate_serial_mismatch() {
        assert!(!validate_serial_confirmation("12345678", "87654321"));
    }

    #[test]
    fn test_validate_serial_empty_input() {
        assert!(!validate_serial_confirmation("12345678", ""));
    }

    #[test]
    fn test_validate_serial_empty_whitespace_input() {
        assert!(!validate_serial_confirmation("12345678", "   \n"));
    }

    #[test]
    fn test_validate_serial_partial_match() {
        assert!(!validate_serial_confirmation("12345678", "1234"));
    }

    #[test]
    fn test_validate_serial_case_sensitive() {
        assert!(!validate_serial_confirmation("AABBCCDD", "aabbccdd"));
    }

    #[test]
    fn test_validate_serial_superset_rejected() {
        assert!(!validate_serial_confirmation("12345678", "123456789"));
    }
}
