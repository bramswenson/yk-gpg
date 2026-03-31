use crate::types::{CardSerial, Fingerprint, ParseError};

/// Unified error type for all kdub library operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KdubError {
    #[error("invalid fingerprint: {0}")]
    InvalidFingerprint(String),
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),
    #[error("invalid PIN format: {0}")]
    InvalidPin(String),
    #[error("usage error: {0}")]
    UsageError(String),
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("config error: {0}")]
    Config(String),
    #[error("ephemeral directory error: {0}")]
    EphemeralDir(String),
    #[error("key generation error: {0}")]
    KeyGen(String),
    #[error("backup error: {0}")]
    Backup(String),
    #[error("backup not found for fingerprint: {0}")]
    BackupNotFound(Fingerprint),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("ambiguous identity: {0}")]
    AmbiguousIdentity(String),
    #[error("key renewal error: {0}")]
    Renew(String),
    #[error("key rotation error: {0}")]
    Rotate(String),
    #[error("publish error: {0}")]
    Publish(String),
    #[error(
        "key is on card serial {0}. Run `kdub key restore` from backup to get the certify key, then retry."
    )]
    KeyOnCard(CardSerial),
    #[error("card error: {0}")]
    Card(String),
    #[error("no smart card detected: {0}")]
    CardNotFound(String),
    #[error("missing dependency: {0}")]
    MissingDependency(String),
    #[error("operation cancelled")]
    Cancelled,
    #[error("not yet implemented: {0}")]
    NotImplemented(&'static str),
    #[error("tails download error: {0}")]
    TailsDownload(String),
    #[error("tails flash error: {0}")]
    TailsFlash(String),
    #[error("tails persist error: {0}")]
    TailsPersist(String),
    #[error("tails: unsupported on this platform: {0}")]
    TailsUnsupported(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl KdubError {
    /// Map error to process exit code (README exit code table)
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::NotImplemented(_) => 1,
            Self::InvalidFingerprint(_)
            | Self::InvalidKeyId(_)
            | Self::InvalidPin(_)
            | Self::Parse(_) => 1,
            Self::UsageError(_) => 2,
            Self::Config(_) => 1,
            Self::KeyGen(_) => 1,
            Self::Backup(_) => 1,
            Self::BackupNotFound(_) => 4,
            Self::KeyNotFound(_) => 4,
            Self::AmbiguousIdentity(_) => 1,
            Self::Renew(_) => 1,
            Self::Rotate(_) => 1,
            Self::Publish(_) => 1,
            Self::KeyOnCard(_) => 4,
            Self::Card(_) => 5,
            Self::CardNotFound(_) => 5,
            Self::MissingDependency(_) => 3,
            Self::Cancelled => 6,
            Self::EphemeralDir(_) => 1,
            Self::TailsDownload(_) => 1,
            Self::TailsFlash(_) => 1,
            Self::TailsPersist(_) => 1,
            Self::TailsUnsupported(_) => 2,
            Self::Io(_) => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_invalid_fingerprint() {
        let err = KdubError::InvalidFingerprint("bad".into());
        assert_eq!(err.to_string(), "invalid fingerprint: bad");
    }

    #[test]
    fn display_invalid_key_id() {
        let err = KdubError::InvalidKeyId("0xZZ".into());
        assert_eq!(err.to_string(), "invalid key ID: 0xZZ");
    }

    #[test]
    fn display_invalid_pin() {
        let err = KdubError::InvalidPin("too short".into());
        assert_eq!(err.to_string(), "invalid PIN format: too short");
    }

    #[test]
    fn display_parse() {
        let err = KdubError::Parse(ParseError("bad input".into()));
        assert_eq!(err.to_string(), "parse error: bad input");
    }

    #[test]
    fn display_not_implemented() {
        let err = KdubError::NotImplemented("card setup");
        assert_eq!(err.to_string(), "not yet implemented: card setup");
    }

    #[test]
    fn display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let err = KdubError::Io(io_err);
        assert_eq!(err.to_string(), "file missing");
    }

    #[test]
    fn exit_code_not_implemented() {
        assert_eq!(KdubError::NotImplemented("x").exit_code(), 1);
    }

    #[test]
    fn exit_code_validation_errors() {
        assert_eq!(KdubError::InvalidFingerprint("x".into()).exit_code(), 1);
        assert_eq!(KdubError::InvalidKeyId("x".into()).exit_code(), 1);
        assert_eq!(KdubError::InvalidPin("x".into()).exit_code(), 1);
        assert_eq!(KdubError::Parse(ParseError("x".into())).exit_code(), 1);
    }

    #[test]
    fn display_ephemeral_dir() {
        let err = KdubError::EphemeralDir("no tmpfs".into());
        assert_eq!(err.to_string(), "ephemeral directory error: no tmpfs");
    }

    #[test]
    fn exit_code_ephemeral_dir() {
        assert_eq!(KdubError::EphemeralDir("test".into()).exit_code(), 1);
    }

    #[test]
    fn exit_code_io() {
        let io_err = std::io::Error::other("oops");
        assert_eq!(KdubError::Io(io_err).exit_code(), 1);
    }

    #[test]
    fn display_key_on_card() {
        let serial: crate::types::CardSerial = "12345678".parse().unwrap();
        let err = KdubError::KeyOnCard(serial);
        assert_eq!(
            err.to_string(),
            "key is on card serial 12345678. Run `kdub key restore` from backup to get the certify key, then retry."
        );
    }

    #[test]
    fn exit_code_key_on_card() {
        let serial: crate::types::CardSerial = "12345678".parse().unwrap();
        assert_eq!(KdubError::KeyOnCard(serial).exit_code(), 4);
    }

    #[test]
    fn display_usage_error() {
        let err = KdubError::UsageError("invalid --key-type: rsa2048".into());
        assert_eq!(err.to_string(), "usage error: invalid --key-type: rsa2048");
    }

    #[test]
    fn exit_code_usage_error() {
        assert_eq!(KdubError::UsageError("bad arg".into()).exit_code(), 2);
    }

    #[test]
    fn parse_error_converts_to_kdub_error() {
        let parse_err = ParseError("test".into());
        let kdub_err: KdubError = parse_err.into();
        assert!(matches!(kdub_err, KdubError::Parse(_)));
    }

    #[test]
    fn io_error_converts_to_kdub_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let kdub_err: KdubError = io_err.into();
        assert!(matches!(kdub_err, KdubError::Io(_)));
    }

    #[test]
    fn display_card_error() {
        let err = KdubError::Card("timeout".into());
        assert_eq!(err.to_string(), "card error: timeout");
    }

    #[test]
    fn exit_code_card_error() {
        assert_eq!(KdubError::Card("timeout".into()).exit_code(), 5);
    }

    #[test]
    fn display_card_not_found() {
        let err = KdubError::CardNotFound("no card".into());
        assert_eq!(err.to_string(), "no smart card detected: no card");
    }

    #[test]
    fn exit_code_card_not_found() {
        assert_eq!(KdubError::CardNotFound("no card".into()).exit_code(), 5);
    }

    #[test]
    fn display_missing_dependency() {
        let err = KdubError::MissingDependency("ykman".into());
        assert_eq!(err.to_string(), "missing dependency: ykman");
    }

    #[test]
    fn exit_code_missing_dependency() {
        assert_eq!(KdubError::MissingDependency("ykman".into()).exit_code(), 3);
    }

    #[test]
    fn display_cancelled() {
        let err = KdubError::Cancelled;
        assert_eq!(err.to_string(), "operation cancelled");
    }

    #[test]
    fn exit_code_cancelled() {
        assert_eq!(KdubError::Cancelled.exit_code(), 6);
    }

    #[test]
    fn display_tails_download() {
        let err = KdubError::TailsDownload("connection refused".into());
        assert_eq!(err.to_string(), "tails download error: connection refused");
    }

    #[test]
    fn exit_code_tails_download() {
        assert_eq!(
            KdubError::TailsDownload("connection refused".into()).exit_code(),
            1
        );
    }

    #[test]
    fn display_tails_flash() {
        let err = KdubError::TailsFlash("device busy".into());
        assert_eq!(err.to_string(), "tails flash error: device busy");
    }

    #[test]
    fn exit_code_tails_flash() {
        assert_eq!(KdubError::TailsFlash("device busy".into()).exit_code(), 1);
    }

    #[test]
    fn display_tails_persist() {
        let err = KdubError::TailsPersist("cryptsetup failed".into());
        assert_eq!(err.to_string(), "tails persist error: cryptsetup failed");
    }

    #[test]
    fn exit_code_tails_persist() {
        assert_eq!(
            KdubError::TailsPersist("cryptsetup failed".into()).exit_code(),
            1
        );
    }

    #[test]
    fn display_tails_unsupported() {
        let err = KdubError::TailsUnsupported("persist requires Linux".into());
        assert_eq!(
            err.to_string(),
            "tails: unsupported on this platform: persist requires Linux"
        );
    }

    #[test]
    fn exit_code_tails_unsupported() {
        assert_eq!(
            KdubError::TailsUnsupported("persist requires Linux".into()).exit_code(),
            2
        );
    }

    #[test]
    fn display_config() {
        let err = KdubError::Config("missing field: key_type".into());
        assert_eq!(err.to_string(), "config error: missing field: key_type");
    }

    #[test]
    fn exit_code_config() {
        assert_eq!(KdubError::Config("bad config".into()).exit_code(), 1);
    }

    #[test]
    fn display_key_gen() {
        let err = KdubError::KeyGen("entropy exhausted".into());
        assert_eq!(err.to_string(), "key generation error: entropy exhausted");
    }

    #[test]
    fn exit_code_key_gen() {
        assert_eq!(KdubError::KeyGen("oops".into()).exit_code(), 1);
    }

    #[test]
    fn display_backup() {
        let err = KdubError::Backup("write failed".into());
        assert_eq!(err.to_string(), "backup error: write failed");
    }

    #[test]
    fn exit_code_backup() {
        assert_eq!(KdubError::Backup("write failed".into()).exit_code(), 1);
    }

    #[test]
    fn display_backup_not_found() {
        let fp: crate::types::Fingerprint =
            "D3B9C00B365DC5B752A6554A0630571A396BC2A7".parse().unwrap();
        let err = KdubError::BackupNotFound(fp);
        assert_eq!(
            err.to_string(),
            "backup not found for fingerprint: D3B9C00B365DC5B752A6554A0630571A396BC2A7"
        );
    }

    #[test]
    fn exit_code_backup_not_found() {
        let fp: crate::types::Fingerprint =
            "D3B9C00B365DC5B752A6554A0630571A396BC2A7".parse().unwrap();
        assert_eq!(KdubError::BackupNotFound(fp).exit_code(), 4);
    }

    #[test]
    fn display_key_not_found() {
        let err = KdubError::KeyNotFound("DEADBEEF".into());
        assert_eq!(err.to_string(), "key not found: DEADBEEF");
    }

    #[test]
    fn exit_code_key_not_found() {
        assert_eq!(KdubError::KeyNotFound("x".into()).exit_code(), 4);
    }

    #[test]
    fn display_ambiguous_identity() {
        let err = KdubError::AmbiguousIdentity("alice@example.com matches 2 keys".into());
        assert_eq!(
            err.to_string(),
            "ambiguous identity: alice@example.com matches 2 keys"
        );
    }

    #[test]
    fn exit_code_ambiguous_identity() {
        assert_eq!(KdubError::AmbiguousIdentity("x".into()).exit_code(), 1);
    }

    #[test]
    fn display_renew() {
        let err = KdubError::Renew("subkey expired".into());
        assert_eq!(err.to_string(), "key renewal error: subkey expired");
    }

    #[test]
    fn exit_code_renew() {
        assert_eq!(KdubError::Renew("x".into()).exit_code(), 1);
    }

    #[test]
    fn display_rotate() {
        let err = KdubError::Rotate("card not writable".into());
        assert_eq!(err.to_string(), "key rotation error: card not writable");
    }

    #[test]
    fn exit_code_rotate() {
        assert_eq!(KdubError::Rotate("x".into()).exit_code(), 1);
    }

    #[test]
    fn display_publish() {
        let err = KdubError::Publish("rate limited".into());
        assert_eq!(err.to_string(), "publish error: rate limited");
    }

    #[test]
    fn exit_code_publish() {
        assert_eq!(KdubError::Publish("x".into()).exit_code(), 1);
    }
}
