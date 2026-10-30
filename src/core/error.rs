//! Port of `license-errors.ts`.

use serde::{Deserialize, Serialize};

/// Error codes returned by the validate-key endpoint, plus SDK-side codes for
/// failures that never reached a definitive server answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseErrorCode {
    /// The key does not exist for this product.
    NotFound,
    /// The license expiration date has passed.
    LicenseExpired,
    /// The license doesn't include this app version.
    VersionNotAllowed,
    /// The license is active on its maximum number of machines.
    MachineLimitReached,
    /// The vendor's plan limit was exceeded.
    PlanLimitExceeded,
    /// The request was refused as malformed (or the key was empty).
    ValidationError,
    /// The server failed.
    InternalError,
    /// Server unreachable, timed out, or answered with an unknown error.
    NetworkError,
    /// Server answered 2xx but its token was missing or failed verification.
    InvalidResponse,
}

impl LicenseErrorCode {
    /// The wire string, e.g. `"not_found"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::LicenseExpired => "license_expired",
            Self::VersionNotAllowed => "version_not_allowed",
            Self::MachineLimitReached => "machine_limit_reached",
            Self::PlanLimitExceeded => "plan_limit_exceeded",
            Self::ValidationError => "validation_error",
            Self::InternalError => "internal_error",
            Self::NetworkError => "network_error",
            Self::InvalidResponse => "invalid_response",
        }
    }

    /// Codes the server may send that are reported as-is; any other server
    /// code becomes [`LicenseErrorCode::NetworkError`].
    pub(crate) fn from_server_code(code: &str) -> Option<Self> {
        match code {
            "not_found" => Some(Self::NotFound),
            "license_expired" => Some(Self::LicenseExpired),
            "version_not_allowed" => Some(Self::VersionNotAllowed),
            "machine_limit_reached" => Some(Self::MachineLimitReached),
            "plan_limit_exceeded" => Some(Self::PlanLimitExceeded),
            "validation_error" => Some(Self::ValidationError),
            "internal_error" => Some(Self::InternalError),
            _ => None,
        }
    }

    /// True for codes that say something about the customer's license, and
    /// therefore lock the app. Every other failure is treated like the server
    /// being unreachable.
    pub fn is_locking(self) -> bool {
        matches!(
            self,
            Self::NotFound
                | Self::LicenseExpired
                | Self::VersionNotAllowed
                | Self::MachineLimitReached
        )
    }
}

impl std::fmt::Display for LicenseErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// In state `VERSION_NOT_ALLOWED`, the latest version the license allows.
///
/// Electron's `string | null | undefined`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum LatestAllowedVersion {
    /// Not a server version refusal (`undefined` in JS): any other state, or
    /// a refusal by the stored token while offline, which only knows the max
    /// version, not the latest release.
    #[default]
    NotApplicable,
    /// The license allows no version (`null` in JS).
    NoneAllowed,
    /// The latest version the license allows.
    Version(String),
}

impl LatestAllowedVersion {
    /// `None` for [`NotApplicable`](Self::NotApplicable), else `Some(None)`
    /// or `Some(Some(version))`.
    pub fn as_option(&self) -> Option<Option<&str>> {
        match self {
            Self::NotApplicable => None,
            Self::NoneAllowed => Some(None),
            Self::Version(v) => Some(Some(v)),
        }
    }
}

/// A failed license validation. Branch on [`code`](Self::code), never on
/// `message`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct LicenseError {
    /// What went wrong.
    pub code: LicenseErrorCode,
    /// Human-readable description, for logs.
    pub message: String,
    /// HTTP status, when the server answered.
    pub status: Option<u16>,
    /// For `version_not_allowed`: latest version the license allows.
    pub latest_allowed_version: LatestAllowedVersion,
}

impl LicenseError {
    pub(crate) fn new(code: LicenseErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            status: None,
            latest_allowed_version: LatestAllowedVersion::NotApplicable,
        }
    }

    pub(crate) fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// True when the license itself was refused (the app should lock).
    pub fn is_locking(&self) -> bool {
        self.code.is_locking()
    }
}

/// Invalid plugin configuration: a developer error, reported at startup.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// `product_id` is empty.
    #[error("productId is required")]
    MissingProductId,
    /// `public_key` is empty.
    #[error("publicKey is required")]
    MissingPublicKey,
    /// `public_key` is not an Ed25519 SPKI PEM.
    #[error("publicKey is not a valid Ed25519 SPKI PEM: {0}")]
    InvalidPublicKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_codes_like_electron() {
        for code in [
            LicenseErrorCode::NotFound,
            LicenseErrorCode::LicenseExpired,
            LicenseErrorCode::VersionNotAllowed,
            LicenseErrorCode::MachineLimitReached,
            LicenseErrorCode::PlanLimitExceeded,
            LicenseErrorCode::ValidationError,
            LicenseErrorCode::InternalError,
            LicenseErrorCode::NetworkError,
            LicenseErrorCode::InvalidResponse,
        ] {
            assert_eq!(
                serde_json::to_value(code).unwrap(),
                serde_json::Value::String(code.to_string())
            );
            assert_eq!(
                LicenseErrorCode::from_server_code(code.as_str()).is_some(),
                !matches!(
                    code,
                    LicenseErrorCode::NetworkError | LicenseErrorCode::InvalidResponse
                )
            );
        }
    }

    #[test]
    fn locking_codes() {
        assert!(LicenseError::new(LicenseErrorCode::NotFound, "x").is_locking());
        assert!(LicenseErrorCode::LicenseExpired.is_locking());
        assert!(LicenseErrorCode::VersionNotAllowed.is_locking());
        assert!(LicenseErrorCode::MachineLimitReached.is_locking());
        assert!(!LicenseErrorCode::PlanLimitExceeded.is_locking());
        assert!(!LicenseErrorCode::NetworkError.is_locking());
    }

    #[test]
    fn latest_allowed_version_as_option() {
        assert_eq!(LatestAllowedVersion::NotApplicable.as_option(), None);
        assert_eq!(LatestAllowedVersion::NoneAllowed.as_option(), Some(None));
        assert_eq!(
            LatestAllowedVersion::Version("2.3".into()).as_option(),
            Some(Some("2.3"))
        );
    }

    #[test]
    fn config_error_messages() {
        assert_eq!(
            ConfigError::MissingProductId.to_string(),
            "productId is required"
        );
        assert_eq!(
            ConfigError::MissingPublicKey.to_string(),
            "publicKey is required"
        );
    }
}
