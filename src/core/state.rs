//! Port of `license-state.ts`.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use super::error::LicenseErrorCode;

/// The license state of the app.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LicenseState {
    /// Startup validation in progress.
    Loading,
    /// No license key stored yet: ask the user for one.
    MissingKey,
    /// Valid license, verified online or with the stored token.
    Active,
    /// The key does not exist for this product.
    InvalidKey,
    /// The license expiration date has passed.
    Expired,
    /// The license doesn't include this app version. See
    /// [`LicenseManager::latest_allowed_version`](crate::LicenseManager::latest_allowed_version).
    VersionNotAllowed,
    /// The license is active on its maximum number of machines.
    MachineLimitReached,
    /// Server unreachable and no valid stored token.
    OfflineExpired,
    /// Server unreachable and the system clock was rolled back.
    ClockTampered,
}

impl LicenseState {
    /// The wire string, e.g. `"ACTIVE"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Loading => "LOADING",
            Self::MissingKey => "MISSING_KEY",
            Self::Active => "ACTIVE",
            Self::InvalidKey => "INVALID_KEY",
            Self::Expired => "EXPIRED",
            Self::VersionNotAllowed => "VERSION_NOT_ALLOWED",
            Self::MachineLimitReached => "MACHINE_LIMIT_REACHED",
            Self::OfflineExpired => "OFFLINE_EXPIRED",
            Self::ClockTampered => "CLOCK_TAMPERED",
        }
    }
}

impl std::fmt::Display for LicenseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether the last validation reached the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfflineState {
    /// The last validation reached the server.
    Online,
    /// The server could not be reached: the app runs on the stored token.
    Offline {
        /// Expiry of the stored token, or `None` when there is no valid token.
        valid_until: Option<SystemTime>,
        /// Time left before `valid_until`; zero without a valid token.
        remaining: Duration,
    },
}

/// State the app locks into when the server refuses the license
/// (`LOCKED_STATES`). `None` for non-locking codes.
pub(crate) fn locked_state(code: LicenseErrorCode) -> Option<LicenseState> {
    match code {
        LicenseErrorCode::NotFound => Some(LicenseState::InvalidKey),
        LicenseErrorCode::LicenseExpired => Some(LicenseState::Expired),
        LicenseErrorCode::VersionNotAllowed => Some(LicenseState::VersionNotAllowed),
        LicenseErrorCode::MachineLimitReached => Some(LicenseState::MachineLimitReached),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_states_like_electron() {
        for state in [
            LicenseState::Loading,
            LicenseState::MissingKey,
            LicenseState::Active,
            LicenseState::InvalidKey,
            LicenseState::Expired,
            LicenseState::VersionNotAllowed,
            LicenseState::MachineLimitReached,
            LicenseState::OfflineExpired,
            LicenseState::ClockTampered,
        ] {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{state}\"")
            );
        }
    }

    #[test]
    fn locked_states() {
        assert_eq!(
            locked_state(LicenseErrorCode::NotFound),
            Some(LicenseState::InvalidKey)
        );
        assert_eq!(
            locked_state(LicenseErrorCode::LicenseExpired),
            Some(LicenseState::Expired)
        );
        assert_eq!(
            locked_state(LicenseErrorCode::VersionNotAllowed),
            Some(LicenseState::VersionNotAllowed)
        );
        assert_eq!(
            locked_state(LicenseErrorCode::MachineLimitReached),
            Some(LicenseState::MachineLimitReached)
        );
        assert_eq!(locked_state(LicenseErrorCode::NetworkError), None);
    }
}
