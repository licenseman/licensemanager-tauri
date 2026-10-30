//! Serializable shapes sent to the webview.

use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::core::{
    LatestAllowedVersion, LicenseError, LicenseErrorCode, LicenseManager, LicenseState,
    OfflineState,
};

/// [`OfflineState`] as JSON: `{ mode: "online" }` or
/// `{ mode: "offline", validUntil: number | null, remainingMs: number }`,
/// times in ms since the epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum OfflineStateDto {
    /// The last validation reached the server.
    Online,
    /// The app runs on the stored token.
    Offline {
        /// Expiry of the stored token in ms since the epoch, or `null`.
        #[serde(rename = "validUntil")]
        valid_until: Option<u64>,
        /// Time left before `validUntil`, in ms.
        #[serde(rename = "remainingMs")]
        remaining_ms: u64,
    },
}

impl From<OfflineState> for OfflineStateDto {
    fn from(state: OfflineState) -> Self {
        match state {
            OfflineState::Online => Self::Online,
            OfflineState::Offline {
                valid_until,
                remaining,
            } => Self::Offline {
                valid_until: valid_until.map(|t| {
                    t.duration_since(UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                }),
                remaining_ms: u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX),
            },
        }
    }
}

/// `undefined` (field absent) for `NotApplicable`, else `string | null`.
fn latest_to_dto(latest: &LatestAllowedVersion) -> Option<Option<String>> {
    latest.as_option().map(|v| v.map(str::to_owned))
}

/// Everything the webview needs to render the license, in one call. Also the
/// payload of the `licensemanager://state-changed` event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// The license state.
    pub state: LicenseState,
    /// Whether the last validation reached the server.
    pub offline: OfflineStateDto,
    /// Absent unless the server refused this version: then the latest
    /// allowed version, or `null` when none is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_allowed_version: Option<Option<String>>,
}

impl Snapshot {
    /// The current snapshot of `manager`.
    pub fn of(manager: &LicenseManager) -> Self {
        Self {
            state: manager.state(),
            offline: manager.offline_state().into(),
            latest_allowed_version: latest_to_dto(&manager.latest_allowed_version()),
        }
    }
}

/// Return value of `get_latest_allowed_version`: an object, so that
/// "not applicable" (absent) differs from "none allowed" (`null`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LatestAllowedVersionDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_allowed_version: Option<Option<String>>,
}

impl From<&LatestAllowedVersion> for LatestAllowedVersionDto {
    fn from(latest: &LatestAllowedVersion) -> Self {
        Self {
            latest_allowed_version: latest_to_dto(latest),
        }
    }
}

/// A [`LicenseError`] as JSON: `{ code, message, status?, latestAllowedVersion? }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseErrorDto {
    /// The error code, e.g. `"not_found"`.
    pub code: LicenseErrorCode,
    /// Human-readable description.
    pub message: String,
    /// HTTP status, when the server answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// For `version_not_allowed`: latest allowed version, or `null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_allowed_version: Option<Option<String>>,
}

impl From<LicenseError> for LicenseErrorDto {
    fn from(error: LicenseError) -> Self {
        Self {
            code: error.code,
            latest_allowed_version: latest_to_dto(&error.latest_allowed_version),
            message: error.message,
            status: error.status,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    #[test]
    fn serializes_offline_states() {
        assert_eq!(
            serde_json::to_value(OfflineStateDto::from(OfflineState::Online)).unwrap(),
            json!({ "mode": "online" })
        );
        assert_eq!(
            serde_json::to_value(OfflineStateDto::from(OfflineState::Offline {
                valid_until: Some(UNIX_EPOCH + Duration::from_millis(1_767_225_600_000)),
                remaining: Duration::from_millis(1234),
            }))
            .unwrap(),
            json!({ "mode": "offline", "validUntil": 1_767_225_600_000u64, "remainingMs": 1234 })
        );
        assert_eq!(
            serde_json::to_value(OfflineStateDto::from(OfflineState::Offline {
                valid_until: None,
                remaining: Duration::ZERO,
            }))
            .unwrap(),
            json!({ "mode": "offline", "validUntil": null, "remainingMs": 0 })
        );
    }

    #[test]
    fn serializes_latest_allowed_version_absent_null_or_string() {
        let dto = |latest: LatestAllowedVersion| {
            serde_json::to_value(LatestAllowedVersionDto::from(&latest)).unwrap()
        };
        assert_eq!(dto(LatestAllowedVersion::NotApplicable), json!({}));
        assert_eq!(
            dto(LatestAllowedVersion::NoneAllowed),
            json!({ "latestAllowedVersion": null })
        );
        assert_eq!(
            dto(LatestAllowedVersion::Version("2.3.1".into())),
            json!({ "latestAllowedVersion": "2.3.1" })
        );

        let snapshot = Snapshot {
            state: LicenseState::VersionNotAllowed,
            offline: OfflineStateDto::Online,
            latest_allowed_version: Some(None),
        };
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap(),
            json!({ "state": "VERSION_NOT_ALLOWED", "offline": { "mode": "online" }, "latestAllowedVersion": null })
        );
        let snapshot = Snapshot {
            latest_allowed_version: None,
            state: LicenseState::Active,
            ..snapshot
        };
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap(),
            json!({ "state": "ACTIVE", "offline": { "mode": "online" } })
        );
    }

    #[test]
    fn serializes_errors() {
        let error = LicenseError {
            code: LicenseErrorCode::VersionNotAllowed,
            message: "nope".into(),
            status: Some(403),
            latest_allowed_version: LatestAllowedVersion::Version("2.3.1".into()),
        };
        assert_eq!(
            serde_json::to_value(LicenseErrorDto::from(error)).unwrap(),
            json!({ "code": "version_not_allowed", "message": "nope", "status": 403, "latestAllowedVersion": "2.3.1" })
        );
        let error = LicenseError::new(LicenseErrorCode::NetworkError, "offline");
        assert_eq!(
            serde_json::to_value(LicenseErrorDto::from(error)).unwrap(),
            json!({ "code": "network_error", "message": "offline" })
        );
    }
}
