//! Commands invoked by `@licenseman/tauri` as `plugin:licensemanager|<command>`.

use tauri::{command, AppHandle, Runtime};

use crate::core::LicenseState;
use crate::models::{LatestAllowedVersionDto, LicenseErrorDto, OfflineStateDto, Snapshot};
use crate::LicensemanagerExt;

#[command]
pub(crate) fn get_state<R: Runtime>(app: AppHandle<R>) -> LicenseState {
    app.license().state()
}

#[command]
pub(crate) async fn ready<R: Runtime>(app: AppHandle<R>) -> LicenseState {
    app.license().clone().ready().await
}

#[command]
pub(crate) fn get_license<R: Runtime>(app: AppHandle<R>) -> Snapshot {
    Snapshot::of(app.license())
}

#[command]
pub(crate) async fn set_license_key<R: Runtime>(
    app: AppHandle<R>,
    key: String,
) -> Result<LicenseState, LicenseErrorDto> {
    let manager = app.license().clone();
    manager.set_license_key(&key).await.map_err(Into::into)
}

#[command]
pub(crate) async fn refresh<R: Runtime>(app: AppHandle<R>) -> LicenseState {
    app.license().clone().refresh().await
}

#[command]
pub(crate) fn get_offline_state<R: Runtime>(app: AppHandle<R>) -> OfflineStateDto {
    app.license().offline_state().into()
}

#[command]
pub(crate) fn get_latest_allowed_version<R: Runtime>(app: AppHandle<R>) -> LatestAllowedVersionDto {
    (&app.license().latest_allowed_version()).into()
}

#[command]
pub(crate) fn get_portal_url<R: Runtime>(app: AppHandle<R>) -> String {
    app.license().portal_url()
}

#[command]
pub(crate) fn is_clock_tampered<R: Runtime>(app: AppHandle<R>) -> bool {
    app.license().is_clock_tampered()
}

/// Last 5 characters of the key, to show which key is active without
/// exposing it.
#[command]
pub(crate) fn get_license_key_hint<R: Runtime>(app: AppHandle<R>) -> Option<String> {
    app.license().license_key().map(|key| key_hint(&key))
}

#[command]
pub(crate) fn get_license_key<R: Runtime>(app: AppHandle<R>) -> Option<String> {
    app.license().license_key()
}

#[command]
pub(crate) async fn get_fingerprint<R: Runtime>(app: AppHandle<R>) -> String {
    app.license().clone().fingerprint().await
}

fn key_hint(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    chars[chars.len().saturating_sub(5)..].iter().collect()
}

#[cfg(test)]
mod tests {
    use super::key_hint;

    #[test]
    fn hints_the_last_5_characters() {
        assert_eq!(key_hint("7KQ2M-X9ZPA-H4TRC-WN6EY-B3JDF"), "B3JDF");
        assert_eq!(key_hint("abc"), "abc");
        assert_eq!(key_hint("ééééééé"), "ééééé");
    }
}
