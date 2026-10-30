use std::time::Duration;

use tauri_plugin_licensemanager::{LicenseState, LicensemanagerExt};

/// Product to test against. Override at build time with
/// `LICENSEMANAGER_PRODUCT_ID` and `LICENSEMANAGER_PUBLIC_KEY`.
const PRODUCT_ID: &str = match option_env!("LICENSEMANAGER_PRODUCT_ID") {
    Some(id) => id,
    None => "x7Kp2QaZ",
};
const PUBLIC_KEY: &str = match option_env!("LICENSEMANAGER_PUBLIC_KEY") {
    Some(key) => key,
    None => {
        "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAR7nrFiZ0PzxzBq6B85FIm/6XwzX71cBpkN3xNr9FpfY=
-----END PUBLIC KEY-----"
    }
};

/// A feature that must stay locked without a license: checked in Rust, where
/// the webview can't bypass it.
#[tauri::command]
fn premium_feature(app: tauri::AppHandle) -> Result<String, String> {
    if app.license().state() != LicenseState::Active {
        return Err("This feature needs an active license.".into());
    }
    Ok("Premium feature unlocked.".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut licensing = tauri_plugin_licensemanager::Builder::new(PRODUCT_ID, PUBLIC_KEY)
        .min_offline_duration(Duration::from_secs(14 * 86_400));
    if let Some(url) = option_env!("LICENSEMANAGER_API_BASE_URL") {
        licensing = licensing.api_base_url(url);
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(licensing.build())
        .invoke_handler(tauri::generate_handler![premium_feature])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
