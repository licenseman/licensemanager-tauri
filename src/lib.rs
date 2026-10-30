#![deny(missing_docs)]
//! Tauri v2 plugin for [licensemanager.dev](https://licensemanager.dev): license
//! key activation, offline tokens, background renewal, clock tampering
//! detection and machine fingerprinting.
//!
//! Register the plugin with a [`Builder`], then reach the [`LicenseManager`]
//! with [`LicensemanagerExt::license`]:
//!
//! ```no_run
//! use std::time::Duration;
//! use tauri_plugin_licensemanager::{LicenseState, LicensemanagerExt};
//!
//! const PUBLIC_KEY: &str = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
//!
//! #[tauri::command]
//! fn export_pdf(app: tauri::AppHandle) -> Result<(), String> {
//!     if app.license().state() != LicenseState::Active {
//!         return Err("A license is required".into());
//!     }
//!     Ok(())
//! }
//!
//! // `context` is `tauri::generate_context!()` in an app.
//! fn run(context: tauri::Context) {
//!     tauri::Builder::default()
//!         .plugin(
//!             tauri_plugin_licensemanager::Builder::new("x7Kp2QaZ", PUBLIC_KEY)
//!                 .min_offline_duration(Duration::from_secs(14 * 86_400))
//!                 .build(),
//!         )
//!         .invoke_handler(tauri::generate_handler![export_pdf])
//!         .run(context)
//!         .expect("error while running tauri application");
//! }
//! # fn main() {}
//! ```
//!
//! See <https://licensemanager.dev/docs/tauri>.

use std::path::PathBuf;
use std::time::Duration;

use tauri::plugin::TauriPlugin;
use tauri::{Manager, RunEvent, Runtime};

mod commands;
mod core;
mod models;

use crate::core::options::{LicenseManagerOptions, TestHooks};
pub use crate::core::{
    ConfigError, LatestAllowedVersion, LicenseError, LicenseErrorCode, LicenseManager,
    LicenseState, MachineFingerprint, OfflineState, Subscription,
};
pub use crate::models::{LicenseErrorDto, OfflineStateDto, Snapshot};

/// Name of this SDK.
pub const SDK_NAME: &str = "tauri-plugin-licensemanager";

/// Event emitted to every webview on each state change, with a [`Snapshot`].
pub const STATE_CHANGED_EVENT: &str = "licensemanager://state-changed";

const MOBILE_ERROR: &str =
    "tauri-plugin-licensemanager supports desktop only (macOS, Windows, Linux)";

/// Configures and builds the plugin.
///
/// Configuration is in code only: hard-code the public key in the app.
#[derive(Debug)]
#[must_use = "call `.build()` and pass the result to `tauri::Builder::plugin`"]
pub struct Builder {
    product_id: String,
    public_key: String,
    fingerprint: Option<MachineFingerprint>,
    version: Option<String>,
    machine_name: Option<String>,
    platform: Option<String>,
    min_offline_duration: Duration,
    api_base_url: Option<String>,
    storage_dirs: Option<Vec<PathBuf>>,
    testing: Option<TestHooks>,
}

impl Builder {
    /// A plugin for `product_id`, verifying tokens with `public_key`, the
    /// product's Ed25519 public key (SPKI PEM).
    pub fn new(product_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            product_id: product_id.into(),
            public_key: public_key.into(),
            fingerprint: None,
            version: None,
            machine_name: None,
            platform: None,
            min_offline_duration: Duration::ZERO,
            api_base_url: None,
            storage_dirs: None,
            testing: None,
        }
    }

    /// Machine component of the fingerprint, replacing the native machine id
    /// (still hashed). A string is used verbatim; see
    /// [`MachineFingerprint::from_fn`] for a function.
    pub fn fingerprint(mut self, fingerprint: impl Into<MachineFingerprint>) -> Self {
        self.fingerprint = Some(fingerprint.into());
        self
    }

    /// App version, sent on validation and checked offline against the
    /// license's max version. Defaults to the version in `tauri.conf.json`
    /// (or `Cargo.toml`).
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Machine name shown in the dashboard. Defaults to the hostname.
    pub fn machine_name(mut self, machine_name: impl Into<String>) -> Self {
        self.machine_name = Some(machine_name.into());
        self
    }

    /// Platform shown in the dashboard. Defaults to `macOS`, `Windows` or
    /// `Linux`.
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = Some(platform.into());
        self
    }

    /// How long the app must keep working offline. The license is
    /// re-validated at 2/3 of the token lifetime, or earlier so that at least
    /// this much validity remains, but never sooner than 1 day after the last
    /// validation. Default: zero.
    pub fn min_offline_duration(mut self, duration: Duration) -> Self {
        self.min_offline_duration = duration;
        self
    }

    /// Override the API origin. Intended for tests.
    pub fn api_base_url(mut self, url: impl Into<String>) -> Self {
        self.api_base_url = Some(url.into());
        self
    }

    /// Override persistence locations. Not part of the semver API.
    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    pub fn storage_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.storage_dirs = Some(dirs);
        self
    }

    /// Replace the SDK's I/O. Not part of the semver API.
    #[cfg(feature = "test-util")]
    #[doc(hidden)]
    pub fn testing(mut self, hooks: testing::TestHooks) -> Self {
        self.testing = Some(hooks);
        self
    }

    #[cfg(test)]
    fn test_hooks(mut self, dirs: Vec<PathBuf>, hooks: TestHooks) -> Self {
        self.storage_dirs = Some(dirs);
        self.testing = Some(hooks);
        self
    }

    fn into_options(
        self,
        default_version: String,
        runtime: tokio::runtime::Handle,
    ) -> LicenseManagerOptions {
        LicenseManagerOptions {
            product_id: self.product_id,
            public_key: self.public_key,
            fingerprint: self.fingerprint,
            version: self.version.unwrap_or(default_version),
            machine_name: self.machine_name,
            platform: self.platform,
            min_offline_duration: self.min_offline_duration,
            api_base_url: self.api_base_url,
            storage_dirs: self.storage_dirs,
            runtime,
            testing: self.testing,
        }
    }

    /// Build the plugin. A configuration error fails the app setup.
    pub fn build<R: Runtime>(self) -> TauriPlugin<R> {
        tauri::plugin::Builder::new("licensemanager")
            .invoke_handler(tauri::generate_handler![
                commands::get_state,
                commands::ready,
                commands::get_license,
                commands::set_license_key,
                commands::refresh,
                commands::get_offline_state,
                commands::get_latest_allowed_version,
                commands::get_portal_url,
                commands::is_clock_tampered,
                commands::get_license_key_hint,
                commands::get_license_key,
                commands::get_fingerprint,
            ])
            .setup(move |app, _api| {
                setup(app, self)?;
                Ok(())
            })
            .on_event(|app, event| {
                if let RunEvent::Exit = event {
                    if let Some(manager) = app.try_state::<LicenseManager>() {
                        manager.dispose();
                    }
                }
            })
            .build()
    }
}

/// Keeps the event forwarding alive for the app's lifetime.
struct EventForwarding {
    _subscription: Subscription,
}

#[cfg(mobile)]
fn setup<R: Runtime>(_app: &tauri::AppHandle<R>, _builder: Builder) -> Result<(), String> {
    Err(MOBILE_ERROR.into())
}

#[cfg(not(mobile))]
fn setup<R: Runtime>(app: &tauri::AppHandle<R>, builder: Builder) -> Result<(), String> {
    use tauri::Emitter;

    let _ = MOBILE_ERROR;
    let options = builder.into_options(
        app.package_info().version.to_string(),
        tauri::async_runtime::handle().inner().clone(),
    );
    let manager = LicenseManager::new(options).map_err(|e| e.to_string())?;
    let handle = app.clone();
    let subscription = manager.on_state_change(move |state| {
        if let Some(manager) = handle.try_state::<LicenseManager>() {
            let snapshot = Snapshot {
                state,
                ..Snapshot::of(&manager)
            };
            let _ = handle.emit(STATE_CHANGED_EVENT, snapshot);
        }
    });
    app.manage(manager);
    app.manage(EventForwarding {
        _subscription: subscription,
    });
    Ok(())
}

/// Access to the [`LicenseManager`] from an `App`, `AppHandle`, `Window`…
pub trait LicensemanagerExt<R: Runtime> {
    /// The app's license manager. Panics if the plugin isn't registered.
    fn license(&self) -> &LicenseManager;
}

impl<R: Runtime, T: Manager<R>> LicensemanagerExt<R> for T {
    fn license(&self) -> &LicenseManager {
        self.state::<LicenseManager>().inner()
    }
}

/// Test hooks and fakes. Not part of the semver API.
#[cfg(feature = "test-util")]
#[doc(hidden)]
#[allow(missing_docs)]
pub mod testing {
    use std::sync::Arc;

    pub use crate::core::api::{post_validate_key, ValidateKeyRequest};
    pub use crate::core::clock::Clock;
    pub use crate::core::options::TestHooks;
    pub use crate::core::store::{SecretBackend, SecretBackendError, SecureStore};
    pub use crate::core::test_support::*;
    pub use crate::core::transport::{HttpResponse, Transport, TransportError};
    use crate::{Builder, ConfigError, LicenseManager};

    /// A [`LicenseManager`] without Tauri, on the current Tokio runtime.
    pub fn manager(builder: Builder, default_version: &str) -> Result<LicenseManager, ConfigError> {
        LicenseManager::new(
            builder.into_options(default_version.into(), tokio::runtime::Handle::current()),
        )
    }

    /// The production HTTP transport.
    pub fn reqwest_transport() -> Arc<dyn Transport> {
        Arc::new(crate::core::transport::ReqwestTransport::new())
    }

    /// The OS keyring backend, if available.
    pub fn os_keyring() -> Option<Arc<dyn SecretBackend>> {
        crate::core::store::default_backend()
    }
}

#[cfg(test)]
mod tests;
