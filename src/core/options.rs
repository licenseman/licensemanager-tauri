//! Internal options of [`LicenseManager`](super::LicenseManager), filled by
//! the plugin `Builder`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use super::clock::Clock;
use super::fingerprint::MachineFingerprint;
use super::store::SecretBackend;
use super::transport::Transport;

pub(crate) struct LicenseManagerOptions {
    pub product_id: String,
    /// SPKI PEM, Ed25519.
    pub public_key: String,
    pub fingerprint: Option<MachineFingerprint>,
    /// The Builder's value, else `app.package_info().version`.
    pub version: String,
    /// Default: hostname.
    pub machine_name: Option<String>,
    /// Default: `"macOS"`, `"Windows"`, `"Linux"` or `std::env::consts::OS`.
    pub platform: Option<String>,
    pub min_offline_duration: Duration,
    /// Default: `https://api.licensemanager.dev`; trailing slashes trimmed.
    pub api_base_url: Option<String>,
    /// Tests only.
    pub storage_dirs: Option<Vec<PathBuf>>,
    pub runtime: tokio::runtime::Handle,
    pub testing: Option<TestHooks>,
}

#[cfg(test)]
impl LicenseManagerOptions {
    /// Options with defaults, for `product_id` and `public_key`.
    pub(crate) fn new(
        product_id: impl Into<String>,
        public_key: impl Into<String>,
        version: impl Into<String>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            product_id: product_id.into(),
            public_key: public_key.into(),
            fingerprint: None,
            version: version.into(),
            machine_name: None,
            platform: None,
            min_offline_duration: Duration::ZERO,
            api_base_url: None,
            storage_dirs: None,
            runtime,
            testing: None,
        }
    }
}

/// Replacements for the SDK's I/O, for tests. Not part of the semver API.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct TestHooks {
    /// HTTP transport (default: reqwest).
    pub transport: Option<Arc<dyn Transport>>,
    /// Keyring backend: `Some(None)` forces the file fallback (default: OS keyring).
    pub secret_backend: Option<Option<Arc<dyn SecretBackend>>>,
    /// Wall clock (default: system clock).
    pub clock: Option<Arc<dyn Clock>>,
}

impl std::fmt::Debug for TestHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestHooks").finish_non_exhaustive()
    }
}
