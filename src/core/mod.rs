//! The licensing logic. Must not import `tauri` (checked in CI), so it can
//! become its own crate later.

pub(crate) mod api;
pub(crate) mod clock;
pub(crate) mod environment;
pub(crate) mod error;
pub(crate) mod fingerprint;
pub(crate) mod manager;
pub(crate) mod options;
pub(crate) mod retry;
pub(crate) mod state;
pub(crate) mod store;
pub(crate) mod token;
pub(crate) mod transport;
pub(crate) mod version;

#[cfg(any(test, feature = "test-util"))]
pub(crate) mod test_support;

pub use error::{ConfigError, LatestAllowedVersion, LicenseError, LicenseErrorCode};
pub use fingerprint::MachineFingerprint;
pub use manager::{LicenseManager, Subscription};
pub use state::{LicenseState, OfflineState};
