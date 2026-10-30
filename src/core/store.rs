//! Port of `secure-store.ts`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};

/// Keyring service shared by every app embedding the SDK.
pub(crate) const KEYRING_SERVICE: &str = "dev.licensemanager.sdk";

/// A keyring operation failed (store locked, access denied, no backend…).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct SecretBackendError(pub String);

/// An OS secret store, addressed by service and account.
pub trait SecretBackend: Send + Sync + 'static {
    /// The stored secret, or `None` when there is none.
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, SecretBackendError>;
    /// Create or replace a secret.
    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), SecretBackendError>;
    /// Delete a secret; deleting a missing one may succeed or fail.
    fn delete(&self, service: &str, account: &str) -> Result<(), SecretBackendError>;
}

/// The OS keyring, through the same stores as `@napi-rs/keyring`, so entries
/// written by the Electron SDK are found here.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
struct KeyringBackend {
    store: Arc<keyring_core::CredentialStore>,
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl KeyringBackend {
    fn load() -> Option<Self> {
        let config = std::collections::HashMap::new();
        #[cfg(target_os = "macos")]
        let store: Arc<keyring_core::CredentialStore> =
            apple_native_keyring_store::keychain::Store::new_with_configuration(&config).ok()?;
        #[cfg(target_os = "windows")]
        let store: Arc<keyring_core::CredentialStore> =
            windows_native_keyring_store::Store::new_with_configuration(&config).ok()?;
        // Secret Service, else the kernel keyring, like `@napi-rs/keyring`.
        #[cfg(target_os = "linux")]
        let store: Arc<keyring_core::CredentialStore> =
            match dbus_secret_service_keyring_store::Store::new_with_configuration(&config) {
                Ok(store) => store,
                Err(_) => {
                    linux_keyutils_keyring_store::Store::new_with_configuration(&config).ok()?
                }
            };
        Some(Self { store })
    }

    fn entry(
        &self,
        service: &str,
        account: &str,
    ) -> Result<keyring_core::Entry, SecretBackendError> {
        self.store
            .build(service, account, None)
            .map_err(backend_error)
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn backend_error(error: keyring_core::Error) -> SecretBackendError {
    SecretBackendError(error.to_string())
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
impl SecretBackend for KeyringBackend {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, SecretBackendError> {
        match self.entry(service, account)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(error) => Err(backend_error(error)),
        }
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), SecretBackendError> {
        self.entry(service, account)?
            .set_password(value)
            .map_err(backend_error)
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), SecretBackendError> {
        self.entry(service, account)?
            .delete_credential()
            .map_err(backend_error)
    }
}

/// The OS keyring, loaded once per process; `None` when unavailable (e.g.
/// no Secret Service nor kernel keyring), which means files only.
pub(crate) fn default_backend() -> Option<Arc<dyn SecretBackend>> {
    static BACKEND: OnceLock<Option<Arc<dyn SecretBackend>>> = OnceLock::new();
    BACKEND
        .get_or_init(|| {
            #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
            {
                KeyringBackend::load().map(|b| Arc::new(b) as Arc<dyn SecretBackend>)
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
            {
                None
            }
        })
        .clone()
}

/// Per-product persistence for small secret strings (install ID, last-seen
/// timestamp, license key and token).
///
/// Primary backend is the OS secret store. When it is unavailable or fails,
/// values are mirrored to redundant, non-obvious files so they survive app
/// uninstall/reinstall. Every entry is namespaced by `product_id`.
///
/// Calls are blocking (a keychain prompt may wait on the user): async code
/// uses the `*_async` variants, which run on the blocking pool.
#[derive(Clone)]
pub struct SecureStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    product_id: String,
    dirs: Vec<PathBuf>,
    backend: Option<Arc<dyn SecretBackend>>,
}

impl SecureStore {
    /// A store for `product_id`, in `dirs` (default: the OS locations) and the
    /// given keyring backend (`None`: files only).
    pub fn new(
        product_id: &str,
        dirs: Option<Vec<PathBuf>>,
        backend: Option<Arc<dyn SecretBackend>>,
    ) -> Self {
        let dirs = dirs.unwrap_or_else(|| default_dirs(&namespace(product_id)));
        Self {
            inner: Arc::new(StoreInner {
                product_id: product_id.to_owned(),
                dirs,
                backend,
            }),
        }
    }

    fn account(&self, key: &str) -> String {
        format!("{}:{key}", self.inner.product_id)
    }

    /// The value from the keyring, else from the first readable non-empty file.
    pub fn get(&self, key: &str) -> Option<String> {
        if let Some(backend) = &self.inner.backend {
            if let Ok(Some(value)) = backend.get(KEYRING_SERVICE, &self.account(key)) {
                return Some(value);
            }
        }
        self.inner.dirs.iter().find_map(|dir| {
            fs::read_to_string(dir.join(file_name(key)))
                .ok()
                .filter(|value| !value.is_empty())
        })
    }

    /// Write to the keyring (best effort) and to every file location.
    pub fn set(&self, key: &str, value: &str) {
        if let Some(backend) = &self.inner.backend {
            let _ = backend.set(KEYRING_SERVICE, &self.account(key), value);
        }
        for dir in &self.inner.dirs {
            let _ = write_private(dir, &file_name(key), value);
        }
    }

    /// Delete from the keyring (best effort) and from every file location.
    pub fn delete(&self, key: &str) {
        if let Some(backend) = &self.inner.backend {
            let _ = backend.delete(KEYRING_SERVICE, &self.account(key));
        }
        for dir in &self.inner.dirs {
            let _ = fs::remove_file(dir.join(file_name(key)));
        }
    }

    /// [`get`](Self::get) on the blocking pool.
    pub(crate) async fn get_async(&self, key: &'static str) -> Option<String> {
        let store = self.clone();
        tokio::task::spawn_blocking(move || store.get(key))
            .await
            .ok()
            .flatten()
    }

    /// [`set`](Self::set) on the blocking pool.
    pub(crate) async fn set_async(&self, key: &'static str, value: String) {
        let store = self.clone();
        let _ = tokio::task::spawn_blocking(move || store.set(key, &value)).await;
    }

    /// [`delete`](Self::delete) on the blocking pool.
    pub(crate) async fn delete_async(&self, key: &'static str) {
        let store = self.clone();
        let _ = tokio::task::spawn_blocking(move || store.delete(key)).await;
    }
}

fn write_private(dir: &Path, name: &str, value: &str) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(dir.join(name))?.write_all(value.as_bytes())
}

/// GUID-looking per-product id with no "license" marker.
pub(crate) fn namespace(product_id: &str) -> String {
    let digest = Sha256::digest(format!("{KEYRING_SERVICE}:{product_id}"));
    hex::encode(digest)[..32].to_owned()
}

/// Obscure, stable file name per key (no readable marker).
pub(crate) fn file_name(key: &str) -> String {
    format!("{}.dat", &hex::encode(Sha256::digest(key))[..24])
}

fn default_dirs(namespace: &str) -> Vec<PathBuf> {
    let home = std::env::home_dir().unwrap_or_default();
    let hidden = format!(".{namespace}");
    if cfg!(target_os = "macos") {
        vec![
            home.join("Library")
                .join("Application Support")
                .join(&hidden),
            home.join("Library").join("Caches").join(&hidden),
        ]
    } else if cfg!(windows) {
        let program_data = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData"));
        let app_data = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("AppData").join("Roaming"));
        vec![program_data.join(namespace), app_data.join(namespace)]
    } else {
        vec![
            home.join(".config").join(&hidden),
            home.join(".local").join("share").join(&hidden),
        ]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tempfile::TempDir;

    use super::*;
    use crate::core::test_support::MemoryBackend;

    fn dirs() -> (TempDir, TempDir) {
        (TempDir::new().unwrap(), TempDir::new().unwrap())
    }

    fn files_only(product_id: &str, dirs: &[&TempDir]) -> SecureStore {
        SecureStore::new(
            product_id,
            Some(dirs.iter().map(|d| d.path().to_owned()).collect()),
            None,
        )
    }

    #[test]
    fn golden_namespace_and_file_names() {
        assert_eq!(namespace("x7Kp2QaZ"), "ea8ac6eca49d93514868857bb07922b4");
        assert_eq!(file_name("installId"), "ca8a5f3f684e28ccf496a00b.dat");
        assert_eq!(file_name("licenseKey"), "4d7f38bbfba5e53684683337.dat");
        assert_eq!(file_name("licenseToken"), "110af1ca6fb7b596b2a37cc3.dat");
        assert_eq!(file_name("lastSeen"), "758c78e59ed6d3a1649c33a8.dat");
    }

    // File fallback.

    #[test]
    fn returns_none_for_an_unknown_key() {
        let (a, b) = dirs();
        assert_eq!(files_only("prod-1", &[&a, &b]).get("installId"), None);
    }

    #[test]
    fn round_trips_a_value() {
        let (a, b) = dirs();
        let store = files_only("prod-1", &[&a, &b]);
        store.set("installId", "secret");
        assert_eq!(store.get("installId").as_deref(), Some("secret"));
    }

    #[test]
    fn mirrors_writes_so_a_surviving_copy_is_still_readable() {
        let (a, b) = dirs();
        let store = files_only("prod-1", &[&a, &b]);
        store.set("installId", "secret");
        fs::remove_dir_all(a.path()).unwrap();
        assert_eq!(store.get("installId").as_deref(), Some("secret"));
    }

    #[test]
    fn deletes_a_value_from_every_location() {
        let (a, b) = dirs();
        let store = files_only("prod-1", &[&a, &b]);
        store.set("installId", "secret");
        store.delete("installId");
        assert_eq!(store.get("installId"), None);
        // Deleting a missing value is a no-op.
        store.delete("installId");
    }

    #[test]
    fn isolates_different_product_ids() {
        let (a, b) = dirs();
        let store_a = files_only("prod-a", &[&a]);
        let store_b = files_only("prod-b", &[&b]);
        store_a.set("installId", "from-a");
        store_b.set("installId", "from-b");
        assert_eq!(store_a.get("installId").as_deref(), Some("from-a"));
        assert_eq!(store_b.get("installId").as_deref(), Some("from-b"));
    }

    #[test]
    fn never_writes_a_key_verbatim_in_the_filename() {
        let (a, _) = dirs();
        files_only("prod-1", &[&a]).set("installId", "secret");
        let names: Vec<String> = fs::read_dir(a.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names.len(), 1);
        assert!(!names[0].contains("installId"));
        assert!(names[0].ends_with(".dat"));
        assert!(names[0]
            .trim_end_matches(".dat")
            .chars()
            .all(|c| c.is_ascii_hexdigit()));
    }

    #[cfg(unix)]
    #[test]
    fn writes_files_with_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let (a, _) = dirs();
        files_only("prod-1", &[&a]).set("installId", "secret");
        let mode = fs::metadata(a.path().join(file_name("installId")))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn skips_empty_files() {
        let (a, b) = dirs();
        fs::write(a.path().join(file_name("installId")), "").unwrap();
        fs::write(b.path().join(file_name("installId")), "kept").unwrap();
        assert_eq!(
            files_only("prod-1", &[&a, &b]).get("installId").as_deref(),
            Some("kept")
        );
    }

    // Keyring backend.

    #[test]
    fn prefers_the_keyring_over_files_and_namespaces_by_product_id() {
        let (a, b) = dirs();
        let backend = Arc::new(MemoryBackend::default());
        let store_a =
            SecureStore::new("prod-a", Some(vec![a.path().into()]), Some(backend.clone()));
        let store_b =
            SecureStore::new("prod-b", Some(vec![b.path().into()]), Some(backend.clone()));
        store_a.set("installId", "from-a");
        store_b.set("installId", "from-b");

        // The keyring wins over a diverging file.
        fs::write(a.path().join(file_name("installId")), "stale").unwrap();
        assert_eq!(store_a.get("installId").as_deref(), Some("from-a"));
        assert_eq!(store_b.get("installId").as_deref(), Some("from-b"));
        assert_eq!(
            backend.entries(),
            HashMap::from([
                (
                    format!("{KEYRING_SERVICE}::prod-a:installId"),
                    "from-a".to_owned()
                ),
                (
                    format!("{KEYRING_SERVICE}::prod-b:installId"),
                    "from-b".to_owned()
                ),
            ])
        );

        store_a.delete("installId");
        assert_eq!(store_a.get("installId"), None);
        assert_eq!(backend.entries().len(), 1);
    }

    struct Failing;

    impl SecretBackend for Failing {
        fn get(&self, _: &str, _: &str) -> Result<Option<String>, SecretBackendError> {
            Err(SecretBackendError("no keyring".into()))
        }
        fn set(&self, _: &str, _: &str, _: &str) -> Result<(), SecretBackendError> {
            Err(SecretBackendError("no keyring".into()))
        }
        fn delete(&self, _: &str, _: &str) -> Result<(), SecretBackendError> {
            Err(SecretBackendError("no keyring".into()))
        }
    }

    #[test]
    fn falls_back_to_files_when_the_keyring_throws() {
        let (a, _) = dirs();
        let store = SecureStore::new(
            "prod-1",
            Some(vec![a.path().into()]),
            Some(Arc::new(Failing)),
        );
        store.set("installId", "secret");
        assert_eq!(store.get("installId").as_deref(), Some("secret"));
        store.delete("installId");
        assert_eq!(store.get("installId"), None);
    }

    #[test]
    fn computes_os_appropriate_default_locations_when_no_dirs_are_given() {
        let ns = namespace("x7Kp2QaZ");
        let dirs = default_dirs(&ns);
        assert_eq!(dirs.len(), 2);
        let home = std::env::home_dir().unwrap();
        if cfg!(target_os = "macos") {
            assert_eq!(
                dirs[0],
                home.join("Library/Application Support")
                    .join(format!(".{ns}"))
            );
            assert_eq!(dirs[1], home.join("Library/Caches").join(format!(".{ns}")));
        } else if cfg!(windows) {
            assert!(dirs.iter().all(|d| d.ends_with(&ns)));
        } else {
            assert_eq!(dirs[0], home.join(".config").join(format!(".{ns}")));
            assert_eq!(dirs[1], home.join(".local/share").join(format!(".{ns}")));
        }
        // Read-only: avoid writing into the real home directory.
        let store = SecureStore::new(&format!("prod-{}", rand::random::<u64>()), None, None);
        assert_eq!(store.get("installId"), None);
    }

    #[tokio::test]
    async fn async_variants_use_the_same_values() {
        let (a, _) = dirs();
        let store = files_only("prod-1", &[&a]);
        store.set_async("installId", "secret".into()).await;
        assert_eq!(
            store.get_async("installId").await.as_deref(),
            Some("secret")
        );
        store.delete_async("installId").await;
        assert_eq!(store.get_async("installId").await, None);
    }

    #[test]
    fn memory_backend_is_shareable() {
        let backend = MemoryBackend::default();
        backend.set("s", "a", "v").unwrap();
        assert_eq!(backend.get("s", "a").unwrap().as_deref(), Some("v"));
        backend.delete("s", "a").unwrap();
        assert_eq!(backend.get("s", "a").unwrap(), None);
    }
}
