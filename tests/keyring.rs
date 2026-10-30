//! Round-trips through the real OS keychain. Ignored by default; CI runs them
//! on macOS and Windows with `--ignored keyring`.

use tauri_plugin_licensemanager::testing::{os_keyring, SecureStore};

#[test]
#[ignore = "touches the real OS keychain"]
fn keyring_round_trip() {
    let backend = os_keyring().expect("no OS keyring available");
    let product_id = format!("ci-{}", std::process::id());
    let dir = tempfile::TempDir::new().unwrap();
    let store = SecureStore::new(
        &product_id,
        Some(vec![dir.path().to_owned()]),
        Some(backend.clone()),
    );

    store.set("installId", "from-keyring");
    let account = format!("{product_id}:installId");
    assert_eq!(
        backend
            .get("dev.licensemanager.sdk", &account)
            .unwrap()
            .as_deref(),
        Some("from-keyring")
    );
    // The keyring wins over the file mirror.
    std::fs::remove_dir_all(dir.path()).unwrap();
    assert_eq!(store.get("installId").as_deref(), Some("from-keyring"));

    store.delete("installId");
    assert_eq!(
        backend.get("dev.licensemanager.sdk", &account).unwrap(),
        None
    );
    assert_eq!(store.get("installId"), None);
}
