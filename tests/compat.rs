//! Cross-SDK compatibility with `@licenseman/electron`. Ignored by default;
//! CI runs `node scripts/compat/electron-store.mjs` first, then this test with
//! `COMPAT_DIR` set.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use serde_json::Value;
use tauri_plugin_licensemanager::testing::{manager, FakeTransport, SecureStore, TestHooks};
use tauri_plugin_licensemanager::{Builder, LicenseManager};

const PRODUCT_ID: &str = "x7Kp2QaZ";
const MACHINE: &str = "compat-machine";

fn compat_dir() -> PathBuf {
    PathBuf::from(std::env::var("COMPAT_DIR").expect("COMPAT_DIR is not set"))
}

/// Files only, fixed machine value, no network.
fn open(store_dir: &Path) -> LicenseManager {
    let builder = Builder::new(PRODUCT_ID, Keys::pem())
        .fingerprint(MACHINE)
        .storage_dirs(vec![store_dir.to_owned()])
        .testing(TestHooks {
            transport: Some(Arc::new(FakeTransport::new())),
            secret_backend: Some(None),
            clock: None,
        });
    manager(builder, "1.0.0").unwrap()
}

struct Keys;

impl Keys {
    fn pem() -> String {
        tauri_plugin_licensemanager::testing::Keys::get()
            .public_pem
            .clone()
    }
}

#[tokio::test]
#[ignore = "needs `node scripts/compat/electron-store.mjs` and COMPAT_DIR"]
async fn compat_with_electron() {
    // Electron wrote, Rust reads.
    let expected: Value = serde_json::from_slice(
        &std::fs::read(compat_dir().join("electron").join("expected.json")).unwrap(),
    )
    .unwrap();
    let store_dir = PathBuf::from(expected["storeDir"].as_str().unwrap());
    let lm = open(&store_dir);
    let fingerprint = lm.fingerprint().await;
    lm.dispose();
    assert_eq!(fingerprint, expected["fingerprint"].as_str().unwrap());
    let install_id = SecureStore::new(PRODUCT_ID, Some(vec![store_dir]), None).get("installId");
    assert_eq!(install_id.as_deref(), fingerprint.split(':').nth(1));

    // Rust writes, Electron reads.
    let rust_dir = compat_dir().join("rust").join("store");
    let _ = std::fs::remove_dir_all(&rust_dir);
    let lm = open(&rust_dir);
    let fingerprint = lm.fingerprint().await;
    lm.dispose();
    SecureStore::new(PRODUCT_ID, Some(vec![rust_dir.clone()]), None)
        .set("licenseKey", "KEY-FROM-RUST");

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/compat/electron-store.mjs");
    let output = Command::new("node")
        .arg(script)
        .arg("read")
        .arg(&rust_dir)
        .env("COMPAT_DIR", compat_dir())
        .output()
        .expect("node is required");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let read: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(read["fingerprint"], fingerprint.as_str());
    assert_eq!(read["licenseKey"], "KEY-FROM-RUST");
}
