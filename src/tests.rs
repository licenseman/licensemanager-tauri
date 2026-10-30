//! Plugin tests, on Tauri's mock runtime.

use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tauri::test::{mock_builder, mock_context, noop_assets, MockRuntime};
use tauri::{App, Listener, RunEvent, WebviewWindowBuilder};
use tempfile::TempDir;

use crate::commands;
use crate::core::clock::Clock;
use crate::core::options::TestHooks;
use crate::core::test_support::{
    fail, ok, Claims, FakeClock, FakeTransport, Keys, MemoryBackend, KEY, PRODUCT_ID,
};
use crate::{Builder, LicenseState, LicensemanagerExt, STATE_CHANGED_EVENT};

struct Fixture {
    app: App<MockRuntime>,
    transport: Arc<FakeTransport>,
    _dir: TempDir,
}

fn fixture(configure: impl FnOnce(Builder) -> Builder) -> Fixture {
    let transport = Arc::new(FakeTransport::new());
    let dir = TempDir::new().unwrap();
    let builder = Builder::new(PRODUCT_ID, Keys::get().public_pem.clone())
        .fingerprint("fixed-machine")
        .api_base_url("https://api.test")
        .test_hooks(
            vec![dir.path().to_owned()],
            TestHooks {
                transport: Some(transport.clone()),
                secret_backend: Some(Some(Arc::new(MemoryBackend::default()))),
                clock: Some(Arc::new(FakeClock::new())),
            },
        );
    let app = mock_builder()
        .plugin(configure(builder).build())
        .build(mock_context(noop_assets()))
        .unwrap();
    Fixture {
        app,
        transport,
        _dir: dir,
    }
}

fn serve_valid(transport: &FakeTransport) {
    let clock = FakeClock::new();
    transport.on_validate(move |body| {
        let claims = Claims {
            sub: body["key"].as_str().unwrap().into(),
            ..Claims::new(body["fingerprint"].as_str().unwrap(), clock.now_ms())
        };
        async move { ok(&Keys::get().sign_with(&claims.to_json())) }
    });
}

fn to_json<T: serde::Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn registers_and_exposes_the_license_manager() {
    let f = fixture(|b| b);
    let state = tauri::async_runtime::block_on(f.app.license().ready());
    assert_eq!(state, LicenseState::MissingKey);
    assert_eq!(f.app.handle().license().state(), LicenseState::MissingKey);
    // The version defaults to the app's.
    assert_eq!(f.app.package_info().version.to_string(), "0.1.0");
}

#[test]
fn fails_setup_on_a_config_error() {
    let result = mock_builder()
        .plugin(Builder::new("", "pem").build())
        .build(mock_context(noop_assets()));
    let error = result.unwrap_err().to_string();
    assert!(error.contains("productId is required"), "{error}");

    let result = mock_builder()
        .plugin(Builder::new(PRODUCT_ID, "not a pem").build())
        .build(mock_context(noop_assets()));
    assert!(result.unwrap_err().to_string().contains("publicKey"));
}

#[test]
fn serializes_command_results() {
    let f = fixture(|b| b.version("2.3.1"));
    let app = f.app.handle().clone();
    tauri::async_runtime::block_on(async {
        assert_eq!(
            to_json(commands::ready(app.clone()).await),
            json!("MISSING_KEY")
        );
        assert_eq!(
            to_json(commands::get_state(app.clone())),
            json!("MISSING_KEY")
        );
        assert_eq!(
            to_json(commands::get_license(app.clone())),
            json!({ "state": "MISSING_KEY", "offline": { "mode": "online" } })
        );
        assert_eq!(
            to_json(commands::get_offline_state(app.clone())),
            json!({ "mode": "online" })
        );
        assert_eq!(
            to_json(commands::get_latest_allowed_version(app.clone())),
            json!({})
        );
        assert_eq!(
            to_json(commands::get_portal_url(app.clone())),
            json!(format!(
                "https://app.licensemanager.dev/portal/{PRODUCT_ID}"
            ))
        );
        assert_eq!(
            to_json(commands::is_clock_tampered(app.clone())),
            json!(false)
        );
        assert_eq!(
            to_json(commands::get_license_key_hint(app.clone())),
            Value::Null
        );
        assert_eq!(to_json(commands::get_license_key(app.clone())), Value::Null);
        let fp = commands::get_fingerprint(app.clone()).await;
        assert!(fp.ends_with(&format!(":{PRODUCT_ID}")));

        // Refused: error DTO, with latestAllowedVersion.
        f.transport.on_validate(|_| async {
            fail(
                403,
                "version_not_allowed",
                json!({ "latestAllowedVersion": "2.0.0" }),
            )
        });
        let error = commands::set_license_key(app.clone(), KEY.into())
            .await
            .unwrap_err();
        assert_eq!(
            to_json(error),
            json!({ "code": "version_not_allowed", "message": "nope", "status": 403, "latestAllowedVersion": "2.0.0" })
        );

        // Accepted.
        serve_valid(&f.transport);
        let state = commands::set_license_key(app.clone(), KEY.into())
            .await
            .unwrap();
        assert_eq!(to_json(state), json!("ACTIVE"));
        assert_eq!(to_json(commands::get_license_key(app.clone())), json!(KEY));
        assert_eq!(
            to_json(commands::get_license_key_hint(app.clone())),
            json!("B3JDF")
        );
        assert_eq!(f.transport.last_body_version(), "2.3.1");

        // Refused at refresh: locked, latestAllowedVersion null.
        f.transport
            .on_validate(|_| async { fail(403, "version_not_allowed", json!({})) });
        assert_eq!(
            to_json(commands::refresh(app.clone()).await),
            json!("VERSION_NOT_ALLOWED")
        );
        assert_eq!(
            to_json(commands::get_latest_allowed_version(app.clone())),
            json!({ "latestAllowedVersion": null })
        );
        assert_eq!(
            to_json(commands::get_license(app.clone())),
            json!({ "state": "VERSION_NOT_ALLOWED", "offline": { "mode": "online" }, "latestAllowedVersion": null })
        );
    });
}

impl FakeTransport {
    fn last_body_version(&self) -> String {
        self.requests().last().unwrap().1["version"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

#[test]
fn emits_the_snapshot_on_every_state_change() {
    let f = fixture(|b| b);
    tauri::async_runtime::block_on(f.app.license().ready());
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = events.clone();
    f.app.listen_any(STATE_CHANGED_EVENT, move |event| {
        recorded
            .lock()
            .unwrap()
            .push(serde_json::from_str::<Value>(event.payload()).unwrap());
    });
    serve_valid(&f.transport);
    tauri::async_runtime::block_on(f.app.license().set_license_key(KEY)).unwrap();
    f.transport
        .on_validate(|_| async { fail(404, "not_found", json!({})) });
    tauri::async_runtime::block_on(f.app.license().refresh());
    assert_eq!(
        *events.lock().unwrap(),
        vec![
            json!({ "state": "ACTIVE", "offline": { "mode": "online" } }),
            json!({ "state": "INVALID_KEY", "offline": { "mode": "online" } }),
        ]
    );
}

#[test]
fn disposes_on_exit() {
    let f = fixture(|b| b);
    let manager = f.app.license().clone();
    tauri::async_runtime::block_on(manager.ready());
    let window = WebviewWindowBuilder::new(&f.app, "main", Default::default())
        .build()
        .unwrap();
    f.app.run_return(move |_, event| {
        if let RunEvent::Ready = event {
            window.destroy().unwrap();
        }
    });
    assert!(manager.is_disposed());
}

#[test]
fn default_permission_set_contains_exactly_the_default_commands() {
    let default: toml::Value = toml::from_str(include_str!("../permissions/default.toml")).unwrap();
    let mut permissions: Vec<&str> = default["default"]["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    permissions.sort_unstable();
    assert_eq!(
        permissions,
        vec![
            "allow-get-latest-allowed-version",
            "allow-get-license",
            "allow-get-license-key-hint",
            "allow-get-offline-state",
            "allow-get-portal-url",
            "allow-get-state",
            "allow-is-clock-tampered",
            "allow-ready",
            "allow-refresh",
            "allow-set-license-key",
        ]
    );
    // The full key and the fingerprint need their own permission.
    for command in ["get_license_key", "get_fingerprint"] {
        let path = format!(
            "{}/permissions/autogenerated/commands/{command}.toml",
            env!("CARGO_MANIFEST_DIR")
        );
        assert!(std::path::Path::new(&path).exists(), "{path}");
    }
}
