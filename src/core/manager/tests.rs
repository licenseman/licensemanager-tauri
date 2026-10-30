//! Ports of `license-state.test.ts` and `license-manager.test.ts`, plus
//! Tauri-specific tests. Time is Tokio's paused clock; the wall clock is a
//! [`FakeClock`] following it.

use std::sync::atomic::AtomicUsize;
use std::time::{Duration, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{json, Value};
use tempfile::TempDir;

use super::*;
use crate::core::clock::{decode_timestamp, encode_timestamp};
use crate::core::fingerprint::hash_machine_value;
use crate::core::options::TestHooks;
use crate::core::store::SecretBackend;
use crate::core::test_support::{
    fail, ok, Claims, FakeClock, FakeTransport, Keys, MemoryBackend, KEY, PRODUCT_ID, START_MS,
};
use crate::core::transport::{HttpResponse, TransportError};

type Respond = dyn Fn() -> Result<HttpResponse, TransportError> + Send + Sync;

const HOUR: i64 = 60 * 60 * 1000;
const DAY: i64 = 24 * HOUR;
const WEEK: i64 = 7 * DAY;

struct Harness {
    transport: Arc<FakeTransport>,
    clock: Arc<FakeClock>,
    backend: Arc<MemoryBackend>,
    dir: TempDir,
    keys: &'static Keys,
    current: Mutex<Option<LicenseManager>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(lm) = lock(&self.current).take() {
            lm.dispose();
        }
    }
}

impl Harness {
    fn new() -> Self {
        Self {
            transport: Arc::new(FakeTransport::new()),
            clock: Arc::new(FakeClock::new()),
            backend: Arc::new(MemoryBackend::default()),
            dir: TempDir::new().unwrap(),
            keys: Keys::get(),
            current: Mutex::new(None),
        }
    }

    fn options(&self) -> LicenseManagerOptions {
        let mut options = LicenseManagerOptions::new(
            PRODUCT_ID,
            self.keys.public_pem.clone(),
            "2.3.1",
            tokio::runtime::Handle::current(),
        );
        options.fingerprint = Some("fixed-machine".into());
        options.api_base_url = Some("https://api.test/".into());
        options.storage_dirs = Some(vec![self.dir.path().to_owned()]);
        options.testing = Some(TestHooks {
            transport: Some(self.transport.clone()),
            secret_backend: Some(Some(self.backend.clone())),
            clock: Some(self.clock.clone()),
        });
        options
    }

    fn make(&self) -> LicenseManager {
        self.make_with(|_| {})
    }

    fn make_with(&self, f: impl FnOnce(&mut LicenseManagerOptions)) -> LicenseManager {
        if let Some(previous) = lock(&self.current).take() {
            previous.dispose();
        }
        let mut options = self.options();
        f(&mut options);
        let lm = LicenseManager::new(options).unwrap();
        *lock(&self.current) = Some(lm.clone());
        lm
    }

    fn store(&self) -> SecureStore {
        SecureStore::new(
            PRODUCT_ID,
            Some(vec![self.dir.path().to_owned()]),
            Some(self.backend.clone()),
        )
    }

    /// Fingerprint of this test install, without triggering any validation.
    async fn fingerprint(&self) -> String {
        let lm = self.make();
        let fp = lm.fingerprint().await;
        lm.dispose();
        lock(&self.current).take();
        fp
    }

    fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    fn sign(&self, claims: &Claims) -> String {
        self.keys.sign_with(&claims.to_json())
    }

    /// Server issuing valid tokens for whatever key/fingerprint it gets.
    fn serve_valid(&self, lifetime_ms: i64) {
        let (clock, keys) = (self.clock.clone(), self.keys);
        self.transport.on_validate(move |body| {
            let claims = Claims {
                sub: body["key"].as_str().unwrap().into(),
                lifetime: Duration::from_millis(lifetime_ms as u64),
                ..Claims::new(body["fingerprint"].as_str().unwrap(), clock.now_ms())
            };
            async move { ok(&keys.sign_with(&claims.to_json())) }
        });
    }

    fn serve(
        &self,
        response: impl Fn() -> Result<HttpResponse, TransportError> + Send + Sync + 'static,
    ) {
        self.transport
            .on_validate(move |_| futures::future::ready(response()));
    }

    async fn seed(&self, lifetime_ms: i64, issued_at_ms: i64) {
        let fp = self.fingerprint().await;
        self.store().set("licenseKey", KEY);
        let claims = Claims {
            lifetime: Duration::from_millis(lifetime_ms as u64),
            ..Claims::new(&fp, issued_at_ms)
        };
        self.store().set("licenseToken", &self.sign(&claims));
    }

    fn validate_calls(&self) -> usize {
        self.transport.validate_calls()
    }

    fn last_body(&self) -> Value {
        self.transport.requests().last().unwrap().1.clone()
    }
}

/// Advance Tokio (and fake wall) time, running every timer on the way, then
/// let pending work (including blocking store calls) finish.
async fn advance(ms: i64) {
    tokio::time::sleep(Duration::from_millis(ms as u64)).await;
    flush().await;
}

/// Let pending work finish: paused time only moves once the runtime is idle
/// and no blocking task runs.
async fn flush() {
    tokio::time::sleep(Duration::from_millis(1)).await;
}

fn offline_at(expires_at_ms: i64, now_ms: i64) -> OfflineState {
    OfflineState::Offline {
        valid_until: Some(UNIX_EPOCH + Duration::from_millis(expires_at_ms as u64)),
        remaining: Duration::from_millis((expires_at_ms - now_ms) as u64),
    }
}

fn no_extra() -> Value {
    json!({})
}

// license-state.test.ts › startup

#[tokio::test(start_paused = true)]
async fn is_missing_key_without_a_stored_key_and_makes_no_request() {
    let h = Harness::new();
    let lm = h.make();
    assert_eq!(lm.ready().await, LicenseState::MissingKey);
    assert_eq!(h.validate_calls(), 0);
}

#[tokio::test(start_paused = true)]
async fn starts_loading_and_always_validates_online() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    assert_eq!(lm.state(), LicenseState::Loading);
    assert_eq!(lm.ready().await, LicenseState::Active);
    flush().await;
    assert_eq!(h.validate_calls(), 1);
    assert_eq!(lm.offline_state(), OfflineState::Online);
}

#[tokio::test(start_paused = true)]
async fn resolves_from_a_valid_stored_token_without_waiting_for_the_server() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    h.transport.on_validate(|_| futures::future::pending());
    let lm = h.make();
    assert_eq!(lm.ready().await, LicenseState::Active);
    flush().await;
    assert_eq!(h.validate_calls(), 1);
    assert_eq!(lm.offline_state(), OfflineState::Online);
}

#[tokio::test(start_paused = true)]
async fn waits_for_the_server_without_a_valid_stored_token() {
    let h = Harness::new();
    h.seed(WEEK, START_MS - 2 * WEEK).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let (clock, keys, counter) = (h.clock.clone(), h.keys, calls.clone());
    h.transport.on_validate(move |body| {
        let response = if counter.fetch_add(1, Ordering::SeqCst) < 2 {
            fail(503, "unavailable", json!({}))
        } else {
            ok(&keys.sign_with(
                &Claims::new(body["fingerprint"].as_str().unwrap(), clock.now_ms()).to_json(),
            ))
        };
        futures::future::ready(response)
    });
    let lm = h.make();
    assert_eq!(lm.ready().await, LicenseState::Active);
    assert_eq!(h.validate_calls(), 3);
    assert_eq!(lm.offline_state(), OfflineState::Online);
}

#[tokio::test(start_paused = true)]
async fn sends_the_documented_request() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    h.serve_valid(3 * WEEK);
    let lm = h.make_with(|o| {
        o.machine_name = Some("Jane's MacBook".into());
        o.platform = Some("macOS".into());
    });
    lm.ready().await;
    flush().await;
    let (url, body) = h.transport.requests()[0].clone();
    assert_eq!(
        url,
        format!("https://api.test/v1/products/{PRODUCT_ID}/validate-key")
    );
    assert_eq!(
        body,
        json!({
            "key": KEY,
            "fingerprint": lm.fingerprint().await,
            "version": "2.3.1",
            "name": "Jane's MacBook",
            "platform": "macOS",
        })
    );
}

#[tokio::test(start_paused = true)]
async fn locks_on_a_refusal_and_drops_the_token() {
    for (status, code, state) in [
        (404, "not_found", LicenseState::InvalidKey),
        (403, "license_expired", LicenseState::Expired),
        (403, "version_not_allowed", LicenseState::VersionNotAllowed),
        (
            403,
            "machine_limit_reached",
            LicenseState::MachineLimitReached,
        ),
    ] {
        let h = Harness::new();
        h.seed(3 * WEEK, START_MS).await;
        let extra = if code == "version_not_allowed" {
            json!({ "latestAllowedVersion": "2.3.1" })
        } else {
            json!({})
        };
        h.serve(move || fail(status, code, extra.clone()));
        let lm = h.make();
        // The stored token is valid: the refusal arrives in the background.
        assert_eq!(lm.ready().await, LicenseState::Active);
        flush().await;
        assert_eq!(lm.state(), state, "{code}");
        assert_eq!(h.store().get("licenseToken"), None);
        assert_eq!(lm.license_key().as_deref(), Some(KEY));
        if code == "version_not_allowed" {
            assert_eq!(
                lm.latest_allowed_version(),
                LatestAllowedVersion::Version("2.3.1".into())
            );
        } else {
            assert_eq!(
                lm.latest_allowed_version(),
                LatestAllowedVersion::NotApplicable
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn falls_back_to_the_stored_token_on_non_locking_failures() {
    let failures: Vec<(&str, Arc<Respond>)> = vec![
        (
            "network error",
            Arc::new(|| Err(TransportError("fetch failed".into()))),
        ),
        (
            "402 plan_limit_exceeded",
            Arc::new(|| fail(402, "plan_limit_exceeded", no_extra())),
        ),
        (
            "500 internal_error",
            Arc::new(|| fail(500, "internal_error", no_extra())),
        ),
        (
            "422 validation_error",
            Arc::new(|| fail(422, "validation_error", no_extra())),
        ),
        ("unknown code", Arc::new(|| fail(418, "teapot", no_extra()))),
        (
            "non-JSON body",
            Arc::new(|| {
                Ok(HttpResponse {
                    status: 502,
                    body: b"<html>".to_vec(),
                })
            }),
        ),
    ];
    for (name, failure) in failures {
        let h = Harness::new();
        h.seed(3 * WEEK, START_MS - DAY).await;
        h.serve(move || failure());
        let lm = h.make();
        assert_eq!(lm.ready().await, LicenseState::Active);
        // Background validation gives up within 5 minutes.
        advance(5 * 60 * 1000).await;
        assert_eq!(lm.state(), LicenseState::Active, "{name}");
        let expires_at = START_MS - DAY + 3 * WEEK;
        assert_eq!(
            lm.offline_state(),
            offline_at(expires_at, h.now()),
            "{name}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn is_offline_expired_when_offline_with_an_expired_token() {
    let h = Harness::new();
    h.seed(WEEK, START_MS - 2 * WEEK).await;
    let lm = h.make();
    assert_eq!(lm.ready().await, LicenseState::OfflineExpired);
    assert_eq!(
        lm.offline_state(),
        OfflineState::Offline {
            valid_until: None,
            remaining: Duration::ZERO
        }
    );
}

#[tokio::test(start_paused = true)]
async fn is_offline_expired_when_offline_without_a_token() {
    let h = Harness::new();
    h.fingerprint().await;
    h.store().set("licenseKey", KEY);
    assert_eq!(h.make().ready().await, LicenseState::OfflineExpired);
}

#[tokio::test(start_paused = true)]
async fn is_clock_tampered_when_offline_and_the_clock_went_back() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    h.store().set("lastSeen", &encode_timestamp(START_MS + DAY));
    assert_eq!(h.make().ready().await, LicenseState::ClockTampered);
}

#[tokio::test(start_paused = true)]
async fn trusts_the_server_over_a_tampered_clock() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    h.store().set("lastSeen", &encode_timestamp(START_MS + DAY));
    h.serve_valid(3 * WEEK);
    assert_eq!(h.make().ready().await, LicenseState::Active);
}

// license-state.test.ts › max version (mv) offline

async fn seed_max_version(h: &Harness, mv: Option<&str>) {
    let fp = h.fingerprint().await;
    h.store().set("licenseKey", KEY);
    let claims = Claims {
        mv: mv.map(str::to_owned),
        ..Claims::new(&fp, START_MS)
    };
    h.store().set("licenseToken", &h.sign(&claims));
}

#[tokio::test(start_paused = true)]
async fn mv_allows_older_versions_offline() {
    for (mv, version) in [
        (Some("2"), "2.3.1"),
        (Some("2.3"), "2.3.1"),
        (Some("3"), "2.3.1"),
        (None, "9.0.0"),
    ] {
        let h = Harness::new();
        seed_max_version(&h, mv).await;
        let lm = h.make_with(|o| o.version = version.into());
        assert_eq!(
            lm.ready().await,
            LicenseState::Active,
            "mv {mv:?} allows {version}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn refuses_a_newer_major_minor_offline_and_keeps_the_token() {
    for (mv, version) in [("2", "3.0.0"), ("2.3", "2.4.0")] {
        let h = Harness::new();
        seed_max_version(&h, Some(mv)).await;
        let lm = h.make_with(|o| o.version = version.into());
        assert_eq!(lm.ready().await, LicenseState::VersionNotAllowed);
        assert_eq!(
            lm.latest_allowed_version(),
            LatestAllowedVersion::NotApplicable
        );
        assert!(h.store().get("licenseToken").is_some());
    }
}

#[tokio::test(start_paused = true)]
async fn lets_the_server_override_mv_once_reachable() {
    let h = Harness::new();
    seed_max_version(&h, Some("2")).await;
    let lm = h.make_with(|o| o.version = "3.0.0".into());
    assert_eq!(lm.ready().await, LicenseState::VersionNotAllowed);

    // Time-limited updates: the server allows 3.0.0 although an old token said "2".
    h.serve_valid(3 * WEEK);
    advance(5 * 60 * 1000).await;
    assert_eq!(lm.state(), LicenseState::Active);
}

// license-state.test.ts › token verification

#[tokio::test(start_paused = true)]
async fn rejects_tokens_that_fail_verification() {
    type MakeToken = Box<dyn Fn(&str, i64) -> String + Send + Sync>;
    let keys = Keys::get();
    let cases: Vec<(&str, MakeToken)> = vec![
        (
            "another product",
            Box::new(move |fp, now| {
                keys.sign_with(
                    &Claims {
                        aud: "other".into(),
                        ..Claims::new(fp, now)
                    }
                    .to_json(),
                )
            }),
        ),
        (
            "another key",
            Box::new(move |fp, now| {
                keys.sign_with(
                    &Claims {
                        sub: "OTHER-KEY".into(),
                        ..Claims::new(fp, now)
                    }
                    .to_json(),
                )
            }),
        ),
        (
            "another machine",
            Box::new(move |_, now| keys.sign_with(&Claims::new("other-machine", now).to_json())),
        ),
        (
            "another signing key",
            Box::new(move |fp, now| keys.sign_with_other_key(&Claims::new(fp, now).to_json())),
        ),
        (
            "an expired token",
            Box::new(move |fp, _| {
                keys.sign_with(
                    &Claims {
                        lifetime: Duration::from_millis(HOUR as u64),
                        ..Claims::new(fp, START_MS - DAY)
                    }
                    .to_json(),
                )
            }),
        ),
        (
            "missing iat",
            Box::new(move |fp, now| {
                let mut claims = Claims::new(fp, now).to_json();
                claims.as_object_mut().unwrap().remove("iat");
                keys.sign_with(&claims)
            }),
        ),
        (
            "missing exp",
            Box::new(move |fp, now| {
                let mut claims = Claims::new(fp, now).to_json();
                claims.as_object_mut().unwrap().remove("exp");
                keys.sign_with(&claims)
            }),
        ),
        (
            "an unsigned token",
            Box::new(move |fp, _| {
                let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "none" }).to_string());
                let payload = URL_SAFE_NO_PAD
                    .encode(json!({ "aud": PRODUCT_ID, "sub": KEY, "fp": fp }).to_string());
                format!("{header}.{payload}.")
            }),
        ),
        (
            "a non-EdDSA token",
            Box::new(move |fp, now| {
                jsonwebtoken::encode(
                    &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                    &Claims::new(fp, now).to_json(),
                    &jsonwebtoken::EncodingKey::from_secret(keys.public_pem.as_bytes()),
                )
                .unwrap()
            }),
        ),
    ];
    for (name, make_token) in cases {
        let h = Harness::new();
        let clock = h.clock.clone();
        let make_token = Arc::new(make_token);
        h.transport.on_validate(move |body| {
            let token = make_token(body["fingerprint"].as_str().unwrap(), clock.now_ms());
            async move { ok(&token) }
        });
        let lm = h.make();
        lm.ready().await;
        let error = lm.set_license_key(KEY).await.unwrap_err();
        assert_eq!(error.code, LicenseErrorCode::InvalidResponse, "{name}");
        assert_eq!(error.status, Some(200), "{name}");
        assert_eq!(lm.state(), LicenseState::MissingKey, "{name}");
        assert_eq!(h.store().get("licenseToken"), None, "{name}");
    }
}

#[tokio::test(start_paused = true)]
async fn rejects_a_2xx_without_token() {
    let h = Harness::new();
    h.serve(|| {
        Ok(HttpResponse {
            status: 200,
            body: b"{}".to_vec(),
        })
    });
    let lm = h.make();
    lm.ready().await;
    let error = lm.set_license_key(KEY).await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::InvalidResponse);
    assert_eq!(error.status, Some(200));
}

// license-state.test.ts › setLicenseKey

#[tokio::test(start_paused = true)]
async fn activates_and_persists_key_and_token() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    let states = Arc::new(Mutex::new(Vec::new()));
    let recorded = states.clone();
    let _subscription = lm.on_state_change(move |s| lock(&recorded).push(s));

    assert_eq!(
        lm.set_license_key(&format!("  {KEY}\n")).await,
        Ok(LicenseState::Active)
    );
    assert_eq!(*lock(&states), vec![LicenseState::Active]);
    assert_eq!(lm.license_key().as_deref(), Some(KEY));
    assert_eq!(h.store().get("licenseKey").as_deref(), Some(KEY));
    assert!(h.store().get("licenseToken").is_some());
}

#[tokio::test(start_paused = true)]
async fn keeps_the_key_s_case() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key("abc-def").await.unwrap();
    assert_eq!(h.last_body()["key"], "abc-def");
}

#[tokio::test(start_paused = true)]
async fn throws_on_a_refused_key_and_leaves_the_current_license_alone() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    flush().await;
    let token = h.store().get("licenseToken");

    h.serve(|| fail(404, "not_found", no_extra()));
    let error = lm.set_license_key("TYPO").await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NotFound);
    assert_eq!(error.status, Some(404));
    assert_eq!(lm.state(), LicenseState::Active);
    assert_eq!(lm.license_key().as_deref(), Some(KEY));
    assert_eq!(h.store().get("licenseToken"), token);
}

#[tokio::test(start_paused = true)]
async fn throws_network_error_when_offline() {
    let h = Harness::new();
    let lm = h.make();
    lm.ready().await;
    let error = lm.set_license_key(KEY).await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    assert_eq!(error.status, None);
    assert_eq!(lm.state(), LicenseState::MissingKey);
    assert_eq!(h.store().get("licenseKey"), None);
}

#[tokio::test(start_paused = true)]
async fn reports_latest_allowed_version() {
    let h = Harness::new();
    h.serve(|| {
        fail(
            403,
            "version_not_allowed",
            json!({ "latestAllowedVersion": null }),
        )
    });
    let lm = h.make();
    lm.ready().await;
    let error = lm.set_license_key(KEY).await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::VersionNotAllowed);
    assert_eq!(
        error.latest_allowed_version,
        LatestAllowedVersion::NoneAllowed
    );
}

#[tokio::test(start_paused = true)]
async fn rejects_an_empty_key_without_a_request() {
    let h = Harness::new();
    let lm = h.make();
    lm.ready().await;
    let error = lm.set_license_key("   ").await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::ValidationError);
    assert_eq!(error.message, "The license key is empty");
    assert_eq!(h.validate_calls(), 0);
}

// license-state.test.ts › retries

#[tokio::test(start_paused = true)]
async fn retries_transient_failures_on_set_license_key() {
    let h = Harness::new();
    let lm = h.make();
    lm.ready().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let (clock, keys, counter) = (h.clock.clone(), h.keys, calls.clone());
    h.transport.on_validate(move |body| {
        let response = if counter.fetch_add(1, Ordering::SeqCst) < 2 {
            fail(503, "unavailable", json!({}))
        } else {
            ok(&keys.sign_with(
                &Claims::new(body["fingerprint"].as_str().unwrap(), clock.now_ms()).to_json(),
            ))
        };
        futures::future::ready(response)
    });
    assert_eq!(lm.set_license_key(KEY).await, Ok(LicenseState::Active));
    assert_eq!(h.validate_calls(), 3);
}

#[tokio::test(start_paused = true)]
async fn does_not_retry_final_answers() {
    for (status, code) in [
        (404, "not_found"),
        (402, "plan_limit_exceeded"),
        (422, "validation_error"),
    ] {
        let h = Harness::new();
        let lm = h.make();
        lm.ready().await;
        h.serve(move || fail(status, code, no_extra()));
        let error = lm.set_license_key(KEY).await.unwrap_err();
        assert_eq!(error.code.as_str(), code);
        assert_eq!(h.validate_calls(), 1, "{code}");
    }
}

#[tokio::test(start_paused = true)]
async fn gives_up_on_set_license_key_within_30_seconds() {
    let h = Harness::new();
    let lm = h.make();
    lm.ready().await;
    let started_at = h.now();
    let error = lm.set_license_key(KEY).await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    assert!(h.validate_calls() > 1);
    assert!(h.now() - started_at <= 30 * 1000);
}

#[tokio::test(start_paused = true)]
async fn gives_up_on_a_hanging_server_within_30_seconds() {
    let h = Harness::new();
    let lm = h.make();
    lm.ready().await;
    h.transport.on_validate(|_| futures::future::pending());
    let started_at = h.now();
    let error = lm.set_license_key(KEY).await.unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    // 10 s timeouts, so a few attempts fit.
    assert!(h.validate_calls() >= 2);
    assert!(h.now() - started_at <= 30 * 1000);
}

#[tokio::test(start_paused = true)]
async fn retries_longer_in_the_background() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let (clock, keys, counter) = (h.clock.clone(), h.keys, calls.clone());
    h.transport.on_validate(move |body| {
        let response = if counter.fetch_add(1, Ordering::SeqCst) < 7 {
            Err(TransportError("fetch failed".into()))
        } else {
            ok(&keys.sign_with(
                &Claims {
                    sub: body["key"].as_str().unwrap().into(),
                    ..Claims::new(body["fingerprint"].as_str().unwrap(), clock.now_ms())
                }
                .to_json(),
            ))
        };
        futures::future::ready(response)
    });
    advance(2 * WEEK).await;
    for _ in 0..60 {
        if calls.load(Ordering::SeqCst) >= 8 {
            break;
        }
        advance(5000).await;
    }
    flush().await;
    assert_eq!(calls.load(Ordering::SeqCst), 8);
    assert_eq!(lm.offline_state(), OfflineState::Online);
}

#[tokio::test(start_paused = true)]
async fn stops_retrying_after_dispose() {
    let h = Harness::new();
    let lm = h.make();
    lm.ready().await;
    let result = tokio::spawn({
        let lm = lm.clone();
        async move { lm.set_license_key(KEY).await }
    });
    flush().await;
    lm.dispose();
    let error = result.await.unwrap().unwrap_err();
    assert_eq!(error.code, LicenseErrorCode::NetworkError);
    assert_eq!(h.validate_calls(), 1);
}

// license-state.test.ts › automatic refresh

#[tokio::test(start_paused = true)]
async fn re_validates_at_2_3_of_the_token_lifetime() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();
    assert_eq!(h.validate_calls(), 1);

    advance(2 * WEEK - 1000).await;
    assert_eq!(h.validate_calls(), 1);
    advance(1000).await;
    assert_eq!(h.validate_calls(), 2);
    assert_eq!(lm.state(), LicenseState::Active);
}

#[tokio::test(start_paused = true)]
async fn honours_min_offline_duration() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make_with(|o| o.min_offline_duration = Duration::from_millis((3 * WEEK / 2) as u64));
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();

    advance(3 * WEEK / 2 - 1000).await;
    assert_eq!(h.validate_calls(), 1);
    advance(1000).await;
    assert_eq!(h.validate_calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn goes_offline_on_failure_retries_with_backoff_then_expires() {
    let h = Harness::new();
    h.serve_valid(3 * DAY);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();

    h.serve(|| fail(500, "internal_error", no_extra()));
    advance(2 * DAY - 1000).await;
    assert_eq!(h.validate_calls(), 1);
    // Retried for up to 5 min before giving up.
    advance(5 * 60 * 1000).await;
    let after_first_round = h.validate_calls();
    assert!(after_first_round > 2);
    assert_eq!(lm.state(), LicenseState::Active);
    assert!(matches!(lm.offline_state(), OfflineState::Offline { .. }));

    // Then 5 min until the next round.
    advance(4 * 60 * 1000).await;
    assert_eq!(h.validate_calls(), after_first_round);
    advance(2 * 60 * 1000).await;
    assert!(h.validate_calls() > after_first_round);

    advance(DAY).await;
    assert_eq!(lm.state(), LicenseState::OfflineExpired);

    h.serve_valid(3 * DAY);
    advance(HOUR).await;
    assert_eq!(lm.state(), LicenseState::Active);
    assert_eq!(lm.offline_state(), OfflineState::Online);
}

#[tokio::test(start_paused = true)]
async fn locks_when_the_license_is_refused_at_refresh() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();

    h.serve(|| fail(403, "license_expired", no_extra()));
    advance(2 * WEEK).await;
    assert_eq!(lm.state(), LicenseState::Expired);

    // No more scheduled validations once locked.
    advance(10 * WEEK).await;
    assert_eq!(h.validate_calls(), 2);

    h.serve_valid(3 * WEEK);
    assert_eq!(lm.refresh().await, LicenseState::Active);
}

#[tokio::test(start_paused = true)]
async fn handles_lifetimes_longer_than_the_max_timer_step() {
    let h = Harness::new();
    h.serve_valid(90 * DAY);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();

    advance(60 * DAY - 1000).await;
    assert_eq!(h.validate_calls(), 1);
    advance(1000).await;
    assert_eq!(h.validate_calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn catches_up_within_an_hour_when_the_wall_clock_jumps_ahead() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();

    flush().await;
    // Simulates system sleep: wall time moves past the refresh point without timers firing.
    h.clock.jump(2 * WEEK);
    advance(HOUR).await;
    assert_eq!(h.validate_calls(), 2);
}

#[tokio::test(start_paused = true)]
async fn stops_after_dispose() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();
    lm.dispose();
    advance(3 * WEEK).await;
    assert_eq!(h.validate_calls(), 1);
}

// license-manager.test.ts

/// `<base64 sha256 of machine>:<base64 install ID>:<productId>`
fn assert_fingerprint_format(fp: &str, product_id: &str) {
    let parts: Vec<&str> = fp.splitn(3, ':').collect();
    assert_eq!(parts.len(), 3, "{fp}");
    for part in &parts[..2] {
        assert_eq!(part.len(), 44, "{fp}");
        assert!(part.ends_with('='), "{fp}");
        assert!(part[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'));
    }
    assert_eq!(parts[2], product_id);
}

#[tokio::test(start_paused = true)]
async fn constructor_validation() {
    let h = Harness::new();
    let err = |f: fn(&mut LicenseManagerOptions)| {
        let mut options = h.options();
        f(&mut options);
        LicenseManager::new(options).unwrap_err()
    };
    assert_eq!(err(|o| o.product_id.clear()), ConfigError::MissingProductId);
    assert_eq!(err(|o| o.public_key.clear()), ConfigError::MissingPublicKey);
    assert!(matches!(
        err(|o| o.public_key = "pub".into()),
        ConfigError::InvalidPublicKey(_)
    ));
}

#[tokio::test(start_paused = true)]
async fn fingerprint_is_stable_and_mixes_machine_install_id_and_product() {
    let h = Harness::new();
    let lm = h.make();
    let fp = lm.fingerprint().await;
    assert_fingerprint_format(&fp, PRODUCT_ID);
    assert!(fp.starts_with(&format!("{}:", hash_machine_value("fixed-machine"))));
    assert_eq!(lm.fingerprint().await, fp);
}

#[tokio::test(start_paused = true)]
async fn persists_the_install_id_so_the_fingerprint_is_stable_across_instances() {
    let h = Harness::new();
    let first = h.make().fingerprint().await;
    let second = h.make().fingerprint().await;
    assert_eq!(second, first);
    let install_id = first.split(':').nth(1).unwrap();
    assert_eq!(h.store().get("installId").as_deref(), Some(install_id));
}

#[tokio::test(start_paused = true)]
async fn fingerprint_differs_per_product() {
    let h = Harness::new();
    let a = h
        .make_with(|o| o.product_id = "prod-a".into())
        .fingerprint()
        .await;
    let b = h
        .make_with(|o| o.product_id = "prod-b".into())
        .fingerprint()
        .await;
    assert_ne!(a, b);
    assert_fingerprint_format(&a, "prod-a");
}

#[tokio::test(start_paused = true)]
async fn honours_a_custom_async_fingerprint_function() {
    let h = Harness::new();
    let lm = h.make_with(|o| {
        o.fingerprint = Some(MachineFingerprint::from_fn(|| async {
            "custom".to_owned()
        }));
    });
    let fp = lm.fingerprint().await;
    assert_fingerprint_format(&fp, PRODUCT_ID);
    assert!(fp.starts_with(&format!("{}:", hash_machine_value("custom"))));
}

#[tokio::test(start_paused = true)]
async fn uses_the_native_machine_id_by_default() {
    let h = Harness::new();
    let lm = h.make_with(|o| o.fingerprint = None);
    let fp = lm.fingerprint().await;
    assert_fingerprint_format(&fp, PRODUCT_ID);
    assert!(fp.starts_with(&format!(
        "{}:",
        hash_machine_value(&crate::core::fingerprint::read_machine_id().await)
    )));
}

fn read_last_seen(h: &Harness) -> Option<i64> {
    decode_timestamp(h.store().get("lastSeen").as_deref())
}

// › clock tamper detection (offline fallback)

#[tokio::test(start_paused = true)]
async fn records_the_current_time_on_construction() {
    let h = Harness::new();
    h.make();
    flush().await;
    assert_eq!(read_last_seen(&h), Some(START_MS));
}

#[tokio::test(start_paused = true)]
async fn flags_a_backwards_clock_jump() {
    let h = Harness::new();
    h.store().set("lastSeen", &encode_timestamp(START_MS + DAY));
    let lm = h.make();
    flush().await;
    assert!(lm.is_clock_tampered());
}

#[tokio::test(start_paused = true)]
async fn runs_hourly_and_keeps_the_stored_time_monotonic_on_forward_progress() {
    let h = Harness::new();
    let lm = h.make();
    flush().await;
    assert!(!lm.is_clock_tampered());

    advance(HOUR).await;
    assert!(!lm.is_clock_tampered());
    assert_eq!(read_last_seen(&h), Some(START_MS + HOUR));
}

#[tokio::test(start_paused = true)]
async fn flags_tampering_when_a_scheduled_run_sees_an_earlier_time() {
    let h = Harness::new();
    let lm = h.make();
    flush().await;
    assert!(!lm.is_clock_tampered());

    h.clock.jump(-2 * HOUR);
    advance(HOUR).await;
    assert!(lm.is_clock_tampered());
}

// › clock tamper detection (network time)

#[tokio::test(start_paused = true)]
async fn flags_a_system_clock_behind_network_time() {
    let h = Harness::new();
    h.transport.set_network_time_ms(START_MS + DAY);
    let lm = h.make();
    flush().await;
    assert!(lm.is_clock_tampered());
}

#[tokio::test(start_paused = true)]
async fn flags_a_system_clock_ahead_of_network_time() {
    let h = Harness::new();
    h.transport.set_network_time_ms(START_MS - DAY);
    let lm = h.make();
    flush().await;
    assert!(lm.is_clock_tampered());
}

#[tokio::test(start_paused = true)]
async fn tolerates_small_skew_from_network_time() {
    let h = Harness::new();
    h.transport.set_network_time_ms(START_MS + 60_000);
    let lm = h.make();
    flush().await;
    assert!(!lm.is_clock_tampered());
}

#[tokio::test(start_paused = true)]
async fn trusts_network_time_over_a_stored_value_from_the_future() {
    let h = Harness::new();
    h.store().set("lastSeen", &encode_timestamp(START_MS + DAY));
    h.transport.set_network_time_ms(START_MS);
    let lm = h.make();
    flush().await;
    assert!(!lm.is_clock_tampered());
    // Stored value is reset to network time, so going offline later does not
    // false-flag against the bogus future value.
    assert_eq!(read_last_seen(&h), Some(START_MS));
}

#[tokio::test(start_paused = true)]
async fn falls_back_to_the_stored_value_when_the_date_header_is_missing() {
    let h = Harness::new();
    h.transport.set_network_time(Ok(None));
    h.store().set("lastSeen", &encode_timestamp(START_MS + DAY));
    let lm = h.make();
    flush().await;
    assert!(lm.is_clock_tampered());
}

// › getPortalUrl

#[tokio::test(start_paused = true)]
async fn links_to_the_product_s_portal() {
    let h = Harness::new();
    let lm = h.make_with(|o| o.product_id = "prod-1".into());
    assert_eq!(
        lm.portal_url(),
        "https://app.licensemanager.dev/portal/prod-1"
    );
}

#[tokio::test(start_paused = true)]
async fn encodes_the_product_id() {
    let h = Harness::new();
    let lm = h.make_with(|o| o.product_id = "a/b c".into());
    assert_eq!(
        lm.portal_url(),
        "https://app.licensemanager.dev/portal/a%2Fb%20c"
    );
}

// › dispose

#[tokio::test(start_paused = true)]
async fn dispose_stops_the_interval() {
    let h = Harness::new();
    let lm = h.make();
    flush().await;
    lm.dispose();
    lm.dispose(); // idempotent
    advance(2 * HOUR).await;
    assert_eq!(read_last_seen(&h), Some(START_MS));
}

#[tokio::test(start_paused = true)]
async fn dropping_the_last_handle_stops_background_work() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    lm.set_license_key(KEY).await.unwrap();
    lock(&h.current).take();
    drop(lm);
    advance(3 * WEEK).await;
    assert_eq!(h.validate_calls(), 1);
    assert_eq!(read_last_seen(&h), Some(START_MS));
}

// Tauri-specific

#[tokio::test(start_paused = true)]
async fn concurrent_refresh_calls_share_one_request() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    flush().await;
    let before = h.validate_calls();

    let (clock, keys) = (h.clock.clone(), h.keys);
    h.transport.on_validate(move |body| {
        let token = keys.sign_with(
            &Claims::new(body["fingerprint"].as_str().unwrap(), clock.now_ms()).to_json(),
        );
        async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            ok(&token)
        }
    });
    let (a, b) = tokio::join!(lm.refresh(), lm.refresh());
    assert_eq!((a, b), (LicenseState::Active, LicenseState::Active));
    assert_eq!(h.validate_calls(), before + 1);
}

#[tokio::test(start_paused = true)]
async fn an_interactive_caller_is_not_held_by_a_background_retry() {
    let h = Harness::new();
    h.seed(3 * WEEK, START_MS).await;
    // The startup background validation hangs; later requests succeed.
    let calls = Arc::new(AtomicUsize::new(0));
    let (clock, keys, counter) = (h.clock.clone(), h.keys, calls.clone());
    h.transport.on_validate(move |body| {
        let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
        let token = keys.sign_with(
            &Claims::new(body["fingerprint"].as_str().unwrap(), clock.now_ms()).to_json(),
        );
        async move {
            if first {
                futures::future::pending::<()>().await;
            }
            ok(&token)
        }
    });
    let lm = h.make();
    assert_eq!(lm.ready().await, LicenseState::Active);
    flush().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let started_at = h.now();
    assert_eq!(lm.refresh().await, LicenseState::Active);
    assert!(h.now() - started_at < 1000);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(lm.offline_state(), OfflineState::Online);
}

#[tokio::test(start_paused = true)]
async fn a_panicking_listener_does_not_stop_other_listeners_or_the_state_machine() {
    let h = Harness::new();
    h.serve_valid(3 * WEEK);
    let lm = h.make();
    lm.ready().await;
    let _panicking = lm.on_state_change(|_| panic!("listener bug"));
    let states = Arc::new(Mutex::new(Vec::new()));
    let recorded = states.clone();
    let subscription = lm.on_state_change(move |s| lock(&recorded).push(s));
    let mut receiver = lm.subscribe();
    assert_eq!(*receiver.borrow_and_update(), LicenseState::MissingKey);

    assert_eq!(lm.set_license_key(KEY).await, Ok(LicenseState::Active));
    assert_eq!(*lock(&states), vec![LicenseState::Active]);
    assert!(receiver.has_changed().unwrap());
    assert_eq!(*receiver.borrow_and_update(), LicenseState::Active);

    // Dropping the subscription removes the listener.
    drop(subscription);
    h.serve(|| fail(404, "not_found", no_extra()));
    assert_eq!(lm.refresh().await, LicenseState::InvalidKey);
    assert_eq!(*lock(&states), vec![LicenseState::Active]);
    assert!(format!("{_panicking:?}").contains("Subscription"));
}

#[tokio::test(start_paused = true)]
async fn refresh_without_a_key_returns_the_state() {
    let h = Harness::new();
    let lm = h.make();
    assert_eq!(lm.refresh().await, LicenseState::MissingKey);
    assert_eq!(h.validate_calls(), 0);
    assert!(format!("{lm:?}").contains("MissingKey"));
}

#[tokio::test(start_paused = true)]
async fn falls_back_to_files_without_a_keyring() {
    let h = Harness::new();
    let lm = h.make_with(|o| {
        o.testing.as_mut().unwrap().secret_backend = Some(None);
    });
    let fp = lm.fingerprint().await;
    let files_only = SecureStore::new(PRODUCT_ID, Some(vec![h.dir.path().to_owned()]), None);
    assert_eq!(files_only.get("installId").as_deref(), fp.split(':').nth(1));
    assert!(h
        .backend
        .get("dev.licensemanager.sdk", "x")
        .unwrap()
        .is_none());
}
