//! Fakes for tests: scripted transport, fake wall clock, in-memory keyring and
//! signing keys. Not part of the semver API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::SigningKey;
use futures::future::BoxFuture;
use futures::FutureExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

use super::clock::{from_millis, Clock};
use super::store::{SecretBackend, SecretBackendError};
use super::transport::{HttpResponse, Transport, TransportError};

/// Product used by the tests.
pub const PRODUCT_ID: &str = "x7Kp2QaZ";
/// License key used by the tests.
pub const KEY: &str = "7KQ2M-X9ZPA-H4TRC-WN6EY-B3JDF";
/// 2026-01-01T00:00:00Z, the fake clock's start.
pub const START_MS: i64 = 1_767_225_600_000;

/// Locks a mutex, ignoring poisoning.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Wall clock = [`START_MS`] + elapsed Tokio time (paused in tests) + jumps.
pub struct FakeClock {
    base: tokio::time::Instant,
    offset_ms: AtomicI64,
}

impl FakeClock {
    /// A clock at [`START_MS`].
    pub fn new() -> Self {
        Self::at(START_MS)
    }

    /// A clock at `ms` since the epoch.
    pub fn at(ms: i64) -> Self {
        Self {
            base: tokio::time::Instant::now(),
            offset_ms: AtomicI64::new(ms),
        }
    }

    /// Moves the wall clock by `ms` without moving Tokio time (system sleep,
    /// manual clock change).
    pub fn jump(&self, ms: i64) {
        self.offset_ms.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        let elapsed = i64::try_from(self.base.elapsed().as_millis()).unwrap_or(i64::MAX);
        from_millis(self.offset_ms.load(Ordering::SeqCst) + elapsed)
    }
}

/// In-memory keyring, keyed `"{service}::{account}"`.
#[derive(Default)]
pub struct MemoryBackend {
    map: Mutex<HashMap<String, String>>,
}

impl MemoryBackend {
    /// A copy of every entry.
    pub fn entries(&self) -> HashMap<String, String> {
        lock(&self.map).clone()
    }
}

impl SecretBackend for MemoryBackend {
    fn get(&self, service: &str, account: &str) -> Result<Option<String>, SecretBackendError> {
        Ok(lock(&self.map)
            .get(&format!("{service}::{account}"))
            .cloned())
    }

    fn set(&self, service: &str, account: &str, value: &str) -> Result<(), SecretBackendError> {
        lock(&self.map).insert(format!("{service}::{account}"), value.to_owned());
        Ok(())
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), SecretBackendError> {
        lock(&self.map).remove(&format!("{service}::{account}"));
        Ok(())
    }
}

type ValidateHandler =
    Arc<dyn Fn(Value) -> BoxFuture<'static, Result<HttpResponse, TransportError>> + Send + Sync>;

/// Scripted server, with a log of validate-key requests.
pub struct FakeTransport {
    validate: Mutex<ValidateHandler>,
    network_time: Mutex<Result<Option<String>, TransportError>>,
    requests: Mutex<Vec<(String, Value)>>,
}

impl Default for FakeTransport {
    fn default() -> Self {
        Self {
            validate: Mutex::new(Arc::new(|_| offline())),
            network_time: Mutex::new(Err(TransportError("offline".into()))),
            requests: Mutex::new(Vec::new()),
        }
    }
}

fn offline() -> BoxFuture<'static, Result<HttpResponse, TransportError>> {
    futures::future::ready(Err(TransportError("offline".into()))).boxed()
}

impl FakeTransport {
    /// Offline server.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the validate-key handler; it receives the parsed request body.
    pub fn on_validate<F, Fut>(&self, handler: F)
    where
        F: Fn(Value) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<HttpResponse, TransportError>> + Send + 'static,
    {
        *lock(&self.validate) = Arc::new(move |body| handler(body).boxed());
    }

    /// Answer of the time server: its `Date` header (`Ok(None)`: no header),
    /// or unreachable.
    pub fn set_network_time(&self, date: Result<Option<String>, TransportError>) {
        *lock(&self.network_time) = date;
    }

    /// Serve `ms` since the epoch as the network time.
    pub fn set_network_time_ms(&self, ms: i64) {
        self.set_network_time(Ok(Some(httpdate::fmt_http_date(from_millis(ms)))));
    }

    /// Every validate-key request: URL and parsed body.
    pub fn requests(&self) -> Vec<(String, Value)> {
        lock(&self.requests).clone()
    }

    /// Number of validate-key requests.
    pub fn validate_calls(&self) -> usize {
        lock(&self.requests).len()
    }
}

impl Transport for FakeTransport {
    fn post_validate(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> BoxFuture<'static, Result<HttpResponse, TransportError>> {
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        lock(&self.requests).push((url.to_owned(), body.clone()));
        let handler = lock(&self.validate).clone();
        handler(body)
    }

    fn head_date(&self, _url: &str) -> BoxFuture<'static, Result<Option<String>, TransportError>> {
        futures::future::ready(lock(&self.network_time).clone()).boxed()
    }
}

/// `200 { license: token }`.
pub fn ok(token: &str) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse {
        status: 200,
        body: serde_json::to_vec(&json!({ "license": token })).unwrap(),
    })
}

/// `status { error: { code, message: "nope", ...extra } }`.
pub fn fail(status: u16, code: &str, extra: Value) -> Result<HttpResponse, TransportError> {
    let mut error = json!({ "code": code, "message": "nope" });
    if let (Some(error), Value::Object(extra)) = (error.as_object_mut(), extra) {
        error.extend(extra);
    }
    Ok(HttpResponse {
        status,
        body: serde_json::to_vec(&json!({ "error": error })).unwrap(),
    })
}

/// Ed25519 key pairs, generated once per test run.
pub struct Keys {
    signing: EncodingKey,
    other: EncodingKey,
    /// SPKI PEM of the signing key.
    pub public_pem: String,
}

impl Keys {
    /// The keys of this test run.
    pub fn get() -> &'static Keys {
        static KEYS: OnceLock<Keys> = OnceLock::new();
        KEYS.get_or_init(|| {
            let generate = || SigningKey::from_bytes(&rand::random::<[u8; 32]>());
            let encoding =
                |key: &SigningKey| EncodingKey::from_ed_der(key.to_pkcs8_der().unwrap().as_bytes());
            let signing = generate();
            Keys {
                public_pem: signing
                    .verifying_key()
                    .to_public_key_pem(LineEnding::LF)
                    .unwrap(),
                signing: encoding(&signing),
                other: encoding(&generate()),
            }
        })
    }

    /// Sign arbitrary claims with the product key.
    pub fn sign_with(&self, claims: &Value) -> String {
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), claims, &self.signing).unwrap()
    }

    /// Sign arbitrary claims with another key.
    pub fn sign_with_other_key(&self, claims: &Value) -> String {
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), claims, &self.other).unwrap()
    }
}

/// Claims of a license token, like the server issues them.
#[derive(Clone, Debug)]
pub struct Claims {
    /// `sub`.
    pub sub: String,
    /// `fp`.
    pub fp: String,
    /// `aud`.
    pub aud: String,
    /// `mv`.
    pub mv: Option<String>,
    /// `exp - iat`.
    pub lifetime: Duration,
    /// `iat`, in ms since the epoch.
    pub issued_at_ms: i64,
}

impl Claims {
    /// Claims for [`KEY`] on [`PRODUCT_ID`], valid 3 weeks from `issued_at_ms`.
    pub fn new(fp: &str, issued_at_ms: i64) -> Self {
        Self {
            sub: KEY.into(),
            fp: fp.into(),
            aud: PRODUCT_ID.into(),
            mv: None,
            lifetime: Duration::from_secs(3 * 7 * 86_400),
            issued_at_ms,
        }
    }

    /// As JSON, with `nbf` two hours before `iat`.
    pub fn to_json(&self) -> Value {
        let iat = self.issued_at_ms.div_euclid(1000);
        json!({
            "fp": self.fp,
            "mv": self.mv,
            "aud": self.aud,
            "sub": self.sub,
            "iat": iat,
            "nbf": iat - 2 * 60 * 60,
            "exp": iat + i64::try_from(self.lifetime.as_secs()).unwrap(),
        })
    }
}
