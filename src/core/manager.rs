//! Port of `license-manager.ts`.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, Weak};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use tokio::sync::watch;
use tokio::task::AbortHandle;
use tokio_util::sync::CancellationToken;

use super::api::{self, encode_uri_component, ValidateKeyRequest, DEFAULT_API_BASE_URL};
use super::clock::{from_millis, Clock, ClockGuard, SystemClock};
use super::environment;
use super::error::{ConfigError, LatestAllowedVersion, LicenseError, LicenseErrorCode};
use super::fingerprint::{resolve_machine_fingerprint, MachineFingerprint};
use super::options::LicenseManagerOptions;
use super::retry::{with_retry, RetryPolicy, BACKGROUND_RETRY, INTERACTIVE_RETRY};
use super::state::{locked_state, LicenseState, OfflineState};
use super::store::{default_backend, SecureStore};
use super::token::{compute_refresh_at, TokenPayload, TokenVerifier, ValidatedToken};
use super::transport::{ReqwestTransport, Transport};
use super::version::is_version_allowed;

const INSTALL_ID_KEY: &str = "installId";
const LICENSE_KEY_KEY: &str = "licenseKey";
const LICENSE_TOKEN_KEY: &str = "licenseToken";

const PORTAL_BASE_URL: &str = "https://app.licensemanager.dev/portal";

const MINUTE_MS: i64 = 60 * 1000;
/// Retry backoff between scheduled re-validations while the server is unreachable.
const RETRY_INITIAL_MS: i64 = 5 * MINUTE_MS;
const RETRY_MAX_MS: i64 = 60 * MINUTE_MS;
/// Longest single timer. Longer waits are re-armed in steps, re-checking the
/// wall clock each time, so system sleep or clock changes can't push a
/// validation far past its target date.
const MAX_TIMEOUT_MS: i64 = 60 * MINUTE_MS;

type Listener = Arc<dyn Fn(LicenseState) + Send + Sync>;
type SharedRequest = Shared<BoxFuture<'static, Result<ValidatedToken, LicenseError>>>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The license state machine: one per app, created by the plugin and reached
/// with [`LicensemanagerExt::license`](crate::LicensemanagerExt::license).
///
/// On creation it validates the stored license key (in the background when the
/// stored token is valid) and begins a periodic clock-tamper check. The plugin
/// disposes it when the app exits.
#[derive(Clone)]
pub struct LicenseManager {
    inner: Arc<Inner>,
}

struct Inner {
    product_id: String,
    fingerprint_option: Option<MachineFingerprint>,
    version: String,
    machine_name: String,
    platform: String,
    min_offline_ms: i64,
    api_base_url: String,
    store: SecureStore,
    verifier: TokenVerifier,
    clock_guard: ClockGuard,
    clock: Arc<dyn Clock>,
    transport: Arc<dyn Transport>,
    runtime: tokio::runtime::Handle,
    /// Cancelled on dispose, to stop pending retries and timers.
    cancel: CancellationToken,
    fingerprint: tokio::sync::OnceCell<String>,
    state_tx: watch::Sender<LicenseState>,
    listeners: Mutex<Vec<(u64, Listener)>>,
    next_id: AtomicU64,
    ready: OnceLock<Shared<BoxFuture<'static, LicenseState>>>,
    m: Mutex<Mutable>,
}

struct Mutable {
    key: Option<String>,
    state: LicenseState,
    /// Payload of the current valid token.
    token: Option<TokenPayload>,
    /// False once a request failed to reach a definitive server answer.
    online: bool,
    latest_allowed_version: LatestAllowedVersion,
    retry_delay_ms: i64,
    timer: Option<(u64, AbortHandle)>,
    inflight: Option<Inflight>,
    disposed: bool,
}

struct Inflight {
    key: String,
    policy: RetryPolicy,
    id: u64,
    request: SharedRequest,
}

/// What the stored token allows without asking the server.
enum Stored {
    Active(TokenPayload),
    Refused(LicenseState),
}

impl Stored {
    fn state(&self) -> LicenseState {
        match self {
            Self::Active(_) => LicenseState::Active,
            Self::Refused(state) => *state,
        }
    }
}

/// Keeps a listener registered by
/// [`LicenseManager::on_state_change`] until dropped.
#[must_use = "the listener is removed when the Subscription is dropped"]
pub struct Subscription {
    id: u64,
    inner: Weak<Inner>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.upgrade() {
            lock(&inner.listeners).retain(|(id, _)| *id != self.id);
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .finish()
    }
}

impl LicenseManager {
    /// Created by the plugin's setup. Runs on the given Tokio handle. Reads
    /// the stored key synchronously, then spawns startup validation and the
    /// clock guard.
    pub(crate) fn new(options: LicenseManagerOptions) -> Result<Self, ConfigError> {
        if options.product_id.is_empty() {
            return Err(ConfigError::MissingProductId);
        }
        if options.public_key.is_empty() {
            return Err(ConfigError::MissingPublicKey);
        }
        let hooks = options.testing.unwrap_or_default();
        let clock = hooks.clock.unwrap_or_else(|| Arc::new(SystemClock));
        let transport = hooks
            .transport
            .unwrap_or_else(|| Arc::new(ReqwestTransport::new()));
        let backend = hooks.secret_backend.unwrap_or_else(default_backend);

        let verifier = TokenVerifier::new(&options.public_key, &options.product_id, clock.clone())?;
        let store = SecureStore::new(&options.product_id, options.storage_dirs, backend);
        let runtime = options.runtime;
        let clock_guard =
            ClockGuard::new(store.clone(), clock.clone(), transport.clone(), &runtime);
        let key = store.get(LICENSE_KEY_KEY);
        let (state_tx, _) = watch::channel(LicenseState::Loading);

        let inner = Arc::new(Inner {
            fingerprint_option: options.fingerprint,
            version: options.version,
            machine_name: options.machine_name.unwrap_or_else(environment::hostname),
            platform: options
                .platform
                .unwrap_or_else(environment::default_platform),
            min_offline_ms: i64::try_from(options.min_offline_duration.as_millis())
                .unwrap_or(i64::MAX),
            api_base_url: options
                .api_base_url
                .as_deref()
                .unwrap_or(DEFAULT_API_BASE_URL)
                .trim_end_matches('/')
                .to_owned(),
            product_id: options.product_id,
            store,
            verifier,
            clock_guard,
            clock,
            transport,
            runtime,
            cancel: CancellationToken::new(),
            fingerprint: tokio::sync::OnceCell::new(),
            state_tx,
            listeners: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(0),
            ready: OnceLock::new(),
            m: Mutex::new(Mutable {
                key,
                state: LicenseState::Loading,
                token: None,
                online: true,
                latest_allowed_version: LatestAllowedVersion::NotApplicable,
                retry_delay_ms: RETRY_INITIAL_MS,
                timer: None,
                inflight: None,
                disposed: false,
            }),
        });
        let ready = {
            let inner = inner.clone();
            async move { inner.init().await }.boxed().shared()
        };
        let _ = inner.ready.set(ready.clone());
        inner.runtime.spawn(ready);
        Ok(Self { inner })
    }

    /// Stable per-machine, per-install, per-product fingerprint:
    /// `{base64 sha256 of the machine id}:{random install id}:{product id}`.
    /// Cached after the first call.
    pub async fn fingerprint(&self) -> String {
        self.inner.fingerprint().await
    }

    /// The current state.
    pub fn state(&self) -> LicenseState {
        lock(&self.inner.m).state
    }

    /// Resolves with the state once startup validation has completed, or as
    /// soon as the stored token is found valid; the online validation then
    /// continues in the background. Every caller gets the same state.
    pub async fn ready(&self) -> LicenseState {
        self.inner.ready().await
    }

    /// Call `listener` on every state change, until the returned
    /// [`Subscription`] is dropped. A panicking listener is ignored.
    pub fn on_state_change<F>(&self, listener: F) -> Subscription
    where
        F: Fn(LicenseState) + Send + Sync + 'static,
    {
        let id = self.inner.next_id.fetch_add(1, Ordering::SeqCst);
        lock(&self.inner.listeners).push((id, Arc::new(listener)));
        Subscription {
            id,
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// A receiver of the current state and every change.
    pub fn subscribe(&self) -> watch::Receiver<LicenseState> {
        self.inner.state_tx.subscribe()
    }

    /// Validate a key the user typed and, on success, store it and activate.
    /// The key is trimmed but its case is kept.
    ///
    /// Fails when validation fails for any reason, including the server being
    /// unreachable. Nothing is stored and the current state is left untouched.
    pub async fn set_license_key(&self, input: &str) -> Result<LicenseState, LicenseError> {
        let key = input.trim();
        if key.is_empty() {
            return Err(LicenseError::new(
                LicenseErrorCode::ValidationError,
                "The license key is empty",
            ));
        }
        let validated = self.inner.request(key, INTERACTIVE_RETRY).await?;
        self.inner
            .store
            .set_async(LICENSE_KEY_KEY, key.to_owned())
            .await;
        lock(&self.inner.m).key = Some(key.to_owned());
        self.inner.activate(validated).await;
        Ok(self.state())
    }

    /// Re-validate the stored key now, e.g. after the customer renewed an
    /// expired license. Never fails.
    pub async fn refresh(&self) -> LicenseState {
        self.inner.ready().await;
        let key = lock(&self.inner.m).key.clone();
        match key {
            Some(key) => self.inner.revalidate(key, INTERACTIVE_RETRY).await,
            None => self.state(),
        }
    }

    /// The stored license key, or `None` before one was set.
    pub fn license_key(&self) -> Option<String> {
        lock(&self.inner.m).key.clone()
    }

    /// Link to the customer portal for this product.
    pub fn portal_url(&self) -> String {
        format!(
            "{PORTAL_BASE_URL}/{}",
            encode_uri_component(&self.inner.product_id)
        )
    }

    /// In state `VERSION_NOT_ALLOWED`: the latest version the license allows.
    /// [`NotApplicable`](LatestAllowedVersion::NotApplicable) otherwise, and
    /// when the refusal came from the stored token while offline (it only
    /// knows the max version, not the latest release).
    pub fn latest_allowed_version(&self) -> LatestAllowedVersion {
        lock(&self.inner.m).latest_allowed_version.clone()
    }

    /// Whether the last validation reached the server. When offline, the app
    /// keeps running on the stored token until `valid_until`.
    pub fn offline_state(&self) -> OfflineState {
        let m = lock(&self.inner.m);
        if m.online {
            return OfflineState::Online;
        }
        match &m.token {
            Some(token) if m.state == LicenseState::Active => {
                let expires_at = token.exp.saturating_mul(1000);
                let remaining = (expires_at - self.inner.clock.now_ms()).max(0);
                OfflineState::Offline {
                    valid_until: Some(from_millis(expires_at)),
                    remaining: Duration::from_millis(remaining.unsigned_abs()),
                }
            }
            _ => OfflineState::Offline {
                valid_until: None,
                remaining: Duration::ZERO,
            },
        }
    }

    /// True once a backwards clock jump has been observed.
    pub fn is_clock_tampered(&self) -> bool {
        self.inner.clock_guard.is_tampered()
    }

    /// Stop the periodic clock check, retries and scheduled re-validations.
    /// Idempotent. The plugin calls it when the app exits.
    pub fn dispose(&self) {
        self.inner.dispose();
    }

    #[cfg(test)]
    pub(crate) fn is_disposed(&self) -> bool {
        lock(&self.inner.m).disposed
    }
}

impl std::fmt::Debug for LicenseManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LicenseManager")
            .field("product_id", &self.inner.product_id)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.clock_guard.dispose();
    }
}

impl Inner {
    async fn ready(&self) -> LicenseState {
        match self.ready.get() {
            Some(ready) => ready.clone().await,
            None => lock(&self.m).state,
        }
    }

    fn state(&self) -> LicenseState {
        lock(&self.m).state
    }

    fn key_is(&self, key: &str) -> bool {
        lock(&self.m).key.as_deref() == Some(key)
    }

    fn dispose(&self) {
        let mut m = lock(&self.m);
        m.disposed = true;
        self.cancel.cancel();
        clear_timer(&mut m);
        drop(m);
        self.clock_guard.dispose();
    }

    async fn fingerprint(&self) -> String {
        self.fingerprint
            .get_or_init(|| async {
                let machine = resolve_machine_fingerprint(self.fingerprint_option.as_ref()).await;
                let install_id = self.get_or_create_install_id().await;
                format!("{machine}:{install_id}:{}", self.product_id)
            })
            .await
            .clone()
    }

    async fn get_or_create_install_id(&self) -> String {
        if let Some(existing) = self
            .store
            .get_async(INSTALL_ID_KEY)
            .await
            .filter(|v| !v.is_empty())
        {
            return existing;
        }
        let created = STANDARD.encode(rand::random::<[u8; 32]>());
        self.store.set_async(INSTALL_ID_KEY, created.clone()).await;
        created
    }

    async fn init(self: Arc<Self>) -> LicenseState {
        let Some(key) = lock(&self.m).key.clone() else {
            self.set_state(LicenseState::MissingKey);
            return self.state();
        };
        let stored = self.check_stored_token(&key).await;
        if !self.key_is(&key) {
            return self.state();
        }
        let Stored::Active(payload) = stored else {
            return self.revalidate(key, INTERACTIVE_RETRY).await;
        };
        lock(&self.m).token = Some(payload);
        self.set_state(LicenseState::Active);
        // Confirm with the server without holding up startup.
        let this = self.clone();
        self.runtime.spawn(async move {
            this.revalidate(key, BACKGROUND_RETRY).await;
        });
        self.state()
    }

    /// Validate online; on an error that says nothing about the license, fall
    /// back to the stored token. Never fails.
    async fn revalidate(self: &Arc<Self>, key: String, policy: RetryPolicy) -> LicenseState {
        clear_timer(&mut lock(&self.m));
        match self.request(&key, policy).await {
            Ok(validated) => {
                if !self.key_is(&key) {
                    return self.state();
                }
                self.activate(validated).await;
            }
            Err(error) => {
                if !self.key_is(&key) {
                    return self.state();
                }
                if error.is_locking() {
                    self.lock_license(error.code, error.latest_allowed_version)
                        .await;
                } else {
                    self.validate_offline(&key).await;
                }
            }
        }
        self.state()
    }

    /// Store a freshly validated token and schedule its refresh.
    async fn activate(self: &Arc<Self>, ValidatedToken { token, payload }: ValidatedToken) {
        self.store.set_async(LICENSE_TOKEN_KEY, token).await;
        {
            let mut m = lock(&self.m);
            m.token = Some(payload);
            m.online = true;
            m.retry_delay_ms = RETRY_INITIAL_MS;
            m.latest_allowed_version = LatestAllowedVersion::NotApplicable;
        }
        self.set_state(LicenseState::Active);
        self.schedule_next();
    }

    /// The server refused the license: drop the token and stop refreshing.
    async fn lock_license(
        &self,
        code: LicenseErrorCode,
        latest_allowed_version: LatestAllowedVersion,
    ) {
        self.store.delete_async(LICENSE_TOKEN_KEY).await;
        let Some(state) = locked_state(code) else {
            return;
        };
        {
            let mut m = lock(&self.m);
            m.token = None;
            m.online = true;
            m.latest_allowed_version = match (code, latest_allowed_version) {
                (LicenseErrorCode::VersionNotAllowed, LatestAllowedVersion::NotApplicable) => {
                    LatestAllowedVersion::NoneAllowed
                }
                (LicenseErrorCode::VersionNotAllowed, latest) => latest,
                _ => LatestAllowedVersion::NotApplicable,
            };
        }
        self.set_state(state);
    }

    /// Server unreachable: trust the stored token, unless the clock was rolled
    /// back or the token's max version excludes this app version.
    async fn validate_offline(self: &Arc<Self>, key: &str) {
        lock(&self.m).online = false;
        let stored = self.check_stored_token(key).await;
        if !self.key_is(key) {
            return;
        }
        let state = stored.state();
        {
            let mut m = lock(&self.m);
            m.token = match stored {
                Stored::Active(payload) => Some(payload),
                Stored::Refused(_) => None,
            };
            if state == LicenseState::VersionNotAllowed {
                m.latest_allowed_version = LatestAllowedVersion::NotApplicable;
            }
        }
        self.set_state(state);
        self.schedule_next();
        let mut m = lock(&self.m);
        m.retry_delay_ms = (m.retry_delay_ms * 2).min(RETRY_MAX_MS);
    }

    async fn check_stored_token(&self, key: &str) -> Stored {
        self.clock_guard.ready().await;
        if self.clock_guard.is_tampered() {
            return Stored::Refused(LicenseState::ClockTampered);
        }
        let token = self
            .store
            .get_async(LICENSE_TOKEN_KEY)
            .await
            .filter(|t| !t.is_empty());
        let payload = match token {
            Some(token) => {
                let fingerprint = self.fingerprint().await;
                self.verifier.verify(&token, key, &fingerprint).ok()
            }
            None => None,
        };
        let Some(payload) = payload else {
            return Stored::Refused(LicenseState::OfflineExpired);
        };
        // Keep the token: it works again if the app is downgraded.
        if !is_version_allowed(&self.version, payload.mv.as_deref()) {
            return Stored::Refused(LicenseState::VersionNotAllowed);
        }
        Stored::Active(payload)
    }

    /// Arm the next re-validation: at the refresh point when online; when
    /// offline, retry with backoff but never later than the token expiry.
    fn schedule_next(self: &Arc<Self>) {
        let mut m = lock(&self.m);
        clear_timer(&mut m);
        let Some(key) = m.key.clone().filter(|_| !m.disposed) else {
            return;
        };
        let now = self.clock.now_ms();
        let at = match (&m.token, m.state) {
            (Some(token), LicenseState::Active) => {
                let mut at = compute_refresh_at(token, self.min_offline_ms);
                if !m.online {
                    at = at.max(now + m.retry_delay_ms);
                }
                at.min(token.exp.saturating_mul(1000))
            }
            (_, LicenseState::OfflineExpired | LicenseState::ClockTampered) => {
                now + m.retry_delay_ms
            }
            // Refused by the stored token: the server has the final word.
            (_, LicenseState::VersionNotAllowed) if !m.online => now + m.retry_delay_ms,
            _ => return,
        };
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        // The first step is measured now, not when the task first runs.
        let first_step = tokio::time::Instant::now() + step_until(at, now);
        let handle = self
            .runtime
            .spawn(arm(Arc::downgrade(self), id, key, at, first_step));
        m.timer = Some((id, handle.abort_handle()));
    }

    /// Call validate-key, sharing one in-flight request per key and policy,
    /// so a caller is never held up by a longer background retry budget.
    fn request(self: &Arc<Self>, key: &str, policy: RetryPolicy) -> SharedRequest {
        let mut m = lock(&self.m);
        if let Some(inflight) = &m.inflight {
            if inflight.key == key && inflight.policy == policy {
                return inflight.request.clone();
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let request = {
            let this = self.clone();
            let key = key.to_owned();
            async move {
                let result = this.fetch_token(&key, policy).await;
                let mut m = lock(&this.m);
                if m.inflight.as_ref().is_some_and(|i| i.id == id) {
                    m.inflight = None;
                }
                result
            }
            .boxed()
            .shared()
        };
        m.inflight = Some(Inflight {
            key: key.to_owned(),
            policy,
            id,
            request: request.clone(),
        });
        // Runs to completion even if every caller goes away, like a promise.
        self.runtime.spawn(request.clone());
        request
    }

    async fn fetch_token(
        &self,
        key: &str,
        policy: RetryPolicy,
    ) -> Result<ValidatedToken, LicenseError> {
        let fingerprint = self.fingerprint().await;
        let request = ValidateKeyRequest {
            key: key.to_owned(),
            fingerprint: fingerprint.clone(),
            version: self.version.clone(),
            name: self.machine_name.clone(),
            platform: self.platform.clone(),
        };
        let (token, status) = with_retry(
            |remaining| {
                api::post_validate_key(
                    &*self.transport,
                    &self.api_base_url,
                    &self.product_id,
                    &request,
                    remaining,
                )
            },
            api::is_transient,
            policy,
            &self.cancel,
        )
        .await?;
        match self.verifier.verify(&token, key, &fingerprint) {
            Ok(payload) => Ok(ValidatedToken { token, payload }),
            Err(_) => Err(LicenseError::new(
                LicenseErrorCode::InvalidResponse,
                "The license token failed verification",
            )
            .with_status(status)),
        }
    }

    fn set_state(&self, state: LicenseState) {
        {
            let mut m = lock(&self.m);
            if m.state == state {
                return;
            }
            m.state = state;
        }
        self.state_tx.send_replace(state);
        let listeners: Vec<Listener> = lock(&self.listeners)
            .iter()
            .map(|(_, listener)| listener.clone())
            .collect();
        for listener in listeners {
            // A listener must not break the state machine.
            let _ = catch_unwind(AssertUnwindSafe(|| listener(state)));
        }
    }
}

/// Time to sleep towards `at`, capped at [`MAX_TIMEOUT_MS`].
fn step_until(at: i64, now: i64) -> Duration {
    Duration::from_millis((at - now).clamp(0, MAX_TIMEOUT_MS).unsigned_abs())
}

fn clear_timer(m: &mut Mutable) {
    if let Some((_, timer)) = m.timer.take() {
        timer.abort();
    }
}

/// Wait until `at` (ms since the epoch) in steps of at most
/// [`MAX_TIMEOUT_MS`], re-reading the wall clock at each step, then
/// re-validate with the background policy.
async fn arm(inner: Weak<Inner>, id: u64, key: String, at: i64, first_step: tokio::time::Instant) {
    let (clock, cancel) = match inner.upgrade() {
        Some(inner) => (inner.clock.clone(), inner.cancel.clone()),
        None => return,
    };
    let mut step = first_step;
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(step) => {}
            () = cancel.cancelled() => return,
        }
        let now = clock.now_ms();
        if now >= at {
            break;
        }
        step = tokio::time::Instant::now() + step_until(at, now);
    }
    let Some(inner) = inner.upgrade() else {
        return;
    };
    {
        let mut m = lock(&inner.m);
        if m.timer.as_ref().map(|(timer_id, _)| *timer_id) != Some(id) {
            return;
        }
        // Fired: a later clear must not abort the validation below.
        m.timer = None;
    }
    inner.revalidate(key, BACKGROUND_RETRY).await;
}

#[cfg(test)]
mod tests;
