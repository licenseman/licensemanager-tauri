//! Port of `clock.ts`, plus the wall [`Clock`] the SDK reads time from.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use base64::Engine;
use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use tokio_util::sync::CancellationToken;

use super::store::SecureStore;
use super::transport::Transport;

/// How often the clock-tamper check runs, after the initial run.
const CLOCK_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Server whose HTTP `Date` header is the trusted source of current time.
const TIME_URL: &str = "https://google.com";
const TIME_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// How far the system clock may drift from network time, in either direction,
/// before it counts as tampering. Covers the `Date` header's 1s precision and
/// request latency.
const CLOCK_SKEW_TOLERANCE_MS: i64 = 5 * 60 * 1000;

const LAST_SEEN_KEY: &str = "lastSeen";

/// Source of wall-clock time (`Date.now()`).
pub trait Clock: Send + Sync + 'static {
    /// Current wall-clock time.
    fn now(&self) -> SystemTime;

    /// Current time in milliseconds since the Unix epoch.
    fn now_ms(&self) -> i64 {
        to_millis(self.now())
    }
}

/// The system clock.
pub(crate) struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Milliseconds since the Unix epoch (negative before it).
pub(crate) fn to_millis(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
    }
}

/// Inverse of [`to_millis`].
pub(crate) fn from_millis(ms: i64) -> SystemTime {
    if ms >= 0 {
        UNIX_EPOCH + Duration::from_millis(ms.unsigned_abs())
    } else {
        UNIX_EPOCH - Duration::from_millis(ms.unsigned_abs())
    }
}

/// Detects system clock rollback. Checks once on construction and then
/// hourly; call [`dispose`](Self::dispose) to stop.
pub(crate) struct ClockGuard {
    inner: Arc<GuardInner>,
    ready: Shared<BoxFuture<'static, ()>>,
    cancel: CancellationToken,
}

struct GuardInner {
    store: SecureStore,
    clock: Arc<dyn Clock>,
    transport: Arc<dyn Transport>,
    tampered: AtomicBool,
}

impl ClockGuard {
    pub(crate) fn new(
        store: SecureStore,
        clock: Arc<dyn Clock>,
        transport: Arc<dyn Transport>,
        runtime: &tokio::runtime::Handle,
    ) -> Self {
        let inner = Arc::new(GuardInner {
            store,
            clock,
            transport,
            tampered: AtomicBool::new(false),
        });
        let ready = {
            let inner = inner.clone();
            async move { inner.check().await }.boxed().shared()
        };
        runtime.spawn(ready.clone());

        let cancel = CancellationToken::new();
        {
            let inner = inner.clone();
            let cancel = cancel.clone();
            runtime.spawn(async move {
                loop {
                    tokio::select! {
                        () = tokio::time::sleep(CLOCK_CHECK_INTERVAL) => inner.check().await,
                        () = cancel.cancelled() => break,
                    }
                }
            });
        }
        Self {
            inner,
            ready,
            cancel,
        }
    }

    /// Resolves once the initial check has completed.
    pub(crate) async fn ready(&self) {
        self.ready.clone().await;
    }

    /// True once a backwards clock jump has been observed.
    pub(crate) fn is_tampered(&self) -> bool {
        self.inner.tampered.load(Ordering::SeqCst)
    }

    /// Stop the periodic check.
    pub(crate) fn dispose(&self) {
        self.cancel.cancel();
    }
}

impl GuardInner {
    /// Network time is trusted above all: when reachable, the system clock is
    /// compared against it and the stored last-seen time is reset to it. Only
    /// when offline does the check fall back to the stored maximum, where a
    /// time earlier than it signals clock tampering. Never fails.
    async fn check(&self) {
        if let Some(network_now) = self.network_time().await {
            let skew = (self.clock.now_ms() - network_now).abs();
            self.tampered
                .store(skew > CLOCK_SKEW_TOLERANCE_MS, Ordering::SeqCst);
            self.store
                .set_async(LAST_SEEN_KEY, encode_timestamp(network_now))
                .await;
            return;
        }

        let now = self.clock.now_ms();
        let previous = decode_timestamp(self.store.get_async(LAST_SEEN_KEY).await.as_deref());
        if previous.is_some_and(|previous| now < previous) {
            self.tampered.store(true, Ordering::SeqCst);
            return;
        }
        if previous.is_none_or(|previous| now > previous) {
            self.store
                .set_async(LAST_SEEN_KEY, encode_timestamp(now))
                .await;
        }
    }

    /// Current time according to [`TIME_URL`]'s `Date` header, or `None` when
    /// offline or the header is missing/unparsable.
    async fn network_time(&self) -> Option<i64> {
        let header = tokio::time::timeout(TIME_REQUEST_TIMEOUT, self.transport.head_date(TIME_URL))
            .await
            .ok()?
            .ok()??;
        httpdate::parse_http_date(header.trim()).ok().map(to_millis)
    }
}

/// Store the int as base64 to lightly obscure it.
pub(crate) fn encode_timestamp(ms: i64) -> String {
    STANDARD.encode(ms.to_string())
}

pub(crate) fn decode_timestamp(value: Option<&str>) -> Option<i64> {
    let value = value.filter(|v| !v.is_empty())?;
    let bytes = STANDARD
        .decode(value)
        .or_else(|_| STANDARD_NO_PAD.decode(value.trim_end_matches('=')))
        .ok()?;
    parse_int(&String::from_utf8_lossy(&bytes))
}

/// `Number.parseInt(s, 10)`: optional whitespace and sign, then leading digits.
fn parse_int(s: &str) -> Option<i64> {
    let s = s.trim_start();
    let (negative, digits) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    let value: i64 = digits[..end].parse().ok()?;
    Some(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_last_seen_encoding() {
        assert_eq!(encode_timestamp(1_767_225_600_000), "MTc2NzIyNTYwMDAwMA==");
        assert_eq!(
            decode_timestamp(Some("MTc2NzIyNTYwMDAwMA==")),
            Some(1_767_225_600_000)
        );
    }

    #[test]
    fn decodes_like_parse_int() {
        assert_eq!(decode_timestamp(None), None);
        assert_eq!(decode_timestamp(Some("")), None);
        assert_eq!(decode_timestamp(Some(&STANDARD.encode("12abc"))), Some(12));
        assert_eq!(decode_timestamp(Some(&STANDARD.encode(" -5"))), Some(-5));
        assert_eq!(decode_timestamp(Some(&STANDARD.encode("+7"))), Some(7));
        assert_eq!(decode_timestamp(Some(&STANDARD.encode("abc"))), None);
        assert_eq!(decode_timestamp(Some("MTIz")), Some(123));
        assert_eq!(decode_timestamp(Some("%%%")), None);
    }

    #[test]
    fn millis_round_trip() {
        for ms in [0, 1, 1_767_225_600_000, -1_000] {
            assert_eq!(to_millis(from_millis(ms)), ms);
        }
        assert!(SystemClock.now_ms() > 1_767_225_600_000 - 365 * 86_400_000);
    }
}
