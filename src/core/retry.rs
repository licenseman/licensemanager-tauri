//! Port of `retry.ts`.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// Backoff and budget of one validation's retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetryPolicy {
    /// Delay before the first retry. Doubles after each failed attempt.
    pub initial_delay: Duration,
    /// Cap on a single delay.
    pub max_delay: Duration,
    /// Total time across all attempts and waits.
    pub budget: Duration,
}

/// Kept short when a caller is waiting on the result (startup without a valid
/// stored token, `set_license_key`, `refresh`).
pub(crate) const INTERACTIVE_RETRY: RetryPolicy = RetryPolicy {
    initial_delay: Duration::from_millis(500),
    max_delay: Duration::from_secs(5),
    budget: Duration::from_secs(30),
};

/// Scheduled and startup background validations.
pub(crate) const BACKGROUND_RETRY: RetryPolicy = RetryPolicy {
    initial_delay: Duration::from_secs(2),
    max_delay: Duration::from_secs(60),
    budget: Duration::from_secs(5 * 60),
};

/// No attempt is started with less than this left in the budget.
const MIN_ATTEMPT: Duration = Duration::from_secs(1);

/// Run `attempt` until it succeeds, a non-retryable error is returned or the
/// budget runs out, waiting with exponential backoff and jitter in between.
/// Each attempt receives the time left in the budget, to bound its timeout.
/// Cancelling `cancel` stops retrying; the last error is returned.
pub(crate) async fn with_retry<T, E, F, Fut>(
    mut attempt: F,
    is_retryable: impl Fn(&E) -> bool,
    policy: RetryPolicy,
    cancel: &CancellationToken,
) -> Result<T, E>
where
    F: FnMut(Duration) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let deadline = Instant::now() + policy.budget;
    let mut delay = policy.initial_delay;
    loop {
        let error = match attempt(deadline.saturating_duration_since(Instant::now())).await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        // Equal jitter: half fixed, half random, so retries keep spreading out.
        let wait = delay / 2 + delay.mul_f64(rand::random::<f64>()) / 2;
        if !is_retryable(&error)
            || cancel.is_cancelled()
            || Instant::now() + wait + MIN_ATTEMPT > deadline
        {
            return Err(error);
        }
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = cancel.cancelled() => return Err(error),
        }
        delay = (delay * 2).min(policy.max_delay);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[tokio::test(start_paused = true)]
    async fn returns_the_first_success() {
        let calls = AtomicU32::new(0);
        let result: Result<u32, ()> = with_retry(
            |_| async { Ok(calls.fetch_add(1, Ordering::SeqCst)) },
            |_| true,
            INTERACTIVE_RETRY,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(result, Ok(0));
    }

    #[tokio::test(start_paused = true)]
    async fn passes_the_remaining_budget_and_stays_within_it() {
        let started = Instant::now();
        let mut remaining = Vec::new();
        let result: Result<(), ()> = with_retry(
            |left| {
                remaining.push(left);
                async { Err(()) }
            },
            |_| true,
            INTERACTIVE_RETRY,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(result, Err(()));
        assert!(remaining.len() > 3);
        assert_eq!(remaining[0], INTERACTIVE_RETRY.budget);
        assert!(remaining.windows(2).all(|w| w[1] < w[0]));
        assert!(remaining.iter().all(|left| *left >= MIN_ATTEMPT));
        assert!(started.elapsed() <= INTERACTIVE_RETRY.budget);
    }

    #[tokio::test(start_paused = true)]
    async fn does_not_retry_a_final_error() {
        let calls = AtomicU32::new(0);
        let result: Result<(), u32> = with_retry(
            |_| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(1)
            },
            |_| false,
            INTERACTIVE_RETRY,
            &CancellationToken::new(),
        )
        .await;
        assert_eq!(result, Err(1));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_when_cancelled() {
        let cancel = CancellationToken::new();
        let calls = AtomicU32::new(0);
        let retry = with_retry(
            |_| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<(), _>(())
            },
            |_| true,
            BACKGROUND_RETRY,
            &cancel,
        );
        let cancel_soon = async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel.cancel();
        };
        let (result, ()) = tokio::join!(retry, cancel_soon);
        assert_eq!(result, Err(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Already cancelled: no retry at all.
        let result: Result<(), ()> =
            with_retry(|_| async { Err(()) }, |_| true, BACKGROUND_RETRY, &cancel).await;
        assert_eq!(result, Err(()));
    }
}
