use std::time::{Duration, Instant};

use super::*;

#[tokio::test]
async fn rate_limiter_zero_rate_never_sleeps() {
    let mut rl = RateLimiter::new(0);
    let start = Instant::now();
    rl.acquire(1_000_000).await;
    // Should return almost instantly (< 10 ms).
    assert!(start.elapsed() < Duration::from_millis(10));
}

#[tokio::test]
async fn rate_limiter_large_bucket_does_not_sleep_for_small_request() {
    // 10 MiB/s bucket, request 1 KiB — tokens are available immediately.
    let mut rl = RateLimiter::new(10 * 1024 * 1024);
    let start = Instant::now();
    rl.acquire(1024).await;
    assert!(start.elapsed() < Duration::from_millis(10));
}
