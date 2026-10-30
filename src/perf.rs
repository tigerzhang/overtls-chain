//! Counters and a periodic log line for finding a proxy that gets slower over time.
//!
//! Grep `perf ` in the log. A healthy process keeps `acquire_max_ms` small, `stalls` and
//! `pool_drops` at zero, and `sessions` near `pool_out`. Climbing sessions with a full pool,
//! or a large `acquire_max_ms`, means new requests are waiting on a stuck upstream.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

const REPORT_INTERVAL: Duration = Duration::from_secs(30);
const SLOW_ACQUIRE: Duration = Duration::from_millis(500);

struct AcquireStats {
    ok: AtomicU64,
    fail: AtomicU64,
    wait_us_total: AtomicU64,
    wait_us_max: AtomicU64,
}

static ACQUIRE: AcquireStats = AcquireStats {
    ok: AtomicU64::new(0),
    fail: AtomicU64::new(0),
    wait_us_total: AtomicU64::new(0),
    wait_us_max: AtomicU64::new(0),
};
static STALLS: AtomicU64 = AtomicU64::new(0);
static POOL_DROPS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub(crate) struct PoolSnapshot {
    pub idle: usize,
    pub outstanding: usize,
    pub max: usize,
    pub udp_sources: usize,
}

#[derive(Clone, Copy, Default)]
struct Totals {
    ok: u64,
    fail: u64,
    wait_us: u64,
    stalls: u64,
    pool_drops: u64,
}

pub(crate) fn note_acquire(wait: Duration, ok: bool) {
    let us = u64::try_from(wait.as_micros()).unwrap_or(u64::MAX);
    if ok {
        ACQUIRE.ok.fetch_add(1, Ordering::Relaxed);
    } else {
        ACQUIRE.fail.fetch_add(1, Ordering::Relaxed);
    }
    ACQUIRE.wait_us_total.fetch_add(us, Ordering::Relaxed);
    let mut current = ACQUIRE.wait_us_max.load(Ordering::Relaxed);
    while us > current {
        match ACQUIRE
            .wait_us_max
            .compare_exchange_weak(current, us, Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

pub(crate) fn note_stall() {
    STALLS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn note_pool_drop() {
    POOL_DROPS.fetch_add(1, Ordering::Relaxed);
}

fn load_totals() -> Totals {
    Totals {
        ok: ACQUIRE.ok.load(Ordering::Relaxed),
        fail: ACQUIRE.fail.load(Ordering::Relaxed),
        wait_us: ACQUIRE.wait_us_total.load(Ordering::Relaxed),
        stalls: STALLS.load(Ordering::Relaxed),
        pool_drops: POOL_DROPS.load(Ordering::Relaxed),
    }
}

fn saturating_delta(now: u64, prev: u64) -> u64 {
    now.saturating_sub(prev)
}

/// `idle`, `out`, and `max` are the client WebSocket pool. `udp_sources` is the client UDP
/// source set. Server processes pass `None` for the pool.
pub(crate) fn spawn_reporter<F, Fut>(role: &'static str, sessions: Arc<AtomicUsize>, mut pool_stats: F, quit: crate::CancellationToken)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Option<PoolSnapshot>> + Send + 'static,
{
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REPORT_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval` completes the first tick immediately. Skip it so the first line covers a full window.
        tick.tick().await;

        let mut prev = load_totals();
        loop {
            tokio::select! {
                _ = quit.cancelled() => break,
                _ = tick.tick() => {
                    let pool = pool_stats().await;
                    let now = load_totals();
                    let max_us = ACQUIRE.wait_us_max.swap(0, Ordering::Relaxed);
                    log_window(role, sessions.load(Ordering::Relaxed), pool, &prev, &now, max_us);
                    prev = now;
                }
            }
        }
    });
}

fn log_window(role: &str, sessions: usize, pool: Option<PoolSnapshot>, prev: &Totals, now: &Totals, max_us: u64) {
    let ok = saturating_delta(now.ok, prev.ok);
    let fail = saturating_delta(now.fail, prev.fail);
    let wait_us = saturating_delta(now.wait_us, prev.wait_us);
    let stalls = saturating_delta(now.stalls, prev.stalls);
    let pool_drops = saturating_delta(now.pool_drops, prev.pool_drops);
    let samples = ok + fail;
    let avg_ms = if samples == 0 { 0 } else { wait_us / samples / 1000 };
    let max_ms = max_us / 1000;
    let (fds, rss_kb) = resource_usage();

    let (idle, out, max, udp_sources) = match pool {
        Some(pool) => (
            pool.idle.to_string(),
            pool.outstanding.to_string(),
            pool.max.to_string(),
            pool.udp_sources.to_string(),
        ),
        None => ("-".to_string(), "-".to_string(), "-".to_string(), "-".to_string()),
    };
    let line = format!(
        "perf {role} sessions={sessions} pool_idle={idle} pool_out={out} pool_max={max} udp_sources={udp_sources} acquire_ok={ok} acquire_fail={fail} acquire_avg_ms={avg_ms} acquire_max_ms={max_ms} stalls={stalls} pool_drops={pool_drops} fds={} rss_kb={}",
        fmt_opt(fds),
        fmt_opt(rss_kb),
    );

    let saturated = pool.is_some_and(|pool| pool.max > 0 && pool.outstanding >= pool.max);
    let crowded = match pool {
        Some(pool) if pool.max > 0 => sessions >= pool.max.saturating_mul(2),
        None => sessions >= 200,
        Some(_) => false,
    };
    let sick =
        saturated || crowded || max_us >= u64::try_from(SLOW_ACQUIRE.as_micros()).unwrap_or(u64::MAX) || stalls > 0 || pool_drops > 0;
    if sick {
        log::warn!("{line}");
    } else {
        log::info!("{line}");
    }
}

fn fmt_opt(value: Option<impl std::fmt::Display>) -> String {
    value.map(|value| value.to_string()).unwrap_or_else(|| "-".to_string())
}

fn resource_usage() -> (Option<usize>, Option<u64>) {
    (open_fd_count(), rss_kb())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn open_fd_count() -> Option<usize> {
    // The directory fd itself is included in the listing.
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.count().saturating_sub(1))
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn open_fd_count() -> Option<usize> {
    std::fs::read_dir("/dev/fd").ok().map(|entries| entries.count().saturating_sub(1))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios")))]
fn open_fd_count() -> Option<usize> {
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("VmRSS:") else {
            continue;
        };
        return rest.split_whitespace().next()?.parse().ok();
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn rss_kb() -> Option<u64> {
    None
}
