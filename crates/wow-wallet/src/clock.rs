//! The time now, in seconds since 1970.
//!
//! Unlock times and the pool's timeouts are judged against it. `SystemTime`
//! answers wherever there is an operating system to ask. A browser build has
//! none that std can reach -- `SystemTime::now()` panics there -- so the
//! program supplies `Date.now()` ([`set_clock`]).

use std::sync::OnceLock;

static CLOCK: OnceLock<fn() -> u64> = OnceLock::new();

/// Supply the clock, in seconds since the Unix epoch, where std has none.
///
/// Only the first call takes effect. Elsewhere it replaces the system clock,
/// which is only ever wanted by a test.
pub fn set_clock(clock: fn() -> u64) -> bool {
    CLOCK.set(clock).is_ok()
}

/// Seconds since the Unix epoch: the supplied clock if there is one, and the
/// system's otherwise.
///
/// # Panics
///
/// In a browser build that has not called [`set_clock`], which is a mistake in
/// that build rather than something to guess around. A clock that silently
/// read 0 would call every time-locked output locked and never let a lost
/// transaction time out.
pub fn now() -> u64 {
    if let Some(clock) = CLOCK.get() {
        return clock();
    }
    system_now()
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn system_now() -> u64 {
    panic!(
        "no clock: a browser build must call wow_wallet::clock::set_clock before using the wallet"
    )
}
