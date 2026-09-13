//! Stopping cleanly on Ctrl-C, `SIGINT` or `SIGTERM` (`specs/09` §9).
//!
//! The one place this binary calls the platform directly, which is why the
//! crate is `deny(unsafe_code)` rather than `forbid`: each call below carries
//! the reason it is sound.
//!
//! A handler only sets a flag. The shutdown itself -- closing peers, saving the
//! pool, syncing the store -- happens on the main thread when it next looks,
//! because almost nothing is safe to do inside a signal handler.

#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

static STOP: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicBool = AtomicBool::new(false);

pub fn stop_requested() -> bool {
    STOP.load(Ordering::SeqCst)
}

/// The shutdown has finished. On Windows a console-close handler waits for
/// this, because the process is killed as soon as that handler returns.
pub fn finished() {
    FINISHED.store(true, Ordering::SeqCst);
}

#[cfg(unix)]
pub fn install() -> Result<(), String> {
    extern "C" fn on_signal(_: libc::c_int) {
        // An atomic store is async-signal-safe; nothing else happens here.
        STOP.store(true, Ordering::SeqCst);
    }

    for sig in [libc::SIGINT, libc::SIGTERM] {
        // SAFETY: `action` is zero-initialised, which is a valid `sigaction`,
        // and then given a handler with the signature `sa_handler` expects and
        // an emptied mask. Both pointers passed are valid for the call, and the
        // handler only touches an atomic.
        let r = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
            libc::sigemptyset(&mut action.sa_mask);
            action.sa_flags = libc::SA_RESTART;
            libc::sigaction(sig, &action, std::ptr::null_mut())
        };
        if r != 0 {
            return Err(format!("cannot install a handler for signal {sig}"));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn install() -> Result<(), String> {
    type Handler = unsafe extern "system" fn(u32) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<Handler>, add: i32) -> i32;
    }

    /// `CTRL_CLOSE_EVENT` and later: the console window closing, a log-off, a
    /// shutdown. Windows ends the process when the handler returns.
    const CTRL_CLOSE_EVENT: u32 = 2;

    unsafe extern "system" fn on_ctrl(kind: u32) -> i32 {
        STOP.store(true, Ordering::SeqCst);
        if kind >= CTRL_CLOSE_EVENT {
            // Hold the process open while the main thread shuts down, within
            // the few seconds Windows allows before it kills it anyway.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
            while !FINISHED.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        1
    }

    // SAFETY: `on_ctrl` has the `HandlerRoutine` signature the call documents,
    // and lives for the whole program. It only touches atomics and sleeps.
    let ok = unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    if ok == 0 {
        Err("cannot install a console control handler".into())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
pub fn install() -> Result<(), String> {
    Err("stopping on a signal is not supported on this platform".into())
}
