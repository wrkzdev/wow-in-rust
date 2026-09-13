//! Terminal input.
//!
//! Reading a password without echoing it needs a platform call, so this is the
//! binary's only `unsafe`. Entropy lives in `wow_wallet::entropy`, because the
//! RPC server needs it too and it is not a terminal concern.

use std::io::{BufRead, Write};

pub use wow_wallet::entropy::seeded_rng;

/// Read a line from standard input, or `None` at end of file.
pub fn read_line(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
    }
}

/// Ask a yes/no question, defaulting to no.
pub fn confirm(prompt: &str) -> bool {
    match read_line(&format!("{prompt} (y/N): ")) {
        Some(s) => matches!(s.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
        None => false,
    }
}

/// Read a password without echoing it.
///
/// Falls back to an echoing read only if the terminal mode cannot be changed —
/// when input is a pipe, for instance, where there is nothing to echo to. It
/// says so when it does, rather than letting a user type a password onto a
/// visible line believing otherwise.
pub fn read_password(prompt: &str) -> Option<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();

    let guard = EchoOff::new();
    if guard.is_none() {
        println!("\n(warning: this terminal will echo what you type)");
        print!("{prompt}");
        let _ = std::io::stdout().flush();
    }

    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    drop(guard);
    println!();

    match read {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_string()),
    }
}

/// Turns terminal echo off for as long as it is alive.
struct EchoOff {
    #[cfg(unix)]
    saved: libc::termios,
    #[cfg(windows)]
    saved: u32,
}

#[cfg(unix)]
impl EchoOff {
    fn new() -> Option<EchoOff> {
        // SAFETY: `tcgetattr` writes a `termios` into the buffer we give it and
        // returns non-zero on failure, which covers stdin not being a terminal.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut saved) } != 0 {
            return None;
        }
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: `quiet` is a copy of a `termios` the kernel just produced,
        // with one flag cleared.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &quiet) } != 0 {
            return None;
        }
        Some(EchoOff { saved })
    }
}

#[cfg(unix)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: restoring exactly the `termios` that was read in `new`.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved);
        }
    }
}

#[cfg(windows)]
impl EchoOff {
    fn new() -> Option<EchoOff> {
        const STD_INPUT_HANDLE: u32 = -10i32 as u32;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;

        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
            fn GetConsoleMode(h: *mut core::ffi::c_void, mode: *mut u32) -> i32;
            fn SetConsoleMode(h: *mut core::ffi::c_void, mode: u32) -> i32;
        }

        // SAFETY: `GetStdHandle` returns a borrowed handle that does not need
        // closing; `GetConsoleMode` writes one `u32` and returns zero on
        // failure, which is what a redirected stdin gives.
        unsafe {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0u32;
            if GetConsoleMode(h, &mut mode) == 0 {
                return None;
            }
            if SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) == 0 {
                return None;
            }
            Some(EchoOff { saved: mode })
        }
    }
}

#[cfg(windows)]
impl Drop for EchoOff {
    fn drop(&mut self) {
        const STD_INPUT_HANDLE: u32 = -10i32 as u32;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(n_std_handle: u32) -> *mut core::ffi::c_void;
            fn SetConsoleMode(h: *mut core::ffi::c_void, mode: u32) -> i32;
        }
        // SAFETY: restoring exactly the mode that was read in `new`.
        unsafe {
            SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), self.saved);
        }
    }
}
