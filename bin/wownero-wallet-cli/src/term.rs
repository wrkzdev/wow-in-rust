//! Terminal input.
//!
//! Reading a password without echoing it needs a platform call, so this is the
//! binary's only `unsafe`. Entropy lives in `wow_wallet::entropy`, because the
//! RPC server needs it too and it is not a terminal concern.
//!
//! What is typed at a terminal goes through a line editor: left and right move
//! along the line, up and down through the commands typed before. The history
//! is kept in memory only, so no command is written to disk. Input from a pipe
//! or a file is read as it always was.

use std::io::{BufRead, IsTerminal, Write};
use std::sync::{Mutex, MutexGuard, OnceLock};

use rustyline::DefaultEditor;
use wow_crypto::Zeroizing;

pub use wow_wallet::entropy::seeded_rng;

/// Whether someone is typing at standard input, rather than a pipe or a file
/// feeding it.
pub fn interactive() -> bool {
    std::io::stdin().is_terminal()
}

/// The line editor, when standard input is a terminal it can drive.
fn editor() -> MutexGuard<'static, Option<DefaultEditor>> {
    static EDITOR: OnceLock<Mutex<Option<DefaultEditor>>> = OnceLock::new();
    EDITOR
        .get_or_init(|| {
            Mutex::new(if interactive() {
                DefaultEditor::new().ok()
            } else {
                None
            })
        })
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// Read a line from standard input, or `None` at end of file.
///
/// At a terminal Ctrl-C ends input as end of file does: the editor holds the
/// terminal in raw mode, so it arrives as a key rather than a signal.
pub fn read_line(prompt: &str) -> Option<String> {
    read(prompt, false)
}

/// Read a command: a line that up and down bring back at later prompts.
pub fn read_command(prompt: &str) -> Option<String> {
    read(prompt, true)
}

fn read(prompt: &str, remember: bool) -> Option<String> {
    if let Some(editor) = editor().as_mut() {
        let line = editor.readline(prompt).ok()?;
        if remember && !line.trim().is_empty() {
            let _ = editor.add_history_entry(line.as_str());
        }
        return Some(line);
    }
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
/// when input is a pipe, for instance, where there is nothing to echo to. When
/// there *is* a terminal that will show the input, it says so, rather than
/// letting a user type a password onto a visible line believing otherwise.
///
/// Returned in a [`Zeroizing`], as `contrib/epee/include/wipeable_string.h`
/// holds one: the line the password was read into is wiped as well, so what
/// was typed is not left in the process's memory to be read out of a core
/// dump or the next allocation.
pub fn read_password(prompt: &str) -> Option<Zeroizing<String>> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();

    let guard = EchoOff::new();
    if guard.is_none() && interactive() {
        println!("\n(warning: this terminal will echo what you type)");
        print!("{prompt}");
        let _ = std::io::stdout().flush();
    }

    let mut line = Zeroizing::new(String::new());
    let read = std::io::stdin().lock().read_line(&mut line);
    drop(guard);
    println!();

    match read {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(Zeroizing::new(
            line.trim_end_matches(['\r', '\n']).to_string(),
        )),
    }
}

/// Ask for a new password twice, until the two match.
///
/// Nobody can see what they typed, and a mistyped password on a new wallet
/// locks its owner out of it. A pipe is asked once: a script has no typo to
/// catch, and should not have to send the same line twice.
pub fn read_new_password() -> Option<Zeroizing<String>> {
    const PROMPT: &str = "Enter a new password for the wallet: ";
    if !interactive() {
        return read_password(PROMPT);
    }
    loop {
        let first = read_password(PROMPT)?;
        let second = read_password("Confirm password: ")?;
        if *first == *second {
            return Some(first);
        }
        println!("Passwords do not match. Please try again.");
    }
}

/// Ask until `parse` accepts the answer.
///
/// `parse` gets the trimmed answer and returns `Ok(Some(_))` to accept it,
/// `Ok(None)` to cancel, or `Err` saying why it was refused. A refused answer
/// typed at a terminal is explained and the question asked again. Read from a
/// pipe, it is an error: the next line was written for the next question.
///
/// End of input cancels.
pub fn ask<T>(
    prompt: &str,
    hidden: bool,
    mut parse: impl FnMut(&str) -> Result<Option<T>, String>,
) -> Result<T, String> {
    loop {
        // Wiped whichever way it was read: a hidden answer is a seed or a
        // secret key, and wiping a visible one costs nothing.
        let answer = if hidden {
            read_password(prompt)
        } else {
            read_line(prompt).map(Zeroizing::new)
        }
        .ok_or("no answer; cancelled")?;
        match parse(answer.trim()) {
            Ok(Some(value)) => return Ok(value),
            Ok(None) => return Err("nothing entered; cancelled".into()),
            Err(why) if interactive() => println!("{why}; try again"),
            Err(why) => return Err(why),
        }
    }
}

/// Ask for one of `items` by its number, counting from zero as the C++ wallet
/// does.
pub fn choose(prompt: &str, items: &[String]) -> Result<usize, String> {
    for (i, item) in items.iter().enumerate() {
        println!("  {i} : {item}");
    }
    ask(prompt, false, |s| match s.parse::<usize>() {
        Ok(n) if n < items.len() => Ok(Some(n)),
        _ => Err(format!("enter a number from 0 to {}", items.len() - 1)),
    })
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
