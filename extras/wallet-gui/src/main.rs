// No console window behind the GUI on Windows, in a release build.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result {
    wownero_wallet_gui::native::run()
}

// The browser starts from `wownero-wallet-web`, not from here.
#[cfg(target_arch = "wasm32")]
fn main() {}
