//! A Wownero wallet with a GUI: one egui interface, on the desktop and in a
//! browser.
//!
//! The interface ([`app`]) never touches the wallet. It sends a
//! [`protocol::Command`] over a [`app::Link`] and draws the
//! [`protocol::Event`]s that come back. The other end runs a
//! [`backend::Backend`], which holds the open wallet: on the desktop in a thread
//! of its own ([`native`]), and in a browser in a web worker (the
//! `wownero-wallet-web` crate). Either way it is off the interface's thread,
//! because the wallet blocks: on the node, on CryptoNight, on scanning.

pub mod app;
pub mod backend;
pub mod format;
pub mod nodes;
pub mod protocol;
pub mod qr;

#[cfg(not(target_arch = "wasm32"))]
pub mod native;
