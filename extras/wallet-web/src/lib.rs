//! The web wallet: the GUI wallet's interface on a canvas, and its wallet in a
//! web worker.
//!
//! One wasm module, loaded twice. The page (`static/app.js`) starts a
//! [`Page`], which draws the interface; `static/worker.js` starts a
//! [`WalletWorker`], which holds the wallet. They talk in JSON over
//! `postMessage`. The wallet runs in the worker because it blocks, and a
//! worker is the one place a browser lets a request to the node block.
//!
//! The JavaScript around it is kept small: IndexedDB, choosing and saving
//! files, and the requests themselves.

#![cfg(target_arch = "wasm32")]

mod page;
mod worker;

pub use page::Page;
pub use worker::WalletWorker;

use wasm_bindgen::{JsCast, JsValue};

/// A JavaScript failure, as text.
fn describe(value: &JsValue) -> String {
    if let Some(text) = value.as_string() {
        return text;
    }
    if let Some(error) = value.dyn_ref::<js_sys::Error>() {
        return String::from(error.message());
    }
    format!("{value:?}")
}
