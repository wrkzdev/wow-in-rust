//! The worker's side: the wallet, kept in memory and in IndexedDB, talking to
//! the node with synchronous requests.

use std::collections::BTreeMap;
use std::sync::Arc;

use wasm_bindgen::prelude::*;
use wow_daemon_client::{DaemonClient, HttpError, Transport};
use wow_wallet::store::{MemoryStore, Store};
use wownero_wallet_gui::backend::{Backend, Platform};
use wownero_wallet_gui::nodes::NodeAddress;
use wownero_wallet_gui::protocol::{Command, Event};

use crate::describe;

#[wasm_bindgen]
extern "C" {
    // `self.wowWorker`, in static/worker.js.
    #[wasm_bindgen(catch, js_namespace = wowWorker, js_name = post)]
    fn node_post(url: &str, content_type: &str, body: &[u8]) -> Result<js_sys::Uint8Array, JsValue>;
    #[wasm_bindgen(js_namespace = wowWorker, js_name = keep)]
    fn storage_keep(name: &str, keys: &[u8], cache: &[u8]);
    #[wasm_bindgen(js_namespace = wowWorker, js_name = forget)]
    fn storage_forget(name: &str);
    #[wasm_bindgen(js_namespace = wowWorker, js_name = random)]
    fn random_bytes(length: u32) -> js_sys::Uint8Array;
    #[wasm_bindgen(js_namespace = wowWorker, js_name = isSecure)]
    fn worker_is_secure() -> bool;
}

/// `crypto.getRandomValues`, for [`wow_wallet::entropy::set_random_source`].
fn fill_random(out: &mut [u8]) -> bool {
    // It gives at most 65,536 bytes a call.
    for chunk in out.chunks_mut(65_536) {
        let bytes = random_bytes(chunk.len() as u32);
        if bytes.length() as usize != chunk.len() {
            return false;
        }
        bytes.copy_to(chunk);
    }
    true
}

/// `Date.now()`, in seconds, for [`wow_wallet::clock::set_clock`].
fn clock() -> u64 {
    (js_sys::Date::now() / 1_000.0) as u64
}

/// Requests to a node, as the browser makes them.
#[derive(Debug)]
struct BrowserTransport {
    base: String,
}

impl Transport for BrowserTransport {
    fn post(&self, path: &str, content_type: &str, body: &[u8]) -> Result<Vec<u8>, HttpError> {
        node_post(&format!("{}{path}", self.base), content_type, body)
            .map(|bytes| bytes.to_vec())
            .map_err(|e| HttpError::Transport(describe(&e)))
    }

    fn address(&self) -> &str {
        &self.base
    }
}

/// Wallets in memory, each written to IndexedDB after it is saved.
#[derive(Default)]
struct Browser {
    held: BTreeMap<String, MemoryStore>,
}

impl Platform for Browser {
    fn list(&self) -> Result<Vec<String>, String> {
        Ok(self
            .held
            .iter()
            .filter(|(_, store)| store.exists())
            .map(|(name, _)| name.clone())
            .collect())
    }

    fn location(&self) -> String {
        "this browser".into()
    }

    fn exists(&self, name: &str) -> bool {
        self.held.get(name).is_some_and(|store| store.exists())
    }

    fn store(&mut self, name: &str) -> Result<Box<dyn Store>, String> {
        let store = self
            .held
            .entry(name.to_string())
            .or_insert_with(|| MemoryStore::new(name))
            .clone();
        Ok(Box::new(store))
    }

    fn saved(&mut self, name: &str) {
        let Some(files) = self.held.get(name).map(MemoryStore::files) else {
            return;
        };
        if let Some(keys) = &files.keys {
            storage_keep(name, keys, files.cache.as_deref().unwrap_or_default());
        }
    }

    fn import(&mut self, name: &str, keys: Vec<u8>, cache: Option<Vec<u8>>) -> Result<(), String> {
        self.held
            .insert(name.to_string(), MemoryStore::holding(name, keys, cache));
        self.saved(name);
        Ok(())
    }

    fn export(&mut self, name: &str) -> Result<(Vec<u8>, Option<Vec<u8>>), String> {
        let files = self
            .held
            .get(name)
            .map(MemoryStore::files)
            .ok_or_else(|| format!("there is no wallet named {name}"))?;
        let keys = files
            .keys
            .ok_or_else(|| format!("there is no wallet named {name}"))?;
        Ok((keys, files.cache))
    }

    fn forget(&mut self, name: &str) -> Result<(), String> {
        self.held
            .remove(name)
            .ok_or_else(|| format!("there is no wallet named {name}"))?;
        storage_forget(name);
        Ok(())
    }

    fn set_folder(&mut self, _path: &str) -> Result<(), String> {
        Err("a browser keeps wallets in its own storage, not in a folder".into())
    }

    fn in_browser(&self) -> bool {
        true
    }

    fn secure_page(&self) -> bool {
        worker_is_secure()
    }

    fn connect(&self, node: &NodeAddress) -> DaemonClient {
        DaemonClient::with_transport(Arc::new(BrowserTransport { base: node.url() }))
    }

    fn millis(&self) -> f64 {
        js_sys::Date::now()
    }
}

#[wasm_bindgen]
pub struct WalletWorker {
    post: js_sys::Function,
    /// The wallets handed over before [`WalletWorker::start`].
    kept: Option<Browser>,
    backend: Option<Backend<Browser>>,
}

#[wasm_bindgen]
impl WalletWorker {
    /// `post` carries a message to the page.
    #[wasm_bindgen(constructor)]
    pub fn new(post: js_sys::Function) -> WalletWorker {
        wow_wallet::clock::set_clock(clock);
        wow_wallet::entropy::set_random_source(fill_random);
        WalletWorker {
            post,
            kept: Some(Browser::default()),
            backend: None,
        }
    }

    /// A wallet read back from IndexedDB, before [`WalletWorker::start`].
    pub fn hold(&mut self, name: &str, keys: Vec<u8>, cache: Option<Vec<u8>>) {
        if let Some(kept) = &mut self.kept {
            kept.held
                .insert(name.to_string(), MemoryStore::holding(name, keys, cache));
        }
    }

    /// Start answering, with the wallets held so far.
    pub fn start(&mut self) {
        let browser = self.kept.take().unwrap_or_default();
        let post = self.post.clone();
        let emit = move |event: Event| {
            if let Ok(json) = serde_json::to_string(&event) {
                let _ = post.call1(&JsValue::NULL, &JsValue::from_str(&json));
            }
        };
        let mut backend = Backend::new(browser, emit);
        backend.start();
        self.backend = Some(backend);
    }

    /// A message from the page.
    pub fn handle(&mut self, message: &str) {
        let Some(backend) = &mut self.backend else {
            return;
        };
        match serde_json::from_str::<Command>(message) {
            Ok(command) => backend.handle(command),
            Err(e) => backend.error(format!("an unreadable command: {e}")),
        }
    }

    /// One step of background work. Returns the milliseconds to wait before the
    /// next, or -1 when nothing is due until a message arrives.
    pub fn tick(&mut self) -> i32 {
        match self.backend.as_mut().and_then(Backend::tick) {
            Some(ms) => ms.min(i32::MAX as u32) as i32,
            None => -1,
        }
    }

    /// IndexedDB could not keep a write.
    pub fn storage_failed(&mut self, message: &str) {
        if let Some(backend) = &mut self.backend {
            backend.error(message);
        }
    }
}
