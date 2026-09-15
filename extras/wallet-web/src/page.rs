//! The page's side: the interface, drawn by eframe on a canvas.

use std::cell::RefCell;
use std::rc::Rc;

use eframe::egui;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use wownero_wallet_gui::app::{Host, Settings, WalletApp};
use wownero_wallet_gui::nodes;
use wownero_wallet_gui::protocol::{Bytes, Command, Event, Pick};

use crate::describe;

#[wasm_bindgen]
extern "C" {
    // `window.wowPage`, in static/app.js.
    #[wasm_bindgen(js_namespace = wowPage, js_name = download)]
    fn page_download(name: &str, bytes: &[u8]);
    #[wasm_bindgen(js_namespace = wowPage, js_name = pickFile)]
    fn page_pick_file(accept: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = wowPage, js_name = fetchText)]
    fn page_fetch_text(url: &str) -> js_sys::Promise;
    #[wasm_bindgen(js_namespace = wowPage, js_name = isSecure)]
    fn page_is_secure() -> bool;
}

/// What has come in for the interface, and the context to wake when it does.
#[derive(Default)]
struct Inbox {
    events: Vec<Event>,
    ctx: Option<egui::Context>,
}

fn deliver_to(inbox: &Rc<RefCell<Inbox>>, event: Event) {
    let ctx = {
        let mut inbox = inbox.borrow_mut();
        inbox.events.push(event);
        inbox.ctx.clone()
    };
    if let Some(ctx) = ctx {
        ctx.request_repaint();
    }
}

#[wasm_bindgen]
pub struct Page {
    inbox: Rc<RefCell<Inbox>>,
}

#[wasm_bindgen]
impl Page {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Page {
        Page {
            inbox: Rc::default(),
        }
    }

    /// A message from the worker.
    pub fn deliver(&self, message: &str) {
        let event = serde_json::from_str::<Event>(message).unwrap_or_else(|e| {
            Event::Error(format!("an unreadable message came from the wallet: {e}"))
        });
        deliver_to(&self.inbox, event);
    }

    /// Start the interface on `canvas`. `post` carries a message to the
    /// worker.
    pub fn start(
        &self,
        canvas: web_sys::HtmlCanvasElement,
        post: js_sys::Function,
    ) -> js_sys::Promise {
        let inbox = self.inbox.clone();
        wasm_bindgen_futures::future_to_promise(async move {
            eframe::WebRunner::new()
                .start(
                    canvas,
                    eframe::WebOptions::default(),
                    Box::new(move |cc| {
                        inbox.borrow_mut().ctx = Some(cc.egui_ctx.clone());
                        let settings = Settings::load(cc.storage);
                        let host = WebHost { post, inbox };
                        Ok(Box::new(WalletApp::new(settings, Box::new(host))))
                    }),
                )
                .await?;
            Ok(JsValue::UNDEFINED)
        })
    }
}

struct WebHost {
    post: js_sys::Function,
    inbox: Rc<RefCell<Inbox>>,
}

#[wasm_bindgen]
extern "C" {
    // `window.wowPage.storagePersisted`, in static/app.js: `undefined` until
    // the browser has answered.
    #[wasm_bindgen(js_namespace = wowPage, js_name = storagePersisted)]
    fn page_storage_persisted() -> Option<bool>;
}

impl Host for WebHost {
    fn utc_offset(&self, timestamp: u64) -> i64 {
        // `getTimezoneOffset` is minutes behind UTC: -60 in UTC+1.
        let date = js_sys::Date::new(&JsValue::from_f64(timestamp as f64 * 1_000.0));
        -(date.get_timezone_offset() as i64) * 60
    }

    /// A browser keeps wallets in its own storage, not in a folder.
    fn pick_folder(&mut self, _start: &str) -> Option<String> {
        None
    }

    fn storage_persisted(&self) -> Option<bool> {
        page_storage_persisted()
    }

    /// A browser keeps wallets in its own storage, with no folder to open.
    fn open_folder(&mut self, _path: &str) {}

    fn send(&mut self, command: Command) {
        let json = match serde_json::to_string(&command) {
            Ok(json) => json,
            Err(e) => {
                deliver_to(
                    &self.inbox,
                    Event::Error(format!("a command could not be sent: {e}")),
                );
                return;
            }
        };
        if self
            .post
            .call1(&JsValue::NULL, &JsValue::from_str(&json))
            .is_err()
        {
            deliver_to(
                &self.inbox,
                Event::Error("the wallet could not be reached; reload the page".into()),
            );
        }
    }

    fn receive(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.inbox.borrow_mut().events)
    }

    fn in_browser(&self) -> bool {
        true
    }

    fn secure_page(&self) -> bool {
        page_is_secure()
    }

    fn download(&mut self, name: &str, bytes: &[u8]) {
        page_download(name, bytes);
    }

    fn pick_file(&mut self, purpose: Pick) {
        let promise = page_pick_file(purpose.accept());
        let inbox = self.inbox.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match JsFuture::from(promise).await {
                Ok(picked) if !picked.is_null() && !picked.is_undefined() => {
                    let pair = js_sys::Array::from(&picked);
                    let name = pair.get(0).as_string().unwrap_or_default();
                    let bytes = js_sys::Uint8Array::new(&pair.get(1)).to_vec();
                    deliver_to(
                        &inbox,
                        Event::Picked {
                            purpose,
                            name,
                            bytes: Bytes(bytes),
                        },
                    );
                }
                Ok(_) => {}
                Err(e) => deliver_to(
                    &inbox,
                    Event::Error(format!("the file could not be read: {}", describe(&e))),
                ),
            }
        });
    }

    fn fetch_nodes(&mut self, url: &str) {
        let promise = page_fetch_text(url);
        let inbox = self.inbox.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let result = match JsFuture::from(promise).await {
                Ok(text) => nodes::parse_listing(&text.as_string().unwrap_or_default()),
                Err(e) => Err(format!(
                    "The public node list could not be fetched ({}), so this is the list as it \
                     stood on 15 September 2026.",
                    describe(&e)
                )),
            };
            deliver_to(&inbox, Event::NodeList(result));
        });
    }
}
