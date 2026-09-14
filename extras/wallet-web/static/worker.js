// The wallet: it holds the open wallet, talks to the node, and keeps wallets in
// this browser's IndexedDB. The page only draws.
import init, { WalletWorker } from './wownero_wallet_web.js';

// Messages that arrive before the wallet is ready wait here.
const early = [];
self.onmessage = (event) => early.push(event.data);

const DATABASE = 'wownero-wallet';
const STORE = 'wallets';

let database;
let wallet;
let timer = null;
let stopped = false;

function request(r) {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

function openDatabase() {
  const r = indexedDB.open(DATABASE, 1);
  r.onupgradeneeded = () => r.result.createObjectStore(STORE, { keyPath: 'name' });
  return request(r);
}

function write(change) {
  return new Promise((resolve, reject) => {
    const t = database.transaction(STORE, 'readwrite');
    change(t.objectStore(STORE));
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error || new Error('the write was aborted'));
  });
}

function text(error) {
  return `${(error && error.message) || error}`;
}

// Called from Rust: wallet-web/src/worker.rs.
self.wowWorker = {
  // Synchronous, which the wallet library needs, and which a browser allows in
  // a worker only.
  post(url, contentType, body) {
    const x = new XMLHttpRequest();
    x.open('POST', url, false);
    x.responseType = 'arraybuffer';
    x.timeout = 120000;
    x.setRequestHeader('Content-Type', contentType);
    try {
      // `body` is a view of wasm memory; send a copy.
      x.send(body.slice());
    } catch (error) {
      throw text(error);
    }
    if (x.status !== 200) throw `HTTP ${x.status} ${x.statusText}`.trim();
    return new Uint8Array(x.response);
  },

  keep(name, keys, cache) {
    const record = {
      name,
      keys: keys.slice(),
      cache: cache.length ? cache.slice() : null,
      saved: Date.now(),
    };
    write((store) => store.put(record)).catch((error) =>
      wallet.storage_failed(`${name} could not be kept in this browser: ${text(error)}`));
  },

  forget(name) {
    write((store) => store.delete(name)).catch((error) =>
      wallet.storage_failed(`${name} could not be deleted from this browser: ${text(error)}`));
  },

  random(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  },

  isSecure() {
    return self.location.protocol === 'https:';
  },
};

function stop(error) {
  stopped = true;
  self.postMessage(JSON.stringify({
    Error: `The wallet stopped on an internal error: ${text(error)}. Reload the page; what was saved is kept.`,
  }));
}

// Background work, a step at a time, so messages are handled in between.
function pump() {
  timer = null;
  if (stopped) return;
  let wait;
  try {
    wait = wallet.tick();
  } catch (error) {
    stop(error);
    return;
  }
  if (wait >= 0) timer = setTimeout(pump, wait);
}

function receive(message) {
  if (stopped) return;
  try {
    wallet.handle(message);
  } catch (error) {
    stop(error);
    return;
  }
  if (timer !== null) clearTimeout(timer);
  timer = setTimeout(pump, 0);
}

try {
  await init();
  database = await openDatabase();
  const kept = await request(database.transaction(STORE).objectStore(STORE).getAll());
  wallet = new WalletWorker((message) => self.postMessage(message));
  for (const w of kept) wallet.hold(w.name, w.keys, w.cache ?? undefined);
  wallet.start();
  self.onmessage = (event) => receive(event.data);
  for (const message of early.splice(0)) receive(message);
  timer = setTimeout(pump, 0);
} catch (error) {
  self.postMessage(JSON.stringify({ Error: `The wallet could not start: ${text(error)}` }));
}
