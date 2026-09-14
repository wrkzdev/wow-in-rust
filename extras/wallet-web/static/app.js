// The page: it draws the wallet and keeps nothing but the interface's settings
// (egui's, in localStorage). The wallet itself runs in worker.js.
import init, { Page } from './wownero_wallet_web.js';

// Called from Rust: wallet-web/src/page.rs.
window.wowPage = {
  download(name, bytes) {
    // `bytes` is a view of wasm memory; copy it before it can move.
    const url = URL.createObjectURL(new Blob([bytes.slice()], { type: 'application/octet-stream' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = name;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  },

  pickFile(accept) {
    return new Promise((resolve, reject) => {
      const input = document.createElement('input');
      input.type = 'file';
      input.accept = accept;
      input.style.display = 'none';
      const done = () => input.remove();
      input.addEventListener('change', () => {
        const file = input.files && input.files[0];
        done();
        if (!file) {
          resolve(null);
          return;
        }
        file.arrayBuffer().then((buffer) => resolve([file.name, new Uint8Array(buffer)]), reject);
      });
      input.addEventListener('cancel', () => {
        done();
        resolve(null);
      });
      document.body.append(input);
      input.click();
    });
  },

  async fetchText(url) {
    const response = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.text();
  },

  isSecure() {
    return location.protocol === 'https:';
  },
};

const status = document.getElementById('status');
try {
  // Ask the browser not to clear this site's storage, where the wallets are,
  // when space runs low. It may still say no; exported files are the backup.
  if (navigator.storage && navigator.storage.persist) {
    navigator.storage.persist().catch(() => {});
  }

  await init();
  const page = new Page();
  const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  worker.addEventListener('message', (event) => page.deliver(event.data));
  worker.addEventListener('error', (event) => {
    page.deliver(JSON.stringify({
      Error: `The wallet stopped: ${event.message || 'its worker failed'}. Reload the page.`,
    }));
  });
  await page.start(document.getElementById('wallet'), (message) => worker.postMessage(message));
  status.remove();
} catch (error) {
  status.textContent = `The wallet could not start: ${error}`;
  console.error(error);
}
