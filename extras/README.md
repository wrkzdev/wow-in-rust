# The GUI wallet and the web wallet

> **This is very new software. It has not been fully audited or tested, and it
> may have bugs that lose funds. Use it at your own risk, with amounts you can
> afford to lose.**

Two front ends over the wallet library `wownero-wallet-cli` uses
(`crates/wow-wallet`), with one interface, written with
[egui](https://github.com/emilk/egui), shared between them:

| crate | what it is |
|---|---|
| `wallet-gui` | the desktop wallet for Linux, Windows and macOS, and the interface and wallet logic the web wallet reuses |
| `wallet-web` | the web wallet: static files. The wallet runs in the browser and talks straight to a node |

`extras/` is a Cargo workspace of its own, so the node, the command-line
wallets and their CI never build egui or wasm-bindgen.

## Building

Release archives, in Docker, as the other archives are built. Output goes to
`dist/`, with hashes in `dist/SHA256SUMS`:

```sh
bash docker/build-dist.sh web          # dist/web/wownero-rs-wallet-web-<version>.tar.gz
bash docker/build-dist.sh gui-linux    # x86_64 and aarch64
bash docker/build-dist.sh gui-windows  # x86_64
bash docker/build-dist.sh gui-macos    # on a Mac only; skipped anywhere else
bash docker/build-dist.sh extras       # all four
```

Without Docker:

```sh
# The desktop wallet, for this machine
cargo run --release --manifest-path extras/Cargo.toml -p wownero-wallet-gui

# The web wallet, into extras/wallet-web/dist/
rustup target add wasm32-unknown-unknown
cargo install --locked wasm-bindgen-cli --version <the version build.sh names>
bash extras/wallet-web/build.sh
python3 -m http.server -d extras/wallet-web/dist 8080   # then open http://localhost:8080
```

The first build writes `extras/Cargo.lock`. A Docker build leaves a copy in
`dist/<platform>/extras-Cargo.lock`. Commit it, so later builds resolve the
same dependency versions.

## Nodes

- The default node is `https://wow-node.0z.network:443`: over TLS, and open
  to web pages (CORS), so the desktop and the web wallet can both use it. It
  leads the list in Settings, Node, followed by the public nodes monero.fail
  lists.
- Any `http://` or `https://` address can be typed. A scheme with no port
  means port 80 or 443; no scheme at all means plain HTTP on 34568, as
  wallet-cli's `--daemon-address` does.
- Test asks a node what it is before it is used: its height, network and
  whether it is synced, or why it could not be reached, in full.

## The desktop wallet

- A wallet is its files, as wallet-cli writes them: `<name>.keys` (the C++
  wallet reads it too), `<name>.rscache` and `<name>.address.txt`. They are kept
  in `%APPDATA%\wownero-rs\wallets` on Windows,
  `~/Library/Application Support/wownero-rs/wallets` on macOS and
  `~/.local/share/wownero-rs/wallets` elsewhere. The Open tab changes the
  folder, with a folder chooser, and shows it in the file manager.
- An open wallet is locked: wallet-cli and the C++ wallet cannot open it at the
  same time.
- Nodes over plain HTTP or TLS. An https node's certificate is checked against
  the Mozilla roots. A node with a self-signed certificate, as `wownerod` makes
  one, needs "Accept an https node's certificate whoever signed it" in
  Settings, Node: the connection is still encrypted, but nothing checks who is
  at the other end.
- The log goes to `wownero-wallet-gui.log`, beside the wallets folder, when
  Settings, Logs says to, rotating at 10 MB and keeping five old files.
- Linux needs X11 or Wayland, with OpenGL (Mesa) and libxkbcommon, which any
  desktop has. The folder chooser and the save dialog go through the XDG
  desktop portal.
- macOS: the app is signed ad hoc, not by a developer. After downloading, run
  `xattr -dr com.apple.quarantine "Wownero Wallet.app"`.

## The web wallet

- Static files and nothing else: no server code, no proxy. Serve them from any
  web server, over https.
- Wallets are kept in the browser's IndexedDB, for that site only. The browser
  can clear it, so export each wallet's files (Settings, Wallet, Export files)
  and keep its seed phrase. The overview says when a wallet has not been
  exported from the browser yet, and when the browser has not promised to keep
  the site's storage.
- Import takes a `.keys` file, from this wallet or from Wownero's C++ wallets,
  and optionally this wallet's `.rscache`. Without the cache it scans again
  from the restore height. The C++ wallet's cache is not read.
- The browser talks to the node itself, so the node must allow requests from
  web pages (CORS), and a page served over https can only reach https nodes.
  The C++ node's option is `--rpc-access-control-origins`; a reverse proxy in
  front of a node (nginx, Caddy) can add the headers instead.
- Whoever serves the files can change them. Each archive has a `SHA256SUMS`
  covering every file in it, and the archive itself is in `dist/SHA256SUMS`;
  build it yourself to compare.
- Open a wallet in one tab at a time. Two tabs saving the same wallet overwrite
  each other.

## What it does

- **Wallets:** create; restore from a seed phrase, with a restore height or a
  date to find one from; open; scan again from a height; import and export in
  the browser.
- **Send:** the address checked as it is typed, a fee estimate, a review with
  the total, and, when nothing can be sent, how much is locked and when it
  unlocks.
- **Receive:** the primary address and subaddresses, each with a QR code, a
  label, and whether it has been paid.
- **History:** local time or UTC, confirmations, the details of each transfer,
  filters, and CSV export.
- **Settings:** the wallet's seed phrase, view key and password, and a
  view-only copy of it; the node; a light or dark theme and the text size;
  privacy (hide the balance, close a wallet left alone); the log, with a
  window to read it in.

Not yet: restoring from keys or a view key, accounts, an address book, Tor,
hardware wallets, and mobile packages. The interface already lays itself out
for a phone's width.
