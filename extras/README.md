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

## The desktop wallet

- A wallet is its files, as wallet-cli writes them: `<name>.keys` (the C++
  wallet reads it too), `<name>.rscache` and `<name>.address.txt`. They are kept
  in `%APPDATA%\wownero-rs\wallets` on Windows,
  `~/Library/Application Support/wownero-rs/wallets` on macOS and
  `~/.local/share/wownero-rs/wallets` elsewhere. The Open tab changes the
  folder.
- An open wallet is locked: wallet-cli and the C++ wallet cannot open it at the
  same time.
- Nodes over plain HTTP only, for now: TLS comes with the wallets' TLS support.
  Until then the public list is a snapshot, as the desktop cannot fetch it.
- Linux needs X11 or Wayland, with OpenGL (Mesa) and libxkbcommon, which any
  desktop has.
- macOS: the app is signed ad hoc, not by a developer. After downloading, run
  `xattr -dr com.apple.quarantine "Wownero Wallet.app"`.

## The web wallet

- Static files and nothing else: no server code, no proxy. Serve them from any
  web server, over https.
- Wallets are kept in the browser's IndexedDB, for that site only. The browser
  can clear it, so export each wallet's files (Wallet → Export files) and keep
  its seed phrase.
- Import takes a `.keys` file, from this wallet or from Wownero's C++ wallets,
  and optionally this wallet's `.rscache`. Without the cache it scans again
  from the restore height. The C++ wallet's cache is not read.
- The browser talks to the node itself, so the node must allow requests from
  web pages (CORS). The C++ node's option is `--rpc-access-control-origins`.
  A page served over https can only reach https nodes. The node picker's Test
  button shows what this browser can reach.
- Whoever serves the files can change them. Each archive has a `SHA256SUMS`
  covering every file in it, and the archive itself is in `dist/SHA256SUMS`;
  build it yourself to compare.
- Open a wallet in one tab at a time. Two tabs saving the same wallet overwrite
  each other.

## What it does, and does not do yet

It creates wallets, restores them from a seed phrase, opens them, syncs,
sends (with a review step), receives on subaddresses, shows the history, and
picks a node: a typed address or the public list, each with a Test button.

Not yet: restoring from keys or a view key, accounts, an address book, TLS and
Tor on the desktop, hardware wallets, and mobile packages. The interface already
lays itself out for a phone's width.
