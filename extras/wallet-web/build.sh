#!/usr/bin/env bash
# Build the web wallet: static files, served as they are.
#
#   bash extras/wallet-web/build.sh              # into extras/wallet-web/dist/
#   OUT=/some/dir bash extras/wallet-web/build.sh
#
# Needs the wasm32-unknown-unknown target (rustup target add
# wasm32-unknown-unknown) and wasm-bindgen-cli at exactly the version of the
# wasm-bindgen crate in extras/Cargo.lock. The script says which if they differ.
#
# To try it, serve the folder -- a module worker does not load from file:// --
#   python3 -m http.server -d extras/wallet-web/dist 8080
# and open http://localhost:8080.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
extras=$(dirname "$here")
out=${OUT:-$here/dist}

cd "$extras"
target_dir=${CARGO_TARGET_DIR:-$extras/target}

if [ ! -f Cargo.lock ]; then
  echo "extras/Cargo.lock is missing; resolving dependencies. Commit it, so later builds match." >&2
  cargo generate-lockfile
fi

want=$(awk '$0 == "name = \"wasm-bindgen\"" { getline; gsub(/"/, "", $3); print $3; exit }' Cargo.lock)
have=$(wasm-bindgen --version 2>/dev/null | awk '{ print $2 }' || true)
if [ -z "$want" ]; then
  echo "extras/Cargo.lock names no wasm-bindgen" >&2
  exit 1
fi
if [ "$have" != "$want" ]; then
  echo "wasm-bindgen-cli $want is needed, and ${have:-none} is installed:" >&2
  echo "  cargo install --locked wasm-bindgen-cli --version $want" >&2
  exit 1
fi

cargo build --release --locked --target wasm32-unknown-unknown -p wownero-wallet-web

mkdir -p "$out"
rm -f "$out"/*.html "$out"/*.js "$out"/*.wasm
wasm-bindgen --target web --no-typescript --out-dir "$out" \
  "$target_dir/wasm32-unknown-unknown/release/wownero_wallet_web.wasm"
cp "$here"/static/* "$out"/
echo "built $out"
