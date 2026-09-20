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
# What it writes:
#
#   index.html                                     names the build below
#   b/<version>-<digest>/app.js
#                       /worker.js
#                       /wownero_wallet_web.js     the wasm-bindgen glue
#                       /wownero_wallet_web_bg.wasm
#
# Everything but index.html lives in a directory named after its own contents,
# and nothing reaches outside that directory: app.js finds worker.js through
# import.meta.url, and the glue finds its .wasm the same way. So one build's
# files can never be served against another's -- which is what a kept glue .js
# and a fresh .wasm produce, a LinkError saying some __wbg_* import "requires a
# callable". The filenames used to be fixed, and any cache that held one of
# them across a deploy broke the wallet until it expired.
#
# A host then wants:
#
#   index.html    Cache-Control: no-store                      the only name that moves
#   b/**          Cache-Control: max-age=31536000, immutable   a name means one build, forever
#
# and a deploy that does not delete: leaving the previous b/<...> in place lets
# a page loaded moments earlier finish loading. Prune old ones by hand, later.
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

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
if [ -z "$version" ]; then
  echo "extras/Cargo.toml names no version" >&2
  exit 1
fi

# sha256sum on Linux, shasum on macOS. Both read stdin when given no file.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

cargo build --release --locked --target wasm32-unknown-unknown -p wownero-wallet-web

mkdir -p "$out"
rm -rf "$out/b"
rm -f "$out"/*.html "$out"/*.js "$out"/*.wasm   # the flat layout of an older build

# Built aside and renamed after: the directory cannot be named until its
# contents have been hashed. Kept inside $out, so the rename is not a copy.
stage=$(mktemp -d "$out/.build.XXXXXX")
trap 'rm -rf "$stage"' EXIT

wasm-bindgen --target web --no-typescript --out-dir "$stage" \
  "$target_dir/wasm32-unknown-unknown/release/wownero_wallet_web.wasm"
# Everything in static/ but index.html, which is written last and stays at
# the root: the build directory holds only files the build owns.
for f in "$here"/static/*; do
  [ "$(basename "$f")" = index.html ] || cp "$f" "$stage"/
done

# The digest is the contents and not the clock, so the same sources rebuild to
# the same directory and a reproducible build stays one.
digest=$(cd "$stage" && find . -type f | LC_ALL=C sort \
  | while IFS= read -r f; do sha256 "$f"; done | sha256 | cut -c1-12)
build=$version-$digest

mkdir -p "$out/b"
mv "$stage" "$out/b/$build"
trap - EXIT
chmod -R u=rwX,go=rX "$out/b/$build"

# index.html is the one file a browser is told never to keep, so it is the one
# file allowed to name the build.
sed "s|src=\"app.js\"|src=\"b/$build/app.js\"|" "$here/static/index.html" > "$out/index.html"
if ! grep -q "b/$build/app.js" "$out/index.html"; then
  echo "build.sh: static/index.html no longer loads app.js the way this expects" >&2
  exit 1
fi

echo "built $out (build $build)"
