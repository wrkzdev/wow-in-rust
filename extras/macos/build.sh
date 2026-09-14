#!/usr/bin/env bash
# The GUI wallet for macOS, arm64 and x86_64, each as an app bundle in a
# tar.gz. On a Mac only: AppKit and OpenGL come from Apple's SDK, which no
# Linux container has. `docker/build-dist.sh gui-macos` runs this on macOS and
# skips it elsewhere.
#
#   bash extras/macos/build.sh [out-dir]       # default dist/gui-macos
#
# Needs Xcode's command line tools (xcode-select --install) and rustup.
# The bundles are signed ad hoc, not by a developer: a downloaded copy needs
#   xattr -dr com.apple.quarantine "Wownero Wallet.app"
set -euo pipefail

cd "$(dirname "$0")/../.."

if [ "$(uname -s)" != Darwin ]; then
  echo "the macOS GUI wallet builds on macOS only" >&2
  exit 2
fi

out=${1:-dist/gui-macos}
target_dir=${CARGO_TARGET_DIR:-extras/target}
: "${GIT_REV:=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
export MACOSX_DEPLOYMENT_TARGET=11.0

rustup target add aarch64-apple-darwin x86_64-apple-darwin
if [ ! -f extras/Cargo.lock ]; then
  echo "extras/Cargo.lock is missing; resolving dependencies. Commit it, so later builds match." >&2
  cargo generate-lockfile --manifest-path extras/Cargo.toml
fi
mkdir -p "$out"

for target in aarch64-apple-darwin x86_64-apple-darwin; do
  cargo build --release --locked --manifest-path extras/Cargo.toml \
    --target "$target" -p wownero-wallet-gui

  name=wownero-rs-wallet-gui-$version-$target
  staging=$(mktemp -d)
  app="$staging/$name/Wownero Wallet.app"
  mkdir -p "$app/Contents/MacOS"
  install -m 0755 "$target_dir/$target/release/wownero-wallet-gui" "$app/Contents/MacOS/"
  cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Wownero Wallet</string>
  <key>CFBundleDisplayName</key><string>Wownero Wallet</string>
  <key>CFBundleIdentifier</key><string>io.github.wrkzdev.wow-in-rust.wallet-gui</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleExecutable</key><string>wownero-wallet-gui</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>$MACOSX_DEPLOYMENT_TARGET</string>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
  codesign --force --deep --sign - "$app"

  install -m 0644 extras/README.md "$staging/$name/README.md"
  cat > "$staging/$name/BUILDINFO" <<EOF
name:      $name
git:       $GIT_REV
target:    $target
rustc:     $(rustc -V)
toolchain: $(xcrun clang --version | head -n1), macOS $(sw_vers -productVersion)

A test build: signed ad hoc and unaudited. This is very new software, not fully
audited or tested. Use it at your own risk, with amounts you can afford to lose.
EOF
  tar -C "$staging" -czf "$out/$name.tar.gz" "$name"
  rm -rf "$staging"
  echo "packaged $out/$name.tar.gz"
done
