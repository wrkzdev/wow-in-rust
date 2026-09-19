#!/usr/bin/env bash
# Package the GUI wallet or the web wallet into /out. Runs inside a build
# container, after the build.
#
#   extras/docker/package.sh gui <rust-target> <tar.gz|zip> <toolchain description>
#   extras/docker/package.sh web <folder of built files> <toolchain description>
#
# As docker/package.sh does: entries sorted, owned by 0:0 and stamped with
# SOURCE_DATE_EPOCH, so the same build gives the same archive.
set -euo pipefail

kind=${1:?gui or web}
src=${SRC_DIR:-/src}
out=${OUT_DIR:-/out}
: "${GIT_REV:=unknown}"
: "${SOURCE_DATE_EPOCH:=315532800}"

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$src/Cargo.toml" | head -n1)
# As docker/package.sh: the C++ release these wallets aim to be compatible with.
cpp_version='0.11.4.0 "Kunty Karen"'
staging=$(mktemp -d)

case $kind in
  gui)
    target=$2
    format=$3
    toolchain=$4
    : "${CARGO_TARGET_DIR:?}"
    case $target in
      *windows*) exe=.exe ;;
      *) exe= ;;
    esac
    name=wownero-rs-wallet-gui-$version-$target
    stage=$staging/$name
    mkdir -p "$stage"
    install -m 0755 "$CARGO_TARGET_DIR/$target/release/wownero-wallet-gui$exe" "$stage/"
    ;;
  web)
    built=$2
    toolchain=$3
    target=wasm32-unknown-unknown
    format=tar.gz
    name=wownero-rs-wallet-web-$version
    stage=$staging/$name
    mkdir -p "$stage"
    cp -R "$built"/. "$stage"/
    chmod -R u=rwX,go=rX "$stage"
    ;;
  *)
    echo "package.sh: unknown kind '$kind' (expected gui or web)" >&2
    exit 2
    ;;
esac

install -m 0644 "$src/extras/README.md" "$stage/README.md"
cat > "$stage/BUILDINFO" <<EOF
name:      $name
version:   $version
compat:    Wownero C++ $cpp_version
git:       $GIT_REV
target:    $target
rustc:     $(rustc -V)
toolchain: $toolchain
source:    $(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)

A test build: unsigned and unaudited. This is very new software, not fully
audited or tested. Use it at your own risk, with amounts you can afford to lose.
EOF

# A served web wallet can be checked file by file against this:
#   sha256sum -c SHA256SUMS
if [ "$kind" = web ]; then
  (cd "$stage" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | LC_ALL=C sort \
    | while IFS= read -r f; do sha256sum "$f"; done > SHA256SUMS)
fi

find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$out"

case $format in
  tar.gz)
    tar --sort=name --owner=0 --group=0 --numeric-owner \
        --mtime="@$SOURCE_DATE_EPOCH" -C "$staging" -cf - "$name" \
      | gzip -9n > "$out/$name.tar.gz"
    ;;
  zip)
    (cd "$staging" && find "$name" | LC_ALL=C sort | TZ=UTC zip -X -9 -q "$out/$name.zip" -@)
    ;;
  *)
    echo "package.sh: unknown format '$format'" >&2
    exit 1
    ;;
esac

rm -rf "$staging"
echo "packaged $out/$name.$format"
