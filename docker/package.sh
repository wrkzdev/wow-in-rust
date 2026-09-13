#!/usr/bin/env bash
# Package one target's release binaries into /out. Runs inside a build
# container, after `cargo build --release --target <target>`.
#
#   docker/package.sh <rust-target> <tar.gz|zip> <toolchain description>
#
# Archive entries are sorted, owned by 0:0 and stamped with SOURCE_DATE_EPOCH,
# so identical binaries give an identical archive -- the hashes in
# dist/SHA256SUMS then only move when the binaries do.
set -euo pipefail

target=$1
format=$2
toolchain=$3

# The container layout; overridable so the script can be exercised outside one.
src=${SRC_DIR:-/src}
out=${OUT_DIR:-/out}
: "${CARGO_TARGET_DIR:?}"
: "${GIT_REV:=unknown}"
# zip cannot store dates before 1980, so that is the floor, not 0.
: "${SOURCE_DATE_EPOCH:=315532800}"

version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$src/Cargo.toml" | head -n1)
case $target in
  *windows*) exe=.exe ;;
  *) exe= ;;
esac

name=wownero-rs-$version-$target
staging=$(mktemp -d)
stage=$staging/$name
mkdir -p "$stage" "$out"

for bin in wownerod wownero-wallet-cli wownero-wallet-rpc; do
  install -m 0755 "$CARGO_TARGET_DIR/$target/release/$bin$exe" "$stage/"
done
install -m 0644 "$src/README.md" "$stage/"

cat > "$stage/BUILDINFO" <<EOF
name:      $name
git:       $GIT_REV
target:    $target
rustc:     $(rustc -V)
toolchain: $toolchain
source:    $(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)

A test build: unsigned and unaudited. Read "Status" in README.md before
trusting it with funds.
EOF

find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

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
