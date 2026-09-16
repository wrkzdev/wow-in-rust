#!/usr/bin/env bash
# What in this repository is not Rust, and is it still only what we chose?
#
# The node and the command-line wallets compile exactly one C library: LMDB,
# because `data.mdb` must stay byte-compatible with the C++ node
# (docs/daemon-review.md §G). The RandomWOW C++ submodule and ring's C and
# assembly under the RPC TLS were both replaced with Rust; nothing is supposed
# to bring a toolchain back without someone deciding to.
#
# The desktop GUI compiles one more, which is why this script has a list rather
# than a single name: see ALLOW_extras below.
#
# The check is per target, not for this machine's. The repository cross-builds
# to Linux, Windows, macOS, Android and wasm, and a dependency that pulls in C
# on one of them only would otherwise surface as a cross-build failing weeks
# later. `--target all` would be simpler and is wrong: it drags in Haiku and
# Android dependencies for platforms nothing here ships.
#
# Run it the way CI does:
#
#   bash scripts/check-no-c.sh
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0

# Crates that compile C, C++ or assembly, or need a toolchain present. Matching
# names is the coarse half of the check. Note that `*-sys` on its own is not
# the test: windows-sys and wayland-sys are pure-Rust bindings, one of them
# over a library loaded at run time, and both are welcome.
NATIVE='^(ring|aws-lc-rs|aws-lc-sys|openssl|openssl-sys|cmake|bindgen|cxx|cxx-build|libz-sys|zstd-sys|lz4-sys|curl-sys|libsqlite3-sys|libgit2-sys)$'

# The node, wallet-cli and wallet-rpc. Android is command-line binaries only.
TARGETS_root="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
              x86_64-pc-windows-gnu
              x86_64-apple-darwin aarch64-apple-darwin
              x86_64-linux-android aarch64-linux-android"
ALLOW_root="lmdb-master-sys"

# The desktop GUI and the web wallet. No LMDB: a wallet has no blockchain.
TARGETS_extras="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
                x86_64-pc-windows-gnu
                x86_64-apple-darwin aarch64-apple-darwin
                wasm32-unknown-unknown"
# wayland-backend compiles a small C shim on Linux, reached from eframe's
# default features through winit and smithay-client-toolkit. It is not the
# same thing as linking libwayland -- that is still loaded at run time through
# wayland-sys, so a Linux build needs no system development packages -- but it
# is C, and saying "LMDB is the only C" without this asterisk was wrong.
# Dropping it would mean giving up Wayland support in the desktop wallet.
ALLOW_extras="wayland-backend"

check() {
  local key=$1 manifest=$2 target=$3
  local allow; eval "allow=\$ALLOW_$key"

  local tree
  if ! tree=$(cargo tree --manifest-path "$manifest" --workspace --target "$target" \
                --edges normal,build --prefix none 2>&1); then
    echo "  $target: FAIL -- cannot resolve the dependency tree"
    printf '%s\n' "$tree" | sed 's/^/    /'
    fail=1
    return
  fi

  local banned
  banned=$(printf '%s\n' "$tree" | awk 'NF {print $1}' | sort -u | grep -E "$NATIVE" || true)
  if [ -n "$banned" ]; then
    echo "  $target: FAIL -- these compile C, C++ or assembly, or need a toolchain:"
    printf '    %s\n' $banned
    fail=1
  fi

  # `cc` is what a build script uses to compile C, so ask who depends on it.
  # `--invert` roots the tree at `cc`, which makes depth 1 exactly the crates
  # that compile something; everything deeper merely depends on one of those.
  # A crate can be named anything and still build a C library, which is why
  # this beats matching names. `--invert` exits non-zero when `cc` is not in
  # the graph at all, and that is the best possible answer.
  local direct
  if direct=$(cargo tree --manifest-path "$manifest" --workspace --target "$target" \
                --edges normal,build --invert cc --prefix depth 2>/dev/null); then
    direct=$(printf '%s\n' "$direct" | sed -n 's/^1//p' | awk 'NF {print $1}' | sort -u)
  else
    direct=""
  fi

  local unexpected=""
  local crate
  for crate in $direct; do
    case " $allow " in
      *" $crate "*) ;;
      *) unexpected="$unexpected $crate" ;;
    esac
  done

  if [ -n "$unexpected" ]; then
    echo "  $target: FAIL -- compiles C, and is not on this workspace's list:"
    printf '    %s\n' $unexpected
    fail=1
  elif [ -n "$direct" ]; then
    echo "  $target: ok -- compiles C:$(printf ' %s' $direct)"
  else
    echo "  $target: ok -- no C at all"
  fi
}

run() {
  local key=$1 manifest=$2 label=$3
  local targets; eval "targets=\$TARGETS_$key"
  echo "== $label ($manifest) =="
  local t
  for t in $targets; do
    check "$key" "$manifest" "$t"
  done
}

run root Cargo.toml "node, wallet-cli, wallet-rpc"
run extras extras/Cargo.toml "desktop GUI, web wallet"

if [ "$fail" -ne 0 ]; then
  cat <<'WHY'

Something outside the lists above compiles C. That is a decision to make on
purpose -- and to write down in docs/daemon-review.md §G and in this script --
rather than one to discover when a cross-build breaks.
WHY
  exit 1
fi
echo
echo "Only the C we chose."
