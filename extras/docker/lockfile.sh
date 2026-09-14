#!/usr/bin/env bash
# extras/ has a Cargo.lock of its own. Until one is committed, resolve it here
# and leave a copy beside the archives, to commit so later builds use the same
# versions. Runs inside a build container, from /src.
set -euo pipefail

if [ ! -f extras/Cargo.lock ]; then
  echo "extras/Cargo.lock is missing: resolving the dependencies now." >&2
  cargo generate-lockfile --manifest-path extras/Cargo.toml
  mkdir -p "${OUT_DIR:-/out}"
  cp extras/Cargo.lock "${OUT_DIR:-/out}/extras-Cargo.lock"
fi
