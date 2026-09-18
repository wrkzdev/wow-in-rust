#!/usr/bin/env bash
# extras/ has a Cargo.lock of its own, and it is committed. This checks it is
# there and usable rather than resolving one: a build that quietly picked its
# own dependency versions would not be the build anybody reviewed, and the GUI
# and web wallets are the two things here that handle keys.
#
# It also leaves a copy beside the archives, so a release can be matched
# against the versions it was actually built from. Runs inside a build
# container, from /src.
set -euo pipefail

if [ ! -f extras/Cargo.lock ]; then
  echo "extras/Cargo.lock is missing. It is committed to the repository; a" >&2
  echo "checkout without it is incomplete. Restore it rather than resolving" >&2
  echo "a new one, so this build matches the one that was reviewed." >&2
  exit 1
fi

# --locked in every build command is what actually enforces this; the check
# here is so the failure says why rather than surfacing as a resolver error
# three minutes in.
mkdir -p "${OUT_DIR:-/out}"
cp extras/Cargo.lock "${OUT_DIR:-/out}/extras-Cargo.lock"
