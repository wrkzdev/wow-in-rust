#!/usr/bin/env bash
# Build release archives in Docker and hash them.
#
#   docker/build-dist.sh                  # linux windows macos android
#   docker/build-dist.sh linux android    # a subset
#
# Output:
#   dist/<platform>/wownero-rs-<version>-<rust-target>.{tar.gz,zip}
#   dist/SHA256SUMS                       # every archive under dist/
#
# Needs Docker with BuildKit (Docker Desktop, or Engine 23+). Every build runs
# in a linux/amd64 container, so the host OS does not matter; on an arm64 host
# that means emulation, which is slow but gives the same result.
set -euo pipefail

cd "$(dirname "$0")/.."

all=(linux windows macos android)
if [ $# -eq 0 ]; then
  set -- "${all[@]}"
fi
for p in "$@"; do
  case " ${all[*]} " in
    *" $p "*) ;;
    *) echo "unknown platform '$p' (expected: ${all[*]})" >&2; exit 2 ;;
  esac
done

if [ ! -f third_party/randomwow/src/configuration.h ]; then
  echo "third_party/randomwow is empty. Run:" >&2
  echo "  git submodule update --init third_party/randomwow" >&2
  exit 1
fi

# Provenance for BUILDINFO. A tree with uncommitted changes says so, rather
# than claiming a commit it was not built from.
rev=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [ -n "$(git status --porcelain -- . ':!dist' 2>/dev/null)" ]; then
  rev=$rev-dirty
fi
epoch=$(git log -1 --format=%ct 2>/dev/null || echo 315532800)

mkdir -p dist
printf '*\n' > dist/.gitignore   # build output never belongs in the repo

for p in "$@"; do
  echo "==> $p"
  rm -rf "dist/$p"
  docker buildx build \
    --platform linux/amd64 \
    --file "docker/$p.Dockerfile" \
    --build-arg "GIT_REV=$rev" \
    --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    --target dist \
    --output "type=local,dest=dist/$p" \
    .
done

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

# Hash everything present, not just what this run built, so SHA256SUMS always
# describes the whole of dist/. Paths are relative: `cd dist && sha256sum -c SHA256SUMS`.
(
  cd dist
  find . -mindepth 2 -type f \( -name '*.tar.gz' -o -name '*.zip' \) \
    | sed 's|^\./||' | LC_ALL=C sort \
    | while IFS= read -r f; do sha256 "$f"; done > SHA256SUMS
)

echo
echo "dist/SHA256SUMS:"
cat dist/SHA256SUMS
