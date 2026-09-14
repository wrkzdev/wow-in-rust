#!/usr/bin/env bash
# Build release archives in Docker and hash them.
#
#   docker/build-dist.sh                  # linux windows macos android
#   docker/build-dist.sh linux android    # a subset
#   docker/build-dist.sh extras           # web gui-linux gui-windows gui-macos
#   docker/build-dist.sh web gui-windows  # any of those, by name
#
# Output:
#   dist/<platform>/wownero-rs-<version>-<rust-target>.{tar.gz,zip}
#   dist/web/wownero-rs-wallet-web-<version>.tar.gz
#   dist/gui-<os>/wownero-rs-wallet-gui-<version>-<rust-target>.{tar.gz,zip}
#   dist/SHA256SUMS                       # every archive under dist/
#
# Needs Docker with BuildKit (Docker Desktop, or Engine 23+). Every build runs
# in a linux/amd64 container, so the host OS does not matter; on an arm64 host
# that means emulation, which is slow but gives the same result.
#
# The exception is gui-macos. The GUI needs Apple's SDK, which no container
# has, so on a macOS host it builds natively (extras/macos/build.sh), and on
# any other host it is skipped with a note.
set -euo pipefail

cd "$(dirname "$0")/.."

all=(linux windows macos android)
extras=(web gui-linux gui-windows gui-macos)
if [ $# -eq 0 ]; then
  set -- "${all[@]}"
fi
platforms=()
for p in "$@"; do
  case $p in
    extras) platforms+=("${extras[@]}") ;;
    *)
      case " ${all[*]} ${extras[*]} " in
        *" $p "*) platforms+=("$p") ;;
        *) echo "unknown platform '$p' (expected: ${all[*]} ${extras[*]}, or extras)" >&2; exit 2 ;;
      esac
      ;;
  esac
done

# Provenance for BUILDINFO. A tree with uncommitted changes says so, rather
# than claiming a commit it was not built from.
rev=$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
if [ -n "$(git status --porcelain -- . ':!dist' 2>/dev/null)" ]; then
  rev=$rev-dirty
fi
epoch=$(git log -1 --format=%ct 2>/dev/null || echo 315532800)

mkdir -p dist
printf '*\n' > dist/.gitignore   # build output never belongs in the repo

in_docker() {
  local dockerfile=$1 platform=$2
  rm -rf "dist/$platform"
  docker buildx build \
    --platform linux/amd64 \
    --file "$dockerfile" \
    --build-arg "GIT_REV=$rev" \
    --build-arg "SOURCE_DATE_EPOCH=$epoch" \
    --target dist \
    --output "type=local,dest=dist/$platform" \
    .
}

for p in "${platforms[@]}"; do
  echo "==> $p"
  case $p in
    gui-macos)
      if [ "$(uname -s)" != Darwin ]; then
        echo "skipped: the macOS GUI wallet builds on a macOS host only"
        continue
      fi
      rm -rf "dist/$p"
      GIT_REV=$rev bash extras/macos/build.sh "dist/$p"
      ;;
    web | gui-*) in_docker "extras/docker/$p.Dockerfile" "$p" ;;
    *) in_docker "docker/$p.Dockerfile" "$p" ;;
  esac
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
