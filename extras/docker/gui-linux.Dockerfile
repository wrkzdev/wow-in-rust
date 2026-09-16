# syntax=docker/dockerfile:1
#
# The GUI wallet for Linux x86_64 and aarch64, glibc. Built by
# `docker/build-dist.sh gui-linux`.
#
# Debian bookworm, so it needs glibc >= 2.36 at runtime. X11, Wayland, OpenGL
# and xkbcommon are loaded when the program starts rather than linked, so the
# build needs no development packages, and any desktop that has them runs it.

FROM --platform=linux/amd64 rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_TOOLCHAIN=1.98.1
RUN rustup target add x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu

ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_TARGET_DIR=/build

ARG GIT_REV=unknown
ARG SOURCE_DATE_EPOCH=315532800
ENV GIT_REV=$GIT_REV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

WORKDIR /src
COPY . .

RUN --mount=type=cache,id=wow-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=wow-target-gui-linux,target=/build <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

bash extras/docker/lockfile.sh
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
  cargo build --release --locked --manifest-path extras/Cargo.toml \
    --target "$target" -p wownero-wallet-gui
done
bash extras/docker/package.sh gui x86_64-unknown-linux-gnu tar.gz \
  "gcc $(gcc -dumpfullversion), Debian bookworm"
bash extras/docker/package.sh gui aarch64-unknown-linux-gnu tar.gz \
  "aarch64-linux-gnu-gcc $(aarch64-linux-gnu-gcc -dumpfullversion), Debian bookworm"
EOF

FROM scratch AS dist
COPY --from=build /out/ /
