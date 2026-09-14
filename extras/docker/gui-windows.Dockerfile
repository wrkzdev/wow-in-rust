# syntax=docker/dockerfile:1
#
# The GUI wallet for Windows x86_64 (MinGW-w64), cross-compiled on Linux. Built
# by `docker/build-dist.sh gui-windows`.
#
# Linked with `-static`, as the command-line archives are, so it needs none of
# MinGW's DLLs. OpenGL is Windows' own opengl32.dll.

FROM --platform=linux/amd64 rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends zip gcc-mingw-w64-x86-64-posix \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_TOOLCHAIN=1.98.1
RUN rustup target add x86_64-pc-windows-gnu

ENV CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc-posix \
    AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc-posix \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS="-C link-arg=-static" \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_TARGET_DIR=/build

ARG GIT_REV=unknown
ARG SOURCE_DATE_EPOCH=315532800
ENV GIT_REV=$GIT_REV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

WORKDIR /src
COPY . .

RUN --mount=type=cache,id=wow-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=wow-target-gui-windows,target=/build <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

bash extras/docker/lockfile.sh
cargo build --release --locked --manifest-path extras/Cargo.toml \
  --target x86_64-pc-windows-gnu -p wownero-wallet-gui
bash extras/docker/package.sh gui x86_64-pc-windows-gnu zip \
  "x86_64-w64-mingw32-gcc-posix $(x86_64-w64-mingw32-gcc-posix -dumpfullversion), Debian bookworm, -static"
EOF

FROM scratch AS dist
COPY --from=build /out/ /
