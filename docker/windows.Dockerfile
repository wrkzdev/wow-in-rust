# syntax=docker/dockerfile:1
#
# Windows x86_64 (MinGW-w64), cross-compiled on Linux. Built by
# docker/build-dist.sh.
#
# Linked with `-static`, so the executables do not depend on MinGW's runtime
# DLLs and start on a machine without MinGW. The only C compiled is LMDB.

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
    --mount=type=cache,id=wow-target-windows,target=/build \
    set -eu; \
    cargo build --release --locked --target x86_64-pc-windows-gnu \
      -p wownerod -p wownero-wallet-cli -p wownero-wallet-rpc; \
    bash docker/package.sh x86_64-pc-windows-gnu zip \
      "x86_64-w64-mingw32-gcc-posix $(x86_64-w64-mingw32-gcc-posix -dumpfullversion), Debian bookworm, -static"

FROM scratch AS dist
COPY --from=build /out/ /
