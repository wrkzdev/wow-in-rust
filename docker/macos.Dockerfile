# syntax=docker/dockerfile:1
#
# macOS arm64 and x86_64, cross-linked with zig through cargo-zigbuild. Built by
# docker/build-dist.sh.
#
# No Apple SDK is involved: zig carries the macOS libc headers, and the
# binaries load nothing but system libraries (libSystem, plus libiconv for
# wownerod and the CLI wallet). They require macOS 13 or later.
#
# zig's linker gives the arm64 binaries the ad-hoc code signature arm64 macOS
# needs before it will run anything; the x86_64 ones carry none, which Intel
# macOS does not require. Nothing is notarized, so a downloaded copy is
# quarantined by Gatekeeper until `xattr -d com.apple.quarantine <file>`.
#
# Left unstripped, so nothing rewrites a binary after the linker has signed it.

FROM --platform=linux/amd64 rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends xz-utils \
 && rm -rf /var/lib/apt/lists/*

# 0.16.0 is the release cargo-zigbuild's own CI tests against. Checksum from
# ziglang.org/download/index.json.
ARG ZIG_VERSION=0.16.0
ARG ZIG_SHA256=70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00
RUN curl -fsSLo /tmp/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" \
 && echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - \
 && tar -xJf /tmp/zig.tar.xz -C /opt \
 && ln -s "/opt/zig-x86_64-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig \
 && rm /tmp/zig.tar.xz

ENV RUSTUP_TOOLCHAIN=1.98.1
RUN rustup target add aarch64-apple-darwin x86_64-apple-darwin \
 && cargo install --locked cargo-zigbuild@0.23.4

ENV CARGO_TARGET_DIR=/build

ARG GIT_REV=unknown
ARG SOURCE_DATE_EPOCH=315532800
ENV GIT_REV=$GIT_REV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

WORKDIR /src
COPY . .

RUN --mount=type=cache,id=wow-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=wow-target-macos,target=/build \
    --mount=type=cache,id=wow-zig-cache,target=/root/.cache/zig \
    set -eu; \
    for t in aarch64-apple-darwin x86_64-apple-darwin; do \
      cargo zigbuild --release --locked --target "$t" \
        -p wownerod -p wownero-wallet-cli -p wownero-wallet-rpc; \
      bash docker/package.sh "$t" tar.gz "zig $(zig version), $(cargo-zigbuild --version), no Apple SDK"; \
    done

FROM scratch AS dist
COPY --from=build /out/ /
