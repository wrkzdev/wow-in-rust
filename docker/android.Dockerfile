# syntax=docker/dockerfile:1
#
# Android arm64-v8a and x86_64, API 24+, NDK r28c. Built by
# docker/build-dist.sh.
#
# Command-line binaries -- for Termux or `adb shell`, not an APK.
#
# No armeabi-v7a: wow-storage does not compile for a 32-bit target (a constant
# shifted past 32 bits in usize), so there is nothing to package until it does.
#
# Two link arguments stand in for what wow-randomwow's build.rs does not yet do
# for Android:
#
#   * build.rs links `stdc++`, which on Android is the system library holding
#     little more than operator new/delete. RandomWOW needs the real C++
#     runtime, so libc++ and libc++abi are linked statically here; without them
#     the link fails on __cxa_throw, std::runtime_error and the rest.
#   * RandomWOW's arm64 JIT flushes the instruction cache through
#     __clear_cache, which lives in compiler-rt's builtins archive. The clang
#     driver would normally add that, but rustc links with -nodefaultlibs.

FROM --platform=linux/amd64 rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake ninja-build unzip \
 && rm -rf /var/lib/apt/lists/*

# Checksum from Google's repository manifest (repository2-3.xml, ndk;28.2.13676358).
ARG NDK_VERSION=r28c
ARG NDK_SHA1=a7b54a5de87fecd125a17d54f73c446199e72a64
RUN curl -fsSLo /tmp/ndk.zip "https://dl.google.com/android/repository/android-ndk-${NDK_VERSION}-linux.zip" \
 && echo "${NDK_SHA1}  /tmp/ndk.zip" | sha1sum -c - \
 && unzip -q /tmp/ndk.zip -d /opt \
 && rm /tmp/ndk.zip
ENV ANDROID_NDK_ROOT=/opt/android-ndk-${NDK_VERSION}

ENV RUSTUP_TOOLCHAIN=1.98.1
RUN rustup target add aarch64-linux-android x86_64-linux-android

ENV CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_TARGET_DIR=/build

ARG GIT_REV=unknown
ARG SOURCE_DATE_EPOCH=315532800
ENV GIT_REV=$GIT_REV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

WORKDIR /src
COPY . .

RUN --mount=type=cache,id=wow-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=wow-target-android,target=/build <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

api=24
llvm=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64
builtins=$(echo "$llvm"/lib/clang/*/lib/linux)
clang_version=$("$llvm/bin/clang" --version | head -n1)

# rust target, clang wrapper prefix, compiler-rt arch
for spec in \
  "aarch64-linux-android aarch64-linux-android aarch64" \
  "x86_64-linux-android x86_64-linux-android x86_64"
do
  read -r target prefix arch <<<"$spec"
  var=${target//-/_}
  VAR=${var^^}

  export "CC_$var=$llvm/bin/$prefix$api-clang"
  export "CXX_$var=$llvm/bin/$prefix$api-clang++"
  export "AR_$var=$llvm/bin/llvm-ar"
  export "CARGO_TARGET_${VAR}_LINKER=$llvm/bin/$prefix$api-clang"
  export "CARGO_TARGET_${VAR}_RUSTFLAGS=-C link-arg=-lc++_static -C link-arg=-lc++abi -C link-arg=$builtins/libclang_rt.builtins-$arch-android.a"

  cargo build --release --locked --target "$target" \
    -p wownerod -p wownero-wallet-cli -p wownero-wallet-rpc
  bash docker/package.sh "$target" tar.gz "Android NDK $NDK_VERSION, $clang_version, API $api"
done
EOF

FROM scratch AS dist
COPY --from=build /out/ /
