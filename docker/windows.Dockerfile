# syntax=docker/dockerfile:1
#
# Windows x86_64 (MinGW-w64), cross-compiled on Linux. Built by
# docker/build-dist.sh.
#
# libstdc++ is linked statically. Otherwise wownerod.exe imports
# libstdc++-6.dll, which RandomWOW pulls in, and will not start on a machine
# without MinGW.
#
# `-C link-arg=-static` alone does not do it: wow-randomwow's build.rs declares
# stdc++ as a dynamic library, and the binary still imports the DLL. What works
# is a search directory holding only the static archive, ahead of the
# toolchain's own directory, where libstdc++.dll.a sits beside libstdc++.a.

FROM --platform=linux/amd64 rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS build

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      cmake ninja-build zip gcc-mingw-w64-x86-64-posix g++-mingw-w64-x86-64-posix \
 && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_TOOLCHAIN=1.98.1
RUN rustup target add x86_64-pc-windows-gnu

RUN mkdir -p /opt/static-libstdcxx \
 && ln -s "$(x86_64-w64-mingw32-g++-posix -print-file-name=libstdc++.a)" /opt/static-libstdcxx/libstdc++.a \
 && test -f /opt/static-libstdcxx/libstdc++.a

ENV CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc-posix \
    CXX_x86_64_pc_windows_gnu=x86_64-w64-mingw32-g++-posix \
    AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc-posix \
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS="-L native=/opt/static-libstdcxx -C link-arg=-static" \
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
