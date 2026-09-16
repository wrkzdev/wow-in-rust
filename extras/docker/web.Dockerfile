# syntax=docker/dockerfile:1
#
# The web wallet: static files, compiled to wasm32 and bound by wasm-bindgen.
# Built by `docker/build-dist.sh web`.
#
# wasm-bindgen-cli must match the wasm-bindgen crate exactly, so it is
# installed at the version extras/Cargo.lock names, and kept in the build cache.

FROM --platform=linux/amd64 rust:1.98.1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS build

ENV RUSTUP_TOOLCHAIN=1.98.1
RUN rustup target add wasm32-unknown-unknown

ENV CARGO_TARGET_DIR=/build

ARG GIT_REV=unknown
ARG SOURCE_DATE_EPOCH=315532800
ENV GIT_REV=$GIT_REV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

WORKDIR /src
COPY . .

RUN --mount=type=cache,id=wow-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=wow-target-web,target=/build <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

bash extras/docker/lockfile.sh

version=$(awk '$0 == "name = \"wasm-bindgen\"" { getline; gsub(/"/, "", $3); print $3; exit }' extras/Cargo.lock)
tools=/build/tools/wasm-bindgen-$version
if [ ! -x "$tools/bin/wasm-bindgen" ]; then
  cargo install --locked wasm-bindgen-cli --version "$version" --root "$tools"
fi
export PATH="$tools/bin:$PATH"

OUT=/stage bash extras/wallet-web/build.sh
bash extras/docker/package.sh web /stage "wasm-bindgen $version"
EOF

FROM scratch AS dist
COPY --from=build /out/ /
