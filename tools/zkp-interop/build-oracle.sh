#!/usr/bin/env bash
# Clone and build secp256k1-zkp as a black-box interop oracle.
# Reads its public headers only; never its implementation sources.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="${here}/oracle"
rev="${SECP256K1_ZKP_REV:-master}"

if [ ! -d "$repo" ]; then
  git clone --depth 50 https://github.com/BlockstreamResearch/secp256k1-zkp "$repo"
fi
git -C "$repo" fetch --depth 50 origin "$rev"
git -C "$repo" checkout --detach FETCH_HEAD
echo "oracle rev: $(git -C "$repo" rev-parse HEAD)"

cd "$repo"
./autogen.sh
./configure \
  --enable-module-ecdsa-adaptor \
  --enable-module-ecdsa-s2c \
  --enable-module-generator \
  --enable-module-rangeproof \
  --enable-module-surjectionproof \
  --enable-module-whitelist \
  --enable-module-schnorrsig \
  --enable-experimental \
  --enable-benchmark=no \
  --enable-tests=no \
  --enable-exhaustive-tests=no
make -j"$(nproc)"
echo "built: $repo/.libs/libsecp256k1.a"
