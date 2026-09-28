#!/usr/bin/env bash
# Peer adapter: an OpenSSL built from source (3.5+: X25519MLKEM768, ML-DSA
# certificates, RFC 7250 raw public keys, RFC 8879 compression with zlib).
# Default location: $HOME/openssl-src/bin/openssl (what the CI job builds);
# OPENSSL overrides it.
OPENSSL=${OPENSSL:-$HOME/openssl-src/bin/openssl}
export OPENSSL
# shellcheck source=openssl.sh
. "$(cd "$(dirname "$0")" && pwd)/openssl.sh"
