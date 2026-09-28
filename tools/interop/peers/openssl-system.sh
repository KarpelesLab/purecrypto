#!/usr/bin/env bash
# Peer adapter: the system `openssl` (on the GitHub runner, OpenSSL 3.0.x —
# classical TLS 1.3 only). OPENSSL overrides the binary.
OPENSSL=${OPENSSL:-openssl}
export OPENSSL
# shellcheck source=openssl.sh
. "$(cd "$(dirname "$0")" && pwd)/openssl.sh"
