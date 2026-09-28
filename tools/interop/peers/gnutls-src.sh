#!/usr/bin/env bash
# Peer adapter: a GnuTLS built from source with leancrypto (3.8.10+:
# X25519MLKEM768 and ML-DSA certificates, which no distribution package
# has). Default location: $HOME/gnutls-src/bin (what the CI job builds);
# GNUTLS_SRC overrides the prefix.
GNUTLS_SRC=${GNUTLS_SRC:-$HOME/gnutls-src}
GNUTLS_CLI=${GNUTLS_CLI:-$GNUTLS_SRC/bin/gnutls-cli}
GNUTLS_SERV=${GNUTLS_SERV:-$GNUTLS_SRC/bin/gnutls-serv}
export GNUTLS_CLI GNUTLS_SERV
# shellcheck source=gnutls.sh
. "$(cd "$(dirname "$0")" && pwd)/gnutls.sh"
