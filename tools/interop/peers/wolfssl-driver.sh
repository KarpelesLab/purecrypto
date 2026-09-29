#!/usr/bin/env bash
# Peer adapter: a small DTLS program on libwolfssl (`wolfssl-driver/driver.c`,
# built on first use), for the DTLS resumption and 0-RTT cases wolfSSL's
# example client / server cannot express — above all 0-RTT towards a wolfSSL
# DTLS 1.3 *server*, which needs wolfSSL_dtls13_no_hrr_on_resume() (the
# examples never call it, so they always answer a resumed ClientHello with
# the cookie HelloRetryRequest that rejects early data, RFC 8446 §4.2.10) —
# plus the plain, resume and resume-loss cases of both DTLS versions (DTLS
# 1.2 resuming by RFC 5077 ticket) as a second libwolfssl client / server.
# Everything else is the `wolfssl` peer's (the examples); this adapter SKIPs
# it with that reason.
#
# WOLFSSL_HOME must hold `include/` and `lib/libwolfssl.a` of a libwolfssl
# built with DTLS 1.3, session tickets, early data and
# `-DWOLFSSL_DTLS13_NO_HRR_ON_RESUME` (`.github/workflows/interop.yml`
# installs one next to the examples). The driver prints `key: value` facts
# per connection (see driver.c), which `verify` checks.
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

WOLFSSL_HOME=${WOLFSSL_HOME:-$HOME/wolfssl}
# Built once per run (ROOT is the run's scratch directory), else next to
# the case.
DRIVER=${ROOT:-${WORK:-/tmp}}/wolfssl-driver.bin

build_driver() {
    [ -x "$DRIVER" ] && return 0
    local -a extra=(-lm -lpthread)
    # A macOS libwolfssl validates against the system trust store.
    [ "$(uname -s)" != Darwin ] || extra+=(-framework CoreFoundation -framework Security)
    "${CC:-cc}" -O1 -Wall -o "$DRIVER" "$HERE/wolfssl-driver/driver.c" \
        -I"$WOLFSSL_HOME/include" "$WOLFSSL_HOME/lib/libwolfssl.a" "${extra[@]}" >&2
}

is13() { [ "$CASE_PROTO" = dtls13 ]; }

wolf_cipher() {
    if is13; then
        echo TLS13-AES128-GCM-SHA256
    else
        case $CASE_CERT in
            rsa2048) echo ECDHE-RSA-AES128-GCM-SHA256 ;;
            *) echo ECDHE-ECDSA-AES128-GCM-SHA256 ;;
        esac
    fi
}
wolf_cipher_name() {
    if is13; then
        echo TLS_AES_128_GCM_SHA256
    else
        case $CASE_CERT in
            rsa2048) echo TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ;;
            *) echo TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ;;
        esac
    fi
}
proto_flag() { is13 || echo --dtls12; }

cmd_supports() {
    case $CASE_PROTO in
        dtls13|dtls12) ;;
        *) skip "TLS is covered by the wolfssl peer (the example tools)" ;;
    esac
    case $CASE_FEAT in
        plain|resume|resume-loss|0rtt) ;;
        *) skip "covered by the wolfssl peer (the example tools)" ;;
    esac
    # One combination each: the plain product is the wolfssl peer's.
    if [ "$CASE_CERT" != p256 ] || [ "$CASE_GROUP" != x25519 ] || [ "$CASE_SUITE" != aes128gcm ]; then
        skip "the driver runs P-256 / x25519 / AES-128-GCM only (the product is the wolfssl peer's)"
    fi
    if [ ! -f "$WOLFSSL_HOME/lib/libwolfssl.a" ]; then
        skip "no libwolfssl in \$WOLFSSL_HOME/lib"
    fi
    build_driver || { echo "cannot build the driver"; exit 2; }
    return 0
}

server_cmd() {
    local a=("$DRIVER" server --port @PORT@ --cert "$PKI/$CASE_CERT.crt" --key "$PKI/$CASE_CERT.key"
        --cipher "$(wolf_cipher)" --group "$CASE_GROUP")
    is13 || a+=(--dtls12)
    case $CASE_FEAT in
        resume|resume-loss) a+=(--accept 2) ;;
        # Skip the cookie HRR on a resumption from the ticket's address
        # (RFC 9147 §5.1) and read the 0-RTT data.
        0rtt) a+=(--accept 2 --early-data --no-hrr-on-resume) ;;
    esac
    printf '%s\n' "${a[@]}"
}

cmd_server() {
    build_driver
    local -a a=()
    while IFS= read -r l; do a+=("$l"); done < <(server_cmd)
    start_bg_server idle "${a[@]}"
}

cmd_client() {
    build_driver
    local -a a=("$DRIVER" client --port "$PORT" --ca "$PKI/ca.crt" --sni localhost
        --cipher "$(wolf_cipher)" --group "$CASE_GROUP" --msg "$(cat "$WORK/client.in")")
    is13 || a+=(--dtls12)
    case $CASE_FEAT in
        resume|resume-loss) a+=(--resume) ;;
        0rtt) a+=(--resume --early-data "$PKI/early.txt") ;;
    esac
    local rc=0
    "$TO" "$STEP_TIMEOUT" "${a[@]}" >"$WORK/client.out" 2>"$WORK/client.err" </dev/null || rc=$?
    return $rc
}

# block N FILE: the facts of connection N.
block() {
    awk -v n="$1" '/^== connection /{c=$3; next} c==n' "$2" >"$WORK/conn$1.facts"
    echo "$WORK/conn$1.facts"
}

cmd_verify() {
    local f ok=0 last=1 version
    if [ "$CASE_ROLE" = peer-server ]; then f=$WORK/server.out; else f=$WORK/client.out; fi
    case $CASE_FEAT in resume|resume-loss|0rtt) last=2 ;; esac
    if is13; then version=DTLSv1.3; else version=DTLSv1.2; fi
    local b1 bl
    b1=$(block 1 "$f")
    bl=$(block "$last" "$f")
    expect "$b1" "version: $version" || ok=1
    expect "$b1" "cipher: $(wolf_cipher_name)" || ok=1
    expect "$b1" "resumed: no" || ok=1
    expect "$bl" "version: $version" || ok=1
    case $CASE_FEAT in
        resume|resume-loss|0rtt) expect "$bl" "resumed: yes" || ok=1 ;;
    esac
    case $CASE_FEAT in
        0rtt)
            expect "$bl" "early data: accepted" || ok=1
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$bl" "early data received: early data from purecrypto" || ok=1
            fi ;;
        *) refute "$bl" "early data: accepted" || ok=1 ;;
    esac
    # The application data crossed on the (last) connection: the server saw
    # the client's line; the client got the purecrypto echo back.
    if [ "$CASE_ROLE" = peer-server ]; then
        expect "$bl" "received: ping from client" || ok=1
    else
        expect "$bl" "received: ping from client" || ok=1
        if [ "$CASE_FEAT" = 0rtt ]; then
            expect "$bl" "received: early data from purecrypto" || ok=1
        fi
    fi
    return $ok
}

case ${1:-} in
    info)
        v=$(sed -n 's/^#define LIBWOLFSSL_VERSION_STRING "\(.*\)"$/\1/p' "$WOLFSSL_HOME/include/wolfssl/version.h" 2>/dev/null)
        echo "wolfSSL ${v:-?} driver ($WOLFSSL_HOME)" ;;
    protos) echo "dtls13 dtls12" ;;
    supports) cmd_supports ;;
    server) cmd_server ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|protos|supports|server|client|verify" >&2; exit 2 ;;
esac
