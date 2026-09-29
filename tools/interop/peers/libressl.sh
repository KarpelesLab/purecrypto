#!/usr/bin/env bash
# Peer adapter: LibreSSL's `openssl s_client` / `s_server` (LIBRESSL, default
# $HOME/libressl/bin/openssl — what the CI job builds from the release
# tarball; on macOS the system /usr/bin/openssl is LibreSSL 3.3.x). Not a
# variant of peers/openssl.sh: LibreSSL's apps are OpenSSL-1.0-shaped and
# its TLS 1.3 stack is its own, so the flags, the summaries and the
# limitations all differ.
#
# What LibreSSL cannot express is SKIPped here, with the reason (all
# verified against 4.3.2 and 3.3.6):
#   - no TLS 1.3 session resumption at all: the ClientHello carries neither
#     psk_key_exchange_modes nor pre_shared_key and the server issues no
#     NewSessionTicket — so no PSK resumption and no 0-RTT in either role;
#   - no RFC 7627 extended_master_secret, which purecrypto requires on TLS
#     1.2 (RFC 7627 §5.3, `require_extended_master_secret`): the TLS 1.2
#     fallback aborts with handshake_failure in both roles, deliberately;
#   - no Ed25519 in TLS (the apps cannot load an Ed25519 key, the default
#     signature_algorithms omit ed25519), no ML-DSA, no RFC 8879
#     certificate compression, no RFC 7250 raw public keys, no RFC 8449
#     record_size_limit, nothing that triggers a KeyUpdate;
#   - X25519MLKEM768 from 4.3.0 on; and 3.3's server breaks on a
#     client-initiated KeyUpdate (see cmd_supports).
# Two more behaviours are worked around rather than skipped: `s_server`
# never sends close_notify (it sets the shutdown flags without writing the
# alert, like OpenSSL 1.0's did), so the runner is told through `quirks`
# not to demand one — the adapter itself checks the purecrypto server's log
# for the *client's* close_notify instead; and `s_server` has no
# `-status_file`, so the OCSP case stands up an `openssl ocsp` responder
# (the runner's OpenSSL: LibreSSL's own signs with SHA-1, which
# purecrypto's signature policy refuses) that `-status_url` points at.
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

LIBRESSL=${LIBRESSL:-$HOME/libressl/bin/openssl}
VERSION=$("$LIBRESSL" version 2>/dev/null | awk '$1 == "LibreSSL" { print $2 }')
VERSION=${VERSION:-0}
# The runner's OpenSSL, for the OCSP responder (see above).
OPENSSL=${OPENSSL:-openssl}

# `-naccept` arrived after 3.3: without it the server accepts forever and
# the adapter stops it once its one connection is over. (The usage text is
# captured whole: `… | grep -q` would trip pipefail on the SIGPIPE.)
SERVER_USAGE=$("$LIBRESSL" s_server -help 2>&1 || true)
has_naccept() {
    case $SERVER_USAGE in
        *-naccept*) return 0 ;;
    esac
    return 1
}

# LibreSSL's names for the case's group / suite. The suites are the IANA
# names, which 3.3 already accepts as aliases of its own `AEAD-…` spelling.
lssl_group() {
    case $1 in
        x25519) echo X25519 ;;
        p256) echo P-256 ;;
        p384) echo P-384 ;;
        p521) echo P-521 ;;
        x25519mlkem768) echo X25519MLKEM768 ;;
        secp256r1mlkem768) echo SecP256r1MLKEM768 ;;
    esac
}
lssl_suite() {
    case $1 in
        aes128gcm) echo TLS_AES_128_GCM_SHA256 ;;
        aes256gcm) echo TLS_AES_256_GCM_SHA384 ;;
        chacha20) echo TLS_CHACHA20_POLY1305_SHA256 ;;
    esac
}
# lssl_suite_re SUITE PREFIX: a regex for the suite as the summaries spell
# it after PREFIX (`Cipher    : ` on the client, `CIPHER is ` on the
# server): the IANA name from 3.4 on, `AEAD-AES128-GCM-SHA256` and friends
# before. (No `$` anchor: the pty output ends its lines in CR LF.)
lssl_suite_re() {
    case $1 in
        aes128gcm) echo "^$2(TLS_AES_128_GCM_SHA256|AEAD-AES128-GCM-SHA256)" ;;
        aes256gcm) echo "^$2(TLS_AES_256_GCM_SHA384|AEAD-AES256-GCM-SHA384)" ;;
        chacha20) echo "^$2(TLS_CHACHA20_POLY1305_SHA256|AEAD-CHACHA20-POLY1305-SHA256)" ;;
    esac
}
# The group as `Server Temp Key:` names it (the client prints no such
# line for the ML-KEM hybrid; the purecrypto side pins and checks it).
lssl_group_re() {
    case $1 in
        x25519) echo "^Server Temp Key: ECDH, X25519, 253 bits" ;;
        p256) echo "^Server Temp Key: ECDH, P-256, 256 bits" ;;
        p384) echo "^Server Temp Key: ECDH, P-384, 384 bits" ;;
        *) echo "" ;;
    esac
}
# For the HRR cases as the client: LibreSSL sends key shares for the first
# two groups of its list (one, before 4.x), so the pinned group goes third
# and the purecrypto server's pin costs the round trip either way.
hrr_client_groups() {
    case $1 in
        x25519) echo "P-256:P-384:X25519" ;;
        p256) echo "X25519:P-384:P-256" ;;
        p384) echo "X25519:P-256:P-384" ;;
        x25519mlkem768) echo "X25519:P-256:X25519MLKEM768" ;;
    esac
}

cmd_supports() {
    case $CASE_GROUP in
        x25519mlkem768)
            version_ge "$VERSION" 4.3 || skip "LibreSSL $VERSION has no X25519MLKEM768 (4.3+)" ;;
    esac
    case $CASE_CERT in
        ed25519) skip "LibreSSL has no Ed25519 in TLS (its apps cannot load the key; signature_algorithms omit ed25519)" ;;
        mldsa65) skip "LibreSSL has no ML-DSA" ;;
    esac
    case $CASE_FEAT in
        resume|0rtt|0rtt-hrr|resume-psk)
            skip "LibreSSL's TLS 1.3 has no session resumption (no psk_key_exchange_modes, no NewSessionTicket)" ;;
        extpsk) skip "LibreSSL's TLS 1.3 has no external PSK support" ;;
        keyupdate-peer) skip "LibreSSL's apps have no way to trigger a KeyUpdate" ;;
        # 3.3's server answers a client-initiated KeyUpdate with records
        # neither side can decrypt (bad_record_mac both ways — the same
        # against OpenSSL 3.6's `K`); its client, and 4.3's server, are fine.
        keyupdate)
            [ "$CASE_ROLE" = peer-client ] || version_ge "$VERSION" 3.4 ||
                skip "LibreSSL $VERSION s_server mishandles a client-initiated KeyUpdate (bad_record_mac both ways, also vs OpenSSL)" ;;
        certcomp) skip "LibreSSL does not implement RFC 8879 certificate compression" ;;
        rpk|rpk-client) skip "LibreSSL does not implement RFC 7250 raw public keys" ;;
        rsl) skip "LibreSSL does not implement RFC 8449 record_size_limit" ;;
        tls12)
            skip "LibreSSL has no RFC 7627 extended_master_secret; purecrypto requires it on TLS 1.2 (RFC 7627 §5.3)" ;;
        ocsp)
            [ "$CASE_ROLE" = peer-client ] || command -v "$OPENSSL" >/dev/null 2>&1 ||
                skip "no openssl to run an OCSP responder for s_server -status_url" ;;
    esac
    return 0
}

# s_server: pinned to the case's group and suite; the client's payload is
# printed on stdout and stdin (the runner's `server.in`, fed a second in)
# goes to the client. Only `-CAfile` builds the chain it sends, so the
# oversized chain's intermediate goes there (and only it: with the root
# too, LibreSSL sends all three).
server_args() {
    local a="s_server -accept @PORT@"
    if has_naccept; then a="$a -naccept 1"; fi
    if [ "$CASE_CERT" = large ]; then
        a="$a -cert $PKI/large-leaf.crt -key $PKI/large.key -CAfile $PKI/large-int.crt"
    else
        a="$a -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key -CAfile $PKI/ca.crt"
    fi
    a="$a -tls1_3 -groups $(lssl_group "$CASE_GROUP") -cipher $(lssl_suite "$CASE_SUITE")"
    case $CASE_FEAT in
        mtls) a="$a -Verify 1 -verify_return_error" ;;
        ocsp) a="$a -status -status_url http://127.0.0.1:$RESPONDER_PORT -status_verbose" ;;
        alpn) a="$a -alpn h2,http/1.1" ;;
    esac
    echo "$a"
}

client_args() {
    local a="s_client -connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost -verify_return_error -tls1_3"
    case $CASE_FEAT in
        hrr) a="$a -groups $(hrr_client_groups "$CASE_GROUP")" ;;
        *) a="$a -groups $(lssl_group "$CASE_GROUP")" ;;
    esac
    a="$a -cipher $(lssl_suite "$CASE_SUITE")"
    case $CASE_FEAT in
        mtls) a="$a -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key" ;;
        ocsp) a="$a -status" ;;
        alpn) a="$a -alpn h2,http/1.1" ;;
    esac
    echo "$a"
}

# The server side of a case, run in the foreground by `start_bg_server`
# (through `bash $0 _server`, so the responder and the watchdog share the
# server's process group and die with it):
#   - the OCSP case first starts the responder that `-status_url` names;
#   - without `-naccept`, s_server accepts forever and only a signal ends
#     it — which loses whatever its block-buffered stdout still holds, i.e.
#     the whole connection summary. So it runs on a pty (line-buffered, and
#     stderr folded into server.out), and is stopped once its summary ends
#     in CONNECTION CLOSED (or ERROR).
cmd__server() {
    local rpid="" spid watch=0
    has_naccept || watch=1
    if [ "$CASE_FEAT" = ocsp ]; then
        "$OPENSSL" ocsp -index "$PKI/index.txt" -CA "$PKI/ca.crt" -rsigner "$PKI/ca.crt" \
            -rkey "$PKI/ca.key" -rmd sha256 -ndays 1 -nrequest 1 -port "$RESPONDER_PORT" \
            >"$WORK/responder.out" 2>"$WORK/responder.err" &
        rpid=$!
    fi
    # (A background command's stdin defaults to /dev/null; the server must
    # keep the runner's feeder pipe.)
    if [ "$watch" = 1 ]; then
        # (macOS `script` refuses a fifo on stdin, hence the `cat`.)
        case $(script -V 2>&1 || true) in
            *util-linux*) cat <&0 | script -qec "$(printf '%q ' "$LIBRESSL" "$@")" /dev/null & ;;
            *) cat <&0 | script -q /dev/null "$LIBRESSL" "$@" & ;;
        esac
    else
        "$LIBRESSL" "$@" <&0 &
    fi
    spid=$!
    while kill -0 "$spid" 2>/dev/null; do
        if [ "$watch" = 1 ] && grep -q -E '^(CONNECTION CLOSED|ERROR)' "$WORK/server.out" 2>/dev/null; then
            kill "$spid" 2>/dev/null || true
            break
        fi
        sleep 0.2
    done
    # The `cat` of the pipeline, if any, is still blocked on the feeder
    # pipe — and `wait` on a pipeline's pid waits for the whole job, so
    # it goes first (the responder too: its request has been served).
    # shellcheck disable=SC2046
    kill $(jobs -p) 2>/dev/null || true
    wait "$spid" 2>/dev/null || true
    [ -z "$rpid" ] || kill "$rpid" 2>/dev/null || true
}

cmd_server() {
    RESPONDER_PORT=$(random_port)
    export RESPONDER_PORT
    # shellcheck disable=SC2046
    start_bg_server delayed bash "$0" _server $(server_args)
}

# One s_client run: stdin is the payload, kept open a moment so the echo
# can arrive before EOF ends the session. For the purecrypto-initiated
# KeyUpdate the payload waits a second, so the request is in before the
# client's first write.
cmd_client() {
    local rc=0
    {
        if [ "$CASE_FEAT" = keyupdate ]; then sleep 1; fi
        cat "$WORK/client.in"
        sleep 1
    } | "$TO" "$STEP_TIMEOUT" "$LIBRESSL" $(client_args) \
        >"$WORK/client.out" 2>"$WORK/client.err" || rc=$?
    return $rc
}

cmd_verify() {
    local ok=0 re
    if [ "$CASE_ROLE" = peer-server ]; then
        # s_server names the suite in its summary and the group nowhere
        # (the purecrypto side checks it; the server was pinned). On the
        # pty (3.3) stderr is folded into server.out, so the OCSP callback's
        # lines are looked for in both.
        cat "$WORK/server.out" "$WORK/server.err" >"$WORK/server-both.txt"
        expect_re "$WORK/server.out" "$(lssl_suite_re "$CASE_SUITE" "CIPHER is ")" || ok=1
        # Application data both ways: the payload reached the server, the
        # server's stdin reached the client.
        expect "$WORK/server.out" "ping from client" || ok=1
        expect "$WORK/client.out" "pong from server" || ok=1
        case $CASE_FEAT in
            # `-Verify 1 -verify_return_error`: the handshake only completes
            # with a verified client certificate, which the summary names.
            mtls) expect "$WORK/server.out" "subject=/CN=localhost" || ok=1 ;;
            ocsp)
                expect "$WORK/server-both.txt" "cert_status: ocsp response sent" || ok=1
                expect "$WORK/server-both.txt" "Cert Status: good" || ok=1 ;;
            alpn) expect "$WORK/server.out" "ALPN protocols selected: h2" || ok=1 ;;
        esac
    else
        local f=$WORK/client.out
        expect_re "$f" "^ *Protocol *: TLSv1.3$" || ok=1
        expect_re "$f" "$(lssl_suite_re "$CASE_SUITE" " *Cipher *: ")" || ok=1
        re=$(lssl_group_re "$CASE_GROUP")
        [ -z "$re" ] || expect_re "$f" "$re" || ok=1
        # The purecrypto server echoes the payload.
        expect "$f" "ping from client" || ok=1
        case $CASE_FEAT in
            alpn) expect "$f" "ALPN protocol: h2" || ok=1 ;;
            ocsp) expect "$f" "OCSP Response Status: successful" || ok=1 ;;
        esac
        # s_client does send close_notify; `quirks` only excused the
        # server, so check it here from the purecrypto server's report.
        expect "$WORK/server.err" "close_notify: received" || ok=1
    fi
    return $ok
}

case ${1:-} in
    info) "$LIBRESSL" version ;;
    quirks) echo no-close-notify ;;
    supports) cmd_supports ;;
    server) cmd_server ;;
    _server) shift; cmd__server "$@" ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|quirks|supports|server|client|verify" >&2; exit 2 ;;
esac
