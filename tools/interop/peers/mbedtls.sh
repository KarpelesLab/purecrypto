#!/usr/bin/env bash
# Peer adapter: Mbed TLS `ssl_client2` / `ssl_server2` (the programs under
# programs/ssl of a source build; MBEDTLS_BIN is the directory holding them,
# default $HOME/mbedtls/bin, what the CI job builds and caches).
#
# Both programs are HTTP-shaped rather than stdin-driven: the client sends
# one `GET <request_page> HTTP/1.0` request and prints what comes back, the
# server prints what it read and answers a canned page. The case's payload
# therefore travels as the request page (`request_page="ping from client"`),
# and a purecrypto client gets the canned page instead of an echo. Neither
# program prints the negotiated group, the PSK or the early-data outcome;
# the library's debug log does (`write selected_group:` and `key exchange
# mode:` on the server at level 2, `DHE group name:` and the per-message
# `<Message>: <extension>(N) extension exists.` lines on the client at
# level 3), so the adapter reads that.
#
# What Mbed TLS 4.2 cannot do is SKIPped with the reason: no KeyUpdate at
# all (a received one is an unexpected message), no EdDSA or ML-DSA, no
# ML-KEM hybrids, no RFC 7250 raw public keys, no RFC 8879 certificate
# compression, no `status_request` (OCSP stapling), and no handshake message
# over its fixed 16 KiB I/O buffer.
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

MBEDTLS_BIN=${MBEDTLS_BIN:-$HOME/mbedtls/bin}
CLIENT=$MBEDTLS_BIN/ssl_client2
SERVER=$MBEDTLS_BIN/ssl_server2

mbed_group() {
    case $1 in
        x25519) echo x25519 ;;
        p256) echo secp256r1 ;;
        p384) echo secp384r1 ;;
        p521) echo secp521r1 ;;
    esac
}
mbed_suite() {
    case $1 in
        aes128gcm) echo TLS1-3-AES-128-GCM-SHA256 ;;
        aes256gcm) echo TLS1-3-AES-256-GCM-SHA384 ;;
        chacha20) echo TLS1-3-CHACHA20-POLY1305-SHA256 ;;
    esac
}
other_group() {
    case $1 in
        x25519) echo secp256r1 ;;
        *) echo x25519 ;;
    esac
}

cmd_supports() {
    case $CASE_GROUP in
        x25519mlkem768|secp256r1mlkem768) skip "Mbed TLS has no ML-KEM hybrids" ;;
    esac
    case $CASE_CERT in
        ed25519) skip "Mbed TLS has no EdDSA" ;;
        mldsa65) skip "Mbed TLS has no ML-DSA" ;;
    esac
    case $CASE_FEAT in
        keyupdate|keyupdate-peer) skip "Mbed TLS does not implement TLS 1.3 KeyUpdate (a received one is an unexpected message)" ;;
        certcomp) skip "Mbed TLS has no RFC 8879 certificate compression" ;;
        rpk|rpk-client) skip "Mbed TLS has no RFC 7250 raw public keys" ;;
        ocsp) skip "Mbed TLS has no status_request (OCSP stapling)" ;;
        # A handshake message must fit the fixed 16 KiB I/O buffer
        # (MBEDTLS_SSL_{IN,OUT}_CONTENT_LEN cannot be set any larger): the
        # server cannot write the Certificate, the client cannot reassemble it.
        large-chain) skip "Mbed TLS handles no handshake message over its 16 KiB I/O buffer" ;;
    esac
    return 0
}

# The arguments are built in the ARGS array (the payload has spaces).
ARGS=()

# (buffer_size: the server's read buffer, 200 bytes by default; the
# record_size_limit case sends 3 KiB.)
server_args() {
    ARGS=(server_addr=127.0.0.1 server_port=@PORT@ debug_level=2 "ca_file=$PKI/ca.crt" buffer_size=8192
        "crt_file=$PKI/$CASE_CERT.crt" "key_file=$PKI/$CASE_CERT.key")
    if [ "$CASE_PROTO" = tls12 ]; then
        ARGS+=(force_version=tls12)
    else
        ARGS+=(force_version=tls13 "groups=$(mbed_group "$CASE_GROUP")" "force_ciphersuite=$(mbed_suite "$CASE_SUITE")")
    fi
    case $CASE_FEAT in
        0rtt) ARGS+=(early_data=1) ;;
        # The server answers one request per connection; the rejected early
        # data comes back as a first 1-RTT message before the payload.
        0rtt-hrr) ARGS+=(early_data=1 exchanges=2) ;;
        mtls) ARGS+=(auth_mode=required) ;;
        alpn) ARGS+=(alpn=h2,http/1.1) ;;
        # A response well over the 512-byte limit the purecrypto client
        # advertises, so the server has to split it (the purecrypto side
        # rejects an oversized record).
        rsl) ARGS+=(response_size=3000) ;;
    esac
}

client_args() {
    local groups
    ARGS=(server_addr=127.0.0.1 "server_port=$PORT" server_name=localhost debug_level=3 "ca_file=$PKI/ca.crt"
        auth_mode=required "request_page=$(cat "$WORK/client.in")")
    # A key share goes out for the first group only, so listing another
    # group first costs a HelloRetryRequest for the pinned one.
    case $CASE_FEAT in
        hrr) groups="$(other_group "$CASE_GROUP"),$(mbed_group "$CASE_GROUP")" ;;
        0rtt-hrr) groups=secp256r1,x25519 ;;
        *) groups=$(mbed_group "$CASE_GROUP") ;;
    esac
    if [ "$CASE_PROTO" = tls12 ]; then
        ARGS+=(force_version=tls12)
    else
        ARGS+=(force_version=tls13 "groups=$groups" "force_ciphersuite=$(mbed_suite "$CASE_SUITE")")
    fi
    case $CASE_FEAT in
        resume) ARGS+=(reconnect=1) ;;
        # The request goes out as early data and, once the handshake is
        # done, again as ordinary data (rejected or not).
        0rtt|0rtt-hrr) ARGS+=(reconnect=1 early_data=1) ;;
        mtls) ARGS+=("crt_file=$PKI/$CASE_CERT.crt" "key_file=$PKI/$CASE_CERT.key") ;;
        alpn) ARGS+=(alpn=h2,http/1.1) ;;
    esac
}

cmd_client() {
    local rc=0
    client_args
    "$TO" "$STEP_TIMEOUT" "$CLIENT" "${ARGS[@]}" \
        >"$WORK/client.out" 2>"$WORK/client.err" || rc=$?
    return $rc
}

cmd_verify() {
    local ok=0 suite group
    suite=$(mbed_suite "$CASE_SUITE")
    group=$(mbed_group "$CASE_GROUP")
    if [ "$CASE_ROLE" = peer-server ]; then
        local f=$WORK/server.out
        if [ "$CASE_PROTO" = tls12 ]; then
            expect "$f" "[ Protocol is TLSv1.2 ]" || ok=1
        else
            expect "$f" "[ Protocol is TLSv1.3 ]" || ok=1
            expect "$f" "[ Ciphersuite is $suite ]" || ok=1
            expect "$f" "server hello, write selected_group: $group" || ok=1
        fi
        expect "$f" "ping from client" || ok=1
        case $CASE_FEAT in
            hrr|0rtt-hrr) expect "$f" "=> write hello retry request" || ok=1 ;;
            *) refute "$f" "=> write hello retry request" || ok=1 ;;
        esac
        case $CASE_FEAT in
            resume|0rtt|0rtt-hrr) expect "$f" "key exchange mode: psk_ephemeral" || ok=1 ;;
            *) refute "$f" "key exchange mode: psk" || ok=1 ;;
        esac
        case $CASE_FEAT in
            0rtt)
                expect "$f" " early data bytes read" || ok=1
                expect "$f" "early data from purecrypto" || ok=1 ;;
            *) refute "$f" " early data bytes read" || ok=1 ;;
        esac
        case $CASE_FEAT in
            mtls) expect "$f" "Verifying peer X.509 certificate... ok" || ok=1 ;;
            alpn) expect "$f" "[ Application Layer Protocol is h2 ]" || ok=1 ;;
            # 3000 bytes in 511-byte records (the limit counts the content
            # type byte, RFC 8449 section 4).
            rsl)
                expect "$f" "RecordSizeLimit: 512 Bytes" || ok=1
                expect "$f" "3000 bytes written in 6 fragments" || ok=1 ;;
        esac
    else
        local f=$WORK/client.out
        if [ "$CASE_PROTO" = tls12 ]; then
            expect "$f" "[ Protocol is TLSv1.2 ]" || ok=1
        else
            expect "$f" "[ Protocol is TLSv1.3 ]" || ok=1
            expect "$f" "[ Ciphersuite is $suite ]" || ok=1
            expect "$f" "DHE group name: $group" || ok=1
        fi
        expect "$f" "Verifying peer X.509 certificate... ok" || ok=1
        expect "$f" "ping from client" || ok=1
        case $CASE_FEAT in
            hrr|0rtt-hrr) expect "$f" "received HelloRetryRequest message" || ok=1 ;;
            *) refute "$f" "received HelloRetryRequest message" || ok=1 ;;
        esac
        # The resumed handshake is the second one in the log; the first
        # (a full handshake) has no pre_shared_key in its ServerHello.
        case $CASE_FEAT in
            resume|0rtt|0rtt-hrr)
                expect "$f" "Reconnecting with saved session..." || ok=1
                expect "$f" "ServerHello: pre_shared_key(41) extension exists." || ok=1 ;;
            *) refute "$f" "ServerHello: pre_shared_key(41) extension exists." || ok=1 ;;
        esac
        case $CASE_FEAT in
            0rtt|0rtt-hrr) expect "$f" "bytes of early data written" || ok=1 ;;
        esac
        case $CASE_FEAT in
            0rtt) expect "$f" "EncryptedExtensions: early_data(42) extension exists." || ok=1 ;;
            *) refute "$f" "EncryptedExtensions: early_data(42) extension exists." || ok=1 ;;
        esac
        case $CASE_FEAT in
            mtls) expect "$f" "<= write certificate verify" || ok=1 ;;
            *) expect "$f" "skip write certificate verify" || ok=1 ;;
        esac
        case $CASE_FEAT in
            alpn) expect "$f" "[ Application Layer Protocol is h2 ]" || ok=1 ;;
            rsl) expect "$f" "RecordSizeLimit: 512 Bytes" || ok=1 ;;
        esac
    fi
    return $ok
}

case ${1:-} in
    info) "$CLIENT" build_version=1 2>/dev/null | sed -n 's/^build version: //p' ;;
    supports) cmd_supports ;;
    server) server_args; start_bg_server idle "$SERVER" "${ARGS[@]}" ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|supports|server|client|verify" >&2; exit 2 ;;
esac
