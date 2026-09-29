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
# Beyond TLS this peer speaks DTLS 1.2 (`protos`; Mbed TLS has no DTLS
# 1.3), which makes it the second implementation purecrypto's RFC 9146
# connection IDs are checked against (`cid=1 cid_val=HEX` on both
# programs; the peer's CID is PEER_CID, and `Peer CID (length N Bytes): …`
# in its summary is the purecrypto side's). Over DTLS the programs are
# driven with `dtls=1 force_version=dtls12`; the server does its
# HelloVerifyRequest cookie exchange by default.
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
# The (D)TLS 1.2 suite for the case's certificate kind and AEAD, as
# `force_ciphersuite` takes it and the summary prints it (purecrypto's 1.2
# engines cannot pin a suite from the command line, so this side does).
mbed_suite12() {
    local kx
    case $1 in rsa2048) kx=RSA ;; *) kx=ECDSA ;; esac
    case $2 in
        aes128gcm) echo "TLS-ECDHE-${kx}-WITH-AES-128-GCM-SHA256" ;;
        aes256gcm) echo "TLS-ECDHE-${kx}-WITH-AES-256-GCM-SHA384" ;;
        chacha20) echo "TLS-ECDHE-${kx}-WITH-CHACHA20-POLY1305-SHA256" ;;
    esac
}
is_dtls() { case $CASE_PROTO in dtls*) return 0 ;; esac; return 1; }
# The CID options of both programs for a `cid` case (RFC 9146): the CID
# this side receives under is PEER_CID.
mbed_cid_args() {
    case $CASE_FEAT in
        cid) echo "cid=1 cid_val=$PEER_CID" ;;
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
        x25519mlkem768|secp256r1mlkem768|secp384r1mlkem1024) skip "Mbed TLS has no ML-KEM hybrids" ;;
    esac
    case $CASE_CERT in
        ed25519) skip "Mbed TLS has no EdDSA" ;;
        mldsa65) skip "Mbed TLS has no ML-DSA" ;;
    esac
    case $CASE_FEAT in
        keyupdate|keyupdate-peer) skip "Mbed TLS does not implement TLS 1.3 KeyUpdate (a received one is an unexpected message)" ;;
        certcomp|certcomp-brotli|certcomp-zstd|certcomp-client) skip "Mbed TLS has no RFC 8879 certificate compression" ;;
        rpk|rpk-client) skip "Mbed TLS has no RFC 7250 raw public keys" ;;
        ocsp) skip "Mbed TLS has no status_request (OCSP stapling)" ;;
        # A handshake message must fit the fixed 16 KiB I/O buffer
        # (MBEDTLS_SSL_{IN,OUT}_CONTENT_LEN cannot be set any larger): the
        # server cannot write the Certificate, the client cannot reassemble it.
        large-chain|mtu) skip "Mbed TLS handles no handshake message over its 16 KiB I/O buffer" ;;
        # RFC 8446 §4.2.9: the Mbed TLS server's built-in order prefers
        # psk_ephemeral, then ephemeral, and picks plain psk (psk_ke) only
        # when no (EC)DHE is available — but the purecrypto client still
        # offers a key_share, so the server always finds ephemeral and
        # never selects psk_ke. Its client, though, accepts a psk_ke
        # ServerHello, so the purecrypto-server role runs.
        resume-psk) [ "$CASE_ROLE" = peer-client ] ||
            skip "the Mbed TLS server prefers (psk_)ephemeral and never selects psk_ke while a key_share is offered" ;;
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
    if is_dtls; then
        # shellcheck disable=SC2046
        ARGS+=(dtls=1 force_version=dtls12 "groups=$(mbed_group "$CASE_GROUP")"
            "force_ciphersuite=$(mbed_suite12 "$CASE_CERT" "$CASE_SUITE")" $(mbed_cid_args))
    elif [ "$CASE_PROTO" = tls12 ]; then
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
        # An external PSK by identity/key (RFC 8446 §4.2.11); the
        # certificate stays for a client that offers no PSK.
        extpsk) ARGS+=("psk=$PSK_HEX" "psk_identity=$PSK_IDENTITY") ;;
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
    if is_dtls; then
        # shellcheck disable=SC2046
        ARGS+=(dtls=1 force_version=dtls12 "groups=$groups"
            "force_ciphersuite=$(mbed_suite12 "$CASE_CERT" "$CASE_SUITE")" $(mbed_cid_args))
    elif [ "$CASE_PROTO" = tls12 ]; then
        ARGS+=(force_version=tls12)
    else
        ARGS+=(force_version=tls13 "groups=$groups" "force_ciphersuite=$(mbed_suite "$CASE_SUITE")")
    fi
    case $CASE_FEAT in
        # (D)TLS 1.2: an RFC 5077 ticket; TLS 1.3: a PSK. `resume-loss` is
        # the DTLS resumption through the lossy relay.
        resume|resume-loss) ARGS+=(reconnect=1) ;;
        # PSK-only ticket resumption: reconnect with the saved session; the
        # client advertises both modes (default) and the purecrypto server
        # selects psk_ke.
        resume-psk) ARGS+=(reconnect=1) ;;
        # An external PSK by identity/key; no certificate is verified.
        extpsk) ARGS+=("psk=$PSK_HEX" "psk_identity=$PSK_IDENTITY" auth_mode=none) ;;
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

# The CID summary of a `cid` case (RFC 9146): negotiated, and the CID this
# program sends with is the purecrypto side's (PC_CID as spaced hex).
verify_cid() {
    local f=$1 ok=0
    expect "$f" "(initial handshake) Use of Connection ID has been negotiated." || ok=1
    expect "$f" "(initial handshake) Peer CID (length 4 Bytes): $(echo "$PC_CID" | sed 's/\(..\)/\1 /g')" || ok=1
    return $ok
}

cmd_verify() {
    local ok=0 suite group
    suite=$(mbed_suite "$CASE_SUITE")
    group=$(mbed_group "$CASE_GROUP")
    if is_dtls; then
        verify_dtls
        return $?
    fi
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
            resume|0rtt|0rtt-hrr|extpsk) expect "$f" "key exchange mode: psk_ephemeral" || ok=1 ;;
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
        case $CASE_FEAT in
            extpsk) : ;;  # a PSK handshake sends no certificate
            *) expect "$f" "Verifying peer X.509 certificate... ok" || ok=1 ;;
        esac
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
            resume-psk)
                expect "$f" "Reconnecting with saved session..." || ok=1
                expect "$f" "ServerHello: pre_shared_key(41) extension exists." || ok=1
                # psk_ke: the resumed ServerHello carries no key_share.
                expect "$f" "Selected key exchange mode: psk" || ok=1 ;;
            # An external PSK: pre_shared_key in the ServerHello, no ticket
            # to reconnect with.
            extpsk) expect "$f" "ServerHello: pre_shared_key(41) extension exists." || ok=1 ;;
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

# The DTLS 1.2 view: version and suite from the summary, the group from
# the server's debug log (`ECDHE curve: x25519`; the client's log does not
# name it — the purecrypto server pins it and reports it), the payload
# both ways, and the CIDs.
verify_dtls() {
    local ok=0 f
    if [ "$CASE_ROLE" = peer-server ]; then
        f=$WORK/server.out
        expect "$f" "ECDHE curve: $(mbed_group "$CASE_GROUP")" || ok=1
        expect "$f" "ping from client" || ok=1
    else
        f=$WORK/client.out
        expect "$f" "Verifying peer X.509 certificate... ok" || ok=1
        expect "$f" "ping from client" || ok=1
    fi
    expect "$f" "[ Protocol is DTLSv1.2 ]" || ok=1
    expect "$f" "[ Ciphersuite is $(mbed_suite12 "$CASE_CERT" "$CASE_SUITE") ]" || ok=1
    case $CASE_FEAT in
        alpn) expect "$f" "[ Application Layer Protocol is h2 ]" || ok=1 ;;
        cid) verify_cid "$f" || ok=1 ;;
        *) refute "$f" "Use of Connection ID has been negotiated" || ok=1 ;;
    esac
    # RFC 5077 resumption: the client's second handshake is the abbreviated
    # one (its debug log; the server logs at a level too low to say, and
    # the purecrypto client reports it in that role).
    if [ "$CASE_ROLE" = peer-client ]; then
        case $CASE_FEAT in
            resume|resume-loss)
                expect "$f" "Reconnecting with saved session..." || ok=1
                expect "$f" "a session has been resumed" || ok=1 ;;
            *) refute "$f" "a session has been resumed" || ok=1 ;;
        esac
    fi
    return $ok
}

case ${1:-} in
    info) "$CLIENT" build_version=1 2>/dev/null | sed -n 's/^build version: //p' ;;
    protos) echo "tls13 tls12 dtls12" ;;
    supports) cmd_supports ;;
    server) server_args; start_bg_server idle "$SERVER" "${ARGS[@]}" ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|protos|supports|server|client|verify" >&2; exit 2 ;;
esac
