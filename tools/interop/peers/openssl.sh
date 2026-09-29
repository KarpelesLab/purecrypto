#!/usr/bin/env bash
# Peer adapter: OpenSSL `s_client` / `s_server` (3.0 and later). Shared by
# `openssl-system` (the runner's `openssl`) and `openssl-src` (a build from
# source), which only set OPENSSL before sourcing this file. Capabilities
# are detected from the version string, so one adapter covers 3.0 (classical
# TLS 1.3 only) through 3.5+ (X25519MLKEM768, ML-DSA, RPK, compression).
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

OPENSSL=${OPENSSL:-openssl}
VERSION=$("$OPENSSL" version 2>/dev/null | awk '{print $2}')
VERSION=${VERSION:-0}

# OpenSSL's names for the case's group / suite.
ossl_group() {
    case $1 in
        x25519) echo X25519 ;;
        p256) echo P-256 ;;
        p384) echo P-384 ;;
        p521) echo P-521 ;;
        x25519mlkem768) echo X25519MLKEM768 ;;
        secp256r1mlkem768) echo SecP256r1MLKEM768 ;;
        secp384r1mlkem1024) echo SecP384r1MLKEM1024 ;;
    esac
}
# A regex for the group as the connection summaries spell it: a classical
# group shows as `Peer Temp Key: X25519, 253 bits` / `Peer Temp Key: ECDH,
# prime256v1, 256 bits` (`Server Temp Key:` on 3.0), a KEM hybrid as
# `Negotiated TLS1.3 group: X25519MLKEM768`.
ossl_group_re() {
    case $1 in
        x25519) echo "^(Peer|Server) Temp Key: X25519, 253 bits" ;;
        p256) echo "^(Peer|Server) Temp Key: ECDH, (prime256v1|secp256r1|P-256), 256 bits" ;;
        p384) echo "^(Peer|Server) Temp Key: ECDH, (secp384r1|P-384), 384 bits" ;;
        p521) echo "^(Peer|Server) Temp Key: ECDH, (secp521r1|P-521), 521 bits" ;;
        x25519mlkem768) echo "^(Negotiated TLS1.3 group|Peer Temp Key): X25519MLKEM768" ;;
        secp256r1mlkem768) echo "^(Negotiated TLS1.3 group|Peer Temp Key): SecP256r1MLKEM768" ;;
        secp384r1mlkem1024) echo "^(Negotiated TLS1.3 group|Peer Temp Key): SecP384r1MLKEM1024" ;;
    esac
}
# The group as `Supported groups:` lists it.
ossl_group_offer_name() {
    case $1 in
        x25519) echo x25519 ;;
        p256) echo secp256r1 ;;
        p384) echo secp384r1 ;;
        p521) echo secp521r1 ;;
        x25519mlkem768) echo X25519MLKEM768 ;;
        secp256r1mlkem768) echo SecP256r1MLKEM768 ;;
        secp384r1mlkem1024) echo SecP384r1MLKEM1024 ;;
    esac
}
ossl_suite() {
    case $1 in
        aes128gcm) echo TLS_AES_128_GCM_SHA256 ;;
        aes256gcm) echo TLS_AES_256_GCM_SHA384 ;;
        chacha20) echo TLS_CHACHA20_POLY1305_SHA256 ;;
    esac
}
# For HRR cases: the group the purecrypto side shares first (see run.sh).
other_group() {
    case $1 in
        x25519) echo P-256 ;;
        *) echo X25519 ;;
    esac
}

# RFC 8879 compression needs OpenSSL >= 3.2 built with the library for the
# algorithm (`enable-zlib`, `enable-brotli`, `enable-zstd`); the ones left
# out are in `list -disabled`.
has_comp() {
    ! "$OPENSSL" list -disabled 2>/dev/null | grep -qix -- "$1"
}
has_zlib() { has_comp ZLIB; }

cmd_supports() {
    case $CASE_GROUP in
        x25519mlkem768|secp256r1mlkem768|secp384r1mlkem1024)
            version_ge "$VERSION" 3.5 || skip "OpenSSL $VERSION has no ML-KEM hybrids (3.5+)" ;;
    esac
    case $CASE_CERT in
        mldsa65)
            version_ge "$VERSION" 3.5 || skip "OpenSSL $VERSION has no ML-DSA (3.5+)" ;;
    esac
    case $CASE_FEAT in
        certcomp|certcomp-client)
            version_ge "$VERSION" 3.2 || skip "OpenSSL $VERSION has no certificate compression (3.2+)"
            has_zlib || skip "OpenSSL $VERSION was built without zlib" ;;
        certcomp-brotli)
            version_ge "$VERSION" 3.2 || skip "OpenSSL $VERSION has no certificate compression (3.2+)"
            has_comp BROTLI || skip "OpenSSL $VERSION was built without brotli" ;;
        certcomp-zstd)
            version_ge "$VERSION" 3.2 || skip "OpenSSL $VERSION has no certificate compression (3.2+)"
            has_comp ZSTD || skip "OpenSSL $VERSION was built without zstd" ;;
        rpk|rpk-client)
            version_ge "$VERSION" 3.2 || skip "OpenSSL $VERSION has no RFC 7250 raw public keys (3.2+)" ;;
        rsl)
            skip "OpenSSL does not implement RFC 8449 record_size_limit" ;;
    esac
    return 0
}

# `-brief` puts the connection summary (version, suite, group, peer cert)
# on stderr for every connection; `-rev` echoes each line reversed, except
# where s_server refuses to combine it with `-early_data`. The
# peer-initiated KeyUpdate needs the interactive stdin body (`K`), which
# `-brief` disables along with the other command letters, so that case
# runs the plain server and reads its `CIPHER is` line instead.
server_args() {
    local a="s_server -accept @PORT@ -CAfile $PKI/ca.crt -naccept 1"
    case $CASE_FEAT in
        0rtt|0rtt-hrr) a="$a -brief" ;;
        keyupdate-peer) ;;
        *) a="$a -brief -rev" ;;
    esac
    if [ "$CASE_CERT" = large ]; then
        a="$a -cert $PKI/large-leaf.crt -key $PKI/large.key -cert_chain $PKI/large-int.crt"
    else
        a="$a -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key"
    fi
    if [ "$CASE_PROTO" = tls12 ]; then
        a="$a -tls1_2"
    else
        a="$a -tls1_3 -groups $(ossl_group "$CASE_GROUP") -ciphersuites $(ossl_suite "$CASE_SUITE")"
    fi
    case $CASE_FEAT in
        resume) a="$a -naccept 2" ;;
        # `-allow_no_dhe_kex` lets the server select psk_ke; it does so
        # only when the client advertises nothing else (the purecrypto
        # client advertises psk_ke alone in this case).
        resume-psk) a="$a -naccept 2 -allow_no_dhe_kex" ;;
        extpsk) a="$a -psk_identity $PSK_IDENTITY -psk $PSK_HEX" ;;
        0rtt) a="$a -naccept 2 -early_data -max_early_data 16384" ;;
        # Pinned to X25519 while the purecrypto client shares only P-256:
        # HelloRetryRequest on both connections, 0-RTT refused. With
        # anti-replay on (the default once early data is enabled) OpenSSL
        # keeps tickets stateful and single-use, so the ticket presented in
        # CH1 is gone when CH2 presents it again and the resumption fails
        # outright; `-no_anti_replay` keeps the ticket stateless, which is
        # what a deployment fronting HRR clients with 0-RTT needs anyway.
        0rtt-hrr) a="$a -naccept 2 -early_data -max_early_data 16384 -no_anti_replay" ;;
        mtls) a="$a -Verify 1 -verify_return_error" ;;
        # OpenSSL only sends compressed certificates it pre-compressed
        # (`-cert_comp`); the client's are accepted regardless, and the
        # purecrypto side pins the algorithm.
        certcomp|certcomp-brotli|certcomp-zstd) a="$a -cert_comp" ;;
        certcomp-client) a="$a -Verify 1 -verify_return_error" ;;
        rpk) a="$a -enable_server_rpk" ;;
        rpk-client) a="$a -enable_client_rpk -Verify 1" ;;
        ocsp) a="$a -status_file $OCSP" ;;
        alpn) a="$a -alpn h2,http/1.1" ;;
    esac
    echo "$a"
}

client_args() {
    local a="s_client -connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost"
    if [ "$CASE_PROTO" = tls12 ]; then
        a="$a -tls1_2"
    else
        a="$a -tls1_3 -groups $(ossl_group "$CASE_GROUP") -ciphersuites $(ossl_suite "$CASE_SUITE")"
    fi
    case $CASE_FEAT in
        # OpenSSL sends a key share for the first group only, so listing
        # another group first costs a HelloRetryRequest for the pinned one.
        hrr) a="s_client -connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost -tls1_3 -groups $(other_group "$CASE_GROUP"):$(ossl_group "$CASE_GROUP") -ciphersuites $(ossl_suite "$CASE_SUITE")" ;;
        0rtt-hrr) a="s_client -connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost -tls1_3 -groups P-256:X25519 -ciphersuites $(ossl_suite "$CASE_SUITE")" ;;
        mtls) a="$a -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key" ;;
        # (Unlike the server, s_client compresses its certificate on the
        # fly whenever the CertificateRequest invites it: no option.)
        certcomp-client) a="$a -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key" ;;
        rpk) a="$a -enable_server_rpk" ;;
        rpk-client) a="$a -enable_client_rpk -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key" ;;
        ocsp) a="$a -status" ;;
        alpn) a="$a -alpn h2,http/1.1" ;;
        # The client then advertises both modes; the purecrypto server
        # prefers psk_ke.
        resume-psk) a="$a -allow_no_dhe_kex" ;;
        extpsk) a="$a -psk_identity $PSK_IDENTITY -psk $PSK_HEX" ;;
    esac
    # A raw public key has no chain to validate against -CAfile; OpenSSL
    # reports the verify error and carries on unless told to abort. A PSK
    # handshake has no certificate to verify at all.
    case $CASE_FEAT in
        rpk|extpsk) ;;
        *) a="$a -verify_return_error" ;;
    esac
    echo "$a"
}

# One s_client run: stdin is the payload, kept open a moment so the echo
# (and the session ticket) can arrive before EOF ends the session. For the
# peer-initiated KeyUpdate a `K` line (OpenSSL's interactive command) goes
# first, in its own read — s_client discards the rest of the buffer it
# found the command in. For the purecrypto-initiated one the payload waits
# a second: OpenSSL answers a KeyUpdate(update_requested) with its own only
# on its next write, so writing before the request has arrived would leave
# the reply unsent.
run_client() {
    local tag=$1
    shift
    local rc=0
    {
        case $CASE_FEAT in
            keyupdate-peer) printf 'K\n'; sleep 1 ;;
            keyupdate) sleep 1 ;;
        esac
        cat "$WORK/client.in"
        sleep 1
    } | "$TO" "$STEP_TIMEOUT" "$OPENSSL" $(client_args) "$@" \
        >"$WORK/$tag.out" 2>"$WORK/$tag.err" || rc=$?
    return $rc
}

cmd_client() {
    case $CASE_FEAT in
        resume|resume-psk)
            run_client client -sess_out "$WORK/sess.pem"
            run_client client2 -sess_in "$WORK/sess.pem" ;;
        0rtt|0rtt-hrr)
            run_client client -sess_out "$WORK/sess.pem"
            run_client client2 -sess_in "$WORK/sess.pem" -early_data "$PKI/early.txt" ;;
        *)
            run_client client ;;
    esac
}

cmd_verify() {
    local ok=0 suite
    suite=$(ossl_suite "$CASE_SUITE")
    if [ "$CASE_ROLE" = peer-server ]; then
        local f=$WORK/server.err
        if [ "$CASE_FEAT" = keyupdate-peer ]; then
            # The plain (non-brief) server: its summary is on stdout and
            # names no group; the purecrypto side checks that one.
            expect "$WORK/server.out" "CIPHER is $suite" || ok=1
        elif [ "$CASE_PROTO" = tls12 ]; then
            expect "$f" "Protocol version: TLSv1.2" || ok=1
            expect_re "$f" "^Ciphersuite: (ECDHE|DHE)-" || ok=1
        else
            expect "$f" "Protocol version: TLSv1.3" || ok=1
            expect "$f" "Ciphersuite: $suite" || ok=1
            if version_ge "$VERSION" 3.2; then
                expect_re "$f" "$(ossl_group_re "$CASE_GROUP")" || ok=1
            else
                # 3.0's brief summary names no negotiated group; it does
                # list the client's offer, and the server was pinned.
                expect_re "$f" "^Supported groups: .*$(ossl_group_offer_name "$CASE_GROUP")" || ok=1
            fi
        fi
        # Application data: the reversed echo reached the client, or (no
        # `-rev`) the payload reached the server.
        case $CASE_FEAT in
            0rtt)
                expect "$WORK/server.out" "early data from purecrypto" || ok=1
                expect "$WORK/server.out" "ping from client" || ok=1 ;;
            # (The rejected early data is re-sent as 1-RTT data, so it does
            # reach the server; the purecrypto side reports the rejection.)
            0rtt-hrr)
                expect "$WORK/server.out" "ping from client" || ok=1 ;;
            keyupdate-peer)
                expect "$WORK/server.out" "ping from client" || ok=1 ;;
            *)
                expect "$WORK/client.out" "tneilc morf gnip" || ok=1 ;;
        esac
        case $CASE_FEAT in
            mtls|certcomp-client)
                expect_re "$f" "^Peer certificate: CN ?= ?localhost" || ok=1
                expect "$f" "Verification: OK" || ok=1 ;;
            # (The brief summary says nothing about the PSK; the client
            # side shows the handshake was a PSK one.)
            extpsk) expect "$f" "No peer certificate" || ok=1 ;;
        esac
    else
        local f=$WORK/client.out
        [ -f "$WORK/client2.out" ] && f=$WORK/client2.out
        if [ "$CASE_PROTO" = tls12 ]; then
            expect_re "$f" "^New, TLSv1.2, Cipher is (ECDHE|DHE)-" || ok=1
        else
            case $CASE_FEAT in
                # (A handshake under an external PSK counts as "Reused"
                # for OpenSSL: no certificate, PSK key schedule.)
                resume|0rtt|0rtt-hrr|resume-psk|extpsk) expect "$f" "Reused, TLSv1.3, Cipher is $suite" || ok=1 ;;
                *) expect "$f" "New, TLSv1.3, Cipher is $suite" || ok=1 ;;
            esac
            case $CASE_FEAT in
                # No key exchange on the resumed connection (its summary
                # still names the group of the key share it did not use:
                # `Negotiated TLS1.3 group` reports the client's share);
                # the first connection's is in client.out, and the
                # purecrypto side's report is what shows the mode.
                resume-psk) expect_re "$WORK/client.out" "$(ossl_group_re "$CASE_GROUP")" || ok=1 ;;
                *) expect_re "$f" "$(ossl_group_re "$CASE_GROUP")" || ok=1 ;;
            esac
        fi
        expect "$f" "ping from client" || ok=1
        case $CASE_FEAT in
            0rtt) expect "$f" "Early data was accepted" || ok=1 ;;
            0rtt-hrr) expect "$f" "Early data was rejected" || ok=1 ;;
            *) refute "$f" "Early data was accepted" || ok=1 ;;
        esac
        case $CASE_FEAT in
            alpn) expect "$f" "ALPN protocol: h2" || ok=1 ;;
            ocsp) expect "$f" "OCSP Response Status: successful" || ok=1 ;;
            rpk) expect "$f" "Server raw public key" || ok=1 ;;
            extpsk) expect "$f" "no peer certificate available" || ok=1 ;;
        esac
    fi
    return $ok
}

case ${1:-} in
    info) "$OPENSSL" version ;;
    supports) cmd_supports ;;
    server)
        case $CASE_FEAT in
            keyupdate-peer) start_bg_server delayed "$OPENSSL" $(server_args) ;;
            *) start_bg_server idle "$OPENSSL" $(server_args) ;;
        esac ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|supports|server|client|verify" >&2; exit 2 ;;
esac
