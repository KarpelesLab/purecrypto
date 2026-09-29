#!/usr/bin/env bash
# Peer adapter: BoringSSL's `bssl client` / `bssl server` (the tool behind
# the ECH interop job), at whatever commit BSSL points to (default
# $HOME/bssl/bssl, what the CI job builds).
#
# What the tool cannot express is SKIPped here, with the reason: the server
# has no ALPN or session-ticket knobs beyond the defaults, neither side can
# pin a TLS 1.3 cipher suite (the client offers all three, the server picks
# in its own order), nothing triggers a KeyUpdate, no certificate
# compression algorithm is registered, ML-DSA certificates and RFC 8449
# are not implemented. Neither role of the tool sends close_notify (the
# client half-closes on stdin EOF, the server exits when it reads ours), so
# the runner is told through `quirks` not to demand one.
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

BSSL=${BSSL:-$HOME/bssl/bssl}

bssl_group() {
    case $1 in
        x25519) echo X25519 ;;
        p256) echo P-256 ;;
        p384) echo P-384 ;;
        p521) echo P-521 ;;
        x25519mlkem768) echo X25519MLKEM768 ;;
    esac
}
bssl_suite() {
    case $1 in
        aes128gcm) echo TLS_AES_128_GCM_SHA256 ;;
        aes256gcm) echo TLS_AES_256_GCM_SHA384 ;;
        chacha20) echo TLS_CHACHA20_POLY1305_SHA256 ;;
    esac
}
other_group() {
    case $1 in
        x25519) echo P-256 ;;
        *) echo X25519 ;;
    esac
}

cmd_supports() {
    case $CASE_CERT in
        mldsa65) skip "BoringSSL has no ML-DSA certificates" ;;
    esac
    # BoringSSL's TLS groups are P-256/384/521, X25519, X25519MLKEM768 and
    # a standalone MLKEM1024 (`kNamedGroups` in ssl/ssl_key_share.cc).
    case $CASE_GROUP in
        secp256r1mlkem768|secp384r1mlkem1024) skip "BoringSSL has no NIST-curve ML-KEM hybrids" ;;
    esac
    # The client offers every TLS 1.3 suite and the purecrypto server takes
    # its first, so only that one can be pinned from the peer's side.
    if [ "$CASE_ROLE" = peer-client ] && [ "$CASE_SUITE" != aes128gcm ]; then
        skip "bssl client cannot restrict the TLS 1.3 cipher suites it offers"
    fi
    case $CASE_FEAT in
        keyupdate-peer) skip "bssl has no way to trigger a KeyUpdate" ;;
        certcomp|certcomp-brotli|certcomp-zstd|certcomp-client) skip "the bssl tool registers no certificate compression algorithm" ;;
        alpn) [ "$CASE_ROLE" = peer-client ] || skip "bssl server has no ALPN option" ;;
        rsl) skip "BoringSSL does not implement RFC 8449 record_size_limit" ;;
        # The tool treats SSL_ERROR_EARLY_DATA_REJECTED as fatal instead of
        # resetting and retrying as the API asks.
        0rtt-hrr) [ "$CASE_ROLE" = peer-server ] || skip "bssl client does not recover from rejected 0-RTT" ;;
        # BoringSSL sends a key share for the ML-KEM hybrid whatever its
        # position in the list, so no HelloRetryRequest for it can be forced.
        hrr) [ "$CASE_ROLE" = peer-server ] || [ "$CASE_GROUP" != x25519mlkem768 ] ||
            skip "bssl client always shares X25519MLKEM768; no HRR possible" ;;
        # BoringSSL's default signature preferences leave out Ed25519, and
        # the server has no flag to add it to its CertificateRequest.
        mtls) [ "$CASE_ROLE" = peer-client ] || [ "$CASE_CERT" != ed25519 ] ||
            skip "bssl server has no flag to accept Ed25519 client signatures" ;;
        # RFC 8446 §4.2.9: BoringSSL only ever does psk_dhe_ke — it never
        # offers or selects psk_ke (`SSL_OP_ALLOW_NO_DHE_KEX` is not exposed
        # by the tool and BoringSSL implements no PSK-only key exchange).
        resume-psk) skip "BoringSSL does not implement PSK-only (psk_ke) key exchange" ;;
    esac
    return 0
}

server_args() {
    local a="server -accept @PORT@"
    if [ "$CASE_CERT" = large ]; then
        a="$a -cert $PKI/large.crt -key $PKI/large.key"
    else
        a="$a -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key"
    fi
    if [ "$CASE_PROTO" = tls12 ]; then
        a="$a -max-version tls1.2"
    else
        a="$a -curves $(bssl_group "$CASE_GROUP")"
    fi
    case $CASE_FEAT in
        resume) a="$a -loop" ;;
        0rtt|0rtt-hrr) a="$a -loop -early-data" ;;
        # The tool accepts any client certificate (no CA to verify
        # against); the purecrypto side is what gets verified here.
        mtls) a="$a -require-any-client-cert" ;;
        rpk) a="$a -rpk-key $PKI/$CASE_CERT.key" ;;
        rpk-client) a="$a -require-any-client-cert -accept-cert-types rpk,x509" ;;
        ocsp) a="$a -ocsp-response $OCSP" ;;
        # An external PSK imported per RFC 9258 (`-psk-hex` runs the
        # importer, empty context, SHA-256); the certificate stays for a
        # client that offers no PSK.
        extpsk) a="$a -psk-hex $PSK_HEX -psk-identity $PSK_IDENTITY" ;;
    esac
    echo "$a"
}

client_args() {
    local a="client -connect 127.0.0.1:$PORT -server-name localhost -root-certs $PKI/ca.crt"
    if [ "$CASE_PROTO" = tls12 ]; then
        a="$a -max-version tls1.2"
    else
        a="$a -curves $(bssl_group "$CASE_GROUP")"
    fi
    # Ed25519 is off in BoringSSL's default signature preferences (both
    # verifying and signing); the tool's -sigalgs sets both.
    if [ "$CASE_CERT" = ed25519 ]; then
        a="$a -sigalgs ed25519:ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512"
    fi
    case $CASE_FEAT in
        # A key share goes out for the first group only.
        hrr) a="client -connect 127.0.0.1:$PORT -server-name localhost -root-certs $PKI/ca.crt -curves $(other_group "$CASE_GROUP"):$(bssl_group "$CASE_GROUP")" ;;
        resume) a="$a -test-resumption" ;;
        0rtt) a="$a -test-resumption -early-data @$PKI/early.txt" ;;
        0rtt-hrr) a="client -connect 127.0.0.1:$PORT -server-name localhost -root-certs $PKI/ca.crt -curves P-256:X25519 -test-resumption -early-data @$PKI/early.txt" ;;
        mtls) a="$a -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key" ;;
        # A raw public key cannot be verified against a root store; the
        # tool prints the key it received and the purecrypto side pins.
        rpk) a="client -connect 127.0.0.1:$PORT -server-name localhost -curves $(bssl_group "$CASE_GROUP") -accept-cert-types rpk,x509" ;;
        rpk-client) a="$a -rpk-key $PKI/$CASE_CERT.key" ;;
        ocsp) a="$a -ocsp-stapling" ;;
        alpn) a="$a -alpn-protos h2,http/1.1" ;;
        # An external PSK imported per RFC 9258; no certificate to verify.
        extpsk) a="client -connect 127.0.0.1:$PORT -server-name localhost -curves $(bssl_group "$CASE_GROUP") -psk-hex $PSK_HEX -psk-identity $PSK_IDENTITY" ;;
    esac
    echo "$a"
}

cmd_client() {
    local rc=0
    # For the purecrypto-initiated KeyUpdate the payload waits a second, so
    # the request has arrived before the client's first write carries the
    # reply along.
    {
        if [ "$CASE_FEAT" = keyupdate ]; then sleep 1; fi
        cat "$WORK/client.in"
        sleep 1
    } | "$TO" "$STEP_TIMEOUT" "$BSSL" $(client_args) \
        >"$WORK/client.out" 2>"$WORK/client.err" || rc=$?
    return $rc
}

# The connection summary the tool prints after each handshake, on stderr.
verify_summary() {
    local f=$1 ok=0
    if [ "$CASE_PROTO" = tls12 ]; then
        expect "$f" "Version: TLSv1.2" || ok=1
    else
        expect "$f" "Version: TLSv1.3" || ok=1
        expect "$f" "Cipher: $(bssl_suite "$CASE_SUITE")" || ok=1
        expect "$f" "ECDHE group: $(bssl_group "$CASE_GROUP")" || ok=1
    fi
    case $CASE_FEAT in
        resume|0rtt|0rtt-hrr) expect "$f" "Resumed session: yes" || ok=1 ;;
        *) refute "$f" "Resumed session: yes" || ok=1 ;;
    esac
    case $CASE_FEAT in
        0rtt) expect "$f" "Early data: yes" || ok=1 ;;
        *) refute "$f" "Early data: yes" || ok=1 ;;
    esac
    return $ok
}

cmd_verify() {
    local ok=0
    if [ "$CASE_ROLE" = peer-server ]; then
        verify_summary "$WORK/server.err" || ok=1
        # The server forwards its stdin to the client and prints what the
        # client sent. (Under `-loop` the stdin payload went to the first,
        # ticket-only connection, so the resumed one gets nothing back.)
        expect "$WORK/server.out" "ping from client" || ok=1
        case $CASE_FEAT in
            resume|0rtt|0rtt-hrr) ;;
            *) expect "$WORK/client.out" "pong from server" || ok=1 ;;
        esac
        case $CASE_FEAT in
            0rtt) expect "$WORK/server.out" "early data from purecrypto" || ok=1 ;;
            mtls|rpk-client)
                if [ "$CASE_FEAT" = mtls ]; then
                    expect_re "$WORK/server.err" "^  Cert subject: CN ?= ?localhost" || ok=1
                else
                    expect "$WORK/server.err" "Peer RPK pubkey:" || ok=1
                fi ;;
        esac
    else
        verify_summary "$WORK/client.err" || ok=1
        expect "$WORK/client.out" "ping from client" || ok=1
        case $CASE_FEAT in
            0rtt) expect "$WORK/client.out" "early data from purecrypto" || ok=1 ;;
            alpn) expect "$WORK/client.err" "ALPN protocol: h2" || ok=1 ;;
            ocsp) expect "$WORK/client.err" "OCSP staple: yes" || ok=1 ;;
            rpk) expect "$WORK/client.err" "Peer RPK pubkey:" || ok=1 ;;
        esac
    fi
    return $ok
}

case ${1:-} in
    info) echo "bssl ($BSSL)" ;;
    quirks)
        # Space-separated on one line: run.sh's has_quirk matches
        # space-delimited tokens. BoringSSL's external PSK is the RFC 9258
        # importer only, so the purecrypto side must import too.
        if [ "${CASE_FEAT:-}" = extpsk ]; then
            echo "no-close-notify extpsk-importer"
        else
            echo no-close-notify
        fi ;;
    supports) cmd_supports ;;
    # The server forwards its stdin to the client; for the
    # purecrypto-initiated KeyUpdate the payload waits a second so the
    # request is in before the write that carries BoringSSL's reply.
    server)
        case $CASE_FEAT in
            keyupdate) start_bg_server delayed "$BSSL" $(server_args) ;;
            *) start_bg_server payload "$BSSL" $(server_args) ;;
        esac ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|quirks|supports|server|client|verify" >&2; exit 2 ;;
esac
