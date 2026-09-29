#!/usr/bin/env bash
# Peer adapter: wolfSSL's example programs `examples/client/client` and
# `examples/server/server`, run from WOLFSSL_HOME (default $HOME/wolfssl, a
# directory holding `examples/client/client`, `examples/server/server` and
# the source tree's `certs/` — the examples chdir to the nearest ancestor
# with `certs/dh2048.pem` and refuse to start without one; the server also
# loads `certs/ocsp/*.pem` for its stapling setup).
#
# Beyond TLS 1.3 this peer speaks DTLS 1.2 and DTLS 1.3 (`protos`), which is
# what it is here for: purecrypto's DTLS 1.3 had never met another
# implementation before this adapter.
#
# What the example tools cannot express is SKIPped here, with the reason —
# see `cmd_supports`. Things worth knowing about them: the client sends a
# fixed greeting ("hello wolfssl!") rather than stdin, so a purecrypto
# server is verified by the greeting echoed back; the non-echo server
# reads one message and answers "I hear you fa shizzle!"; the server pins
# a key-exchange group with `-t` / `-Y` / `--force-curve` / `--pqc`
# (which also restricts its `supported_groups`, so a client offering the
# group without a share gets a HelloRetryRequest), the client with `-t`
# (X25519), `-Y` (P-256) or `--pqc` (a hybrid) only, so the purecrypto
# server pins P-384 by HelloRetryRequest and the plain P-384 case in that
# role is skipped; `-J` sends no key share at all (the HRR cases).
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

WOLFSSL_HOME=${WOLFSSL_HOME:-$HOME/wolfssl}
CLIENT=$WOLFSSL_HOME/examples/client/client
SERVER=$WOLFSSL_HOME/examples/server/server
# The examples look for `certs/` from the working directory upwards; every
# path handed to them below is absolute.
enter_home() {
    cd "$WOLFSSL_HOME" || exit 2
}

wolf_version() {
    "$CLIENT" '-?' 2>/dev/null | sed -n '1s/^wolfSSL client \([0-9.]*\).*$/\1/p'
}

# wolfSSL's `-l` spelling of the case's suite.
wolf_suite() {
    case $1 in
        aes128gcm) echo TLS13-AES128-GCM-SHA256 ;;
        aes256gcm) echo TLS13-AES256-GCM-SHA384 ;;
        chacha20) echo TLS13-CHACHA20-POLY1305-SHA256 ;;
    esac
}
# The IANA name its connection summary prints (`SSL cipher suite is …`).
wolf_suite_name() {
    case $1 in
        aes128gcm) echo TLS_AES_128_GCM_SHA256 ;;
        aes256gcm) echo TLS_AES_256_GCM_SHA384 ;;
        chacha20) echo TLS_CHACHA20_POLY1305_SHA256 ;;
    esac
}
# The (D)TLS 1.2 suite for the case's certificate kind and AEAD, as `-l`
# takes it and as the summary prints it (purecrypto's 1.2 engines cannot
# pin a suite from the command line, so this side does in both roles).
wolf_suite12() {
    local kx
    case $1 in rsa2048) kx=RSA ;; *) kx=ECDSA ;; esac
    case $2 in
        aes128gcm) echo "ECDHE-${kx}-AES128-GCM-SHA256" ;;
        aes256gcm) echo "ECDHE-${kx}-AES256-GCM-SHA384" ;;
        chacha20) echo "ECDHE-${kx}-CHACHA20-POLY1305" ;;
    esac
}
wolf_suite12_name() {
    local kx
    case $1 in rsa2048) kx=RSA ;; *) kx=ECDSA ;; esac
    case $2 in
        aes128gcm) echo "TLS_ECDHE_${kx}_WITH_AES_128_GCM_SHA256" ;;
        aes256gcm) echo "TLS_ECDHE_${kx}_WITH_AES_256_GCM_SHA384" ;;
        chacha20) echo "TLS_ECDHE_${kx}_WITH_CHACHA20_POLY1305_SHA256" ;;
    esac
}
# The group as `SSL curve name is …` prints it.
wolf_group_name() {
    case $1 in
        x25519) echo X25519 ;;
        p256) echo SECP256R1 ;;
        p384) echo SECP384R1 ;;
        p521) echo SECP521R1 ;;
        x25519mlkem768) echo X25519MLKEM768 ;;
        secp256r1mlkem768) echo SecP256r1MLKEM768 ;;
        secp384r1mlkem1024) echo SecP384r1MLKEM1024 ;;
    esac
}
# The server's option pinning the case's group (accept-set of one; a
# client that offers it without a share is sent a HelloRetryRequest).
server_group_opt() {
    case $1 in
        x25519) echo "-t" ;;
        p256) echo "-Y" ;;
        p384) echo "--force-curve SECP384R1" ;;
        p521) echo "--force-curve SECP521R1" ;;
        x25519mlkem768) echo "--pqc X25519MLKEM768" ;;
        secp256r1mlkem768) echo "--pqc SecP256r1MLKEM768" ;;
        secp384r1mlkem1024) echo "--pqc SecP384r1MLKEM1024" ;;
    esac
}
# The client's option sharing (only) the case's group, or empty when the
# tool has none for it.
client_group_opt() {
    case $1 in
        x25519) echo "-t" ;;
        p256) echo "-Y" ;;
        x25519mlkem768) echo "--pqc X25519MLKEM768" ;;
        secp256r1mlkem768) echo "--pqc SecP256r1MLKEM768" ;;
        secp384r1mlkem1024) echo "--pqc SecP384r1MLKEM1024" ;;
        *) echo "" ;;
    esac
}

is_dtls() { case $CASE_PROTO in dtls*) return 0 ;; esac; return 1; }
is_13() { case $CASE_PROTO in tls13|dtls13) return 0 ;; esac; return 1; }
# `-v N`: 4 = (D)TLS 1.3, 3 = (D)TLS 1.2; `-u` = UDP.
proto_opts() {
    local v
    if is_13; then v=4; else v=3; fi
    if is_dtls; then echo "-u -v $v"; else echo "-v $v"; fi
}

cmd_supports() {
    case $CASE_FEAT in
        certcomp|certcomp-brotli|certcomp-zstd|certcomp-client) skip "wolfSSL does not implement RFC 8879 certificate compression" ;;
        0rtt-hrr)
            if [ "$CASE_ROLE" = peer-client ]; then
                # The resumed connection shares the group the session
                # negotiated, so nothing the server does makes it take a
                # HelloRetryRequest.
                skip "the wolfSSL example client shares the resumed session's group on the second connection, so it takes no HelloRetryRequest"
            else
                # After answering a resumed ClientHello with a
                # HelloRetryRequest the server deprotects the 0-RTT records
                # it must skip under the early keys it already derived,
                # stays in that read state, and refuses the plaintext second
                # ClientHello with unexpected_message (5.9.4; its own client
                # never exercises this, since it shares the session's group).
                skip "wolfSSL server refuses the second ClientHello after skipping 0-RTT records across a HelloRetryRequest"
            fi ;;
        rsl) skip "wolfSSL does not implement RFC 8449 record_size_limit" ;;
        # The example server staples only responses it fetched itself from
        # the certificate's OCSP responder (no file option); the example
        # client requests stapling with a nonce (WOLFSSL_CSR_OCSP_USE_NONCE)
        # and rejects a response that does not echo it, which a
        # pre-generated stapled response never does.
        ocsp) skip "the wolfSSL examples cannot staple from a file nor accept a stapled response without their nonce" ;;
        # The example server has no raw-public-key option at all, and the
        # example client's `--rpk` offers raw keys for both directions with
        # no X.509 fallback, so it cannot present a raw client key to a
        # server it verifies by certificate.
        rpk) [ "$CASE_ROLE" = peer-client ] ||
            skip "the wolfSSL example server has no raw-public-key option" ;;
        rpk-client) skip "the wolfSSL examples cannot present a raw client key to an X.509 server" ;;
        # The example programs' built-in TLS 1.3 PSK (`-s`) is
        # `Client_identity` with the key the extpsk cases use, so no key
        # file is needed; `-K` forces psk_ke. The client sends its identity
        # verbatim only with `--openssl-psk` (otherwise `my_psk_client_cs_cb`
        # appends the cipher suite), and its `-s` turns certificate
        # verification off, which is what an external-PSK client wants.
        resume-psk|extpsk) : ;;
    esac
    if [ "$CASE_ROLE" = peer-client ]; then
        # The client shares X25519 (-t), P-256 (-Y) or a hybrid (--pqc);
        # P-384 it offers but never shares first, which the hrr case covers.
        if is_13 && [ "$CASE_FEAT" != hrr ] && [ -z "$(client_group_opt "$CASE_GROUP")" ]; then
            skip "the wolfSSL example client has no option to share $CASE_GROUP first (covered by hrr)"
        fi
    fi
    if [ "$CASE_PROTO" = dtls12 ] && [ "$CASE_ROLE" = peer-server ] &&
        [ "$CASE_CERT" = p384 ] && [ "$CASE_GROUP" != p384 ]; then
        # RFC 8422 §5.1.1: a (D)TLS 1.2 client's supported_groups also
        # limits the curves of the ECDSA certificate it accepts, and the
        # wolfSSL server enforces it (handshake_failure) — then uses that
        # same curve for ECDHE whatever the client listed first.
        skip "the wolfSSL (D)TLS 1.2 server takes its ECDSA certificate's curve for ECDHE and requires it in supported_groups (RFC 8422 §5.1.1)"
    fi
    if [ "$CASE_PROTO" = dtls13 ] && [ "$CASE_ROLE" = peer-server ] &&
        [ "$CASE_FEAT" != hrr ]; then
        case $CASE_GROUP in
            x25519mlkem768|secp256r1mlkem768|secp384r1mlkem1024)
                # The stateless server validates the cookie on the first
                # fragment of a ClientHello and drops a cookieless one; a
                # first ClientHello carrying a hybrid share (1216 to 1665
                # bytes) does not fit in one 1200-byte datagram (wolfSSL's
                # own client sends an empty key_share and takes the
                # HelloRetryRequest instead — which the hrr case exercises).
                skip "the wolfSSL stateless DTLS 1.3 server drops a fragmented first ClientHello (the hybrid share does not fit in one datagram; covered by hrr)" ;;
        esac
    fi
    return 0
}

cert_opts() {
    local kind=$1
    if [ "$kind" = large ]; then
        echo "-c $PKI/large.crt -k $PKI/large.key"
    else
        echo "-c $PKI/$kind.crt -k $PKI/$kind.key"
    fi
}

# The server: one connection (two with `-r`: the second must resume),
# reading one message and answering it; `-d` unless the case wants a
# client certificate verified against `-A`.
server_args() {
    local a="-p @PORT@ $(proto_opts) -A $PKI/ca.crt $(cert_opts "$CASE_CERT")"
    if is_13; then
        a="$a -l $(wolf_suite "$CASE_SUITE") $(server_group_opt "$CASE_GROUP")"
    elif is_dtls; then
        a="$a -l $(wolf_suite12 "$CASE_CERT" "$CASE_SUITE")"
    fi
    case $CASE_FEAT in
        mtls|rpk-client) ;;
        *) a="$a -d" ;;
    esac
    case $CASE_FEAT in
        resume) a="$a -r" ;;
        0rtt) a="$a -r -0" ;;
        # Pinned to X25519 while the purecrypto client shares only P-256:
        # HelloRetryRequest on both connections, the early data refused.
        0rtt-hrr) a="$a -r -0" ;;
        # PSK-only ticket resumption: `-r` for a second (resumed)
        # connection, `-K` so the resumption uses psk_ke (no (EC)DHE).
        resume-psk) a="$a -r -K" ;;
        # An external PSK by the built-in identity/key; `-d` above is kept
        # so the server does not demand a client certificate.
        extpsk) a="$a -s" ;;
        keyupdate-peer) a="$a -U" ;;
        rpk) a="$a --rpk" ;;
        alpn) a="$a -L C:h2,http/1.1" ;;
        cid) a="$a --cid $(wolf_cid)" ;;
    esac
    echo "$a"
}

# `--cid STRING` takes the CID as the string's bytes: PEER_CID as ASCII.
wolf_cid() {
    printf '%b' "$(echo "$PEER_CID" | sed 's/\(..\)/\\x\1/g')"
}

# `-w` waits for the purecrypto server's close_notify — except over DTLS
# with `-I`, where the example client writes a second message it never
# reads back: `wolfSSL_shutdown` refuses to send the close_notify while
# that echo is pending ("Pending application data, read it before
# shutdown"), so with `-w` it spins until the timeout and without it the
# client exits with no close_notify at all when the echo arrived first
# (see `cmd_quirks`). Nor under `loss`, where the close_notify may be the
# dropped datagram.
#
# Over TCP the same second message makes `-w` hang the client whenever
# the echo server reads it on its own: `s_server` echoes it, the client's
# first bidirectional `wolfSSL_shutdown` decrypts that echo, and every
# later call returns WOLFSSL_SHUTDOWN_NOT_DONE on "Pending application
# data" without reading — while the socket, holding our close_notify and
# FIN, stays readable, so the `-w` loop spins until the timeout. When the
# message and the client's close_notify arrive together the server has
# already closed and there is no echo, so the case only flaked (on a
# loaded runner). Without `-w` the client still sends its close_notify
# first thing in `wolfSSL_shutdown` (verified on our side, no quirk); only
# its own check that ours arrived is lost, in this one case.
client_shutdown_opt() {
    if [ "$CASE_FEAT" = keyupdate-peer ] || { is_dtls && [ "$CASE_FEAT" = loss ]; }; then
        echo ""
    else
        echo "-w"
    fi
}

# Per-case tool limitations the runner allows for.
cmd_quirks() {
    if [ "${CASE_PROTO:-}" = dtls13 ] && [ "${CASE_ROLE:-}" = peer-client ] &&
        [ "${CASE_FEAT:-}" = keyupdate-peer ]; then
        # The client's `-I` flow (above) may exit without a close_notify;
        # the KeyUpdate exchange itself is what the case verifies.
        echo no-close-notify
    fi
}

client_args() {
    local a="-h 127.0.0.1 -p $PORT $(proto_opts) -A $PKI/ca.crt -S localhost -m $(client_shutdown_opt)"
    if is_13; then
        a="$a -l $(wolf_suite "$CASE_SUITE")"
    elif is_dtls; then
        a="$a -l $(wolf_suite12 "$CASE_CERT" "$CASE_SUITE")"
    fi
    case $CASE_FEAT in
        # `-J` sends no key share: the purecrypto server, pinned to the
        # group, asks for it with a HelloRetryRequest.
        hrr) a="$a -J" ;;
        *) if is_13; then a="$a $(client_group_opt "$CASE_GROUP")"; fi ;;
    esac
    case $CASE_FEAT in
        mtls) a="$a $(cert_opts "$CASE_CERT")" ;;
        rpk-client) a="$a $(cert_opts "$CASE_CERT") --rpk" ;;
        # `-s` (external PSK) turns off the peer-certificate check itself;
        # `-x` would only add noise.
        extpsk) ;;
        *) a="$a -x" ;;
    esac
    case $CASE_FEAT in
        resume) a="$a -r" ;;
        0rtt) a="$a -r -0" ;;
        0rtt-hrr) a="$a -r -0" ;;
        # `-r` reconnects and resumes; `-K` makes the resumed handshake
        # psk_ke.
        resume-psk) a="$a -r -K" ;;
        # `--openssl-psk` sends the identity (`Client_identity`) verbatim,
        # as the interop key expects; without it the example appends the
        # cipher suite to the identity.
        extpsk) a="$a -s --openssl-psk" ;;
        keyupdate-peer) a="$a -I" ;;
        # The example client cannot pin a raw server key: `--rpk` turns its
        # peer check off, so only the purecrypto side (which pins) verifies.
        rpk) a="$a --rpk" ;;
        ocsp) a="$a -W 1" ;;
        alpn) a="$a -L C:h2,http/1.1" ;;
        cid) a="$a --cid $(wolf_cid)" ;;
    esac
    echo "$a"
}

cmd_client() {
    local rc=0
    enter_home
    # shellcheck disable=SC2046
    "$TO" "$STEP_TIMEOUT" "$CLIENT" $(client_args) \
        >"$WORK/client.out" 2>"$WORK/client.err" </dev/null || rc=$?
    return $rc
}

# The CID summary (`CID extension was negotiated`, then `Sending CID is
# HEX` — the purecrypto side's CID, printed without zero padding, which
# PC_CID's bytes do not need).
verify_cid() {
    local f=$1 ok=0
    expect "$f" "CID extension was negotiated" || ok=1
    expect "$f" "Sending CID is $PC_CID" || ok=1
    return $ok
}

# The connection summary the examples print after each handshake (on
# stdout): `SSL version is TLSv1.3`, `SSL cipher suite is …`, `SSL curve
# name is …`.
verify_summary() {
    local f=$1 ok=0
    case $CASE_PROTO in
        tls13) expect "$f" "SSL version is TLSv1.3" || ok=1 ;;
        tls12) expect "$f" "SSL version is TLSv1.2" || ok=1 ;;
        dtls13) expect "$f" "SSL version is DTLSv1.3" || ok=1 ;;
        dtls12) expect "$f" "SSL version is DTLSv1.2" || ok=1 ;;
    esac
    if is_13; then
        expect "$f" "SSL cipher suite is $(wolf_suite_name "$CASE_SUITE")" || ok=1
        expect "$f" "SSL curve name is $(wolf_group_name "$CASE_GROUP")" || ok=1
    elif is_dtls; then
        expect "$f" "SSL cipher suite is $(wolf_suite12_name "$CASE_CERT" "$CASE_SUITE")" || ok=1
        expect "$f" "SSL curve name is $(wolf_group_name "$CASE_GROUP")" || ok=1
    fi
    return $ok
}

cmd_verify() {
    local ok=0
    if [ "$CASE_ROLE" = peer-server ]; then
        verify_summary "$WORK/server.out" || ok=1
        # The message reached the server, its answer reached the client.
        case $CASE_FEAT in
            0rtt)
                expect "$WORK/server.out" "Early Data Client message: early data from purecrypto" || ok=1
                expect "$WORK/server.out" "Client message: ping from client" || ok=1 ;;
            0rtt-hrr)
                refute "$WORK/server.out" "Early Data Client message" || ok=1
                expect "$WORK/server.out" "Client message: ping from client" || ok=1 ;;
            *)
                # (Over DTLS the example server's read path returns without
                # printing the message; its answer, which follows the
                # read, is the evidence.)
                is_dtls || expect "$WORK/server.out" "Client message: ping from client" || ok=1 ;;
        esac
        # (Under `loss` the answer may be the dropped datagram: only the
        # handshake is checked.)
        [ "$CASE_FEAT" = loss ] || expect "$WORK/client.out" "I hear you fa shizzle!" || ok=1
        case $CASE_FEAT in
            resume|0rtt|0rtt-hrr|resume-psk) expect "$WORK/server.out" "SSL reused session" || ok=1 ;;
            *) refute "$WORK/server.out" "SSL reused session" || ok=1 ;;
        esac
        case $CASE_FEAT in
            mtls) expect "$WORK/server.out" "subject: /CN=localhost" || ok=1 ;;
            alpn) expect "$WORK/server.out" "Sent ALPN protocol : h2" || ok=1 ;;
            # The server logs that the peer sent no certificate (a PSK
            # handshake); the message wolfSSL prints to stderr.
            extpsk) expect "$WORK/server.err" "peer has no cert!" || ok=1 ;;
            cid) verify_cid "$WORK/server.out" || ok=1 ;;
        esac
    else
        local f=$WORK/client.out
        verify_summary "$f" || ok=1
        # The greeting came back from the purecrypto echo server.
        [ "$CASE_FEAT" = loss ] || expect "$f" "hello wolfssl!" || ok=1
        case $CASE_FEAT in
            resume|0rtt|0rtt-hrr|resume-psk) expect "$f" "SSL reused session" || ok=1 ;;
            *) refute "$f" "SSL reused session" || ok=1 ;;
        esac
        case $CASE_FEAT in
            alpn) expect "$f" "Received ALPN protocol : h2" || ok=1 ;;
            ocsp) refute "$WORK/client.err" "OCSP" || ok=1 ;;
            cid) verify_cid "$f" || ok=1 ;;
        esac
        if [ -n "$(client_shutdown_opt)" ]; then
            expect "$f" "Bidirectional shutdown complete" || ok=1
        fi
    fi
    return $ok
}

case ${1:-} in
    info) enter_home && echo "wolfSSL $(wolf_version) ($WOLFSSL_HOME)" ;;
    protos) echo "tls13 tls12 dtls13 dtls12" ;;
    quirks) cmd_quirks ;;
    supports) cmd_supports ;;
    # shellcheck disable=SC2046
    server) enter_home && start_bg_server idle "$SERVER" $(server_args) ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|protos|quirks|supports|server|client|verify" >&2; exit 2 ;;
esac
