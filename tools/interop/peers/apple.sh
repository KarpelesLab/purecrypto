#!/usr/bin/env bash
# Peer adapter: Apple's TLS stack — Network.framework (NWConnection /
# NWListener with NWProtocolTLS, `sec_protocol_options_*`) on macOS, driven
# through the small Swift tool in peers/apple/ (built by its build.sh on
# first use; APPLE_INTEROP points at a prebuilt binary).
#
# The TLS stack is the OS's, so the peer version is the macOS version. Its
# public API pins versions, suites, ALPN, the identity (a PKCS#12 the
# purecrypto CLI exports, imported into a throwaway keychain), client
# authentication and OCSP requests; named groups, 0-RTT, session-resumption
# and certificate-compression facts, Ed25519 and raw public keys go through
# SPI from the open-source Security project's SecProtocolPriv.h, resolved
# at run time — a case needing an SPI this macOS lacks is SKIPped by
# `supports` with that reason.
#
# What the stack cannot do is SKIPped here: no way to trigger a KeyUpdate,
# no RFC 8449 record_size_limit, no OCSP staple on the server side, no PSK-
# only resumption, and identities the Security framework cannot hold
# (Ed25519, ML-DSA). Network.framework reports a peer's close_notify and a
# bare FIN alike, so this adapter's `verify` checks the exchange from the
# Apple side and leaves the close_notify verdict to the purecrypto side's
# report (which the runner checks anyway).
#
# The tool logs the negotiated parameters at the end of the exchange (the
# stack rewrites its metadata, unlocked, while the tickets behind the
# handshake come in; see apple/README.md), so the facts follow the `data:`
# lines in its log.
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

P12_PASS=interop

# The tool: `info` (the runner's first call) rebuilds it so source changes
# are picked up; the per-case subcommands only build when it is missing.
APPLE_INTEROP=${APPLE_INTEROP:-$HERE/apple/.build/release/apple-interop}
tool() {
    if [ ! -x "$APPLE_INTEROP" ] || [ "${1:-}" = rebuild ]; then
        "$HERE/apple/build.sh" >/dev/null 2>"$HERE/apple/.build.log" ||
            { cat "$HERE/apple/.build.log" >&2; exit 1; }
    fi
    echo "$APPLE_INTEROP"
}

# The SPI names a case relies on; `supports` SKIPs when one is missing.
spi_or_skip() {
    local t
    t=$(tool)
    if ! "$t" probe "$@" >/dev/null; then
        skip "this macOS lacks the SPI $*"
    fi
}

# p12 KIND: the PKCS#12 for a certificate kind, exported once per run with
# the purecrypto CLI (`large` bundles the leaf; the intermediate travels as
# --chain).
p12() {
    local f=$PKI/$1.p12
    if [ ! -f "$f" ]; then
        case $1 in
            large) "$PURECRYPTO" pkcs12 -export -inkey "$PKI/large.key" -in "$PKI/large-leaf.crt" \
                -passout "pass:$P12_PASS" -out "$f" ;;
            *) "$PURECRYPTO" pkcs12 -export -inkey "$PKI/$1.key" -in "$PKI/$1.crt" \
                -passout "pass:$P12_PASS" -out "$f" ;;
        esac
    fi
    echo "$f"
}

apple_group() {
    case $1 in
        x25519) echo X25519 ;;
        p256) echo P-256 ;;
        p384) echo P-384 ;;
        x25519mlkem768) echo X25519MLKEM768 ;;
    esac
}
apple_suite() {
    case $1 in
        aes128gcm) echo TLS_AES_128_GCM_SHA256 ;;
        aes256gcm) echo TLS_AES_256_GCM_SHA384 ;;
        chacha20) echo TLS_CHACHA20_POLY1305_SHA256 ;;
    esac
}
# The group the Apple side shares first in an HRR case (the other side pins
# CASE_GROUP, so a HelloRetryRequest follows).
other_group() {
    case $1 in
        x25519) echo p256 ;;
        *) echo x25519 ;;
    esac
}

cmd_supports() {
    # The stack's signature_algorithms carry ECDSA and RSA only — no
    # ed25519, with or without the eddsa SPI (checked with `openssl s_server
    # -trace`) — and the keychain has no Ed25519 or ML-DSA key type, so
    # neither can be Apple's identity nor a peer's.
    case $CASE_CERT in
        ed25519) skip "Apple's TLS stack offers no ed25519 signature scheme and holds no Ed25519 keys" ;;
        mldsa65) skip "Apple's TLS stack has no ML-DSA" ;;
    esac
    case $CASE_GROUP in
        x25519mlkem768) spi_or_skip sec_protocol_options_append_tls_key_exchange_group ;;
    esac
    # Pinning a group on the Apple side (so no HelloRetryRequest happens in
    # a plain case, or exactly one does in an HRR case) is SPI.
    case $CASE_FEAT in
        plain|hrr|0rtt-hrr) spi_or_skip sec_protocol_options_append_tls_key_exchange_group ;;
    esac
    case $CASE_FEAT in
        keyupdate-peer) skip "Network.framework has no API to send a KeyUpdate" ;;
        rsl) skip "Apple's TLS stack does not implement RFC 8449 record_size_limit" ;;
        # With early data enabled through the SPI, the listener's connection
        # accepts the client's 0-RTT (EncryptedExtensions says so) but never
        # becomes ready and ends with errSSLClosedNoNotify — with OpenSSL's
        # client too. Rejected early data (the HRR case) completes fine.
        0rtt) [ "$CASE_ROLE" = peer-client ] || skip "a Network.framework server that accepts 0-RTT never completes the connection" ;;
        certcomp) spi_or_skip sec_protocol_metadata_get_tls_certificate_compression_used ;;
        ocsp) [ "$CASE_ROLE" = peer-client ] || skip "Network.framework has no API to staple an OCSP response on a server" ;;
        # Accepting a peer's raw public key works through the SPI (the
        # allowlist is enforced: a key not on it draws bad_certificate);
        # presenting our own fails inside the stack with errSSLInternal.
        rpk)
            [ "$CASE_ROLE" = peer-client ] || skip "presenting a raw public key through Apple's SPI fails with errSSLInternal (-9810)"
            spi_or_skip sec_protocol_options_set_server_raw_public_key_certificates ;;
        rpk-client)
            [ "$CASE_ROLE" = peer-server ] || skip "presenting a raw public key through Apple's SPI fails with errSSLInternal (-9810)"
            spi_or_skip sec_protocol_options_set_client_raw_public_key_certificates ;;
    esac
    case $CASE_FEAT in
        resume|0rtt|0rtt-hrr) spi_or_skip sec_protocol_metadata_get_session_resumed sec_protocol_options_set_tls_early_data_enabled ;;
    esac
    # The stack sends a key share for the ML-KEM hybrid whatever its
    # position in the list, so no HelloRetryRequest for it can be forced.
    if [ "$CASE_FEAT" = hrr ] && [ "$CASE_ROLE" = peer-client ] && [ "$CASE_GROUP" = x25519mlkem768 ]; then
        skip "the Apple client always shares X25519MLKEM768; no HRR possible"
    fi
    return 0
}

version_args() {
    if [ "$CASE_PROTO" = tls12 ]; then
        echo "--min tls12 --max tls12"
    else
        echo "--min tls13 --max tls13"
    fi
}

server_args() {
    local a="server --pass $P12_PASS --ca $PKI/ca.crt --send $WORK/server.in --log $WORK/server.out --port-file $WORK/server.port --read-timeout 1 --deadline $SERVER_TIMEOUT"
    a="$a $(version_args)"
    if [ "$CASE_CERT" = large ]; then
        a="$a --p12 $(p12 large) --chain $PKI/large-int.crt"
    else
        a="$a --p12 $(p12 "$CASE_CERT")"
    fi
    if [ "$CASE_PROTO" = tls13 ]; then
        a="$a --suite $CASE_SUITE"
    fi
    case $CASE_FEAT in
        # The server accepts only the pinned group; the purecrypto client
        # shares another one first, so a HelloRetryRequest follows.
        plain|hrr) a="$a --group $CASE_GROUP" ;;
        resume) a="$a --accept 2" ;;
        0rtt) a="$a --accept 2 --early-data accept" ;;
        0rtt-hrr) a="$a --accept 2 --early-data accept --group x25519" ;;
        mtls) a="$a --client-auth" ;;
        rpk) a="$a --rpk-self" ;;
        rpk-client) a="$a --client-auth --rpk-peer-key $PKI/$CASE_CERT.pub" ;;
        alpn) a="$a --alpn h2,http/1.1" ;;
    esac
    echo "$a"
}

client_args() {
    local a="client --host 127.0.0.1 --port $PORT --sni localhost --ca $PKI/ca.crt --send $WORK/client.in --log $WORK/client.out --log2 $WORK/client2.out --read-timeout 1 --deadline $STEP_TIMEOUT"
    a="$a $(version_args)"
    if [ "$CASE_PROTO" = tls13 ]; then
        a="$a --suite $CASE_SUITE"
    fi
    case $CASE_FEAT in
        plain) a="$a --group $CASE_GROUP" ;;
        # A key share goes out for the first group only; the purecrypto
        # server pins the second.
        hrr) a="$a --group $(other_group "$CASE_GROUP"),$CASE_GROUP" ;;
        resume) a="$a --resume" ;;
        0rtt) a="$a --resume --early-data $PKI/early.txt" ;;
        0rtt-hrr) a="$a --resume --early-data $PKI/early.txt --group p256,x25519" ;;
        mtls) a="$a --p12 $(p12 "$CASE_CERT") --pass $P12_PASS" ;;
        # A raw public key has no chain: the SPI matches it against the
        # allowlist instead of the CA.
        rpk) a="client --host 127.0.0.1 --port $PORT --sni localhost --send $WORK/client.in --log $WORK/client.out --read-timeout 1 --deadline $STEP_TIMEOUT $(version_args) --suite $CASE_SUITE --rpk-peer-key $PKI/$CASE_CERT.pub" ;;
        rpk-client) a="$a --p12 $(p12 "$CASE_CERT") --pass $P12_PASS --rpk-self" ;;
        ocsp) a="$a --ocsp" ;;
        alpn) a="$a --alpn h2,http/1.1" ;;
    esac
    echo "$a"
}

cmd_server() {
    local t i port
    t=$(tool)
    rm -f "$WORK/server.port"
    # shellcheck disable=SC2046
    "$TO" "$SERVER_TIMEOUT" "$t" $(server_args) >"$WORK/server.err" 2>&1 &
    echo $! >"$WORK/server.pid"
    for i in $(seq 1 100); do
        if [ -s "$WORK/server.port" ]; then
            port=$(cat "$WORK/server.port")
            if listening "$port"; then return 0; fi
        fi
        if ! kill -0 "$(cat "$WORK/server.pid")" 2>/dev/null; then break; fi
        sleep 0.1
    done
    echo "apple server did not start"
    return 1
}

cmd_client() {
    local t
    t=$(tool)
    # shellcheck disable=SC2046
    "$TO" "$STEP_TIMEOUT" "$t" $(client_args) >"$WORK/client.err" 2>&1
}

# The negotiated parameters as the Apple side logged them for one session.
verify_session() {
    local f=$1 ok=0
    if [ "$CASE_PROTO" = tls12 ]; then
        expect "$f" "protocol version: TLSv1.2" || ok=1
        return $ok
    fi
    expect "$f" "protocol version: TLSv1.3" || ok=1
    expect "$f" "cipher suite: $(apple_suite "$CASE_SUITE")" || ok=1
    verify_group "$f" || ok=1
    return $ok
}

# The group as the Apple side reports it, for every session in the log: the
# case's group and nothing else, compared as a whole value (`X25519` is not
# `X25519MLKEM768`). The tool has three answers (see its README): the name;
# `unknown (no SPI)` on a macOS without the metadata SPI — the peer cannot
# tell us, and the group is then the purecrypto side's `key exchange:` line
# alone, which the runner checks for every case; and `unavailable`, a read
# the stack did not answer, which is a failure and never a pass.
verify_group() {
    local f=$1 want got
    want=$(apple_group "$CASE_GROUP")
    got=$(sed -n 's/^\(\[[ 0-9.]*\] \)\{0,1\}group: //p' "$f" 2>/dev/null | sort -u)
    case $got in
        "$want"|"unknown (no SPI)") return 0 ;;
    esac
    printf "expected 'group: %s' in %s, got '%s'\n" "$want" "$(basename "$f")" "$(echo "$got" | paste -sd, -)"
    return 1
}

cmd_verify() {
    local ok=0 first second
    if [ "$CASE_ROLE" = peer-server ]; then
        first=$WORK/server.out
        second=$WORK/server.out
    else
        first=$WORK/client.out
        second=$WORK/client2.out
    fi
    verify_session "$first" || ok=1
    case $CASE_FEAT in
        resume|0rtt|0rtt-hrr)
            if [ "$CASE_ROLE" = peer-server ]; then
                # Two sessions in one log: the second must have resumed.
                expect "$first" "--- connection 2" || ok=1
                expect "$first" "resumed: yes" || ok=1
                expect "$first" "--- connection 2 done (0)" || ok=1
            else
                verify_session "$second" || ok=1
                expect "$second" "resumed: yes" || ok=1
                refute "$first" "resumed: yes" || ok=1
            fi ;;
        *) refute "$first" "resumed: yes" || ok=1 ;;
    esac
    case $CASE_FEAT in
        0rtt) expect "$second" "early data accepted: yes" || ok=1 ;;
        *) refute "$second" "early data accepted: yes" || ok=1 ;;
    esac
    case $CASE_FEAT in
        certcomp) expect "$first" "certificate compression: zlib" || ok=1 ;;
        alpn) expect "$first" "alpn: h2" || ok=1 ;;
        mtls)
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$first" "verify: ok" || ok=1
                expect "$first" "peer certificate subject: localhost" || ok=1
            else
                expect "$first" "challenge: client certificate requested" || ok=1
            fi ;;
        # The server required client authentication and holds an allowlist
        # of raw keys; the stack matched the key itself (no verify block
        # runs, no chain is reported) and the handshake completed.
        rpk-client)
            expect "$first" "state: ready" || ok=1
            expect "$first" "peer certificates: 0" || ok=1 ;;
        ocsp) expect "$first" "ocsp response: yes" || ok=1 ;;
        large-chain) [ "$CASE_ROLE" = peer-server ] || expect "$first" "peer certificates: 2" || ok=1 ;;
    esac
    # The application data, both ways.
    if [ "$CASE_ROLE" = peer-server ]; then
        expect "$first" "data: ping from client" || ok=1
        case $CASE_FEAT in
            0rtt) expect "$first" "data: early data from purecrypto" || ok=1 ;;
        esac
        expect "$WORK/client.out" "pong from server" || ok=1
        expect "$first" "close_notify: sent" || ok=1
    else
        expect "$first" "data: ping from client" || ok=1
        expect "$first" "close_notify: sent" || ok=1
        case $CASE_FEAT in
            resume|0rtt|0rtt-hrr) expect "$second" "close_notify: sent" || ok=1 ;;
        esac
    fi
    return $ok
}

case ${1:-} in
    info) "$(tool rebuild)" version ;;
    quirks) ;;
    supports) cmd_supports ;;
    server) cmd_server ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|quirks|supports|server|client|verify" >&2; exit 2 ;;
esac
