#!/usr/bin/env bash
# Peer adapter: Windows SChannel, through .NET's System.Net.Security.SslStream
# (SChannel is what it wraps on Windows). The peer program is the small C#
# console app in peers/schannel/ (both roles); this wrapper builds it once
# with `dotnet build -c Release` and dispatches the subcommands. It runs
# under Git Bash on the Windows CI runner: run.sh switches MSYS path
# conversion off there and hands out Windows-form paths, so the only
# conversion done here is for this directory (`npath`).
#
# What SslStream cannot express on Windows is SKIPped here, with the
# reason. Cipher suites and groups follow the system policy
# (`CipherSuitesPolicy` is Linux/macOS only), so they are pinned from the
# purecrypto side; a peer client offers every suite the policy enables, in
# the policy's order, and can only be checked against the purecrypto
# server's own first preference. The client sends a key share for every
# group it offers and the server's preference cannot be pinned, so no
# HelloRetryRequest can be forced. There is no 0-RTT, KeyUpdate, raw
# public key, certificate compression or record_size_limit API; resumption
# is transparent (the purecrypto side reports it, SslStream does not);
# server-side OCSP stapling happens only from SChannel's own AIA fetch;
# a server credential whose chain exceeds one 16 KiB record is refused;
# Ed25519 and ML-DSA certificates are not supported by SChannel (nor
# loadable by .NET). P-256, P-384 and RSA-2048 are what matters on Windows.
# The CI image's TLS policy leaves out curve25519 and ChaCha20; the
# workflow appends them to the policy before running the matrix.
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

PROJ=$HERE/schannel
OUT=$PROJ/bin/peer
DLL=$OUT/schannel-peer.dll

# npath PATH: the path as a native (Windows) program wants it.
npath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi
}

# The peer program: SCHANNEL_PEER (a prebuilt executable) or the assembly
# built here, run through `dotnet` so no apphost has to locate the runtime.
PEER=()
ensure_built() {
    if [ -n "${SCHANNEL_PEER:-}" ]; then PEER=("$SCHANNEL_PEER"); return 0; fi
    command -v dotnet >/dev/null 2>&1 || { echo "dotnet SDK not found" >&2; return 1; }
    if [ ! -f "$DLL" ]; then
        dotnet build "$(npath "$PROJ/schannel-peer.csproj")" -c Release -o "$(npath "$OUT")" \
            --nologo -v quiet >"$PROJ/build.log" 2>&1 || { cat "$PROJ/build.log" >&2; return 1; }
        [ -f "$DLL" ] || { echo "build produced no $DLL" >&2; cat "$PROJ/build.log" >&2; return 1; }
    fi
    PEER=(dotnet "$(npath "$DLL")")
}

cmd_info() {
    ensure_built
    "${PEER[@]}" info
}

cmd_supports() {
    case $CASE_CERT in
        ed25519) skip "SChannel has no Ed25519 (and .NET cannot load the key)" ;;
        mldsa65) skip "SChannel has no ML-DSA" ;;
    esac
    case $CASE_GROUP in
        x25519mlkem768) skip "SChannel offers no ML-KEM hybrid group" ;;
    esac
    # The client offers every suite the system policy enables, in the
    # system's order, and the purecrypto server takes its own first
    # preference, so only that one can be pinned from the peer's side.
    if [ "$CASE_ROLE" = peer-client ] && [ "$CASE_SUITE" != aes128gcm ]; then
        skip "SslStream cannot restrict cipher suites on Windows (CipherSuitesPolicy is Linux/macOS only)"
    fi
    case $CASE_FEAT in
        0rtt|0rtt-hrr) skip "SslStream has no 0-RTT API and SChannel accepts no early data" ;;
        # The client sends a key share for every group it offers, the
        # server takes the client's share; neither side can be steered
        # into a HelloRetryRequest.
        hrr)
            if [ "$CASE_ROLE" = peer-client ]; then
                skip "SChannel client shares a key for every group it offers; no HRR possible"
            else
                skip "SChannel server group preference follows system policy; no pin"
            fi ;;
        keyupdate-peer) skip "SslStream has no KeyUpdate API" ;;
        # SslStream / SChannel expose no PSK-only resumption or external-PSK
        # interface.
        resume-psk) skip "SslStream exposes no PSK-only (psk_ke) resumption" ;;
        extpsk) skip "SslStream has no external-PSK API" ;;
        certcomp) skip "SChannel does not implement RFC 8879 certificate compression" ;;
        rpk|rpk-client) skip "SChannel does not implement RFC 7250 raw public keys" ;;
        rsl) skip "SChannel does not implement RFC 8449 record_size_limit" ;;
        ocsp) [ "$CASE_ROLE" = peer-client ] || skip "SChannel staples only a response it fetched itself (AIA); no API to supply one" ;;
        # SChannel does not fragment a handshake message across records:
        # a server credential whose chain exceeds one 16 KiB record is
        # refused up front (AcquireCredentialsHandle: SEC_E_INVALID_PARAMETER;
        # the same leaf under a small issuer, or the same intermediate
        # under a small leaf, is fine). Receiving such a chain works.
        large-chain) [ "$CASE_ROLE" = peer-client ] || skip "SChannel cannot send a Certificate message over 16 KiB (credential refused)" ;;
    esac
    return 0
}

common_args() {
    local a=""
    if [ "$CASE_PROTO" = tls12 ]; then a="$a --tls12"; fi
    if [ "$CASE_FEAT" = alpn ]; then a="$a --alpn h2,http/1.1"; fi
    echo "$a"
}

cmd_server() {
    ensure_built
    local a
    a="server --out $(npath "$WORK/server") --send $(npath "$WORK/server.in") $(common_args)"
    if [ "$CASE_CERT" = large ]; then
        a="$a --cert $(npath "$PKI/large-leaf.crt") --key $(npath "$PKI/large.key") --chain $(npath "$PKI/large-int.crt")"
    else
        a="$a --cert $(npath "$PKI/$CASE_CERT.crt") --key $(npath "$PKI/$CASE_CERT.key")"
    fi
    case $CASE_FEAT in
        resume) a="$a --accept 2" ;;
        mtls) a="$a --ca $(npath "$PKI/ca.crt")" ;;
    esac
    rm -f "$WORK/server.port"
    # shellcheck disable=SC2086
    "$TO" "$SERVER_TIMEOUT" "${PEER[@]}" $a >"$WORK/server.err" 2>&1 &
    local pid=$! i
    echo "$pid" >"$WORK/server.pid"
    for i in $(seq 1 100); do
        if [ -s "$WORK/server.port" ]; then return 0; fi
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.1
    done
    echo "peer server did not start"
    cat "$WORK/server.err" 2>/dev/null
    return 1
}

cmd_client() {
    ensure_built
    local a
    a="client --port $PORT --host localhost --ca $(npath "$PKI/ca.crt") --out $(npath "$WORK/client") --send $(npath "$WORK/client.in") $(common_args)"
    case $CASE_FEAT in
        resume) a="$a --connections 2" ;;
        mtls) a="$a --cert $(npath "$PKI/$CASE_CERT.crt") --key $(npath "$PKI/$CASE_CERT.key")" ;;
        # SslStream exposes no staple; with revocation checking on, the
        # platform chain engine has only the stapled response to go by
        # (the leaf carries no AIA URL), so a clean validation shows it
        # was consumed.
        ocsp) a="$a --revocation online" ;;
        # A second round of data after the echo: the purecrypto server's
        # KeyUpdate arrives with the first echo, so the client's second
        # write must carry SChannel's reply KeyUpdate (RFC 8446 §4.6.3).
        keyupdate) a="$a --rounds 2" ;;
    esac
    # shellcheck disable=SC2086
    "$TO" "$STEP_TIMEOUT" "${PEER[@]}" $a >"$WORK/client.err" 2>&1
}

# SslStream names no group on TLS 1.3, but KeyExchangeStrength is the
# curve size, which tells the three apart.
ss_kex_bits() {
    case $1 in
        x25519) echo 255 ;;
        p256) echo 256 ;;
        p384) echo 384 ;;
    esac
}
ss_suite() {
    case $1 in
        aes128gcm) echo TLS_AES_128_GCM_SHA256 ;;
        aes256gcm) echo TLS_AES_256_GCM_SHA384 ;;
        chacha20) echo TLS_CHACHA20_POLY1305_SHA256 ;;
    esac
}

# verify_report FILE: the negotiated parameters of one connection.
verify_report() {
    local f=$1 ok=0
    if [ "$CASE_PROTO" = tls12 ]; then
        expect "$f" "protocol: Tls12" || ok=1
    else
        expect "$f" "protocol: Tls13" || ok=1
        expect "$f" "cipher suite: $(ss_suite "$CASE_SUITE")" || ok=1
        expect_re "$f" "^key exchange: [A-Za-z]+ $(ss_kex_bits "$CASE_GROUP")\$" || ok=1
    fi
    refute "$f" "error:" || ok=1
    case $CASE_FEAT in
        alpn) expect "$f" "alpn: h2" || ok=1 ;;
    esac
    if [ "$CASE_FEAT" = mtls ]; then
        expect "$f" "mutually authenticated: yes" || ok=1
        expect "$f" "peer certificate: CN=localhost" || ok=1
    fi
    if [ "$CASE_ROLE" = peer-client ]; then
        expect "$f" "validation: None" || ok=1
        if [ "$CASE_CERT" = large ]; then
            # Leaf, intermediate and the trusted root.
            expect "$f" "chain length: 3" || ok=1
        fi
    fi
    return $ok
}

cmd_verify() {
    local ok=0
    if [ "$CASE_ROLE" = peer-server ]; then
        verify_report "$WORK/server.out" || ok=1
        expect "$WORK/server.out" "peer close: eof" || ok=1
        if [ "$CASE_FEAT" = resume ]; then
            # The first purecrypto connection only collects a ticket and
            # sends nothing; the second carries the payload.
            verify_report "$WORK/server2.out" || ok=1
            expect "$WORK/server2.out" "ping from client" || ok=1
            expect "$WORK/server2.out" "peer close: eof" || ok=1
        else
            expect "$WORK/server.out" "ping from client" || ok=1
        fi
        # The peer's payload reached the purecrypto client.
        expect "$WORK/client.out" "pong from server" || ok=1
    else
        verify_report "$WORK/client.out" || ok=1
        expect "$WORK/client.out" "ping from client" || ok=1
        expect "$WORK/client.out" "peer close: eof" || ok=1
        if [ "$CASE_FEAT" = resume ]; then
            verify_report "$WORK/client2.out" || ok=1
            expect "$WORK/client2.out" "ping from client" || ok=1
        fi
    fi
    return $ok
}

case ${1:-} in
    info) cmd_info ;;
    quirks) ;;
    supports) cmd_supports ;;
    server) cmd_server ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|quirks|supports|server|client|verify" >&2; exit 2 ;;
esac
