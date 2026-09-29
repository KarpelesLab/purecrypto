#!/usr/bin/env bash
# Peer adapter: GnuTLS `gnutls-cli` / `gnutls-serv` (3.8 and later; the
# binaries from GNUTLS_CLI / GNUTLS_SERV, default the ones on PATH).
#
# Everything is pinned through a priority string (`--priority`): the
# protocol version, the group (`GROUP-X25519`, ...), the cipher (which for
# TLS 1.3 names the suite) and the certificate types. Both tools print the
# negotiated parameters as one `- Description:` line, e.g.
# `(TLS1.3-X.509)-(ECDHE-X25519)-(ECDSA-SECP256R1-SHA256)-(AES-128-GCM)`
# (`Raw Public Key` for RFC 7250, `HYBRID-...` for a KEM hybrid), which is
# what `verify` reads, plus the verbose ECDH block (`Using curve:`) for a
# resumed session, whose description names no group. The debug log
# (`-d 5`: handshake messages, extensions, alerts) supplies what the
# summary leaves out: the KeyUpdate messages, the compressed certificate,
# the close_notify the supervisor below waits for.
#
# What the tools cannot express is SKIPped here with the reason:
# `gnutls-serv` has no command that triggers a KeyUpdate (its
# `**REHANDSHAKE**` is TLS 1.2 renegotiation only); ML-DSA certificates
# and the ML-KEM hybrids depend on the build (3.8.10+ with leancrypto,
# detected from `gnutls-cli -l`); and 0-RTT across a HelloRetryRequest is
# broken in both GnuTLS roles (issue #1429, see `cmd_supports`).
#
# `gnutls-serv` serves forever (no `-naccept`), so `server` runs it under a
# supervisor (`supervise` below) that watches its log for the case's
# connections to close and then stops it, sparing the runner its poll on
# every peer-server case.
#
# Subcommands and environment: see ../README.md.

set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib.sh
. "$HERE/../lib.sh"

GNUTLS_CLI=${GNUTLS_CLI:-gnutls-cli}
GNUTLS_SERV=${GNUTLS_SERV:-gnutls-serv}
VERSION=$("$GNUTLS_CLI" --version 2>/dev/null | head -1 | awk '{print $2}')
VERSION=${VERSION:-0}

# What `-d 5` prints that no check reads, dropped from the logs so a
# failure dump (the runner shows the first 200 lines) keeps the messages,
# extensions, alerts and record sizes that matter.
NOISE='ASSERT: |Not sending extension|(rcvd|sent) signature algo|checking cert compat|cannot use privkey|Preparing extension|Expected Packet'

# The priority keyword for the case's group, how the description line
# spells it, and how the verbose `Using curve:` line does.
gt_group() {
    case $1 in
        x25519) echo GROUP-X25519 ;;
        p256) echo GROUP-SECP256R1 ;;
        p384) echo GROUP-SECP384R1 ;;
        p521) echo GROUP-SECP521R1 ;;
        x25519mlkem768) echo GROUP-X25519-MLKEM768 ;;
        secp256r1mlkem768) echo GROUP-SECP256R1-MLKEM768 ;;
    esac
}
gt_group_desc() {
    case $1 in
        x25519) echo "ECDHE-X25519" ;;
        p256) echo "ECDHE-SECP256R1" ;;
        p384) echo "ECDHE-SECP384R1" ;;
        p521) echo "ECDHE-SECP521R1" ;;
        x25519mlkem768) echo "HYBRID-X25519-MLKEM768" ;;
        secp256r1mlkem768) echo "HYBRID-SECP256R1-MLKEM768" ;;
    esac
}
gt_curve() {
    case $1 in
        x25519) echo X25519 ;;
        p256) echo SECP256R1 ;;
        p384) echo SECP384R1 ;;
        p521) echo SECP521R1 ;;
    esac
}
# The cipher keyword (TLS 1.3 suites are selected by cipher) and its name
# in the description line.
gt_cipher() {
    case $1 in
        aes128gcm) echo AES-128-GCM ;;
        aes256gcm) echo AES-256-GCM ;;
        chacha20) echo CHACHA20-POLY1305 ;;
    esac
}
# For HRR cases: the group the purecrypto side shares first (see run.sh).
other_group() {
    case $1 in
        x25519) echo GROUP-SECP256R1 ;;
        *) echo GROUP-X25519 ;;
    esac
}

# Does this build list the algorithm (a group or signature keyword)?
has_algo() {
    "$GNUTLS_CLI" -l 2>/dev/null | grep -q -- "$1"
}

cmd_supports() {
    case $CASE_GROUP in
        x25519mlkem768) has_algo "GROUP-X25519-MLKEM768" || skip "GnuTLS $VERSION build has no ML-KEM hybrids (3.8.10+ with leancrypto)" ;;
        secp256r1mlkem768) has_algo "GROUP-SECP256R1-MLKEM768" || skip "GnuTLS $VERSION build has no ML-KEM hybrids (3.8.10+ with leancrypto)" ;;
    esac
    case $CASE_CERT in
        mldsa65) has_algo "ML-DSA-65" || skip "GnuTLS $VERSION build has no ML-DSA (3.8.10+ with leancrypto)" ;;
    esac
    case $CASE_FEAT in
        keyupdate-peer)
            [ "$CASE_ROLE" = peer-client ] || skip "gnutls-serv has no command that sends a KeyUpdate" ;;
        # GnuTLS issue #1429 (open since 2022, still in 3.8.13): after a
        # HelloRetryRequest on a 0-RTT offer its client sends the second
        # ClientHello encrypted under the early traffic keys, early_data
        # extension still in (RFC 8446 §4.1.2 wants it plain and without);
        # and its server, which decides to accept early data while parsing
        # the first ClientHello — before it chooses to retry — then treats
        # the plaintext second ClientHello as an early-data record it
        # cannot decrypt and aborts with bad_record_mac.
        0rtt-hrr) skip "GnuTLS mishandles 0-RTT across a HelloRetryRequest (issue #1429)" ;;
        certcomp)
            version_ge "$VERSION" 3.7.4 || skip "GnuTLS $VERSION has no certificate compression (3.7.4+)"
            # (Debian/Ubuntu build the library without zlib.)
            has_algo "COMP-ZLIB" || skip "GnuTLS $VERSION build has no zlib certificate compression" ;;
        # GnuTLS puts the KEM hybrids ahead of every other group whatever
        # the priority string says (`add_hybrid` in lib/priority.c), and
        # the key share goes with the first group: no HelloRetryRequest to
        # the hybrid can be forced from its client.
        hrr) [ "$CASE_ROLE" = peer-server ] || [ "$CASE_GROUP" != x25519mlkem768 ] ||
            skip "gnutls-cli always lists and shares X25519MLKEM768 first; no HRR possible" ;;
    esac
    return 0
}

# The external PSK of the extpsk cases, written to the pskpasswd file
# gnutls-serv reads: `identity:hex-key`.
psk_setup() {
    printf '%s:%s
' "$PSK_IDENTITY" "$PSK_HEX" >"$WORK/psk.passwd"
}

# The priority string for the case. NORMAL, then the version, group and
# cipher pinned (TLS 1.2 keeps the defaults: the case only checks the
# version), then the certificate types for the raw-public-key cases.
priority() {
    local p="NORMAL"
    if [ "$CASE_PROTO" = tls12 ]; then
        p="$p:-VERS-ALL:+VERS-TLS1.2"
    else
        p="$p:-VERS-ALL:+VERS-TLS1.3:-CIPHER-ALL:+$(gt_cipher "$CASE_SUITE")"
        case $CASE_FEAT in
            # The peer client shares another group first (the pinned one
            # is second, and the purecrypto server insists on it); the
            # peer server simply pins.
            hrr)
                if [ "$CASE_ROLE" = peer-client ]; then
                    p="$p:-GROUP-ALL:+$(other_group "$CASE_GROUP"):+$(gt_group "$CASE_GROUP")"
                else
                    p="$p:-GROUP-ALL:+$(gt_group "$CASE_GROUP")"
                fi ;;
            *) p="$p:-GROUP-ALL:+$(gt_group "$CASE_GROUP")" ;;
        esac
    fi
    case $CASE_FEAT in
        # Offer / accept only the raw public key as the identity in
        # question; the other side stays X.509.
        rpk) p="$p:-CTYPE-SRV-ALL:+CTYPE-SRV-RAWPK" ;;
        rpk-client) p="$p:-CTYPE-CLI-ALL:+CTYPE-CLI-RAWPK" ;;
        # An external PSK (RFC 8446 §4.2.11) needs the PSK key exchanges
        # enabled (NORMAL leaves them off): DHE-PSK for psk_dhe_ke, PSK for
        # psk_ke.
        extpsk) p="$p:+ECDHE-PSK:+DHE-PSK:+PSK" ;;
        # PSK-only ticket resumption: gnutls-serv issues no psk_ke-usable
        # ticket, and accepts none, unless plain PSK (psk_ke) is enabled
        # (`+PSK`); NORMAL does ticket resumption with DHE-PSK only. Only
        # the server needs it — gnutls-cli with +PSK but no key offers the
        # external-PSK ciphersuites and sends a malformed hello, so the
        # client (peer-client role) keeps the plain priority and simply
        # advertises both modes, letting the purecrypto server pick psk_ke.
        resume-psk) [ "$CASE_ROLE" = peer-server ] && p="$p:+PSK" ;;
    esac
    echo "$p"
}

# The echo server: every line the client sends comes back and is logged.
server_args() {
    local a="--echo -p @PORT@ -d 5 --priority $(priority) --x509cafile $PKI/ca.crt"
    case $CASE_FEAT in
        # The raw key is the only server identity offered (see priority).
        rpk) a="$a --rawpkkeyfile $PKI/$CASE_CERT.key --rawpkfile $PKI/$CASE_CERT.pub" ;;
        *)
            if [ "$CASE_CERT" = large ]; then
                a="$a --x509certfile $PKI/large.crt --x509keyfile $PKI/large.key"
            else
                a="$a --x509certfile $PKI/$CASE_CERT.crt --x509keyfile $PKI/$CASE_CERT.key"
            fi ;;
    esac
    # A client certificate is requested by default; only the mTLS cases
    # want one. A raw client key has no chain, and gnutls-serv has no
    # allowlist to check it against (its `--verify-client-cert` rejects
    # one with access_denied): required but unverified, as with every
    # other peer tool; the purecrypto side is what presents it.
    case $CASE_FEAT in
        mtls) a="$a --require-client-cert --verify-client-cert" ;;
        rpk-client) a="$a --require-client-cert" ;;
        *) a="$a --disable-client-cert" ;;
    esac
    case $CASE_FEAT in
        0rtt) a="$a --earlydata --maxearlydata 16384" ;;
        certcomp) a="$a --compress-cert zlib" ;;
        ocsp) a="$a --ocsp-response $OCSP" ;;
        alpn) a="$a --alpn h2 --alpn http/1.1" ;;
        rsl) a="$a --recordsize 512" ;;
        # A server that accepts the external PSK by identity (its X.509
        # certificate stays available for a client that offers no PSK).
        extpsk) a="$a --pskpasswd $WORK/psk.passwd" ;;
    esac
    echo "$a"
}

client_args() {
    local a="-p $PORT 127.0.0.1 --sni-hostname localhost --verify-hostname localhost -V -d 5 --priority $(priority)"
    case $CASE_FEAT in
        # A raw public key cannot be validated against a CA (and gnutls-cli
        # has no pin option short of trust-on-first-use); the description
        # line still shows the type. The purecrypto server is what sends it.
        rpk) a="$a --insecure" ;;
        *) a="$a --x509cafile $PKI/ca.crt" ;;
    esac
    case $CASE_FEAT in
        # A key share for the first group only, so the purecrypto server's
        # pin to the second costs a HelloRetryRequest.
        hrr) a="$a --single-key-share" ;;
        # `--resume`: handshake, disconnect, connect again with the
        # session (waiting for the ticket first), then the payload goes
        # over the resumed connection.
        resume) a="$a --resume --waitresumption" ;;
        # PSK-only resumption: gnutls-cli offers both modes; the purecrypto
        # server prefers psk_ke and selects it (no (EC)DHE on the second
        # connection).
        resume-psk) a="$a --resume --waitresumption" ;;
        # An external PSK offered by identity + key; no certificate needed.
        extpsk) a="$a --pskusername $PSK_IDENTITY --pskkey $PSK_HEX" ;;
        0rtt) a="$a --resume --waitresumption --earlydata $PKI/early.txt" ;;
        mtls) a="$a --x509certfile $PKI/$CASE_CERT.crt --x509keyfile $PKI/$CASE_CERT.key" ;;
        rpk-client) a="$a --rawpkkeyfile $PKI/$CASE_CERT.key --rawpkfile $PKI/$CASE_CERT.pub" ;;
        # `^rekey^` on stdin sends KeyUpdate(update_requested).
        keyupdate-peer) a="$a --inline-commands" ;;
        certcomp) a="$a --compress-cert zlib" ;;
        ocsp) a="$a --ocsp" ;;
        alpn) a="$a --alpn h2 --alpn http/1.1" ;;
        rsl) a="$a --recordsize 512" ;;
    esac
    echo "$a"
}

# One gnutls-cli run: stdin is the payload, kept open a moment so the echo
# can arrive; EOF then makes the client send close_notify and wait for
# the server's. For the purecrypto-initiated KeyUpdate the payload waits a
# second: GnuTLS answers a KeyUpdate(update_requested) with its own only on
# its next write, so writing before the request has arrived would leave
# the reply unsent.
cmd_client() {
    local rc=0
    {
        case $CASE_FEAT in
            keyupdate-peer) printf '^rekey^\n' ;;
            keyupdate) sleep 1 ;;
        esac
        cat "$WORK/client.in"
        sleep 1
    } | "$TO" "$STEP_TIMEOUT" "$GNUTLS_CLI" $(client_args) \
        >"$WORK/client.out" 2> >(grep --line-buffered -v -E "$NOISE" >"$WORK/client.err") || rc=$?
    return $rc
}

# supervise N CMD...: run the server; stop it once its log shows N
# connections closed by the client (`Alert[1|0] - Close notify - was
# received`, one per connection at `-d 5`), or when told to.
cmd_supervise() {
    local want=$1 pid n i
    shift
    "$@" 2> >(grep --line-buffered -v -E "$NOISE" >&2) &
    pid=$!
    trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; exit 0' TERM INT
    for i in $(seq 1 3000); do
        if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; exit $?; fi
        n=$(grep -c "Close notify - was received" "$WORK/server.err" 2>/dev/null || true)
        if [ "${n:-0}" -ge "$want" ]; then
            # The server's own close_notify goes out in the same loop
            # iteration; a beat for it to reach the socket.
            sleep 0.5
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            exit 0
        fi
        sleep 0.1
    done
    kill "$pid" 2>/dev/null || true
    exit 0
}

# verify_tls13 LOG: the version, suite, group and resumption status as the
# summary shows them. A full handshake's description line carries the
# group; a resumed session's does not (3.8 prints `(TLS1.3-X.509)--(...)`
# for it), so that case reads the verbose ECDH block's `Using curve` line.
verify_tls13() {
    local f=$1 ok=0
    expect_re "$f" "^- Description: \(TLS1\.3[^)]*\)-.*-\($(gt_cipher "$CASE_SUITE")\)$" || ok=1
    case $CASE_FEAT in
        resume|0rtt)
            expect "$f" "*** This is a resumed session" || ok=1
            expect "$f" " - Using curve: $(gt_curve "$CASE_GROUP")" || ok=1 ;;
        # PSK-only resumption: still a resumed session, but no (EC)DHE, so
        # the description carries no group and there is no `Using curve`.
        resume-psk)
            expect "$f" "*** This is a resumed session" || ok=1 ;;
        # An external PSK authenticates the peer (no certificate); the
        # description names the PSK, not a group.
        extpsk)
            expect "$f" "- PSK authentication. Connected as '$PSK_IDENTITY'" || ok=1 ;;
        *)
            refute "$f" "*** This is a resumed session" || ok=1
            expect_re "$f" "^- Description: \(TLS1\.3[^)]*\)-\($(gt_group_desc "$CASE_GROUP")\)" || ok=1 ;;
    esac
    return $ok
}

# verify_rsl LOG: GnuTLS took purecrypto's 512-byte limit, and every
# protected record it then sent fits it (the 3 KiB echo must have been
# fragmented: 512 + AEAD tag + header = 533 bytes on the wire at most).
verify_rsl() {
    local f=$1 ok=0
    expect "$f" "record_size_limit 512 negotiated" || ok=1
    if grep -E -- "Sent Packet\[[0-9]+\] Application Data\(23\) in epoch [0-9]+ and length: ([0-9]{4,}|[6-9][0-9]{2}|5[4-9][0-9])$" "$f" >/dev/null 2>&1; then
        echo "a record over the 512-byte record_size_limit was sent"
        ok=1
    fi
    return $ok
}

cmd_verify() {
    local ok=0
    if [ "$CASE_ROLE" = peer-server ]; then
        local f=$WORK/server.out e=$WORK/server.err
        if [ "$CASE_PROTO" = tls12 ]; then
            expect_re "$f" "^- Description: \(TLS1\.2[^)]*\)-\((EC)?DHE-" || ok=1
        else
            verify_tls13 "$f" || ok=1
        fi
        # The echo server logs every line the client sent.
        expect "$e" "received cmd: ping from client" || ok=1
        case $CASE_FEAT in
            0rtt)
                # gnutls-serv before 3.8.10 reads the early data and then
                # drops it (`if (r == 0)` where the read returned its
                # length; fixed to `>= 0` in 3.8.10), so the echo cannot
                # show it there: the record layer's log of the decrypted
                # early-data record (27 bytes: the payload) stands in.
                if version_ge "$VERSION" 3.8.10; then
                    expect "$e" "received cmd: early data from purecrypto" || ok=1
                else
                    expect_re "$e" "decrypted early data with length: 27, in epoch" || ok=1
                fi ;;
            mtls)
                expect_re "$f" "^- Description: \(TLS1\.3-X\.509\)" || ok=1
                expect "$f" "- Status: The certificate is trusted." || ok=1
                expect "$f" "- Client Signature:" || ok=1 ;;
            rpk) expect_re "$f" "^- Description: \(TLS1\.3-X\.509-Raw Public Key\)" || ok=1 ;;
            rpk-client) expect_re "$f" "^- Description: \(TLS1\.3-Raw Public Key-X\.509\)" || ok=1 ;;
            keyupdate)
                expect "$e" "received TLS 1.3 key update (1)" || ok=1
                expect "$e" "sending key update (0)" || ok=1 ;;
            alpn) expect "$f" "- Application protocol: h2" || ok=1 ;;
            certcomp) expect "$e" "COMPRESSED CERTIFICATE was queued" || ok=1 ;;
            rsl) verify_rsl "$e" || ok=1 ;;
        esac
    else
        local f=$WORK/client.out e=$WORK/client.err
        if [ "$CASE_PROTO" = tls12 ]; then
            expect_re "$f" "^- Description: \(TLS1\.2[^)]*\)-\((EC)?DHE-" || ok=1
        else
            verify_tls13 "$f" || ok=1
        fi
        expect "$f" "- Handshake was completed" || ok=1
        expect "$f" "ping from client" || ok=1
        expect "$f" "- Peer has closed the GnuTLS connection" || ok=1
        case $CASE_FEAT in
            0rtt) expect "$f" "early data from purecrypto" || ok=1 ;;
            mtls) expect "$f" "- Client Signature:" || ok=1 ;;
            rpk) expect_re "$f" "^- Description: \(TLS1\.3-X\.509-Raw Public Key\)" || ok=1 ;;
            rpk-client) expect_re "$f" "^- Description: \(TLS1\.3-Raw Public Key-X\.509\)" || ok=1 ;;
            keyupdate)
                expect "$e" "received TLS 1.3 key update (1)" || ok=1
                expect "$e" "sending key update (0)" || ok=1 ;;
            keyupdate-peer)
                expect "$f" "- Rekey was completed" || ok=1
                expect "$e" "received TLS 1.3 key update (0)" || ok=1 ;;
            alpn) expect "$f" "- Application protocol: h2" || ok=1 ;;
            ocsp) expect "$f" "OCSP status request," || ok=1 ;;
            certcomp) expect "$e" "COMPRESSED CERTIFICATE (25) was received" || ok=1 ;;
            rsl) verify_rsl "$e" || ok=1 ;;
        esac
    fi
    return $ok
}

# The connections the peer server sees in the case: two when resuming.
connections() {
    case $CASE_FEAT in
        resume|0rtt|resume-psk) echo 2 ;;
        *) echo 1 ;;
    esac
}

case ${1:-} in
    info) "$GNUTLS_CLI" --version | head -1 ;;
    supports) cmd_supports ;;
    server)
        [ "$CASE_FEAT" = extpsk ] && psk_setup
        start_bg_server idle bash "$0" supervise "$(connections)" "$GNUTLS_SERV" $(server_args) ;;
    supervise) shift; cmd_supervise "$@" ;;
    client) cmd_client ;;
    verify) cmd_verify ;;
    *) echo "usage: $0 info|supports|server|client|verify" >&2; exit 2 ;;
esac
