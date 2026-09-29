#!/usr/bin/env bash
# TLS interop matrix runner: purecrypto <-> one peer implementation, both
# roles, over real loopback TCP sockets.
#
#   PURECRYPTO=target/release/purecrypto tools/interop/run.sh --peer openssl-system
#
#   --peer NAME       the adapter under peers/ (openssl-system, openssl-src,
#                     boringssl, ...); see README.md for the contract
#   --filter REGEX    run only the cases whose name matches (extended regex)
#   --list            print the case names and exit
#   --keep            keep the scratch directory
#
# Environment: PURECRYPTO (required), INTEROP_TIMEOUT (seconds per client
# step, default 30), OPENSSL (an `openssl` binary for generating the OCSP
# response; default `openssl` from PATH, the OCSP cases SKIP without one)
# and whatever the adapter reads (OPENSSL, BSSL, ...).
#
# Prints one `PASS|FAIL|SKIP <case> [reason]` line per case and a summary;
# exits non-zero on any FAIL. Every process runs under `timeout`, so a hang
# fails its case instead of the CI job. A failed case dumps every log in its
# work directory.
#
# A case is a set of key=value words:
#   proto=tls13|tls12|dtls13|dtls12  role=peer-server|peer-client
#   cert=<kind>  group=<group>  suite=<suite>  feat=<feature>
# and is named <proto>_<ps|pc>_<feat>_<cert>_<group>_<suite>. The purecrypto
# side is built here from the case; the peer side is the adapter's job. Both
# sides' logs are checked for the negotiated parameters — a handshake that
# completed with the wrong group or suite is a FAIL. The DTLS cases (over
# UDP, `s_client -dtls1_3` / `s_server -dtls1_3`) run only against a peer
# whose adapter lists them in `protos`.
#
# Written for bash 3.2 (the macOS /bin/bash) as well as Linux bash 5.

set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

PEER=""
FILTER=""
LIST=0
KEEP=0
while [ $# -gt 0 ]; do
    case $1 in
        --peer) PEER=$2; shift 2 ;;
        --filter) FILTER=$2; shift 2 ;;
        --list) LIST=1; shift ;;
        --keep) KEEP=1; shift ;;
        -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
[ -n "$PEER" ] || { echo "--peer NAME is required" >&2; exit 2; }
# An adapter is an executable file; a directory of that name (a peer tool's
# sources, e.g. peers/apple/) goes with the peers/NAME.sh next to it.
if [ -f "$HERE/peers/$PEER" ] && [ -x "$HERE/peers/$PEER" ]; then
    ADAPTER=("$HERE/peers/$PEER")
elif [ -f "$HERE/peers/$PEER.sh" ]; then
    ADAPTER=(bash "$HERE/peers/$PEER.sh")
else
    echo "no adapter peers/$PEER or peers/$PEER.sh" >&2
    exit 2
fi

if [ "$LIST" = 0 ]; then
    : "${PURECRYPTO:?set PURECRYPTO to the purecrypto CLI binary}"
    case $PURECRYPTO in
        /*|[A-Za-z]:[/\\]*) ;;
        *) PURECRYPTO=$PWD/$PURECRYPTO ;;
    esac
    export PURECRYPTO
fi
BASE_TIMEOUT=${INTEROP_TIMEOUT:-30}
# set_timeouts N: a step may take N times the base timeout. 1 everywhere
# but in the `loss` cases, where every lost flight costs a retransmission
# backoff of 1, 2, 4, 8 ... seconds.
set_timeouts() {
    STEP_TIMEOUT=$((BASE_TIMEOUT * $1))
    SERVER_TIMEOUT=$((STEP_TIMEOUT * 4))
    export STEP_TIMEOUT SERVER_TIMEOUT
}
set_timeouts 1
export PEER

if command -v timeout >/dev/null 2>&1; then
    TO=timeout
elif command -v gtimeout >/dev/null 2>&1; then
    TO=gtimeout
else
    echo "need coreutils timeout (or gtimeout)" >&2
    exit 2
fi
export TO

log() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------- matrix

CERTS="rsa2048 p256 p384 ed25519 mldsa65"
GROUPS_ALL="x25519 p256 p384 p521 x25519mlkem768 secp256r1mlkem768"
SUITES="aes128gcm aes256gcm chacha20"
# Features beyond the plain handshake, run with cert=p256 group=x25519
# suite=aes128gcm unless the feature says otherwise.
FEATS="resume resume-psk 0rtt 0rtt-hrr hrr keyupdate keyupdate-peer certcomp rpk rpk-client ocsp alpn rsl large-chain tls12 extpsk"
# The DTLS matrix (per DTLS version the adapter's `protos` lists): the plain
# product, then one case per feature. Features TLS has no counterpart for:
# `mtu` (a > 16 KiB chain sent at a 512-byte path MTU: dozens of handshake
# fragments each way), `loss` (a handshake through a relay that drops 20%
# of the datagrams in each direction, pseudo-randomly from a fixed seed —
# `lossy-udp.py` — so fragments of every flight are lost and
# retransmitted: the > 16 KiB chain on DTLS 1.3, whose ACKs retransmit
# only what was lost, a plain one on DTLS 1.2, which retransmits whole
# flights; only the handshake and its parameters are checked, since a
# datagram carrying application data or the close_notify may be the one
# dropped), `loss-final` (the same relay dropping named datagrams instead
# of random ones: the LAST flight of the handshake — see `final_flight_drops`
# — which leaves one side finished and the other still in its handshake;
# the whole exchange is checked), `cid` (RFC 9146 connection IDs: each
# side receives under the CID it named — purecrypto under PC_CID, the peer
# under PEER_CID, which the adapter configures its tool with — and both
# report the pair).
DTLS_GROUPS="x25519 p256 p384 x25519mlkem768"
# The connection IDs of the `cid` cases (hex; every byte >= 0x10 so a tool
# that prints them without zero padding still prints these digits).
export PC_CID=a1b2c3d4
export PEER_CID=776f6c66
DTLS_FEATS="resume 0rtt hrr keyupdate keyupdate-peer alpn large-chain mtu loss loss-final mtls cid"

# The protocols the adapter speaks (`protos`, optional): TLS only unless it
# says otherwise.
peer_protos() {
    local p
    p=$("${ADAPTER[@]}" protos 2>/dev/null || true)
    echo "${p:-tls13 tls12}"
}
peer_speaks() {
    case " $(peer_protos) " in
        *" $1 "*) return 0 ;;
    esac
    return 1
}

matrix() {
    local role cert group suite feat proto
    for role in peer-server peer-client; do
        for cert in $CERTS; do
            for group in $GROUPS_ALL; do
                for suite in $SUITES; do
                    echo "proto=tls13 role=$role cert=$cert group=$group suite=$suite feat=plain"
                done
            done
        done
        for feat in $FEATS; do
            case $feat in
                hrr)
                    # The peer pins each group; the purecrypto side shares
                    # a different one first, so the pin costs a round trip.
                    for group in x25519 p256 p384 x25519mlkem768; do
                        echo "proto=tls13 role=$role cert=p256 group=$group suite=aes128gcm feat=hrr"
                    done ;;
                large-chain)
                    echo "proto=tls13 role=$role cert=large group=x25519 suite=aes128gcm feat=large-chain" ;;
                tls12)
                    echo "proto=tls12 role=$role cert=p256 group=x25519 suite=aes128gcm feat=tls12" ;;
                *)
                    echo "proto=tls13 role=$role cert=p256 group=x25519 suite=aes128gcm feat=$feat" ;;
            esac
        done
        # mTLS with every certificate kind as the CLIENT identity.
        for cert in $CERTS; do
            echo "proto=tls13 role=$role cert=$cert group=x25519 suite=aes128gcm feat=mtls"
        done
    done
    for proto in dtls13 dtls12; do
        peer_speaks $proto || continue
        for role in peer-server peer-client; do
            for cert in $CERTS; do
                for group in $DTLS_GROUPS; do
                    for suite in $SUITES; do
                        echo "proto=$proto role=$role cert=$cert group=$group suite=$suite feat=plain"
                    done
                done
            done
            for feat in $DTLS_FEATS; do
                case $feat in
                    hrr)
                        for group in $DTLS_GROUPS; do
                            echo "proto=$proto role=$role cert=p256 group=$group suite=aes128gcm feat=hrr"
                        done ;;
                    large-chain|mtu)
                        echo "proto=$proto role=$role cert=large group=x25519 suite=aes128gcm feat=$feat" ;;
                    loss|loss-final)
                        if [ $proto = dtls13 ]; then
                            echo "proto=$proto role=$role cert=large group=x25519 suite=aes128gcm feat=$feat"
                        else
                            echo "proto=$proto role=$role cert=p256 group=x25519 suite=aes128gcm feat=$feat"
                        fi ;;
                    *)
                        echo "proto=$proto role=$role cert=p256 group=x25519 suite=aes128gcm feat=$feat" ;;
                esac
            done
        done
    done
}

case_name() {
    local proto role cert group suite feat r
    for w in $1; do
        case $w in
            proto=*) proto=${w#proto=} ;;
            role=*) role=${w#role=} ;;
            cert=*) cert=${w#cert=} ;;
            group=*) group=${w#group=} ;;
            suite=*) suite=${w#suite=} ;;
            feat=*) feat=${w#feat=} ;;
        esac
    done
    case $role in peer-server) r=ps ;; *) r=pc ;; esac
    echo "${proto}_${r}_${feat}_${cert}_${group}_${suite}"
}

if [ "$LIST" = 1 ]; then
    matrix | while read -r spec; do
        n=$(case_name "$spec")
        if [ -z "$FILTER" ] || [[ $n =~ $FILTER ]]; then echo "$n"; fi
    done
    exit 0
fi

# ---------------------------------------------------------------- setup

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/interop-$PEER.XXXXXX")
# MSYS bash on Windows rewrites arguments that look like POSIX paths for
# native programs (`-subj /CN=x` would reach purecrypto.exe as
# `C:/Program Files/.../CN=x`): turn that off and hand out Windows-form
# paths instead, which bash and native programs both accept.
case ${OSTYPE:-} in
    msys*|cygwin*)
        export MSYS_NO_PATHCONV=1
        ROOT=$(cygpath -m "$ROOT")
        ;;
esac
export ROOT
cleanup() {
    stop_servers
    if [ "$KEEP" = 1 ]; then
        log "scratch directory kept: $ROOT"
    else
        rm -rf "$ROOT" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# The external PSK of the `extpsk` cases (RFC 8446 §4.2.11), the same on
# both sides: the identity and key wolfSSL's example programs have built in
# (`Client_identity`, the bytes 01 23 45 67 89 ab cd ef repeated), so the
# one pair serves every peer. A test constant, of course — see
# docs/recommended-usage.md for what a real one must be.
PSK_IDENTITY=Client_identity
PSK_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
export PSK_IDENTITY PSK_HEX

# Certificates and keys, generated with the purecrypto CLI. One CA, one
# leaf per key kind (all for `localhost`; the same files double as client
# identities under mTLS), an oversized chain (> 16 KiB, so the Certificate
# message must be fragmented across records), and the raw public keys /
# OCSP response the RPK and OCSP cases need.
setup_pki() {
    PKI=$ROOT/pki
    export PKI
    mkdir -p "$PKI"
    (
        cd "$PKI"
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out ca.key
        "$PURECRYPTO" x509 -new -ca -key ca.key -subj "/CN=purecrypto interop CA" -out ca.crt
        "$PURECRYPTO" genpkey -algorithm RSA -bits 2048 -out rsa2048.key
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out p256.key
        "$PURECRYPTO" genpkey -algorithm EC -curve P-384 -out p384.key
        "$PURECRYPTO" genpkey -algorithm ED25519 -out ed25519.key
        "$PURECRYPTO" genpkey -algorithm ML-DSA-65 -out mldsa65.key
        for k in rsa2048 p256 p384 ed25519 mldsa65; do
            "$PURECRYPTO" req -key $k.key -subj "/CN=localhost" -out $k.csr
            "$PURECRYPTO" x509 -req -in $k.csr -CA ca.crt -CAkey ca.key -san localhost -out $k.crt
            "$PURECRYPTO" pkey -in $k.key -pubout -out $k.pub
        done
        # The oversized chain: a P-256 leaf under an intermediate CA, each
        # padded past 8 KiB with a long subjectAltName list, so the two
        # certificates together exceed one 16 KiB record.
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out large-int.key
        "$PURECRYPTO" req -key large-int.key -subj "/CN=purecrypto interop intermediate" -out large-int.csr
        "$PURECRYPTO" x509 -req -in large-int.csr -CA ca.crt -CAkey ca.key -ca \
            -san "$(padding_sans int)" -out large-int.crt
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out large.key
        "$PURECRYPTO" req -key large.key -subj "/CN=localhost" -out large.csr
        "$PURECRYPTO" x509 -req -in large.csr -CA large-int.crt -CAkey large-int.key \
            -san "localhost,$(padding_sans leaf)" -out large-leaf.crt
        cat large-leaf.crt large-int.crt >large.crt
        "$PURECRYPTO" pkey -in large.key -pubout -out large.pub
    ) >/dev/null
    chmod 600 "$PKI"/*.key
    printf 'early data from purecrypto\n' >"$PKI/early.txt"
    # A good OCSP response for the p256 leaf, signed by the CA (RFC 6960),
    # from an `openssl` if one is around; the OCSP cases SKIP otherwise.
    OCSP_TOOL=${OPENSSL:-openssl}
    if command -v "$OCSP_TOOL" >/dev/null 2>&1; then
        (
            cd "$PKI"
            printf 'unique_subject = no\n' >index.attr
            : >index.txt
            serial=$("$OCSP_TOOL" x509 -in p256.crt -noout -serial | sed 's/^serial=//')
            printf 'V\t%s\t\t%s\tunknown\t/CN=localhost\n' \
                "$(date -u +%y%m%d%H%M%SZ -d '+1 year' 2>/dev/null || date -u -v+1y +%y%m%d%H%M%SZ)" \
                "$serial" >index.txt
            "$OCSP_TOOL" ocsp -issuer ca.crt -cert p256.crt -reqout ocsp.req >/dev/null 2>&1
            "$OCSP_TOOL" ocsp -index index.txt -CA ca.crt -rsigner ca.crt -rkey ca.key \
                -reqin ocsp.req -respout ocsp.der -ndays 30 >/dev/null 2>&1
        ) || rm -f "$PKI/ocsp.der"
    fi
    if [ -f "$PKI/ocsp.der" ]; then export OCSP=$PKI/ocsp.der; else export OCSP=""; fi
    log "purecrypto: $PURECRYPTO"
    log "peer $PEER: $("${ADAPTER[@]}" info 2>/dev/null || echo unknown)"
    # Documented tool limitations the checks make allowance for.
    QUIRKS=$("${ADAPTER[@]}" quirks 2>/dev/null || true)
    [ -z "$QUIRKS" ] || log "peer quirks: $QUIRKS"
}

# has_quirk TOKEN: declared by the adapter for the peer as a whole (at
# setup, without a case) or for the current case (`quirks` is asked again
# with the CASE_* variables set; an adapter that ignores them answers the
# same both times).
has_quirk() {
    case " $QUIRKS $CASE_QUIRKS " in
        *" $1 "*) return 0 ;;
    esac
    return 1
}

# padding_sans TAG: ~8 KiB of DNS names for a subjectAltName.
padding_sans() {
    local i out=""
    for i in $(seq 1 140); do
        out="$out${out:+,}pad-$1-$(printf '%048d' "$i").example"
    done
    echo "$out"
}

# ---------------------------------------------------------------- purecrypto side

# Names on the purecrypto side (and the expected log lines).
pc_group() {
    case $1 in
        x25519) echo x25519 ;;
        p256) echo secp256r1 ;;
        p384) echo secp384r1 ;;
        x25519mlkem768) echo X25519MLKEM768 ;;
        *) echo "" ;;
    esac
}
pc_suite() {
    case $1 in
        aes128gcm) echo TLS_AES_128_GCM_SHA256 ;;
        aes256gcm) echo TLS_AES_256_GCM_SHA384 ;;
        chacha20) echo TLS_CHACHA20_POLY1305_SHA256 ;;
    esac
}
# The (D)TLS 1.2 suite the case's certificate kind and AEAD map to (the
# peer pins it; purecrypto's 1.2 engines negotiate from their fixed list).
pc_suite12() {
    local kx
    case $1 in rsa2048) kx=RSA ;; *) kx=ECDSA ;; esac
    case $2 in
        aes128gcm) echo "TLS_ECDHE_${kx}_WITH_AES_128_GCM_SHA256" ;;
        aes256gcm) echo "TLS_ECDHE_${kx}_WITH_AES_256_GCM_SHA384" ;;
        chacha20) echo "TLS_ECDHE_${kx}_WITH_CHACHA20_POLY1305_SHA256" ;;
    esac
}
is_dtls() { case $CASE_PROTO in dtls*) return 0 ;; esac; return 1; }
# The s_client / s_server version flag for a DTLS case.
pc_dtls_flag() {
    case $CASE_PROTO in
        dtls13) echo -dtls1_3 ;;
        dtls12) echo -dtls1_2 ;;
    esac
}
# For the HRR cases: the group the purecrypto side shares first (the peer
# pins another one, so a HelloRetryRequest follows).
other_group() {
    case $1 in
        x25519) echo secp256r1 ;;
        *) echo x25519 ;;
    esac
}

# pc_supports: SKIPs for purecrypto's own limits (printed reason, exit 3).
pc_supports() {
    if [ -z "$(pc_group "$CASE_GROUP")" ]; then
        skip "purecrypto does not implement group $CASE_GROUP"
    fi
    case $CASE_FEAT in
        ocsp) [ -n "$OCSP" ] || skip "no openssl to generate an OCSP response" ;;
    esac
    if is_dtls; then
        case $CASE_FEAT in
            resume|0rtt) skip "purecrypto's DTLS engines have no session resumption (nor 0-RTT)" ;;
            mtls) skip "purecrypto's DTLS servers do not support client certificates" ;;
            loss|loss-final) command -v python3 >/dev/null 2>&1 || skip "no python3 for the lossy relay" ;;
        esac
        if [ "$CASE_PROTO" = dtls12 ]; then
            case $CASE_FEAT in
                hrr) skip "DTLS 1.2 has no HelloRetryRequest" ;;
                keyupdate|keyupdate-peer) skip "DTLS 1.2 has no KeyUpdate" ;;
            esac
            case $CASE_GROUP in
                x25519mlkem768) skip "purecrypto's DTLS 1.2 engines have no ML-KEM hybrid" ;;
            esac
            case $CASE_CERT in
                ed25519|mldsa65) skip "purecrypto's (D)TLS 1.2 engines sign with RSA or ECDSA only" ;;
            esac
        fi
    fi
}

pc_ident() {
    echo -cert "$PKI/$1.crt" -key "$PKI/$1.key"
}

# pc_client_args: the s_client arguments for the case (the purecrypto side
# of a peer-server case).
pc_client_args() {
    local a="-connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost -read_timeout 2"
    if is_dtls; then
        # The 1.2 suite is the peer's to pin (`-ciphersuites` takes TLS
        # 1.3 names); the group is pinned here in both versions.
        a="$a $(pc_dtls_flag) -groups $(pc_group "$CASE_GROUP")"
        if [ "$CASE_PROTO" = dtls13 ]; then
            a="$a -ciphersuites $(pc_suite "$CASE_SUITE")"
        fi
        case $CASE_FEAT in
            hrr) a="-connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost -read_timeout 2 $(pc_dtls_flag) -groups $(other_group "$CASE_GROUP"):$(pc_group "$CASE_GROUP") -key-shares $(other_group "$CASE_GROUP") -ciphersuites $(pc_suite "$CASE_SUITE")" ;;
            keyupdate) a="$a -key_update" ;;
            alpn) a="$a -alpn h2,http/1.1" ;;
            mtu) a="$a -mtu 512" ;;
            # Application data is not retransmitted by DTLS: the client
            # asks again when no answer comes, as the peers' tools do.
            loss) a="$a -resend 3" ;;
            cid) a="$a -cid $PC_CID" ;;
        esac
        echo "$a"
        return
    fi
    if [ "$CASE_PROTO" = tls12 ]; then
        a="$a -min_protocol TLSv1.2"
    else
        a="$a -groups $(pc_group "$CASE_GROUP") -ciphersuites $(pc_suite "$CASE_SUITE")"
    fi
    case $CASE_FEAT in
        resume) a="$a -reconnect" ;;
        # PSK-only resumption: the client advertises `psk_ke` alone, so a
        # peer that allows the mode selects it rather than psk_dhe_ke.
        resume-psk) a="$a -reconnect -psk_modes psk_ke" ;;
        extpsk)
            a="$a -psk_identity $PSK_IDENTITY -psk $PSK_HEX"
            # A peer that only speaks the RFC 9258 importer (BoringSSL)
            # needs the derived key + `ImportedIdentity`; others take the
            # PSK as provisioned.
            has_quirk extpsk-importer && a="$a -psk_import" ;;
        0rtt) a="$a -reconnect -early_data $PKI/early.txt" ;;
        # Share only another group: the peer pins x25519, so both the full
        # and the resumed handshake take a HelloRetryRequest, which must
        # reject the early data (RFC 8446 §4.2.10).
        0rtt-hrr) a="-connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost -read_timeout 2 -groups secp256r1:x25519 -key-shares secp256r1 -ciphersuites $(pc_suite "$CASE_SUITE") -reconnect -early_data $PKI/early.txt" ;;
        hrr) a="-connect 127.0.0.1:$PORT -CAfile $PKI/ca.crt -servername localhost -read_timeout 2 -groups $(other_group "$CASE_GROUP"):$(pc_group "$CASE_GROUP") -key-shares $(other_group "$CASE_GROUP") -ciphersuites $(pc_suite "$CASE_SUITE")" ;;
        mtls) a="$a $(pc_ident "$CASE_CERT")" ;;
        keyupdate) a="$a -key_update" ;;
        rpk) a="$a -enable_server_rpk -rpk_peer_key $PKI/$CASE_CERT.pub" ;;
        rpk-client) a="$a $(pc_ident "$CASE_CERT") -enable_client_rpk" ;;
        alpn) a="$a -alpn h2,http/1.1" ;;
        rsl) a="$a -record_size_limit 512" ;;
    esac
    echo "$a"
}

# pc_server_args: the s_server arguments for the case (the purecrypto side
# of a peer-client case).
pc_server_args() {
    local a="-accept 0 -cert $PKI/$CASE_CERT.crt -key $PKI/$CASE_CERT.key"
    if is_dtls; then
        a="$a $(pc_dtls_flag) -groups $(pc_group "$CASE_GROUP")"
        case $CASE_FEAT in
            keyupdate) a="$a -key_update" ;;
            alpn) a="$a -alpn h2,http/1.1" ;;
            mtu) a="$a -mtu 512" ;;
            cid) a="$a -cid $PC_CID" ;;
        esac
        echo "$a"
        return
    fi
    if [ "$CASE_PROTO" = tls12 ]; then
        a="$a -min_protocol TLSv1.2"
    else
        # The group and the suite are both pinned from this side too: a
        # peer client that cannot narrow its offer still lands on the
        # case's pair, or fails the handshake.
        a="$a -groups $(pc_group "$CASE_GROUP") -ciphersuites $(pc_suite "$CASE_SUITE")"
    fi
    case $CASE_FEAT in
        resume) a="$a -naccept 2" ;;
        # The server prefers `psk_ke` when the peer's client advertises it.
        resume-psk) a="$a -naccept 2 -psk_modes psk_ke:psk_dhe_ke" ;;
        extpsk)
            a="$a -psk_identity $PSK_IDENTITY -psk $PSK_HEX"
            has_quirk extpsk-importer && a="$a -psk_import" ;;
        0rtt) a="$a -naccept 2 -early_data" ;;
        # The peer shares only secp256r1; pinning x25519 forces the
        # HelloRetryRequest on both connections.
        0rtt-hrr) a="$a -naccept 2 -early_data" ;;
        mtls) a="$a -Verify $PKI/ca.crt" ;;
        keyupdate) a="$a -key_update" ;;
        rpk) a="$a -enable_server_rpk" ;;
        rpk-client) a="$a -Verify $PKI/ca.crt -enable_client_rpk -rpk_peer_key $PKI/$CASE_CERT.pub" ;;
        ocsp) a="$a -status_file $OCSP" ;;
        alpn) a="$a -alpn h2,http/1.1" ;;
        rsl) a="$a -record_size_limit 512" ;;
    esac
    echo "$a"
}

# pc_verify LOG: the purecrypto side's view of the case (its stderr).
pc_verify() {
    local f=$1 ok=0 group suite
    group=$(pc_group "$CASE_GROUP")
    suite=$(pc_suite "$CASE_SUITE")
    if is_dtls; then
        pc_verify_dtls "$f"
        return $?
    fi
    if [ "$CASE_PROTO" = tls12 ]; then
        if [ "$CASE_ROLE" = peer-server ]; then
            expect "$f" "connected: TLSv1.2" || ok=1
        else
            expect "$f" "handshake complete: TLSv1.2" || ok=1
        fi
        if ! has_quirk no-close-notify; then
            expect "$f" "close_notify: received" || ok=1
        fi
        return $ok
    fi
    if [ "$CASE_ROLE" = peer-server ]; then
        expect "$f" "connected: TLSv1.3" || ok=1
    else
        expect "$f" "handshake complete: TLSv1.3" || ok=1
    fi
    expect "$f" "cipher suite: $suite" || ok=1
    expect "$f" "key exchange: $group" || ok=1
    case $CASE_FEAT in
        hrr|0rtt-hrr) expect "$f" "HelloRetryRequest: yes" || ok=1 ;;
        *) refute "$f" "HelloRetryRequest: yes" || ok=1 ;;
    esac
    case $CASE_FEAT in
        resume|0rtt|0rtt-hrr|resume-psk) expect "$f" "resumed: yes" || ok=1 ;;
        *) refute "$f" "resumed: yes" || ok=1 ;;
    esac
    # The PSK key-exchange mode (RFC 8446 §4.2.9): the resumed connection
    # of `resume-psk` did no (EC)DHE at all (the group line above is the
    # first connection's), every other PSK handshake mixed one in.
    case $CASE_FEAT in
        resume-psk)
            expect "$f" "PSK mode: psk_ke" || ok=1
            expect "$f" "key exchange: none" || ok=1 ;;
        resume|0rtt|0rtt-hrr|extpsk) expect "$f" "PSK mode: psk_dhe_ke" || ok=1 ;;
        *) refute "$f" "PSK mode: psk_" || ok=1 ;;
    esac
    case $CASE_FEAT in
        # A handshake under an external PSK carries no certificate and
        # names the identity (the bare one, or — for the RFC 9258 importer
        # BoringSSL uses — the `ImportedIdentity` structure that wraps it,
        # so match the presence of an identity, not its exact bytes; the
        # peer adapter checks the identity from its own side).
        extpsk)
            refute "$f" "external PSK: none" || ok=1
            expect "$f" "peer certificate: none" || ok=1 ;;
        *) refute "$f" "external PSK: $PSK_IDENTITY" || ok=1 ;;
    esac
    case $CASE_FEAT in
        0rtt) expect "$f" "early data: accepted" || ok=1 ;;
        0rtt-hrr)
            expect "$f" "early data: rejected" || ok=1
            refute "$f" "early data: accepted" || ok=1 ;;
        *) refute "$f" "early data: accepted" || ok=1 ;;
    esac
    case $CASE_FEAT in
        rpk)
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$f" "peer certificate: raw public key" || ok=1
            else
                expect "$f" "own certificate: raw public key" || ok=1
            fi ;;
        rpk-client)
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$f" "own certificate: raw public key" || ok=1
            else
                expect "$f" "peer certificate: raw public key" || ok=1
            fi ;;
        mtls)
            if [ "$CASE_ROLE" = peer-client ]; then
                expect "$f" "peer certificate: X.509" || ok=1
            fi ;;
        large-chain)
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$f" "peer certificate: X.509 (2)" || ok=1
            fi ;;
        certcomp)
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$f" "peer certificate compression: zlib" || ok=1
            else
                expect "$f" "own certificate compression: zlib" || ok=1
            fi ;;
        keyupdate)
            expect_re "$f" "^KeyUpdate: sent [1-9][0-9]*, received [1-9][0-9]*" || ok=1 ;;
        keyupdate-peer)
            expect_re "$f" "^KeyUpdate: sent [1-9][0-9]*, received [1-9][0-9]*" || ok=1 ;;
        ocsp)
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$f" "OCSP staple: yes" || ok=1
            fi ;;
        alpn) expect "$f" "ALPN: h2" || ok=1 ;;
        rsl) expect "$f" "record_size_limit: negotiated" || ok=1 ;;
    esac
    # The peer must end the session with close_notify (RFC 8446 §6.1), not
    # a bare FIN — unless its tool is known never to send one.
    if ! has_quirk no-close-notify; then
        expect "$f" "close_notify: received" || ok=1
    fi
    return $ok
}

# pc_verify_dtls LOG: the DTLS counterpart of pc_verify. A DTLS 1.3
# handshake normally goes through a HelloRetryRequest anyway — the server's
# stateless cookie exchange rides on one (RFC 9147 §5.1) — so the line is
# only demanded (not refuted) outside the `hrr` cases, whose group check
# is what proves the steering.
pc_verify_dtls() {
    local f=$1 ok=0 version suite
    case $CASE_PROTO in dtls13) version=DTLSv1.3 ;; *) version=DTLSv1.2 ;; esac
    if [ "$CASE_ROLE" = peer-server ]; then
        expect "$f" "connected: $version" || ok=1
    else
        expect "$f" "handshake complete: $version" || ok=1
    fi
    if [ "$CASE_PROTO" = dtls13 ]; then
        suite=$(pc_suite "$CASE_SUITE")
    else
        suite=$(pc_suite12 "$CASE_CERT" "$CASE_SUITE")
    fi
    expect "$f" "cipher suite: $suite" || ok=1
    expect "$f" "key exchange: $(pc_group "$CASE_GROUP")" || ok=1
    case $CASE_FEAT in
        hrr) expect "$f" "HelloRetryRequest: yes" || ok=1 ;;
    esac
    refute "$f" "resumed: yes" || ok=1
    refute "$f" "early data: accepted" || ok=1
    case $CASE_FEAT in
        large-chain|mtu)
            if [ "$CASE_ROLE" = peer-server ]; then
                expect "$f" "peer certificate: X.509 (2)" || ok=1
            fi ;;
        keyupdate|keyupdate-peer)
            expect_re "$f" "^KeyUpdate: sent [1-9][0-9]*, received [1-9][0-9]*" || ok=1 ;;
        alpn) expect "$f" "ALPN: h2" || ok=1 ;;
    esac
    # RFC 9146: the CID each side receives under is the other's `tx`.
    case $CASE_FEAT in
        cid) expect "$f" "connection id: rx=$PC_CID tx=$PEER_CID" || ok=1 ;;
        *) expect "$f" "connection id: none" || ok=1 ;;
    esac
    # (Under `loss` the close_notify may be the datagram that was dropped:
    # alerts are not retransmitted.)
    if ! has_quirk no-close-notify && [ "$CASE_FEAT" != loss ]; then
        expect "$f" "close_notify: received" || ok=1
    fi
    return $ok
}

# ---------------------------------------------------------------- servers

PC_SERVER_PID=""
stop_servers() {
    if [ -n "$PC_SERVER_PID" ]; then
        kill "$PC_SERVER_PID" 2>/dev/null || true
        wait "$PC_SERVER_PID" 2>/dev/null || true
        PC_SERVER_PID=""
    fi
    if [ -n "${WORK:-}" ]; then
        if [ -f "$WORK/server.pid" ]; then
            kill "$(cat "$WORK/server.pid")" 2>/dev/null || true
        fi
        if [ -f "$WORK/feeder.pid" ]; then
            kill "$(cat "$WORK/feeder.pid")" 2>/dev/null || true
        fi
        if [ -f "$WORK/relay.pid" ]; then
            kill "$(cat "$WORK/relay.pid")" 2>/dev/null || true
        fi
    fi
}

# final_flight_drops: what the relay drops in a `loss-final` case (its
# LOSSY_DROP syntax), so that the last flight of the handshake is lost
# while its sender already counts the handshake as complete — on DTLS 1.3
# at a moment when the retransmission backoff has grown past the idle time
# after which the purecrypto tools used to say goodbye: the close_notify
# then reached a peer still inside its handshake, which failed it (the
# wolfSSL server: "SSL_accept error, peer sent close notify alert").
#
#   DTLS 1.3, purecrypto client: the server's flight is lost for 3 s (two
#     transmissions: the client retransmits its ClientHello meanwhile, and
#     the server's backoff reaches 4 s), then the client's Finished is lost
#     once. The client must retransmit it one second later (RFC 9147
#     §5.8.1, §5.8.2) and say nothing until the server has acknowledged it.
#   DTLS 1.3, purecrypto server: its ACK for the client's Finished is lost
#     twice, and so is the client's second retransmission of the Finished:
#     the next comes 4 s later. The server must still be there to
#     acknowledge it (RFC 9147 §5.8.1: "the server MUST respond to
#     retransmission of the client's final flight with a retransmit of its
#     ACK").
#   DTLS 1.2, purecrypto client: the client's Finished is lost once, after
#     the server's flight was lost for 3 s; the whole flight is
#     retransmitted on the timer (RFC 6347 §4.2.4).
#   DTLS 1.2, purecrypto server: its Finished is lost twice, and so is the
#     client's second retransmission of its own; the server must still be
#     there for the third, and answer it with its final flight again.
final_flight_drops() {
    case $CASE_PROTO:$CASE_ROLE in
        dtls13:peer-server) echo 's->c@e2~3000,c->s@e2>=60#1' ;;
        dtls13:peer-client) echo 's->c@e3#1-2,c->s@e2>=60#3' ;;
        dtls12:peer-server) echo 's->c@e0>=100~3000,c->s@e1#1' ;;
        dtls12:peer-client) echo 's->c@e1#1-2,c->s@e1#3' ;;
    esac
}

# start_lossy_relay: for the `loss` cases, a relay in front of the server
# on PORT that drops 20% of the datagrams each way; PORT then points at it.
# LOSSY_SEED picks another pseudo-random pattern than the default (1),
# LOSSY_PERCENT another rate; LOSSY_DROP and LOSSY_TRACE are the relay's
# own (see lossy-udp.py): named datagrams to drop, and a packet trace in
# relay.err.
#
# `loss-final` drops no datagram at random, only those of
# `final_flight_drops`.
start_lossy_relay() {
    local rport attempt percent=${LOSSY_PERCENT:-20} drops=${LOSSY_DROP:-}
    if [ "$CASE_FEAT" = loss-final ]; then
        percent=0
        drops=$(final_flight_drops)
    fi
    for attempt in 1 2 3 4 5; do
        rport=$(random_port)
        LOSSY_DROP=$drops python3 "$HERE/lossy-udp.py" "$rport" "$PORT" "$percent" "${LOSSY_SEED:-1}" >"$WORK/relay.out" 2>"$WORK/relay.err" &
        echo $! >"$WORK/relay.pid"
        sleep 0.3
        if kill -0 "$(cat "$WORK/relay.pid")" 2>/dev/null; then
            PORT=$rport
            export PORT
            return 0
        fi
    done
    log "  lossy relay did not start"
    return 1
}

# start_pc_server: `s_server -accept 0`; PORT from the banner.
start_pc_server() {
    local i
    # shellcheck disable=SC2046
    "$TO" "$SERVER_TIMEOUT" "$PURECRYPTO" s_server $(pc_server_args) \
        </dev/null >"$WORK/server.out" 2>"$WORK/server.err" &
    PC_SERVER_PID=$!
    for i in $(seq 1 100); do
        PORT=$(sed -n 's/^listening on [^ ]*:\([0-9][0-9]*\)\( .*\)\{0,1\}$/\1/p' "$WORK/server.err")
        if [ -n "$PORT" ]; then export PORT; return 0; fi
        if ! kill -0 "$PC_SERVER_PID" 2>/dev/null; then break; fi
        sleep 0.1
    done
    log "  purecrypto server did not start"
    return 1
}

# wait_pc_server: the one-shot server exits on its own once its client(s)
# are done; give it a moment, then kill it if it is stuck.
wait_pc_server() {
    local i
    for i in $(seq 1 100); do
        if ! kill -0 "$PC_SERVER_PID" 2>/dev/null; then break; fi
        sleep 0.1
    done
    kill "$PC_SERVER_PID" 2>/dev/null || true
    wait "$PC_SERVER_PID" 2>/dev/null || true
    PC_SERVER_PID=""
}

# wait_peer_server: same for the adapter's server (by pid file).
wait_peer_server() {
    local pid i
    [ -f "$WORK/server.pid" ] || return 0
    pid=$(cat "$WORK/server.pid")
    for i in $(seq 1 100); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.1
    done
    kill "$pid" 2>/dev/null || true
    if [ -f "$WORK/feeder.pid" ]; then kill "$(cat "$WORK/feeder.pid")" 2>/dev/null || true; fi
    # Not our child (the adapter started it): poll until it is gone so its
    # logs are complete.
    for i in $(seq 1 50); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 0.1
    done
}

# ---------------------------------------------------------------- one case

# run_case SPEC: the whole case in the current shell; returns 0 PASS,
# 1 FAIL, 3 SKIP (reason in $REASON).
run_case() {
    local spec=$1 w rc
    REASON=""
    CASE=$spec
    export CASE
    for w in $spec; do
        case $w in
            proto=*) CASE_PROTO=${w#proto=} ;;
            role=*) CASE_ROLE=${w#role=} ;;
            cert=*) CASE_CERT=${w#cert=} ;;
            group=*) CASE_GROUP=${w#group=} ;;
            suite=*) CASE_SUITE=${w#suite=} ;;
            feat=*) CASE_FEAT=${w#feat=} ;;
        esac
    done
    export CASE_PROTO CASE_ROLE CASE_CERT CASE_GROUP CASE_SUITE CASE_FEAT
    case $CASE_FEAT in loss|loss-final) set_timeouts 3 ;; *) set_timeouts 1 ;; esac
    mkdir -p "$WORK"
    # What the client (whichever side) sends, and what a peer server sends
    # back from its stdin. The record_size_limit case sends more than one
    # record's worth, so the limit is actually exercised.
    if [ "$CASE_FEAT" = rsl ]; then
        { printf 'ping from client '; head -c 3000 /dev/zero | tr '\0' 'x'; printf '\n'; } >"$WORK/client.in"
    else
        printf 'ping from client\n' >"$WORK/client.in"
    fi
    if [ "$CASE_FEAT" = keyupdate-peer ]; then
        # A `K` line makes `openssl s_server` send KeyUpdate(update_requested)
        # (its interactive command letters); harmless for other peers.
        printf 'K\npong from server\n' >"$WORK/server.in"
    else
        printf 'pong from server\n' >"$WORK/server.in"
    fi

    # Whose limits apply first: ours, then the peer's. (The caller runs
    # this function with errexit off, so statuses can be inspected.)
    REASON=$(pc_supports)
    rc=$?
    if [ "$rc" = 3 ]; then return 3; fi
    REASON=$("${ADAPTER[@]}" supports)
    rc=$?
    case $rc in
        0) ;;
        3) return 3 ;;
        *) REASON="adapter 'supports' failed ($rc): $REASON"; return 1 ;;
    esac
    CASE_QUIRKS=$("${ADAPTER[@]}" quirks 2>/dev/null || true)

    if [ "$CASE_ROLE" = peer-server ]; then
        if ! "${ADAPTER[@]}" server >"$WORK/adapter-server.log" 2>&1; then
            REASON="peer server did not start"
            return 1
        fi
        PORT=$(cat "$WORK/server.port")
        export PORT
        case $CASE_FEAT in loss|loss-final)
            start_lossy_relay || { REASON="lossy relay did not start"; return 1; } ;;
        esac
        rc=0
        # shellcheck disable=SC2046
        "$TO" "$STEP_TIMEOUT" "$PURECRYPTO" s_client $(pc_client_args) \
            <"$WORK/client.in" >"$WORK/client.out" 2>"$WORK/client.err" || rc=$?
        wait_peer_server
        if [ "$rc" -ne 0 ]; then
            REASON="purecrypto s_client exited $rc"
            return 1
        fi
        REASON=$(pc_verify "$WORK/client.err") || { REASON="purecrypto: $REASON"; return 1; }
        REASON=$("${ADAPTER[@]}" verify) || { REASON="$PEER: $REASON"; return 1; }
    else
        start_pc_server || { REASON="purecrypto s_server did not start"; return 1; }
        case $CASE_FEAT in loss|loss-final)
            start_lossy_relay || { REASON="lossy relay did not start"; return 1; } ;;
        esac
        rc=0
        "${ADAPTER[@]}" client >"$WORK/adapter-client.log" 2>&1 || rc=$?
        wait_pc_server
        # Under `loss` only the handshake is checked (by `verify`, from the
        # summary the peer printed after it): its client's exit status is
        # about the data exchange, which fails when the message or its
        # echo was dropped once too often. A timeout stays a failure.
        if [ "$rc" -ne 0 ] && { [ "$CASE_FEAT" != loss ] || [ "$rc" = 124 ]; }; then
            REASON="peer client exited $rc"
            return 1
        fi
        REASON=$(pc_verify "$WORK/server.err") || { REASON="purecrypto: $REASON"; return 1; }
        REASON=$("${ADAPTER[@]}" verify) || { REASON="$PEER: $REASON"; return 1; }
    fi
    REASON=""
    return 0
}

# ---------------------------------------------------------------- main

setup_pki
PASS=0
FAIL=0
SKIP=0
FAILED=""
while read -r spec; do
    name=$(case_name "$spec")
    if [ -n "$FILTER" ] && ! [[ $name =~ $FILTER ]]; then continue; fi
    WORK=$ROOT/$name
    export WORK
    set +e
    run_case "$spec"
    status=$?
    set -e
    stop_servers
    case $status in
        0)
            PASS=$((PASS + 1))
            echo "PASS $name" ;;
        3)
            SKIP=$((SKIP + 1))
            echo "SKIP $name ($REASON)" ;;
        *)
            FAIL=$((FAIL + 1))
            FAILED="$FAILED $name"
            echo "FAIL $name ($REASON)"
            for f in "$WORK"/*.out "$WORK"/*.err "$WORK"/*.log; do
                [ -f "$f" ] || continue
                [ -s "$f" ] || continue
                log "  ----- $(basename "$f")"
                # (`|| true`: a log over 200 lines makes `head` close the
                # pipe on grep, and pipefail + errexit would end the run.)
                grep -v '^[A-Za-z0-9+/=]\{60,\}$' "$f" | head -200 | sed 's/^/  | /' >&2 || true
            done ;;
    esac
done < <(matrix)

echo ""
echo "interop vs $PEER: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -ne 0 ]; then
    echo "failed:$FAILED"
    exit 1
fi
