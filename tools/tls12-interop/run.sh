#!/usr/bin/env bash
# TLS 1.2 / DTLS 1.2 AEAD cipher-suite interop matrix: purecrypto <-> OpenSSL.
#
# Drives the `purecrypto` CLI (`s_client` / `s_server`) against `openssl`
# over real loopback TCP (TLS 1.2) and UDP (DTLS 1.2) sockets, in both roles,
# with an ECDSA and an RSA certificate, for every AEAD suite the 1.2 engines
# offer: AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. The OpenSSL side pins
# the suite (`-cipher`), so a completed handshake proves that suite's record
# protection and key-block layout on both ends.
#
# Loopback purecrypto<->purecrypto cannot catch a symmetric wire-format bug:
# it passed while the ChaCha20-Poly1305 suites used the AES-GCM explicit
# nonce instead of the RFC 7905 construction, and while the DTLS 1.2
# transcript hashed TLS-shaped handshake headers instead of the DTLS ones
# (RFC 6347 §4.2.6). This matrix fails on either.
#
# The OpenSSL -> purecrypto DTLS 1.2 cases run twice: once as OpenSSL sends
# by default, and once with the ClientHello forced across two datagrams
# (`_fragch`), which the purecrypto server's stateless cookie path used to
# refuse outright — a client on a small path MTU could never complete the
# HelloVerifyRequest round trip, and this harness hid it behind `-mtu 1500`.
#
#   OPENSSL=/path/to/openssl PURECRYPTO=/path/to/purecrypto tools/tls12-interop/run.sh
#
# Optional: TLS12_INTEROP_TIMEOUT (seconds per client step, default 20),
# TLS12_INTEROP_KEEP=1 (keep the scratch directory), TLS12_INTEROP_ONLY=<case>
# (run a single case by name, e.g. `tls12_pc_to_ossl_ec_chacha20` or
# `dtls12_ossl_to_pc_ec_aes128gcm_fragch`).
#
# Every process runs under `timeout`, so a hang fails its case fast instead of
# burning the CI job. The purecrypto server binds port 0 and reports the port
# it got; `openssl s_server` has no such mode, so it is started on a random
# high port and retried on a collision.
#
# Written for bash 3.2 (the macOS /bin/bash) as well as Linux bash 5.

set -euo pipefail

: "${PURECRYPTO:?set PURECRYPTO to the purecrypto CLI binary}"
OPENSSL=${OPENSSL:-openssl}
STEP_TIMEOUT=${TLS12_INTEROP_TIMEOUT:-20}
ONLY=${TLS12_INTEROP_ONLY:-}

if command -v timeout >/dev/null 2>&1; then
    TO=timeout
elif command -v gtimeout >/dev/null 2>&1; then
    TO=gtimeout
else
    echo "need coreutils timeout (or gtimeout)" >&2
    exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/tls12-interop.XXXXXX")
# A pipe that never delivers data and never reaches EOF, for the stdin of
# `openssl s_server`: on a closed or EOF stdin it prints DONE and exits
# before any client arrives. Opened read-write so no writer process is
# needed (and nothing for `wait` to linger on).
mkfifo "$WORK/idle-stdin"
exec 3<>"$WORK/idle-stdin"
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    if [ "${TLS12_INTEROP_KEEP:-0}" = 1 ]; then
        echo "scratch directory kept: $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

log() { printf '%s\n' "$*" >&2; }

# ---------------------------------------------------------------- material

setup() {
    local d=$WORK/pki
    mkdir -p "$d"
    (
        cd "$d"
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out ca.key
        "$PURECRYPTO" x509 -new -ca -key ca.key -subj "/CN=TLS 1.2 interop CA" -out ca.crt
        # One ECDSA (P-256) and one RSA-2048 leaf, both for `localhost`:
        # the ECDHE-ECDSA-* and ECDHE-RSA-* suites need matching keys.
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out ec.key
        "$PURECRYPTO" req -key ec.key -subj "/CN=localhost" -out ec.csr
        "$PURECRYPTO" x509 -req -in ec.csr -CA ca.crt -CAkey ca.key -san localhost -out ec.crt
        "$PURECRYPTO" genpkey -algorithm RSA -bits 2048 -out rsa.key
        "$PURECRYPTO" req -key rsa.key -subj "/CN=localhost" -out rsa.csr
        "$PURECRYPTO" x509 -req -in rsa.csr -CA ca.crt -CAkey ca.key -san localhost -out rsa.crt
    ) >/dev/null
    chmod 600 "$d"/*.key
    PKI=$d
    log "openssl: $("$OPENSSL" version)"
}

# ---------------------------------------------------------------- helpers

# expect FILE STRING: FILE must contain STRING (fixed-string match).
expect() {
    if ! grep -q -F -- "$2" "$1"; then
        log "  expected '$2' in $(basename "$1")"
        return 1
    fi
}

# The OpenSSL cipher name for a certificate kind (ec|rsa) and a suite
# (aes128gcm|aes256gcm|chacha20).
ossl_cipher() {
    local auth suite
    case $1 in
        ec) auth=ECDHE-ECDSA ;;
        rsa) auth=ECDHE-RSA ;;
    esac
    case $2 in
        aes128gcm) suite=AES128-GCM-SHA256 ;;
        aes256gcm) suite=AES256-GCM-SHA384 ;;
        chacha20) suite=CHACHA20-POLY1305 ;;
    esac
    printf '%s-%s' "$auth" "$suite"
}

# listening PROTO PORT: is a tcp|udp socket bound on PORT?
listening() {
    if command -v ss >/dev/null 2>&1; then
        if [ "$1" = tcp ]; then
            ss -Hltn "sport = :$2" 2>/dev/null | grep -q .
        else
            ss -Hlun "sport = :$2" 2>/dev/null | grep -q .
        fi
    elif [ "$1" = tcp ]; then
        lsof -nP -iTCP:"$2" -sTCP:LISTEN >/dev/null 2>&1
    else
        lsof -nP -iUDP:"$2" >/dev/null 2>&1
    fi
}

# start_ossl_server DIR PROTO ARGS... — `openssl s_server` on a random high
# port, retried on a collision; sets PORT and SERVER_PID. Its stdin is the
# idle pipe on fd 3 (see above). `-mtu 1500` pins the DTLS fragment size,
# since s_server cannot query the loopback path MTU on every platform and
# would otherwise fragment to the 256-byte minimum.
start_ossl_server() {
    local dir=$1 proto=$2 attempt i
    shift 2
    local vers=-tls1_2
    if [ "$proto" = udp ]; then vers="-dtls1_2 -mtu 1500"; fi
    for attempt in 1 2 3 4 5; do
        PORT=$(((RANDOM % 25000) + 30000))
        # shellcheck disable=SC2086
        "$TO" 60 "$OPENSSL" s_server -accept "$PORT" $vers -naccept 1 \
            -CAfile "$PKI/ca.crt" "$@" <&3 >"$dir/server.out" 2>"$dir/server.err" &
        SERVER_PID=$!
        for i in $(seq 1 100); do
            if listening "$proto" "$PORT"; then return 0; fi
            if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
            sleep 0.1
        done
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    done
    log "  openssl s_server did not start"
    return 1
}

# start_pc_server DIR PROTO ARGS... — `purecrypto s_server -accept 0`; reads
# the port back from the `listening on` banner; sets PORT and SERVER_PID.
start_pc_server() {
    local dir=$1 proto=$2 i
    shift 2
    local vers=-tls1_2
    if [ "$proto" = udp ]; then vers=-dtls1_2; fi
    "$TO" 60 "$PURECRYPTO" s_server -accept 0 "$vers" "$@" \
        </dev/null >"$dir/server.out" 2>"$dir/server.err" &
    SERVER_PID=$!
    for i in $(seq 1 100); do
        PORT=$(sed -n 's/^listening on [^ ]*:\([0-9][0-9]*\).*$/\1/p' "$dir/server.err")
        if [ -n "$PORT" ]; then return 0; fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
        sleep 0.1
    done
    log "  purecrypto server did not start"
    return 1
}

# stop_server: wait for a one-shot server to exit (bounded by its timeout),
# or kill it.
stop_server() {
    local mode=${1:-wait}
    if [ -z "$SERVER_PID" ]; then return 0; fi
    if [ "$mode" = kill ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
}

# pc_client DIR PROTO — purecrypto s_client sending one line; stdin stays
# open a moment so the echo can come back before EOF ends the session. The
# exit status lands in RC.
pc_client() {
    local dir=$1 proto=$2
    local vers=-tls1_2
    if [ "$proto" = udp ]; then vers=-dtls1_2; fi
    RC=0
    (printf 'ping from purecrypto\n'; sleep 1) |
        "$TO" "$STEP_TIMEOUT" "$PURECRYPTO" s_client -connect "127.0.0.1:$PORT" "$vers" \
            -CAfile "$PKI/ca.crt" -servername localhost \
            >"$dir/client.out" 2>"$dir/client.err" || RC=$?
}

# The fragmented-ClientHello variant of the OpenSSL -> purecrypto DTLS
# cases. A ClientHello pinned to one suite is ~160 bytes (~200 with the
# HelloVerifyRequest cookie), which fits one record even at OpenSSL's
# minimum link MTU of 256 (`-mtu`, IPv4: 203 bytes of handshake payload per
# record). An ALPN offer of one long name pushes both the first and the
# cookie-bearing ClientHello past that, so each arrives in two records and
# datagrams (RFC 6347 §4.2.3) and the server has to reassemble it before it
# can run the cookie check. The server is told to select the short name, so
# the ALPN negotiation is verified as well, and `-msg` lets the case check
# that the ClientHello really went out in more than one record.
FRAG_ALPN_OFFER=dtls12-interop-padding-so-that-both-the-first-and-the-cookie-bearing-client-hello-fragment,dtls12-interop
FRAG_ALPN_PICK=dtls12-interop
FRAG_MTU=256

# ossl_client DIR PROTO CIPHER [fragch] — openssl s_client pinned to CIPHER,
# sending one line to the purecrypto echo server; the exit status lands in
# RC. With `fragch` (UDP only) the ClientHello is forced across two
# datagrams, see above; without it OpenSSL sends as it does by default.
ossl_client() {
    local dir=$1 proto=$2 cipher=$3 variant=${4:-plain}
    local vers=-tls1_2 alpn=
    if [ "$proto" = udp ]; then vers=-dtls1_2; fi
    if [ "$variant" = fragch ]; then
        vers="$vers -mtu $FRAG_MTU -msg"
        alpn="-alpn $FRAG_ALPN_OFFER"
    fi
    RC=0
    # shellcheck disable=SC2086
    (printf 'ping from openssl\n'; sleep 1) |
        "$TO" "$STEP_TIMEOUT" "$OPENSSL" s_client -connect "127.0.0.1:$PORT" $vers $alpn \
            -cipher "$cipher" -CAfile "$PKI/ca.crt" -servername localhost \
            >"$dir/client.out" 2>"$dir/client.err" || RC=$?
}

rc_is() {
    if [ "$RC" -ne "$1" ]; then
        log "  client exited $RC, expected $1"
        return 1
    fi
}

# expect_fragmented_client_hello FILE: the `-msg` transcript in FILE must
# show the first ClientHello leaving in at least two records. `-msg` prints
# one `>>>` line per record header written (labelled `RecordHeader` by
# OpenSSL 3.2+, `content_type=256` by 3.0), and nothing else goes out
# before the HelloVerifyRequest (the first `<<<` line) comes back.
expect_fragmented_client_hello() {
    local n
    n=$(awk '/^<<</ { exit }
             /^>>> / && (/RecordHeader/ || /content_type=256/) { n++ }
             END { print n + 0 }' "$1")
    if [ "$n" -lt 2 ]; then
        log "  ClientHello went out in $n record(s); expected it fragmented"
        return 1
    fi
}

# ---------------------------------------------------------------- cases

# purecrypto client -> openssl server pinned to one suite. Over TCP the
# server runs `-rev` and the client must get its line back reversed; over
# UDP s_server has no echo mode, so the line is checked at the server.
case_pc_to_ossl() {
    local d=$1 proto=$2 kind=$3 suite=$4 # $5 (variant) is always `plain`
    local cipher
    cipher=$(ossl_cipher "$kind" "$suite")
    local rev=-rev
    if [ "$proto" = udp ]; then rev=; fi
    # shellcheck disable=SC2086
    start_ossl_server "$d" "$proto" -cipher "$cipher" \
        -cert "$PKI/$kind.crt" -key "$PKI/$kind.key" $rev
    pc_client "$d" "$proto"
    stop_server kill
    rc_is 0
    if [ "$proto" = tcp ]; then
        expect "$d/client.err" "connected: TLSv1.2"
        expect "$d/client.out" "otpyrcerup morf gnip"
        # `-rev` reports the connection on stderr.
        expect "$d/server.err" "Ciphersuite: $cipher"
    else
        expect "$d/client.err" "connected: DTLSv1.2"
        expect "$d/server.out" "ping from purecrypto"
        expect "$d/server.out" "CIPHER is $cipher"
    fi
}

# openssl client pinned to one suite -> purecrypto echo server. The
# `fragch` variant (UDP only) sends the ClientHello in two datagrams.
case_ossl_to_pc() {
    local d=$1 proto=$2 kind=$3 suite=$4 variant=${5:-plain}
    local cipher alpn=
    cipher=$(ossl_cipher "$kind" "$suite")
    if [ "$variant" = fragch ]; then alpn="-alpn $FRAG_ALPN_PICK"; fi
    # shellcheck disable=SC2086
    start_pc_server "$d" "$proto" -cert "$PKI/$kind.crt" -key "$PKI/$kind.key" $alpn
    ossl_client "$d" "$proto" "$cipher" "$variant"
    stop_server kill
    rc_is 0
    expect "$d/client.out" "ping from openssl"
    expect "$d/client.out" "Cipher    : $cipher"
    if [ "$proto" = tcp ]; then
        expect "$d/client.out" "Protocol  : TLSv1.2"
    else
        expect "$d/client.out" "Protocol  : DTLSv1.2"
        expect "$d/server.err" "handshake complete: DTLSv1.2"
    fi
    if [ "$variant" = fragch ]; then
        expect "$d/client.out" "ALPN protocol: $FRAG_ALPN_PICK"
        expect_fragmented_client_hello "$d/client.out"
    fi
}

# ---------------------------------------------------------------- main

setup
PASS=0
FAIL=0
FAILED=""
for proto in tcp udp; do
    for dir in pc_to_ossl ossl_to_pc; do
        for kind in ec rsa; do
            for suite in aes128gcm aes256gcm chacha20; do
                variants=plain
                if [ "$proto" = udp ] && [ "$dir" = ossl_to_pc ]; then
                    variants="plain fragch"
                fi
                for variant in $variants; do
                    name=tls12
                    if [ "$proto" = udp ]; then name=dtls12; fi
                    c="${name}_${dir}_${kind}_${suite}"
                    if [ "$variant" != plain ]; then c="${c}_${variant}"; fi
                    if [ -n "$ONLY" ] && [ "$c" != "$ONLY" ]; then continue; fi
                    cdir=$WORK/$c
                    mkdir -p "$cdir"
                    log "=== $c"
                    # Run each case in a subshell with `set -e`, so the
                    # first failed check ends the case (and only the case),
                    # and any server it left running is stopped with it.
                    set +e
                    (
                        set -e
                        trap 'stop_server kill' EXIT
                        "case_$dir" "$cdir" "$proto" "$kind" "$suite" "$variant"
                    )
                    status=$?
                    set -e
                    if [ "$status" -eq 0 ]; then
                        PASS=$((PASS + 1))
                        log "--- PASS $c"
                    else
                        FAIL=$((FAIL + 1))
                        FAILED="$FAILED $c"
                        log "--- FAIL $c"
                        for f in "$cdir"/*.out "$cdir"/*.err; do
                            [ -f "$f" ] || continue
                            log "  ----- $(basename "$f")"
                            sed 's/^/  | /' "$f" >&2
                        done
                    fi
                done
            done
        done
    done
done

log ""
log "TLS 1.2 / DTLS 1.2 interop vs OpenSSL: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
    log "failed:$FAILED"
    exit 1
fi
