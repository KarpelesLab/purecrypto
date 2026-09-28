#!/usr/bin/env bash
# QUIC v1 interop matrix: purecrypto <-> quic-go and OpenSSL.
#
# Drives the `purecrypto` CLI (`q_client` / `q_server`) against the quic-go
# peer in tools/quic-interop/quicgo (both roles) and against `openssl
# s_client -quic` (OpenSSL 3.5+; client role only — s_server has no QUIC
# mode, see the OpenSSL section below) over real loopback UDP sockets. The
# application protocol is the echo of `q_server`: every bidirectional stream
# is echoed, every unidirectional stream answered on a unidirectional stream,
# every DATAGRAM echoed.
#
# Each case checks the outcome from BOTH sides' logs: the negotiated ALPN and
# cipher suite, whether 0-RTT / Retry / resumption happened, the key phase
# after a key update, the byte count and SHA-256 of what each side sent and
# received, and the close reason. quic-go's qlog trace (QLOGDIR) supplies what
# its application cannot see: the Retry packet, the version-negotiation
# packet, key-update and ECN validation events, and the stateless reset.
#
#   QUICGO=/path/to/quicgo-peer PURECRYPTO=/path/to/purecrypto \
#   OPENSSL=/path/to/openssl tools/quic-interop/run.sh
#
# Optional: QUIC_INTEROP_TIMEOUT (seconds per client step, default 30),
# QUIC_INTEROP_LOSS_TIMEOUT (seconds for the lossy 8 MiB cases, default
# 120 — see below), QUIC_INTEROP_KEEP=1 (keep the scratch directory),
# QUIC_INTEROP_ONLY=<case> (run a single case by name, e.g.
# `go_pc_to_go_retry`), QUIC_INTEROP_ECN=1 (require ECN validation to
# succeed — on by default on Linux, where the CLI's raw-syscall ECN path
# exists; elsewhere the case is skipped), OPENSSL unset or empty skips the
# OpenSSL cases.
#
# Every process runs under `timeout`, so a hang fails its case fast instead of
# burning the CI job. Both servers bind port 0 and report the port they got.
# Each PASS/FAIL line carries the case's wall time.
#
# The loss cases get their own, generous deadline on every timer along the
# path (the `timeout` wrappers and both peers' internal `-timeout`s): 8 MiB
# through 2 % loss completes in a second or two on loopback, but RFC 9002
# NewReno keeps the window small under loss and a loaded runner stretches
# every PTO, so a short deadline could fail a correct implementation. The
# first master run did exactly that with `q_server`'s default 30 s: a real
# deadlock (a lost MAX_STREAM_DATA that was never sent again) hid behind
# what looked like a slow transfer.
#
# Written for bash 3.2 (the macOS /bin/bash) as well as Linux bash 5.

set -euo pipefail

: "${PURECRYPTO:?set PURECRYPTO to the purecrypto CLI binary}"
: "${QUICGO:?set QUICGO to the quicgo-peer binary (go build in tools/quic-interop/quicgo)}"
OPENSSL=${OPENSSL:-}
STEP_TIMEOUT=${QUIC_INTEROP_TIMEOUT:-30}
LOSS_TIMEOUT=${QUIC_INTEROP_LOSS_TIMEOUT:-120}
# The deadline the current case's client step runs under; the loss cases
# raise it (each case runs in its own subshell, so the change is local).
CLIENT_TIMEOUT=$STEP_TIMEOUT
# The `timeout` wrapper on servers: they outlive the client step by a margin.
SERVER_TIMEOUT=$((LOSS_TIMEOUT + 30))
ONLY=${QUIC_INTEROP_ONLY:-}
case $(uname -s) in
    Linux) ECN_EXPECTED=${QUIC_INTEROP_ECN:-1} ;;
    *) ECN_EXPECTED=${QUIC_INTEROP_ECN:-0} ;;
esac

if command -v timeout >/dev/null 2>&1; then
    TO=timeout
elif command -v gtimeout >/dev/null 2>&1; then
    TO=gtimeout
else
    echo "need coreutils timeout (or gtimeout)" >&2
    exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/quic-interop.XXXXXX")
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    if [ "${QUIC_INTEROP_KEEP:-0}" = 1 ]; then
        echo "scratch directory kept: $WORK" >&2
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

log() { printf '%s\n' "$*" >&2; }

# Milliseconds since the epoch: GNU `date` gives nanoseconds; macOS `date`
# prints `%N` literally, so fall back to whole seconds there.
now_ms() {
    local ns
    ns=$(date +%s%N 2>/dev/null)
    case $ns in
        '' | *[!0-9]*) echo $(($(date +%s) * 1000)) ;;
        *) echo $((ns / 1000000)) ;;
    esac
}

# elapsed_s START_MS: seconds since START_MS, with millisecond precision.
elapsed_s() {
    local ms=$(($(now_ms) - $1))
    printf '%d.%03ds' $((ms / 1000)) $((ms % 1000))
}

# ---------------------------------------------------------------- material

setup() {
    local d=$WORK/pki
    mkdir -p "$d"
    (
        cd "$d"
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out ca.key
        "$PURECRYPTO" x509 -new -ca -key ca.key -subj "/CN=QUIC interop CA" -out ca.crt
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out leaf.key
        "$PURECRYPTO" req -key leaf.key -subj "/CN=localhost" -out leaf.csr
        "$PURECRYPTO" x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -san localhost -out leaf.crt
    ) >/dev/null
    chmod 600 "$d"/*.key
    PKI=$d
    printf 'ping from the QUIC interop matrix\n' >"$WORK/small.txt"
    # Multi-line, for the DATAGRAM case (one datagram per line).
    printf 'datagram one\ndatagram two\ndatagram three\ndatagram four\n' >"$WORK/lines.txt"
    # 8 MiB: several thousand packets each way, past the flow-control
    # windows, past quic-go's first key update (100 packets) and its first
    # connection-ID rotation (10 000 packets sent).
    head -c 8388608 /dev/urandom >"$WORK/big.bin"
    SMALL_SHA=$(sha256_of "$WORK/small.txt")
    BIG_SHA=$(sha256_of "$WORK/big.bin")
    log "quic-go peer: $QUICGO"
    if [ -n "$OPENSSL" ]; then log "openssl: $("$OPENSSL" version)"; fi
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# ---------------------------------------------------------------- helpers

# expect FILE STRING: FILE must contain STRING (fixed-string match).
expect() {
    if ! grep -q -F -- "$2" "$1"; then
        log "  expected '$2' in $(basename "$1")"
        return 1
    fi
}

# expect_not FILE STRING: FILE must NOT contain STRING.
expect_not() {
    if grep -q -F -- "$2" "$1"; then
        log "  did not expect '$2' in $(basename "$1")"
        return 1
    fi
}

# expect_qlog DIR STRING: some qlog trace under DIR contains STRING.
expect_qlog() {
    if ! grep -q -F -- "$2" "$1"/*.sqlog 2>/dev/null; then
        log "  expected '$2' in a qlog trace under $(basename "$1")"
        return 1
    fi
}

# expect_qlog_received DIR FRAME: a qlog trace under DIR records a received
# packet carrying a FRAME frame. (`grep -c` reads all its input, so the
# pipeline never trips `pipefail` on an early exit.)
expect_qlog_received() {
    local n
    n=$(cat "$1"/*.sqlog 2>/dev/null | grep -F '"name":"transport:packet_received"' | grep -c -F -- "\"frame_type\":\"$2\"" || true)
    if [ "$n" -eq 0 ]; then
        log "  expected a received $2 frame in a qlog trace under $(basename "$1")"
        return 1
    fi
}

# wait_for FILE STRING [SECONDS]: poll until FILE contains STRING.
wait_for() {
    local i n=${3:-100}
    for i in $(seq 1 "$n"); do
        if grep -q -F -- "$2" "$1" 2>/dev/null; then return 0; fi
        sleep 0.1
    done
    log "  timed out waiting for '$2' in $(basename "$1")"
    return 1
}

# start_go_server DIR ARGS... — the quic-go server on port 0; reads the port
# back from its banner; sets PORT and SERVER_PID.
start_go_server() {
    local dir=$1 i
    shift
    QLOGDIR="$dir/qlog-server" "$TO" "$SERVER_TIMEOUT" "$QUICGO" server -addr 127.0.0.1:0 \
        -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" -alpn pc-echo "$@" \
        </dev/null >"$dir/server.out" 2>"$dir/server.err" &
    SERVER_PID=$!
    for i in $(seq 1 100); do
        PORT=$(sed -n 's/^.*listening on [^ ]*:\([0-9][0-9]*\).*$/\1/p' "$dir/server.err")
        if [ -n "$PORT" ]; then return 0; fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
        sleep 0.1
    done
    log "  quic-go server did not start"
    return 1
}

# start_pc_server DIR ARGS... — `purecrypto q_server -accept 127.0.0.1:0`;
# reads the port back from the `listening on` banner; sets PORT and
# SERVER_PID. Pass `-accept host:port` in ARGS to pin the port (restart).
start_pc_server() {
    local dir=$1 i accept=127.0.0.1:0
    shift
    "$TO" "$SERVER_TIMEOUT" "$PURECRYPTO" q_server -accept "$accept" -alpn pc-echo \
        -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" "$@" \
        </dev/null >"$dir/server.out" 2>>"$dir/server.err" &
    SERVER_PID=$!
    for i in $(seq 1 100); do
        PORT=$(sed -n 's/^listening on [^ ]*:\([0-9][0-9]*\).*$/\1/p' "$dir/server.err" | tail -1)
        if [ -n "$PORT" ]; then return 0; fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
        sleep 0.1
    done
    log "  purecrypto server did not start"
    return 1
}

# stop_server [wait|kill]: wait for a one-shot server to exit (bounded by
# its timeout), or kill it.
stop_server() {
    local mode=${1:-wait}
    if [ -z "$SERVER_PID" ]; then return 0; fi
    if [ "$mode" = kill ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
}

# pc_client DIR INPUT ARGS... — purecrypto q_client sending INPUT; stdout to
# client.out, stderr to client.err; the exit status lands in RC.
pc_client() {
    local dir=$1 input=$2
    shift 2
    RC=0
    "$TO" "$CLIENT_TIMEOUT" "$PURECRYPTO" q_client -connect "127.0.0.1:$PORT" -alpn pc-echo \
        -CAfile "$PKI/ca.crt" -servername localhost -timeout "$CLIENT_TIMEOUT" "$@" \
        <"$input" >"$dir/client.out" 2>"$dir/client.err" || RC=$?
}

# go_client DIR INPUT ARGS... — the quic-go client; same conventions.
go_client() {
    local dir=$1 input=$2
    shift 2
    RC=0
    QLOGDIR="$dir/qlog-client" "$TO" "$CLIENT_TIMEOUT" "$QUICGO" client -addr "127.0.0.1:$PORT" \
        -alpn pc-echo -cafile "$PKI/ca.crt" -sni localhost -in "$input" \
        -timeout "${CLIENT_TIMEOUT}s" "$@" \
        </dev/null >"$dir/client.out" 2>"$dir/client.err" || RC=$?
}

rc_is() {
    if [ "$RC" -ne "$1" ]; then
        log "  client exited $RC, expected $1"
        return 1
    fi
}

# echoed DIR FILE SHA: client.out equals FILE (by SHA-256).
echoed() {
    local got
    got=$(sha256_of "$1/client.out")
    if [ "$got" != "$3" ]; then
        log "  client.out sha256=$got, expected $3 ($(basename "$2"))"
        return 1
    fi
}

# The negotiated-parameter checks every quic-go case makes: same ALPN and
# suite reported by both sides.
negotiated_go_server() {
    local d=$1 suite=${2:-TLS_AES_128_GCM_SHA256}
    expect "$d/client.err" "negotiated: alpn=pc-echo suite=$suite"
    expect "$d/server.err" "alpn=pc-echo suite=$suite"
}
negotiated_pc_server() {
    local d=$1 suite=${2:-TLS_AES_128_GCM_SHA256}
    expect "$d/client.err" "alpn=pc-echo suite=$suite"
    expect "$d/server.err" "negotiated: alpn=pc-echo suite=$suite"
}

# ---------------------------------------------------------------- quic-go: purecrypto client -> quic-go server

case_go_pc_to_go_bidi() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_go_server "$d"
    expect "$d/client.err" "exchange 1: bidi 34 bytes sent sha256=$SMALL_SHA, 34 bytes received sha256=$SMALL_SHA"
    expect "$d/server.err" "echoed 34 bytes sha256=$SMALL_SHA"
    expect "$d/server.err" "closed: application error 0x0 () by remote"
}

case_go_pc_to_go_uni() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -uni
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_go_server "$d"
    expect "$d/client.err" "exchange 1: uni 34 bytes sent sha256=$SMALL_SHA, 34 bytes received sha256=$SMALL_SHA"
    expect "$d/server.err" "uni 2: echoed 34 bytes sha256=$SMALL_SHA on uni 3"
}

case_go_pc_to_go_large() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/big.bin"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/big.bin" "$BIG_SHA"
    negotiated_go_server "$d"
    expect "$d/server.err" "echoed 8388608 bytes sha256=$BIG_SHA"
    # quic-go initiates a key update after its first 100 packets and rotates
    # its connection ID after ~10 000; both must have been followed.
    expect_qlog "$d/qlog-server" '"trigger":"local_update","key_type":"server_1rtt_secret","key_phase":1'
    expect_qlog "$d/qlog-server" '"frame_type":"retire_connection_id"'
}

# Loss: the quic-go side drops 1 in 50 datagrams each way; RFC 9002
# recovery on both sides has to fill the holes and the checksums still match.
# Every deadline on the path is the generous LOSS_TIMEOUT (see the header).
case_go_pc_to_go_loss() {
    local d=$1
    CLIENT_TIMEOUT=$LOSS_TIMEOUT
    start_go_server "$d" -loss 50 -timeout "${LOSS_TIMEOUT}s"
    pc_client "$d" "$WORK/big.bin"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/big.bin" "$BIG_SHA"
    expect "$d/server.err" "echoed 8388608 bytes sha256=$BIG_SHA"
    expect_qlog "$d/qlog-server" '"name":"recovery:packet_lost"'
}

case_go_pc_to_go_retry() {
    local d=$1
    start_go_server "$d" -retry
    pc_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_go_server "$d"
    expect "$d/client.err" "retry=yes"
    # quic-go sends the Retry from its transport, before any connection (and
    # any qlog trace) exists; the accepted connection records the outcome.
    expect "$d/server.err" "addr_verified=true"
}

case_go_pc_to_go_resume() {
    local d=$1
    start_go_server "$d" -naccept 2
    pc_client "$d" "$WORK/small.txt" -reconnect
    stop_server
    rc_is 0
    expect "$d/client.err" "session ticket received (0-RTT not permitted)"
    expect "$d/client.err" "reconnecting with the session ticket (0-RTT not offered)"
    expect "$d/client.err" "negotiated: alpn=pc-echo suite=TLS_AES_128_GCM_SHA256 resumed=no"
    expect "$d/client.err" "negotiated: alpn=pc-echo suite=TLS_AES_128_GCM_SHA256 resumed=yes early_data=none"
    expect "$d/server.err" "conn 1 from 127.0.0.1"
    expect "$d/server.err" "used0rtt=false resumed=false"
    expect "$d/server.err" "conn 2 from 127.0.0.1"
    expect "$d/server.err" "used0rtt=false resumed=true"
    # Both connections echoed.
    [ "$(grep -c "echoed 34 bytes sha256=$SMALL_SHA" "$d/server.err")" -eq 2 ]
}

case_go_pc_to_go_0rtt() {
    local d=$1
    start_go_server "$d" -naccept 2 -0rtt
    pc_client "$d" "$WORK/small.txt" -reconnect -early-data
    stop_server
    rc_is 0
    expect "$d/client.err" "session ticket received (0-RTT permitted)"
    expect "$d/client.err" "reconnecting with the session ticket (0-RTT offered)"
    expect "$d/client.err" "resumed=yes early_data=accepted"
    expect "$d/server.err" "conn 2 from 127.0.0.1"
    expect "$d/server.err" "used0rtt=true resumed=true"
    [ "$(grep -c "echoed 34 bytes sha256=$SMALL_SHA" "$d/server.err")" -eq 2 ]
}

case_go_pc_to_go_keyupdate() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -key-update
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    expect "$d/client.err" "key update initiated: now sending in phase 1"
    expect "$d/client.err" "key update confirmed: phase 1"
    expect_qlog "$d/qlog-server" '"trigger":"remote_update","key_type":"server_1rtt_secret","key_phase":1'
}

case_go_pc_to_go_chacha20() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -ciphersuites TLS_CHACHA20_POLY1305_SHA256
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_go_server "$d" TLS_CHACHA20_POLY1305_SHA256
}

case_go_pc_to_go_aes256() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -ciphersuites TLS_AES_256_GCM_SHA384
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_go_server "$d" TLS_AES_256_GCM_SHA384
}

case_go_pc_to_go_close() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -close-code 4660 -close-reason "going away"
    stop_server
    rc_is 0
    expect "$d/client.err" "closing: application error 0x1234"
    expect "$d/server.err" "closed: application error 0x1234 (going away) by remote"
}

case_go_pc_to_go_idle() {
    local d=$1
    start_go_server "$d" -idle 1s
    pc_client "$d" "$WORK/small.txt" -linger 6000
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    expect "$d/client.err" "closed: idle timeout"
    expect "$d/server.err" "closed: idle timeout"
}

case_go_pc_to_go_datagram() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/lines.txt" -datagram
    stop_server
    rc_is 0
    expect "$d/client.err" "exchange 1: datagram 55 bytes sent"
    # Four datagrams out, four echoed back (any order over loopback, so
    # compare the sorted lines).
    [ "$(sort "$d/client.out" | tr '\n' '|')" = "datagram four|datagram one|datagram three|datagram two|" ]
    [ "$(grep -c "echoed datagram" "$d/server.err")" -eq 4 ]
}

case_go_pc_to_go_migrate() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -exchanges 2 -pause 300 -migrate
    stop_server
    rc_is 0
    expect "$d/client.err" "migrated: now sending from"
    expect "$d/client.err" "exchange 2: bidi 34 bytes sent"
    # The connection was accepted from one client port and ended on another:
    # quic-go validated the new path (PATH_CHALLENGE / PATH_RESPONSE both
    # ways) and switched to it.
    local p1 p2
    p1=$(sed -n 's/.*conn 1 from 127.0.0.1:\([0-9]*\):.*$/\1/p' "$d/server.err")
    p2=$(sed -n 's/.*conn 1: closed.*(last address 127.0.0.1:\([0-9]*\))$/\1/p' "$d/server.err")
    if [ -z "$p1" ] || [ -z "$p2" ] || [ "$p1" = "$p2" ]; then
        log "  expected the connection to end on a different port than it started, got '$p1' and '$p2'"
        return 1
    fi
    expect_qlog_received "$d/qlog-server" path_response
    expect_qlog_received "$d/qlog-server" path_challenge
}

case_go_pc_to_go_switchcid() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -exchanges 2 -pause 200 -switch-cid
    stop_server
    rc_is 0
    expect "$d/client.err" "switched to a new destination connection id"
    expect "$d/client.err" "exchange 2: bidi 34 bytes sent"
    # quic-go saw its old connection ID retired and kept serving.
    expect_qlog_received "$d/qlog-server" retire_connection_id
}

# Stateless reset: the quic-go server is killed after the first exchange and
# restarted on the same port with the same stateless-reset key; the client's
# next packet draws a reset (RFC 9000 §10.3) that it must recognise.
case_go_pc_to_go_reset() {
    local d=$1 key
    key=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
    start_go_server "$d" -reset-key "$key" -naccept 0
    local port=$PORT
    pc_client_bg "$d" "$WORK/small.txt" -exchanges 2 -pause 2000
    wait_for "$d/client.err" "exchange 1: bidi"
    stop_server kill
    QLOGDIR="$d/qlog-server2" "$TO" 60 "$QUICGO" server -addr "127.0.0.1:$port" \
        -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" -alpn pc-echo -reset-key "$key" -naccept 0 \
        </dev/null >"$d/server2.out" 2>"$d/server2.err" &
    SERVER_PID=$!
    wait_client
    stop_server kill
    rc_is 1
    expect "$d/client.err" "closed: stateless reset"
}

# ---------------------------------------------------------------- quic-go: quic-go client -> purecrypto server

case_go_go_to_pc_bidi() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_pc_server "$d"
    expect "$d/client.err" "bidi 34 bytes sent sha256=$SMALL_SHA, 34 bytes received sha256=$SMALL_SHA"
    expect "$d/server.err" "stream 0: 34 bytes received sha256=$SMALL_SHA"
    expect "$d/server.err" "closed: application error 0x0 () by peer"
}

case_go_go_to_pc_uni() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/small.txt" -mode uni
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_pc_server "$d"
    expect "$d/client.err" "uni 34 bytes sent sha256=$SMALL_SHA, 34 bytes received sha256=$SMALL_SHA"
    expect "$d/server.err" "stream 2: 34 bytes received on the uni stream, answering on uni 3"
}

case_go_go_to_pc_large() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/big.bin"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/big.bin" "$BIG_SHA"
    negotiated_pc_server "$d"
    expect "$d/server.err" "stream 0: 8388608 bytes received sha256=$BIG_SHA"
    expect_qlog "$d/qlog-client" '"trigger":"local_update","key_type":"client_1rtt_secret","key_phase":1'
    expect_qlog "$d/qlog-client" '"frame_type":"retire_connection_id"'
}

case_go_go_to_pc_loss() {
    local d=$1
    CLIENT_TIMEOUT=$LOSS_TIMEOUT
    start_pc_server "$d" -timeout "$LOSS_TIMEOUT"
    go_client "$d" "$WORK/big.bin" -loss 50
    stop_server
    rc_is 0
    echoed "$d" "$WORK/big.bin" "$BIG_SHA"
    expect "$d/server.err" "stream 0: 8388608 bytes received sha256=$BIG_SHA"
    expect_qlog "$d/qlog-client" '"name":"recovery:packet_lost"'
}

case_go_go_to_pc_retry() {
    local d=$1
    start_pc_server "$d" -retry
    go_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    negotiated_pc_server "$d"
    expect "$d/server.err" "retry=yes"
    expect_qlog "$d/qlog-client" '"packet_type":"retry"'
}

case_go_go_to_pc_resume() {
    local d=$1
    start_pc_server "$d" -naccept 2
    go_client "$d" "$WORK/small.txt" -reconnect
    stop_server
    rc_is 0
    expect "$d/client.err" "connection 1: alpn=pc-echo suite=TLS_AES_128_GCM_SHA256 curve=X25519MLKEM768 version=1 used0rtt=false resumed=false"
    expect "$d/client.err" "connection 2: alpn=pc-echo suite=TLS_AES_128_GCM_SHA256 curve=X25519MLKEM768 version=1 used0rtt=false resumed=true"
    expect "$d/server.err" "resumed=no early_data=none"
    expect "$d/server.err" "resumed=yes early_data=none"
    [ "$(grep -c "34 bytes received sha256=$SMALL_SHA" "$d/server.err")" -eq 2 ]
}

case_go_go_to_pc_0rtt() {
    local d=$1
    start_pc_server "$d" -naccept 2 -early-data
    go_client "$d" "$WORK/small.txt" -reconnect -0rtt
    stop_server
    rc_is 0
    expect "$d/client.err" "connection 2: 0-RTT offered"
    expect "$d/client.err" "used0rtt=true resumed=true"
    expect "$d/server.err" "resumed=yes early_data=accepted"
    [ "$(grep -c "34 bytes received sha256=$SMALL_SHA" "$d/server.err")" -eq 2 ]
}

case_go_go_to_pc_keyupdate() {
    local d=$1
    start_pc_server "$d" -key-update
    go_client "$d" "$WORK/small.txt" -linger 500ms
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    expect "$d/server.err" "key update initiated: now sending in phase 1"
    expect "$d/server.err" "key update confirmed: phase 1"
    expect_qlog "$d/qlog-client" '"trigger":"remote_update","key_type":"client_1rtt_secret","key_phase":1'
}

# The suite cannot be pinned in this direction: Go's crypto/tls does not let
# a client restrict TLS 1.3 suites, and purecrypto's `cipher_suites` is a
# client-side knob (the server follows the client's order). The purecrypto
# server's ChaCha20-Poly1305 and AES-256-GCM record protection is exercised
# by the OpenSSL client cases below instead.
case_go_go_to_pc_chacha20() {
    log "  SKIP: neither side can pin the suite in this direction (covered by ossl_to_pc_chacha20)"
    return 77
}

case_go_go_to_pc_aes256() {
    log "  SKIP: neither side can pin the suite in this direction (covered by ossl_to_pc_aes256)"
    return 77
}

case_go_go_to_pc_close() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/small.txt" -close-code 4660 -close-reason "going away"
    stop_server
    rc_is 0
    expect "$d/client.err" "closed locally with 0x1234"
    expect "$d/server.err" "closed: application error 0x1234 (going away) by peer"
}

case_go_go_to_pc_idle() {
    local d=$1
    start_pc_server "$d" -idle-timeout 1000
    go_client "$d" "$WORK/small.txt" -linger 6s
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    expect "$d/client.err" "closed: idle timeout"
    expect "$d/server.err" "closed: idle timeout"
}

case_go_go_to_pc_datagram() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/lines.txt" -mode datagram
    stop_server
    rc_is 0
    [ "$(sort "$d/client.out" | tr '\n' '|')" = "datagram four|datagram one|datagram three|datagram two|" ]
    [ "$(grep -c "echoed datagram" "$d/server.err")" -eq 4 ]
}

case_go_go_to_pc_migrate() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/small.txt" -exchanges 2 -pause 300ms -migrate
    stop_server
    rc_is 0
    expect "$d/client.err" "connection 1: migrated to"
    expect "$d/client.err" "connection 1 exchange 2: bidi 34 bytes sent"
    expect "$d/server.err" "peer migrated to 127.0.0.1:"
    local p1 p2
    p1=$(sed -n 's/^stream 0: 34 bytes received.* from 127.0.0.1:\([0-9]*\)$/\1/p' "$d/server.err")
    p2=$(sed -n 's/^stream 4: 34 bytes received.* from 127.0.0.1:\([0-9]*\)$/\1/p' "$d/server.err")
    if [ -z "$p1" ] || [ -z "$p2" ] || [ "$p1" = "$p2" ]; then
        log "  expected the two streams from different ports, got '$p1' and '$p2'"
        return 1
    fi
    # quic-go probed the new path first (RFC 9000 §9.1) and got its
    # PATH_RESPONSE there; the server then challenged the path itself.
    expect_qlog_received "$d/qlog-client" path_response
    expect_qlog_received "$d/qlog-client" path_challenge
}

case_go_go_to_pc_switchcid() {
    local d=$1
    start_pc_server "$d" -switch-cid
    go_client "$d" "$WORK/small.txt" -exchanges 2 -pause 200ms
    stop_server
    rc_is 0
    expect "$d/server.err" "switched to a new destination connection id"
    expect "$d/client.err" "connection 1 exchange 2: bidi 34 bytes sent"
    expect_qlog_received "$d/qlog-client" retire_connection_id
}

# Version negotiation: the quic-go client offers QUIC v2 first (RFC 9369),
# which the purecrypto server does not speak; its Version Negotiation packet
# must list v1 and the client must retry with it.
case_go_go_to_pc_vn() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/small.txt" -versions v2,v1
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    expect "$d/client.err" "version=1"
    expect "$d/server.err" "version negotiation sent to 127.0.0.1:"
    # quic-go starts a fresh connection (new trace) for the retry with v1.
    [ "$(ls "$d"/qlog-client/*.sqlog | wc -l)" -eq 2 ]
}

# Stateless reset: the purecrypto server is killed after the first exchange
# and restarted on the same port with the same reset key (`-reset-key`); the
# quic-go client's next packet draws a reset it must recognise.
case_go_go_to_pc_reset() {
    local d=$1 key
    key=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
    start_pc_server "$d" -reset-key "$key" -naccept 0
    local port=$PORT
    go_client_bg "$d" "$WORK/small.txt" -exchanges 2 -pause 2s
    wait_for "$d/client.err" "connection 1 exchange 1: bidi"
    stop_server kill
    "$TO" 60 "$PURECRYPTO" q_server -accept "127.0.0.1:$port" -alpn pc-echo \
        -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" -reset-key "$key" -naccept 0 \
        </dev/null >"$d/server2.out" 2>"$d/server2.err" &
    SERVER_PID=$!
    wait_client
    stop_server kill
    rc_is 1
    expect "$d/client.err" "stateless reset"
}

# ECN: both sides mark ECT(0) and echo the counts in ACKs (RFC 9000 §13.4);
# each must report the path as ECN-capable. Needs the CLI's Linux ECN path.
case_go_pc_to_go_ecn() {
    local d=$1
    if [ "$ECN_EXPECTED" != 1 ]; then
        log "  SKIP: ECN over the CLI socket is Linux-only"
        return 77
    fi
    start_go_server "$d"
    pc_client "$d" "$WORK/big.bin"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/big.bin" "$BIG_SHA"
    expect "$d/client.err" "ecn validated: yes"
    expect_qlog "$d/qlog-server" '"name":"recovery:ecn_state_updated","data":{"new":"capable"}'
}

case_go_go_to_pc_ecn() {
    local d=$1
    if [ "$ECN_EXPECTED" != 1 ]; then
        log "  SKIP: ECN over the CLI socket is Linux-only"
        return 77
    fi
    start_pc_server "$d"
    go_client "$d" "$WORK/big.bin" -linger 300ms
    stop_server
    rc_is 0
    echoed "$d" "$WORK/big.bin" "$BIG_SHA"
    expect "$d/server.err" "ecn validated: yes"
    expect_qlog "$d/qlog-client" '"name":"recovery:ecn_state_updated","data":{"new":"capable"}'
}

# X25519MLKEM768: the default key share on both sides (Go 1.24+ crypto/tls,
# purecrypto); pinned here so a regression to X25519 is caught. quic-go
# reports the group; purecrypto's negotiation line does not, so the
# purecrypto side is pinned by offering only that share.
case_go_pc_to_go_mlkem() {
    local d=$1
    start_go_server "$d"
    pc_client "$d" "$WORK/small.txt" -key-shares X25519MLKEM768
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    expect "$d/server.err" "curve=X25519MLKEM768"
}

case_go_go_to_pc_mlkem() {
    local d=$1
    start_pc_server "$d"
    go_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    echoed "$d" "$WORK/small.txt" "$SMALL_SHA"
    expect "$d/client.err" "curve=X25519MLKEM768"
}

# Background clients for the stateless-reset cases: the server has to be
# restarted while the client waits between its exchanges.
CLIENT_PID=""
pc_client_bg() {
    local dir=$1 input=$2
    shift 2
    "$TO" "$CLIENT_TIMEOUT" "$PURECRYPTO" q_client -connect "127.0.0.1:$PORT" -alpn pc-echo \
        -CAfile "$PKI/ca.crt" -servername localhost -timeout "$CLIENT_TIMEOUT" "$@" \
        <"$input" >"$dir/client.out" 2>"$dir/client.err" &
    CLIENT_PID=$!
}
go_client_bg() {
    local dir=$1 input=$2
    shift 2
    QLOGDIR="$dir/qlog-client" "$TO" "$CLIENT_TIMEOUT" "$QUICGO" client -addr "127.0.0.1:$PORT" \
        -alpn pc-echo -cafile "$PKI/ca.crt" -sni localhost -in "$input" \
        -timeout "${CLIENT_TIMEOUT}s" "$@" \
        </dev/null >"$dir/client.out" 2>"$dir/client.err" &
    CLIENT_PID=$!
}
wait_client() {
    RC=0
    wait "$CLIENT_PID" || RC=$?
    CLIENT_PID=""
}

# ---------------------------------------------------------------- OpenSSL: openssl s_client -quic -> purecrypto server
#
# OpenSSL (3.5+) ships a QUIC client in s_client; s_server has no QUIC mode
# and the server-side API (SSL_new_listener) has no command-line front end,
# so only the client direction is covered here. s_client -quic sends stdin
# on one bidirectional stream and prints what comes back; it closes the
# connection when stdin hits EOF.

ossl_client() {
    local dir=$1 input=$2
    shift 2
    RC=0
    (cat "$input"; sleep "${OSSL_LINGER:-1}") |
        "$TO" "$CLIENT_TIMEOUT" "$OPENSSL" s_client -quic -connect "127.0.0.1:$PORT" -alpn pc-echo \
            -CAfile "$PKI/ca.crt" -servername localhost -verify_return_error "$@" \
            >"$dir/client.out" 2>"$dir/client.err" || RC=$?
}

case_ossl_to_pc_bidi() {
    local d=$1
    start_pc_server "$d"
    ossl_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    expect "$d/client.out" "ping from the QUIC interop matrix"
    expect "$d/client.out" "Protocol: QUICv1"
    expect "$d/client.out" "Cipher    : TLS_AES_128_GCM_SHA256"
    expect "$d/server.err" "negotiated: alpn=pc-echo suite=TLS_AES_128_GCM_SHA256"
    expect "$d/server.err" "34 bytes received sha256=$SMALL_SHA"
}

case_ossl_to_pc_chacha20() {
    local d=$1
    start_pc_server "$d"
    ossl_client "$d" "$WORK/small.txt" -ciphersuites TLS_CHACHA20_POLY1305_SHA256
    stop_server
    rc_is 0
    expect "$d/client.out" "ping from the QUIC interop matrix"
    expect "$d/client.out" "Cipher    : TLS_CHACHA20_POLY1305_SHA256"
    expect "$d/server.err" "negotiated: alpn=pc-echo suite=TLS_CHACHA20_POLY1305_SHA256"
}

case_ossl_to_pc_retry() {
    local d=$1
    start_pc_server "$d" -retry
    ossl_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    expect "$d/client.out" "ping from the QUIC interop matrix"
    expect "$d/server.err" "retry=yes"
}

# `-nocommands`: s_client otherwise reads a line starting with K/Q/R as a
# command (key update / quit / renegotiate), which random bytes will hit.
case_ossl_to_pc_large() {
    local d=$1
    start_pc_server "$d"
    OSSL_LINGER=3 ossl_client "$d" "$WORK/big.bin" -nocommands
    stop_server
    rc_is 0
    expect "$d/server.err" "8388608 bytes received sha256=$BIG_SHA"
}

case_ossl_to_pc_resume() {
    local d=$1
    start_pc_server "$d" -naccept 2
    ossl_client "$d" "$WORK/small.txt" -sess_out "$d/sess.pem"
    rc_is 0
    expect "$d/client.out" "ping from the QUIC interop matrix"
    [ -s "$d/sess.pem" ] || { log "  no session written"; return 1; }
    ossl_client "$d" "$WORK/small.txt" -sess_in "$d/sess.pem"
    stop_server
    rc_is 0
    expect "$d/client.out" "Reused, TLSv1.3"
    expect "$d/server.err" "resumed=yes"
}

case_ossl_to_pc_mlkem() {
    local d=$1
    start_pc_server "$d"
    # s_client -quic does not print the negotiated group; -trace shows the
    # ServerHello's key_share entry instead.
    ossl_client "$d" "$WORK/small.txt" -groups X25519MLKEM768 -trace
    stop_server
    rc_is 0
    expect "$d/client.out" "ping from the QUIC interop matrix"
    expect "$d/client.out" "NamedGroup: X25519MLKEM768"
}

case_ossl_to_pc_aes256() {
    local d=$1
    start_pc_server "$d"
    ossl_client "$d" "$WORK/small.txt" -ciphersuites TLS_AES_256_GCM_SHA384
    stop_server
    rc_is 0
    expect "$d/client.out" "ping from the QUIC interop matrix"
    expect "$d/client.out" "Cipher    : TLS_AES_256_GCM_SHA384"
    expect "$d/server.err" "negotiated: alpn=pc-echo suite=TLS_AES_256_GCM_SHA384"
}

# The server initiates the key update; OpenSSL rejects one that arrives
# before it has confirmed the handshake (KEY_UPDATE_ERROR "again too soon"),
# which is what a server flipping keys in the HANDSHAKE_DONE flight did.
case_ossl_to_pc_keyupdate() {
    local d=$1
    start_pc_server "$d" -key-update
    ossl_client "$d" "$WORK/small.txt"
    stop_server
    rc_is 0
    expect "$d/client.out" "ping from the QUIC interop matrix"
    expect "$d/server.err" "key update initiated: now sending in phase 1"
    expect "$d/server.err" "key update confirmed: phase 1"
}

# ---------------------------------------------------------------- main

setup
PASS=0
FAIL=0
SKIP=0
FAILED=""
CASES="
go_pc_to_go_bidi go_pc_to_go_uni go_pc_to_go_large go_pc_to_go_loss go_pc_to_go_retry
go_pc_to_go_resume go_pc_to_go_0rtt go_pc_to_go_keyupdate go_pc_to_go_chacha20 go_pc_to_go_aes256
go_pc_to_go_close go_pc_to_go_idle go_pc_to_go_datagram go_pc_to_go_migrate go_pc_to_go_switchcid
go_pc_to_go_reset go_pc_to_go_ecn go_pc_to_go_mlkem
go_go_to_pc_bidi go_go_to_pc_uni go_go_to_pc_large go_go_to_pc_loss go_go_to_pc_retry
go_go_to_pc_resume go_go_to_pc_0rtt go_go_to_pc_keyupdate go_go_to_pc_chacha20 go_go_to_pc_aes256
go_go_to_pc_close go_go_to_pc_idle go_go_to_pc_datagram go_go_to_pc_migrate go_go_to_pc_switchcid
go_go_to_pc_vn go_go_to_pc_reset go_go_to_pc_ecn go_go_to_pc_mlkem
"
if [ -n "$OPENSSL" ]; then
    CASES="$CASES ossl_to_pc_bidi ossl_to_pc_chacha20 ossl_to_pc_aes256 ossl_to_pc_retry
           ossl_to_pc_large ossl_to_pc_resume ossl_to_pc_mlkem ossl_to_pc_keyupdate"
fi
for c in $CASES; do
    if [ -n "$ONLY" ] && [ "$c" != "$ONLY" ]; then continue; fi
    cdir=$WORK/$c
    mkdir -p "$cdir"
    log "=== $c"
    started=$(now_ms)
    # Run each case in a subshell with `set -e`, so the first failed check
    # ends the case (and only the case), and any server or background client
    # it left running is stopped with it.
    set +e
    (
        set -e
        trap 'stop_server kill; if [ -n "$CLIENT_PID" ]; then kill "$CLIENT_PID" 2>/dev/null || true; fi' EXIT
        "case_$c" "$cdir"
    )
    status=$?
    set -e
    took=$(elapsed_s "$started")
    if [ "$status" -eq 0 ]; then
        PASS=$((PASS + 1))
        log "--- PASS $c ($took)"
    elif [ "$status" -eq 77 ]; then
        SKIP=$((SKIP + 1))
        log "--- SKIP $c"
    else
        FAIL=$((FAIL + 1))
        FAILED="$FAILED $c"
        log "--- FAIL $c ($took)"
        for f in "$cdir"/*.err "$cdir"/*.out; do
            [ -f "$f" ] || continue
            log "  ----- $(basename "$f") ($(wc -c <"$f" | tr -d ' ') bytes)"
            # Binary payloads (the large cases) are not worth printing.
            head -c 2000 "$f" | LC_ALL=C tr -c '[:print:]\n' '.' | sed 's/^/  | /' >&2 || true
        done
    fi
done

log ""
log "QUIC interop: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -ne 0 ]; then
    log "failed:$FAILED"
    exit 1
fi
