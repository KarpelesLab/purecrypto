#!/usr/bin/env bash
# Encrypted Client Hello (RFC 9849) interop matrix: purecrypto <-> BoringSSL.
#
# Drives the `purecrypto` CLI (`s_client` / `s_server` / `generate-ech`, built
# with `--features ech`) against BoringSSL's `bssl` tool over real loopback TCP
# sockets, in both roles. Loopback purecrypto<->purecrypto cannot catch a
# symmetric wire-format bug; this can.
#
#   BSSL=/path/to/bssl PURECRYPTO=/path/to/purecrypto tools/ech-interop/run.sh
#
# Optional: ECH_INTEROP_TIMEOUT (seconds per client step, default 20),
# ECH_INTEROP_KEEP=1 (keep the scratch directory), ECH_INTEROP_ONLY=<case>
# (run a single case by name).
#
# Every process runs under `timeout`, so a hang fails its case fast instead of
# burning the CI job. The purecrypto server binds port 0 and reports the port
# it got; the bssl server has no such mode, so it is started on a random high
# port and retried on a collision.
#
# Written for bash 3.2 (the macOS /bin/bash) as well as Linux bash 5.

set -euo pipefail

: "${BSSL:?set BSSL to the bssl binary}"
: "${PURECRYPTO:?set PURECRYPTO to the purecrypto CLI binary (built with --features ech)}"
STEP_TIMEOUT=${ECH_INTEROP_TIMEOUT:-20}
ONLY=${ECH_INTEROP_ONLY:-}

if command -v timeout >/dev/null 2>&1; then
    TO=timeout
elif command -v gtimeout >/dev/null 2>&1; then
    TO=gtimeout
else
    echo "need coreutils timeout (or gtimeout)" >&2
    exit 2
fi

WORK=$(mktemp -d "${TMPDIR:-/tmp}/ech-interop.XXXXXX")
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    if [ "${ECH_INTEROP_KEEP:-0}" = 1 ]; then
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
        "$PURECRYPTO" x509 -new -ca -key ca.key -subj "/CN=ECH interop CA" -out ca.crt
        "$PURECRYPTO" genpkey -algorithm EC -curve P-256 -out leaf.key
        "$PURECRYPTO" req -key leaf.key -subj "/CN=public.example" -out leaf.csr
        # One certificate covers both the ECHConfig public_name (what a
        # rejected handshake authenticates) and the inner, secret name.
        "$PURECRYPTO" x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key \
            -san "public.example,secret.example" -out leaf.crt
    ) >/dev/null
    local e=$WORK/ech
    mkdir -p "$e"
    # Key material from each tool, so each side also loads the other's
    # formats: the bssl server runs on purecrypto-generated keys, the
    # purecrypto server on bssl-generated ones.
    "$BSSL" generate-ech -public-name public.example -config-id 17 \
        -out-ech-config-list "$e/bs.list" -out-ech-config "$e/bs.cfg" \
        -out-private-key "$e/bs.key"
    "$PURECRYPTO" generate-ech -public-name public.example -config-id 42 \
        -out-ech-config-list "$e/pc.list" -out-ech-config "$e/pc.cfg" \
        -out-private-key "$e/pc.key" 2>/dev/null
    # "Stale" configs: same public_name and config_id as the live ones, but
    # a key the servers do not hold — what a client with an outdated DNS
    # record sends. The server must reject and hand out retry_configs.
    "$BSSL" generate-ech -public-name public.example -config-id 42 \
        -out-ech-config-list "$e/stale-pc.list" -out-ech-config "$e/stale-pc.cfg" \
        -out-private-key "$e/stale-pc.key"
    "$PURECRYPTO" generate-ech -public-name public.example -config-id 17 \
        -out-ech-config-list "$e/stale-bs.list" -out-ech-config "$e/stale-bs.cfg" \
        -out-private-key "$e/stale-bs.key" 2>/dev/null
    # bssl writes its private keys 0644; purecrypto warns about that.
    chmod 600 "$e"/*.key "$d"/*.key
    PKI=$d
    ECH=$e
}

# ---------------------------------------------------------------- helpers

# expect FILE STRING: FILE must contain STRING (fixed-string match).
expect() {
    if ! grep -q -F -- "$2" "$1"; then
        log "  expected '$2' in $(basename "$1")"
        return 1
    fi
}

# refute FILE STRING: FILE must not contain STRING.
refute() {
    if grep -q -F -- "$2" "$1"; then
        log "  did not expect '$2' in $(basename "$1")"
        return 1
    fi
}

listening() {
    if command -v ss >/dev/null 2>&1; then
        ss -Hltn "sport = :$1" 2>/dev/null | grep -q .
    else
        lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
    fi
}

# start_bssl_server DIR ARGS... — sets PORT and SERVER_PID.
start_bssl_server() {
    local dir=$1 attempt i
    shift
    for attempt in 1 2 3 4 5; do
        PORT=$(((RANDOM % 25000) + 30000))
        "$TO" 60 "$BSSL" server -accept "$PORT" "$@" \
            </dev/null >"$dir/server.out" 2>"$dir/server.err" &
        SERVER_PID=$!
        for i in $(seq 1 100); do
            if listening "$PORT"; then return 0; fi
            if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
            sleep 0.1
        done
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    done
    log "  bssl server did not start"
    return 1
}

# start_pc_server DIR ARGS... — `-accept 0`; sets PORT and SERVER_PID.
start_pc_server() {
    local dir=$1 i
    shift
    "$TO" 60 "$PURECRYPTO" s_server -accept 0 "$@" \
        </dev/null >"$dir/server.out" 2>"$dir/server.err" &
    SERVER_PID=$!
    for i in $(seq 1 100); do
        PORT=$(sed -n 's/^listening on .*:\([0-9][0-9]*\)$/\1/p' "$dir/server.err")
        if [ -n "$PORT" ]; then return 0; fi
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then break; fi
        sleep 0.1
    done
    log "  purecrypto server did not start"
    return 1
}

# stop_server: wait for a one-shot server to exit (bounded by its timeout),
# or kill a looping one.
stop_server() {
    local mode=${1:-wait}
    if [ -z "$SERVER_PID" ]; then return 0; fi
    if [ "$mode" = kill ]; then kill "$SERVER_PID" 2>/dev/null || true; fi
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
}

# pc_client DIR ARGS... — purecrypto s_client sending an HTTP GET; the exit
# status lands in RC.
pc_client() {
    local dir=$1
    shift
    RC=0
    printf 'GET / HTTP/1.0\r\n\r\n' |
        "$TO" "$STEP_TIMEOUT" "$PURECRYPTO" s_client -connect "127.0.0.1:$PORT" \
            -CAfile "$PKI/ca.crt" "$@" >"$dir/client.out" 2>"$dir/client.err" || RC=$?
}

# bssl_client DIR ARGS... — bssl client sending one line to the purecrypto
# echo server; the exit status lands in RC.
bssl_client() {
    local dir=$1
    shift
    RC=0
    printf 'ping from bssl\n' |
        "$TO" "$STEP_TIMEOUT" "$BSSL" client -connect "127.0.0.1:$PORT" \
            -root-certs "$PKI/ca.crt" "$@" >"$dir/client.out" 2>"$dir/client.err" || RC=$?
}

# A purecrypto client talking to `bssl server -www` exits 1 only because
# bssl closes the socket without a close_notify; anything else is a failure.
pc_client_ok() {
    if [ "$RC" -eq 0 ]; then return 0; fi
    if [ "$RC" -eq 1 ] && grep -q "closed without close_notify" "$1/client.err"; then
        return 0
    fi
    log "  purecrypto client exited $RC"
    return 1
}

rc_is() {
    if [ "$RC" -ne "$1" ]; then
        log "  client exited $RC, expected $1"
        return 1
    fi
}

rc_nonzero() {
    if [ "$RC" -eq 0 ]; then
        log "  client exited 0, expected a failure"
        return 1
    fi
    if [ "$RC" -eq 124 ]; then
        log "  client timed out"
        return 1
    fi
}

# ---------------------------------------------------------------- cases

# purecrypto client -> bssl server, ECH accepted, inner SNI at the server.
case_pc_to_bssl_accept() {
    local d=$1
    start_bssl_server "$d" -www -key "$PKI/leaf.key" -cert "$PKI/leaf.crt" \
        -ech-key "$ECH/pc.key" -ech-config "$ECH/pc.cfg"
    pc_client "$d" -servername secret.example -ech-config-list "$ECH/pc.list"
    stop_server
    pc_client_ok "$d"
    expect "$d/client.err" "ECH: accepted"
    expect "$d/client.out" "Encrypted ClientHello: yes"
    expect "$d/client.out" "Client sent SNI: secret.example"
    expect "$d/server.err" "Encrypted ClientHello: yes"
}

# Same, but the bssl server wants P-256 and the client shares only X25519:
# HelloRetryRequest with the ECH HRR accept confirmation (RFC 9849 §7.2.1).
case_pc_to_bssl_hrr() {
    local d=$1
    start_bssl_server "$d" -www -debug -curves P-256 \
        -key "$PKI/leaf.key" -cert "$PKI/leaf.crt" \
        -ech-key "$ECH/pc.key" -ech-config "$ECH/pc.cfg"
    pc_client "$d" -servername secret.example -ech-config-list "$ECH/pc.list" \
        -key-shares x25519
    stop_server
    pc_client_ok "$d"
    expect "$d/server.err" "send_hello_retry_request"
    expect "$d/client.err" "ECH: accepted"
    expect "$d/client.out" "Encrypted ClientHello: yes"
    expect "$d/client.out" "Client sent SNI: secret.example"
    expect "$d/client.out" "ECDHE group: P-256"
}

# purecrypto client with a stale config -> bssl server rejects; the client
# authenticates public.example, surfaces retry_configs, and a second
# connection with those configs is accepted (RFC 9849 §6.1.6).
case_pc_to_bssl_reject_retry() {
    local d=$1
    start_bssl_server "$d" -www -loop -key "$PKI/leaf.key" -cert "$PKI/leaf.crt" \
        -ech-key "$ECH/pc.key" -ech-config "$ECH/pc.cfg"
    pc_client "$d" -servername secret.example -ech-config-list "$ECH/stale-pc.list" \
        -ech-retry-configs-out "$d/retry.bin"
    mv "$d/client.out" "$d/client1.out"
    mv "$d/client.err" "$d/client1.err"
    local rc1=$RC
    pc_client "$d" -servername secret.example -ech-config-list "$d/retry.bin"
    stop_server kill
    RC=$rc1
    rc_nonzero
    expect "$d/client1.err" "ECH: rejected"
    expect "$d/client1.err" "ECH retry_configs:"
    refute "$d/client1.out" "Encrypted ClientHello"
    if ! cmp -s "$d/retry.bin" "$ECH/pc.list"; then
        log "  retry_configs differ from the server's ECHConfigList"
        return 1
    fi
    # The retried connection.
    RC=0
    expect "$d/client.err" "ECH: accepted"
    expect "$d/client.out" "Encrypted ClientHello: yes"
    expect "$d/client.out" "Client sent SNI: secret.example"
}

# Rejection across a HelloRetryRequest: the HRR carries no ECH confirmation,
# so the client continues on the outer hello (CH2 re-sealed, never the
# secret name in clear) and ends with retry_configs (RFC 9849 §6.1.4-6).
case_pc_to_bssl_hrr_reject() {
    local d=$1
    start_bssl_server "$d" -www -debug -curves P-256 \
        -key "$PKI/leaf.key" -cert "$PKI/leaf.crt" \
        -ech-key "$ECH/pc.key" -ech-config "$ECH/pc.cfg"
    pc_client "$d" -servername secret.example -ech-config-list "$ECH/stale-pc.list" \
        -key-shares x25519 -ech-retry-configs-out "$d/retry.bin"
    stop_server
    rc_nonzero
    expect "$d/server.err" "send_hello_retry_request"
    expect "$d/client.err" "ECH: rejected"
    if ! cmp -s "$d/retry.bin" "$ECH/pc.list"; then
        log "  retry_configs differ from the server's ECHConfigList"
        return 1
    fi
}

# purecrypto client, GREASE ECH, against a bssl server without ECH keys and
# against one with them (which then "rejects" and sends retry_configs the
# GREASE client must ignore, RFC 9849 §6.2.1).
case_pc_to_bssl_grease() {
    local d=$1
    start_bssl_server "$d" -www -key "$PKI/leaf.key" -cert "$PKI/leaf.crt"
    pc_client "$d" -servername secret.example -ech-grease
    stop_server
    pc_client_ok "$d"
    expect "$d/client.err" "ECH: GREASE"
    expect "$d/client.out" "Encrypted ClientHello: no"
    expect "$d/client.out" "Client sent SNI: secret.example"

    start_bssl_server "$d" -www -key "$PKI/leaf.key" -cert "$PKI/leaf.crt" \
        -ech-key "$ECH/pc.key" -ech-config "$ECH/pc.cfg"
    pc_client "$d" -servername secret.example -ech-grease
    stop_server
    pc_client_ok "$d"
    expect "$d/client.err" "ECH: GREASE"
    expect "$d/client.out" "Encrypted ClientHello: no"
    expect "$d/client.out" "Client sent SNI: secret.example"
}

# bssl client -> purecrypto server, ECH accepted, data echoed back.
case_bssl_to_pc_accept() {
    local d=$1
    start_pc_server "$d" -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" \
        -ech-key "$ECH/bs.key" -ech-config "$ECH/bs.cfg"
    bssl_client "$d" -server-name secret.example -ech-config-list "$ECH/bs.list"
    stop_server
    rc_is 0
    expect "$d/client.err" "Encrypted ClientHello: yes"
    expect "$d/client.out" "ping from bssl"
    expect "$d/server.err" "SNI: secret.example"
    expect "$d/server.err" "ECH: accepted"
}

# bssl client shares only X25519, the purecrypto server prefers P-256: HRR.
case_bssl_to_pc_hrr() {
    local d=$1
    start_pc_server "$d" -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" \
        -ech-key "$ECH/bs.key" -ech-config "$ECH/bs.cfg" -prefer-group secp256r1
    bssl_client "$d" -server-name secret.example -ech-config-list "$ECH/bs.list" \
        -curves X25519:P-256
    stop_server
    rc_is 0
    expect "$d/client.err" "Encrypted ClientHello: yes"
    expect "$d/client.err" "ECDHE group: P-256"
    expect "$d/client.out" "ping from bssl"
    expect "$d/server.err" "SNI: secret.example"
    expect "$d/server.err" "ECH: accepted"
}

# bssl client with a stale config -> the purecrypto server rejects, completes
# the outer handshake as public.example and sends retry_configs; bssl aborts
# with ECH_REJECTED (it has no retry-config printout, so the configs
# themselves are checked in the other direction).
case_bssl_to_pc_reject() {
    local d=$1
    start_pc_server "$d" -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" \
        -ech-key "$ECH/bs.key" -ech-config "$ECH/bs.cfg"
    bssl_client "$d" -server-name secret.example -ech-config-list "$ECH/stale-bs.list"
    stop_server
    rc_nonzero
    expect "$d/client.err" "ECH_REJECTED"
    refute "$d/client.out" "ping from bssl"
    expect "$d/server.err" "SNI: public.example"
    expect "$d/server.err" "ECH: not accepted"
    refute "$d/server.err" "secret.example"
}

# The same rejection across a purecrypto-server HelloRetryRequest.
case_bssl_to_pc_hrr_reject() {
    local d=$1
    start_pc_server "$d" -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" \
        -ech-key "$ECH/bs.key" -ech-config "$ECH/bs.cfg" -prefer-group secp256r1
    bssl_client "$d" -server-name secret.example -ech-config-list "$ECH/stale-bs.list" \
        -curves X25519:P-256
    stop_server
    rc_nonzero
    expect "$d/client.err" "ECH_REJECTED"
    expect "$d/server.err" "SNI: public.example"
    expect "$d/server.err" "ECH: not accepted"
    refute "$d/server.err" "secret.example"
}

# bssl client, GREASE ECH -> purecrypto server with ECH keys: a normal
# handshake on the (only) ClientHello.
case_bssl_to_pc_grease() {
    local d=$1
    start_pc_server "$d" -cert "$PKI/leaf.crt" -key "$PKI/leaf.key" \
        -ech-key "$ECH/bs.key" -ech-config "$ECH/bs.cfg"
    bssl_client "$d" -server-name secret.example -ech-grease
    stop_server
    rc_is 0
    expect "$d/client.err" "Encrypted ClientHello: no"
    expect "$d/client.out" "ping from bssl"
    expect "$d/server.err" "SNI: secret.example"
    expect "$d/server.err" "ECH: not accepted"
}

CASES="
pc_to_bssl_accept
pc_to_bssl_hrr
pc_to_bssl_reject_retry
pc_to_bssl_hrr_reject
pc_to_bssl_grease
bssl_to_pc_accept
bssl_to_pc_hrr
bssl_to_pc_reject
bssl_to_pc_hrr_reject
bssl_to_pc_grease
"

# ---------------------------------------------------------------- main

setup
PASS=0
FAIL=0
FAILED=""
for c in $CASES; do
    if [ -n "$ONLY" ] && [ "$c" != "$ONLY" ]; then continue; fi
    dir=$WORK/$c
    mkdir -p "$dir"
    log "=== $c"
    # Run each case in a subshell with `set -e`, so the first failed check
    # ends the case (and only the case), and any server it left running is
    # stopped with it. (`set -e` is ignored inside an `if` condition, hence
    # the explicit status capture.)
    set +e
    (
        set -e
        trap 'stop_server kill' EXIT
        "case_$c" "$dir"
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
        for f in "$dir"/*.out "$dir"/*.err; do
            [ -f "$f" ] || continue
            log "  ----- $(basename "$f")"
            sed 's/^/  | /' "$f" >&2
        done
    fi
done

log ""
log "ECH interop: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
    log "failed:$FAILED"
    exit 1
fi
