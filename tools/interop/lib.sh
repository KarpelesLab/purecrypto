# Helpers for shell peer adapters (sourced by peers/*.sh) and by run.sh.
# Written for bash 3.2 (the macOS /bin/bash) as well as Linux bash 5.
#
# An adapter is invoked with the case already parsed into CASE_PROTO,
# CASE_ROLE, CASE_CERT, CASE_GROUP, CASE_SUITE and CASE_FEAT, plus WORK (the
# case directory), PKI (the certificate directory), TO (the `timeout`
# binary), STEP_TIMEOUT and, for `client`, PORT. See README.md.

# skip REASON: what a `supports` subcommand calls to report a SKIP.
skip() {
    printf '%s\n' "$*"
    exit 3
}

# expect FILE STRING: FILE must contain STRING (fixed-string match); prints
# the mismatch and returns 1 otherwise. `verify` subcommands chain these.
expect() {
    if ! grep -q -F -- "$2" "$1" 2>/dev/null; then
        printf "expected '%s' in %s\n" "$2" "$(basename "$1")"
        return 1
    fi
}

# refute FILE STRING: FILE must not contain STRING.
refute() {
    if grep -q -F -- "$2" "$1" 2>/dev/null; then
        printf "did not expect '%s' in %s\n" "$2" "$(basename "$1")"
        return 1
    fi
}

# expect_re FILE REGEX: FILE must have a line matching REGEX (extended).
expect_re() {
    if ! grep -q -E -- "$2" "$1" 2>/dev/null; then
        printf "expected /%s/ in %s\n" "$2" "$(basename "$1")"
        return 1
    fi
}

# listening PORT: is a TCP socket listening on PORT?
listening() {
    if command -v ss >/dev/null 2>&1; then
        ss -Hltn "sport = :$1" 2>/dev/null | grep -q .
    else
        lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
    fi
}

# random_port: a port in the ephemeral-ish 30000..54999 range.
random_port() {
    echo $(((RANDOM % 25000) + 30000))
}

# start_bg_server STDIN CMD ARGS... — for peers whose server takes a fixed
# port (no `-accept 0`): picks a random port, exported as PORT and
# substituted for the literal token `@PORT@` in ARGS, starts the command in
# the background under `timeout`, waits until the port is listening, and
# records $WORK/server.pid + $WORK/server.port. Retries on a collision (the
# process exits before listening). STDIN says what the server reads:
#   idle     a pipe that never delivers data nor EOF (`openssl s_server`
#            quits on EOF)
#   payload  $WORK/server.in at once, then the idle pipe (a peer that
#            forwards stdin to the client sends the payload)
#   delayed  $WORK/server.in one second in, then the idle pipe (for a
#            peer that must first finish the handshake on its own — e.g.
#            `openssl s_server` skips its connection summary when stdin
#            data drives the handshake through SSL_write)
start_bg_server() {
    local mode=$1 attempt i pid port arg
    shift
    local -a cmd
    for attempt in 1 2 3 4 5; do
        port=$(random_port)
        cmd=()
        for arg in "$@"; do
            case $arg in
                *@PORT@*) cmd+=("${arg//@PORT@/$port}") ;;
                *) cmd+=("$arg") ;;
            esac
        done
        # The feeder keeps the pipe open for the server's lifetime so stdin
        # never hits EOF.
        rm -f "$WORK/server.fifo"
        mkfifo "$WORK/server.fifo"
        case $mode in
            payload) (cat "$WORK/server.in"; sleep "$SERVER_TIMEOUT") >"$WORK/server.fifo" & ;;
            delayed) (sleep 1; cat "$WORK/server.in"; sleep "$SERVER_TIMEOUT") >"$WORK/server.fifo" & ;;
            *) (sleep "$SERVER_TIMEOUT") >"$WORK/server.fifo" & ;;
        esac
        echo $! >"$WORK/feeder.pid"
        "$TO" "$SERVER_TIMEOUT" "${cmd[@]}" <"$WORK/server.fifo" \
            >"$WORK/server.out" 2>"$WORK/server.err" &
        pid=$!
        for i in $(seq 1 100); do
            if listening "$port"; then
                echo "$pid" >"$WORK/server.pid"
                echo "$port" >"$WORK/server.port"
                PORT=$port
                export PORT
                return 0
            fi
            if ! kill -0 "$pid" 2>/dev/null; then break; fi
            sleep 0.1
        done
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        if [ -f "$WORK/feeder.pid" ]; then
            kill "$(cat "$WORK/feeder.pid")" 2>/dev/null || true
        fi
    done
    echo "peer server did not start (last attempt on port $port)"
    return 1
}

# version_ge A B: is dotted version A >= B? (numeric fields, e.g. 3.0.13 3.2)
version_ge() {
    local a b i x y
    IFS=. read -r -a a <<<"$1"
    IFS=. read -r -a b <<<"$2"
    for i in 0 1 2; do
        x=${a[$i]:-0}
        y=${b[$i]:-0}
        x=${x%%[!0-9]*}
        y=${y%%[!0-9]*}
        if [ "${x:-0}" -gt "${y:-0}" ]; then return 0; fi
        if [ "${x:-0}" -lt "${y:-0}" ]; then return 1; fi
    done
    return 0
}

# The certificate / key file for a cert kind (rsa2048|p256|p384|ed25519|
# mldsa65|large), and the client identity for the mtls feature.
cert_file() { echo "$PKI/$1.crt"; }
key_file() { echo "$PKI/$1.key"; }
