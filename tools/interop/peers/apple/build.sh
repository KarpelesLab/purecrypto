#!/usr/bin/env bash
# Builds the apple-interop tool (release) with the Swift toolchain of the
# host — the TLS stack under test is the OS's, so nothing else is fetched.
# Prints the binary's path. Idempotent: `swift build` is a no-op when the
# sources have not changed.
set -euo pipefail
cd "$(dirname "$0")"
swift build -c release --product apple-interop >&2
echo "$PWD/.build/release/apple-interop"
