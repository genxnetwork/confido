#!/bin/bash

cd -- "$(dirname -- "$0")" || exit 1

if cargo build --locked; then
    args=("${1:-127.0.0.1:8001}" "${2:-/tmp/confido}" "${3:-sha256}")
    if [[ -n "${4:-}" ]]; then
        args+=(--tls-hostname "$4")
    fi
    RUST_LOG="${RUST_LOG:-info}" sudo -E ./target/debug/confido-server "${args[@]}"
else
    echo "Build failed, not running the server"
    exit 1
fi
