#!/bin/bash

cd -- "$(dirname -- "$0")" || exit 1

if cargo build; then
    RUST_LOG="${RUST_LOG:-info}" sudo -E ./target/debug/confido_server "${1:-127.0.0.1:8000}" "${2:-/tmp/confido}" "${3:-sha256}"
else
    echo "Build failed, not running the server"
    exit 1
fi
