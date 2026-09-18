#!/bin/bash

export PATH="/home/azureuser/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin:$PATH"

cargo build
if [ $? -eq 0 ]; then
    RUST_LOG="${RUST_LOG:-info}" sudo -E ./target/debug/confido_server 127.0.0.1:8001 /tmp/confido sha256
else
    echo "Build failed, not running the server"
fi


