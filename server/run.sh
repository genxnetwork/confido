#!/bin/bash

cargo build
if [ $? -eq 0 ]; then
    RUST_LOG=debug sudo -E ./target/debug/confido_server 127.0.0.1:8000 /tmp/confido sha1
else
    echo "Build failed, not running the server"
fi


