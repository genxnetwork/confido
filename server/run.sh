#!/bin/bash

cargo build
RUST_LOG=debug sudo -E ./target/debug/confido_server 127.0.0.1:8000 /tmp/confido


