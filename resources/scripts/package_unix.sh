#!/bin/sh
if [ -z "$SKIP_BUILD" ]; then
    cargo build --release --all-features --bin mirage-client-gui --bin mirage-client-daemon
fi
