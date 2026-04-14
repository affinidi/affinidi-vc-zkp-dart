#!/usr/bin/env bash
# Build iOS static lib (profile ios = no LTO, symbols visible) and verify C symbols.
set -e
cd "$(dirname "$0")"
cargo clean
cargo build --profile ios --target aarch64-apple-ios
LIB=target/aarch64-apple-ios/ios/librust_eddsa_helper.a
echo "--- Artifact: $LIB ---"
ls -la "$LIB"
echo "--- Symbols (eddsa) ---"
xcrun nm "$LIB" 2>/dev/null | grep -E 'eddsa' || { echo "eddsa_sign NOT IN RUST"; exit 1; }
echo "OK: eddsa symbols present in archive."
