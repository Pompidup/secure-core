#!/usr/bin/env bash
set -euo pipefail

echo "Building ffi-harness (release)..."
cargo build --release -p ffi-harness

echo ""
echo "Running ffi-harness..."
if cargo run --release -p ffi-harness; then
    echo ""
    echo "FFI HARNESS PASSED"
    exit 0
else
    echo ""
    echo "FFI HARNESS FAILED"
    exit 1
fi
