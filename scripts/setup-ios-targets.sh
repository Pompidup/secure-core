#!/usr/bin/env bash
set -euo pipefail

# ── Install Rust iOS compilation targets ─────────────────────────────────

echo "==> Installing iOS Rust targets"

rustup target add aarch64-apple-ios          # iPhone device
rustup target add aarch64-apple-ios-sim      # Simulator Apple Silicon
rustup target add x86_64-apple-ios           # Simulator Intel (optional)

echo "==> Done. Installed targets:"
rustup target list --installed | grep -E '(ios|apple)'
