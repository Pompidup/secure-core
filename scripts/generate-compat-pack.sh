#!/usr/bin/env bash
set -euo pipefail

# Generates the compat pack golden files for .enc V1 format.
# These files are committed to testdata/compat/v1/ and used by CI.
#
# Usage:
#   ./scripts/generate-compat-pack.sh          # skip if files already exist
#   ./scripts/generate-compat-pack.sh --force   # regenerate all files

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPAT_DIR="$ROOT_DIR/testdata/compat/v1"

FORCE=false
if [[ "${1:-}" == "--force" ]]; then
    FORCE=true
fi

# Check if golden files already exist
if [[ "$FORCE" == false ]] && [[ -f "$COMPAT_DIR/vectors.json" ]]; then
    echo "Compat pack already exists at $COMPAT_DIR"
    echo "Use --force to regenerate."
    exit 0
fi

echo "Generating compat pack V1..."

cd "$ROOT_DIR/secure-core"
cargo test --test generate_compat_pack --features _test-vectors -- --ignored 2>&1

echo ""
echo "Generated files:"
find "$COMPAT_DIR" -type f | sort | while read -r f; do
    size=$(wc -c < "$f" | tr -d ' ')
    echo "  $(basename "$(dirname "$f")")/$(basename "$f")  ($size bytes)"
done

echo ""
echo "Compat pack V1 generated successfully."
echo "Commit these files to ensure cross-platform compatibility."
