#!/usr/bin/env bash
set -euo pipefail

# Verify that include/secure_core.h matches the Rust FFI exports.
# This script extracts the expected ABI from Rust source and compares
# it against the shipped C header.

HEADER="include/secure_core.h"
TYPES_RS="secure-core/src/ffi/types.rs"
FUNCS_RS="secure-core/src/ffi/functions.rs"

errors=0

echo "Checking FFI header synchronization..."

# 1. Header file must exist
if [ ! -f "$HEADER" ]; then
    echo "::error::Missing $HEADER"
    exit 1
fi

# 2. All exported function names in Rust must appear in the header
rust_functions=$(grep 'pub.*extern "C" fn ' "$FUNCS_RS" | sed 's/.*extern "C" fn \([a-z_]*\).*/\1/' | sort)
for fn in $rust_functions; do
    if ! grep -q "$fn" "$HEADER"; then
        echo "::error::Function '$fn' exported in Rust but missing from $HEADER"
        errors=$((errors + 1))
    fi
done

# 3. All status code values must match between Rust and C header
check_status() {
    local rust_name="$1"
    local c_name="$2"
    local expected_value="$3"

    rust_val=$(grep "pub const ${rust_name}:" "$TYPES_RS" | sed 's/.*= \([0-9]*\);.*/\1/')
    c_val=$(grep "#define ${c_name} " "$HEADER" | awk '{print $NF}')

    if [ "$rust_val" != "$expected_value" ]; then
        echo "::error::Rust ${rust_name} = ${rust_val}, expected ${expected_value}"
        errors=$((errors + 1))
    fi
    if [ "$c_val" != "$expected_value" ]; then
        echo "::error::C ${c_name} = ${c_val}, expected ${expected_value}"
        errors=$((errors + 1))
    fi
}

check_status "FFI_OK" "SECURE_CORE_OK" "0"
check_status "FFI_ERROR_INVALID_FORMAT" "SECURE_CORE_ERROR_INVALID_FORMAT" "1"
check_status "FFI_ERROR_UNSUPPORTED_VERSION" "SECURE_CORE_ERROR_UNSUPPORTED_VERSION" "2"
check_status "FFI_ERROR_CRYPTO" "SECURE_CORE_ERROR_CRYPTO" "3"
check_status "FFI_ERROR_IO" "SECURE_CORE_ERROR_IO" "4"
check_status "FFI_ERROR_INVALID_PARAM" "SECURE_CORE_ERROR_INVALID_PARAM" "5"

# 4. Struct names must be present
for struct_name in SecureCoreBuffer SecureCoreResult; do
    if ! grep -q "$struct_name" "$HEADER"; then
        echo "::error::Struct '$struct_name' missing from $HEADER"
        errors=$((errors + 1))
    fi
done

# 5. Header guard must be present
if ! grep -q "SECURE_CORE_H" "$HEADER"; then
    echo "::error::Missing include guard SECURE_CORE_H in $HEADER"
    errors=$((errors + 1))
fi

if [ "$errors" -gt 0 ]; then
    echo ""
    echo "::error::Header C desynchronise ($errors erreurs). Mettre a jour include/secure_core.h"
    exit 1
fi

echo "FFI header is in sync with Rust exports."
