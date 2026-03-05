# Compatibility Promises — .enc V1 Format

## Golden Rule

**Tout fichier `.enc` V1 produit par Android v1.0+ sera dechiffrable par iOS V1 et toutes
versions futures V1.x.**

Any `.enc` file produced by any platform implementing V1 (Android, iOS, desktop) must be
decryptable by any other V1-compatible platform, now and in all future V1.x releases.

## Compat Pack

The directory `testdata/compat/v1/` contains golden reference files:

| Vector | Size | Description |
|--------|------|-------------|
| `image_small` | 1 KB | Small binary pattern |
| `image_medium` | 500 KB | Medium binary pattern |
| `pdf_large` | 5 MB | Large binary pattern |
| `text_small` | 256 B | UTF-8 text |
| `error_tampered` | — | Corrupted ciphertext (must reject) |
| `error_truncated` | — | Truncated file (must reject) |
| `error_future_version` | — | Version=99 header (must reject) |

Each success vector includes:
- `plain.bin` — original plaintext
- `encrypted.enc` — deterministic `.enc` blob (fixed DEK + nonce)
- `metadata.json` — expected header fields and content hash

## Breaking Change Policy

**Modifier ce pack sans procedure de migration = breaking change = nouveau major.**

Modifying the compat pack without a migration procedure is a breaking change and requires
a new major version.

### What constitutes a breaking change:
- Changing the header layout (magic, field order, field sizes)
- Changing the encryption algorithm or its parameters
- Changing how AAD (Additional Authenticated Data) is computed
- Any change that causes an existing `.enc` V1 file to fail decryption

### What is NOT a breaking change:
- Adding new flag bits (readers must ignore unknown flags)
- Adding new algorithm IDs (readers reject unknown algorithms gracefully)
- Extending the header via `header_length` field (forward compatibility)

## Migration Procedure

If a V2 format is needed:

1. Create `testdata/compat/v2/` with new golden files
2. Keep `testdata/compat/v1/` — V1 tests must continue to pass
3. Both V1 and V2 compat tests run in CI simultaneously
4. Update `EncHeader::from_bytes()` to accept both versions
5. Document the migration path in `docs/enc-format-v2.md`
6. Bump the crate major version

## Regenerating the Pack

```bash
# Only if you know what you're doing and have verified no format regression:
./scripts/generate-compat-pack.sh --force
```

The generator uses deterministic encryption (fixed DEK + nonce via `_test-vectors` feature)
to ensure byte-for-byte reproducibility. Re-running the generator with the same code must
produce identical files.
