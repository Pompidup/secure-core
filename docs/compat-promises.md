# Compatibility Promises — .enc V1 and V1.1 Formats

## Golden Rule

**Tout fichier `.enc` V1 ou V1.1 produit par Android v1.0+ / v0.2.0+ sera dechiffrable
par iOS V1/V1.1 et toutes versions futures V1.x.**

Any `.enc` file produced by any platform implementing V1.x (Android, iOS, desktop) must be
decryptable by any other V1.x-compatible platform, now and in all future V1.x releases.
V1.1 adds streaming truncation detection without breaking any V1.0 reader (the new header
flag is strictly additive and pre-V1.1 blobs keep their legacy AAD layout).

## Compat Packs

### V1 — in-memory (`.enc`, `encrypt_bytes` / `decrypt_bytes`)

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

### V1.1 — streaming (`encrypt_stream` / `decrypt_stream`)

The directory `testdata/compat/v1_1/stream/` contains golden reference streams:

| Vector | Plaintext size | Chunks | Description |
|--------|----------------|--------|-------------|
| `stream_single_chunk` | 2 KiB | 1 | Minimal stream — tests the final-chunk marker on a one-chunk blob |
| `stream_multi_chunk` | `CHUNK_SIZE × 2 + 777` B (≈128.8 KiB) | 3 | Exercises non-final chunk 0, non-final chunk 1, final chunk 2 |

Each vector carries `plain.bin`, `encrypted.enc`, and `metadata.json`; `vectors.json` and
`test_deks.json` catalog the pack. `encrypted.enc` is produced with a fixed base nonce via
`encrypt_stream_with_nonce_test` (behind the `_test-vectors` feature), so regeneration is
byte-for-byte reproducible.

`tests/compat_tests.rs` verifies each V1.1 vector for: (a) round-trip decryption, (b)
`FLAG_STREAM_FINAL_CHUNK` present in the header, (c) last-chunk stripping is rejected,
(d) byte-for-byte regeneration.

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
- Adding a new sibling directory in `testdata/compat/` (e.g. `v1_1/stream/`) for newly
  frozen layouts — existing subtrees must stay byte-for-byte identical.

#### V1.1 — `FLAG_STREAM_FINAL_CHUNK` (additive, 2026-04)

Streaming `.enc` blobs now opt into truncation detection by setting `flags & 0x0001`.
Retro-compat is preserved: `decrypt_stream` still accepts blobs with `flags == 0` using
the legacy per-chunk-only AAD. See `docs/enc-format-v1.md#streaming-v1.1` for semantics.
The V1 in-memory pack in `testdata/compat/v1/` is unaffected; V1.1 ships its own pack
under `testdata/compat/v1_1/stream/`.

### Diff-check policy

The `compat-tests` CI job regenerates the full corpus via
`cargo test --test generate_compat_pack --features _test-vectors -- --ignored` and then
runs `git diff --quiet testdata/compat/`. **Any diff — on `v1/` OR on `v1_1/`** —
fails the build. An intentional format change requires (a) a version bump documented in
`CHANGELOG.md`, (b) a migration note in this file, and (c) a deliberate commit of the
regenerated fixtures.

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
