# Compatibility Promises — .enc V1, V1.1 and V2 Formats

## Golden Rule

**Tout fichier `.enc` V1 (in-memory), V1.1 (stream) ou V2 (stream) produit par une
plateforme compatible sera dechiffrable par toutes les versions 1.x de secure-core.**

V2 (1.0.0, streaming only) authenticates the full header in every chunk; secure-core 1.x
writes V2 streams and still reads V1.1 streams. V2 files are **not** readable by
secure-core 0.x (clean `UnsupportedVersion` error). See `docs/enc-format-v2.md`.

Any `.enc` file produced by any platform implementing V1.x (Android, iOS, desktop) must be
decryptable by any other V1.x-compatible platform, now and in all future V1.x releases.
V1.1 adds streaming truncation detection without breaking any V1.0 reader (the new header
flag is strictly additive and pre-V1.1 blobs keep their legacy AAD layout).

**Exception (security):** legacy V1.0 *streams* (`flags == 0`, written before 0.3.0) are
rejected by `decrypt_stream` / `decrypt_file` since 0.5.0, and **cannot be read at all
since 1.0.0**: the migration-only `*_allow_legacy` API of 0.5.x/0.6.x is removed (see
V1.1 below). In-memory V1 blobs are not affected.

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
`encrypt_stream_v1_1_with_nonce_test` (behind the `_test-vectors` feature, the only V1.1
writer left since 1.0.0), so regeneration is byte-for-byte reproducible.

`tests/compat_tests.rs` verifies each V1.1 vector for: (a) round-trip decryption, (b)
`FLAG_STREAM_FINAL_CHUNK` present in the header, (c) last-chunk stripping is rejected,
(d) byte-for-byte regeneration.

### V2 — streaming (`encrypt_stream` / `decrypt_stream`, 1.0.0+)

The directory `testdata/compat/v2/stream/` contains golden reference streams in the V2
layout (version 2, chunk AAD = header || BE32(index | final marker)):

| Vector | Plaintext size | Chunks | Description |
|--------|----------------|--------|-------------|
| `stream_empty` | 0 B | 1 | One empty final chunk (45 B file) |
| `stream_single_chunk` | 2 KiB | 1 | Minimal non-empty stream |
| `stream_multi_chunk` | `CHUNK_SIZE × 2 + 777` B | 3 | Two full chunks and a partial final chunk |

Produced with `encrypt_stream_with_nonce_test` (fixed base nonce, own test keys).
`tests/compat_tests.rs` checks that each vector decrypts with a V2 header, that truncation
and a downgrade to V1.1 are rejected, and that it regenerates byte-for-byte. The pack was
also verified independently with Apple CryptoKit from the specification alone.

## Breaking Change Policy

**Modifier ce pack sans procedure de migration = breaking change = nouveau major.**

Modifying the compat pack without a migration procedure is a breaking change and requires
a new major version.

### What constitutes a breaking change:
- Changing the header layout (magic, field order, field sizes)
- Changing the encryption algorithm or its parameters
- Changing how AAD (Additional Authenticated Data) is computed
- Any change that causes an existing `.enc` V1, V1.1 or V2 file to fail decryption

### What is NOT a breaking change:
- Adding new flag bits for **in-memory** blobs (readers must ignore unknown flags: the header is authenticated)
- Adding new algorithm IDs (readers reject unknown algorithms gracefully)
- Extending the header via `header_length` field (forward compatibility)
- Adding a new sibling directory in `testdata/compat/` (e.g. `v1_1/stream/`, `v2/stream/`)
  for newly frozen layouts — existing subtrees must stay byte-for-byte identical.

Unknown flag bits in a **stream** header are rejected (`InvalidFormat`), in V1.1 (header
not authenticated) and in V2 (semantics unknown to the reader). A new streaming flag
therefore requires readers that know it: it is additive for writers, but not readable by
older streaming readers.

#### V1.1 — `FLAG_STREAM_FINAL_CHUNK` (additive, 2026-04)

Streaming `.enc` blobs now opt into truncation detection by setting `flags & 0x0001`.

**0.5.0: deliberate security exception to the golden rule.** The stream header is not
authenticated, so accepting `flags == 0` let an attacker clear the flag of a truncated
V1.1 stream and have it decrypt as legacy. `decrypt_stream` / `decrypt_file` (and the
C/JNI `decrypt_file` entry points) now reject `flags == 0` streams with `InvalidFormat`.
In 0.5.x and 0.6.x, pre-0.3.0 streams remained decryptable through a migration-only API
(`decrypt_stream_allow_legacy`, `api::decrypt_file_allow_legacy`,
`secure_core_decrypt_file_allow_legacy`, `nativeDecryptFileAllowLegacy`), with no
truncation detection, for a one-time re-encryption to V1.1.

**1.0.0: that API is removed** (breaking, major version). Migration path: re-encrypt
legacy streams with secure-core 0.5.x or 0.6.x, then upgrade. No byte of any golden file
changes. See `docs/enc-format-v1.md#streaming-v1.1` for semantics.
The V1 in-memory pack in `testdata/compat/v1/` is unaffected; V1.1 ships its own pack
under `testdata/compat/v1_1/stream/`.

#### V2 — header in every chunk's AAD (1.0.0, breaking)

`encrypt_stream` / `encrypt_file` (and their C/JNI entry points) write version-2 streams.
Why: in V1.1 the stream header is not authenticated, which made GHSA-43rf-fggr-vcgg
possible and left every future header field forgeable (ADR-003). Readers keep accepting
V1.1, so no existing file needs migrating; re-encrypting V1.1 files to V2 is optional.
Breaking because secure-core 0.x cannot read V2. The `v1/` and `v1_1/` packs are
unchanged; V2 ships `testdata/compat/v2/stream/`.

### Diff-check policy

The `compat-tests` CI job regenerates the full corpus via
`cargo test --test generate_compat_pack --features _test-vectors -- --ignored` and then
checks `git status --porcelain testdata/compat/`. **Any change — on `v1/`, `v1_1/` or
`v2/`, including a regenerated file that is not committed** — fails the build. An intentional format change requires (a) a version bump documented in
`CHANGELOG.md`, (b) a migration note in this file, and (c) a deliberate commit of the
regenerated fixtures.

## Migration Procedure

Followed for V2 (1.0.0); apply the same steps for any future format version:

1. Create `testdata/compat/vN/` with new golden files
2. Keep the existing packs — their tests must continue to pass, byte-identical
3. All compat tests run in CI simultaneously
4. Update `EncHeader::from_bytes()` and the decoders to accept every supported version
5. Document the format and the migration path in `docs/enc-format-vN.md` (+ an ADR)
6. Bump the crate major version

## Regenerating the Pack

```bash
# Only if you know what you're doing and have verified no format regression:
./scripts/generate-compat-pack.sh --force
```

The generator uses deterministic encryption (fixed DEK + nonce via `_test-vectors` feature)
to ensure byte-for-byte reproducibility. Re-running the generator with the same code must
produce identical files.
