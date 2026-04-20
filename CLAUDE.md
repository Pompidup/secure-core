# CLAUDE.md — secure-core

Guide de collaboration Claude Code pour ce repository.

---

## Mission du projet

`secure-core` est une **librairie cryptographique Rust pure** pour la plateforme Pompidup (coffre-fort documentaire mobile).

- **Bytes-in / bytes-out**, zéro persistance interne.
- Consommée en FFI par des apps **Kotlin/JNI (Android)** et **Swift (iOS)**.
- Invariants sécurité : pas de plaintext sur disque, pas de secret dans les logs, DEK `ZeroizeOnDrop`.

Le stockage (SQLite, metadata JSON, keystore OS) est **hors périmètre** : c'est le rôle du platform layer mobile, documenté dans `docs/platform-contract.md`.

---

## Stack

- **Rust** stable (pinned via `rust-toolchain.toml`), edition 2021
- **Workspace Cargo** : `secure-core` (lib `cdylib`/`staticlib`/`rlib`) + `ffi-harness` (bin de test FFI)
- **Crypto** : `aes-gcm 0.10`, `argon2 0.5`, `rand 0.8`, `zeroize 1`
- **FFI** : `libc 0.2`, `jni 0.21` (feature `jni`)
- **Sérialisation** : `serde`, `serde_json`, `base64`
- **Dev** : `criterion` (bench), `tempfile`, `sha2`
- **Features** : `_test-vectors` (nonces déterministes), `jni`, `log`

---

## Architecture

**Pattern** : librairie en couches. **Ce n'est pas une application hexagonale** au sens DDD — pas d'use-cases, pas de ports/adapters. Les conventions globales d'architecture hexagonale ne s'appliquent donc **que partiellement** ici. Les règles qui restent pertinentes :

- **Isolation forte du cœur crypto** : aucune dépendance à un framework, un ORM, du HTTP.
- **Surfaces FFI séparées** : `ffi/` (C ABI) et `jni_bridge.rs` (Android) sont des _boundary adapters_ ; la logique doit rester dans `crypto`, `streaming`, `api`, `recovery`, `format`.
- **Zéro logique dans les boundaries** : `ffi/functions.rs` et `jni_bridge.rs` ne doivent contenir que validation d'inputs + marshalling + délégation.

### Modules

```
secure-core/src/
├── crypto.rs        AES-256-GCM in-memory, type Dek (ZeroizeOnDrop)
├── streaming.rs     Chunked 64 KiB, nonces dérivés par XOR(base, chunk_idx)
├── format.rs        Header .enc V1 (25 B : SENC | v | algo | nonce | flags | len)
├── api.rs           Wrappers fichiers (encrypt_file / decrypt_file)
├── metadata.rs      DocumentMetadata, WrapsEnvelope, DeviceWrap, FolderMetadata
├── recovery.rs      Wrap/unwrap DEK par passphrase (Argon2id 64 MiB, t=3, p=4)
├── validation.rs    Validation longueur DEK/nonce
├── error.rs         SecureCoreError (5 variantes, codes FFI alignés)
├── logging.rs       Helpers log sans secrets (feature `log`)
├── ffi/             Surface C ABI (types + 7 fonctions extern "C")
└── jni_bridge.rs    Pont JNI Android (feature `jni`)
```

### Règles de frontière à respecter

- **Ne jamais** faire entrer une dépendance framework/IO réseau/ORM dans les modules du cœur (`crypto`, `streaming`, `format`, `api`, `recovery`, `metadata`, `validation`).
- **Ne jamais** écrire de plaintext sur disque en dehors du path explicite `decrypt_file(output_path)`.
- **Ne jamais** logger de clé, passphrase, nonce ou plaintext. Le feature `log` ne doit émettre que : nom d'opération + `doc_id` + codes d'erreur.
- **Tout `unsafe {`** DOIT être précédé d'un commentaire `// SAFETY:` sur la ligne juste au-dessus — le CI `no-unsafe` rejette le PR sinon.

---

## Tests

- Framework : tests Rust natifs (`#[cfg(test)]` inline + `tests/` intégration).
- **Pas de mocks** — tout est testé réel, en mémoire (`Cursor`) ou sur disque (`tempfile`). Cohérent avec les conventions globales (pas de `mockall`, pas d'auto-mock).
- **TDD strict** : écrire le test avant l'implémentation.
- **Golden files** : `testdata/compat/v1/` versionnés. Tout diff binaire non-intentionnel fait échouer le CI (`compat-tests` job).
- **FFI harness** : binaire `ffi-harness` rejoué en CI pour vérifier la surface C ABI.
- **Couverture** : `cargo llvm-cov --fail-under-lines 80`, exclut `jni_bridge.rs` et `logging.rs` (nécessitent JVM/env spécifique).
- **Déterminisme** : les fonctions `*_with_nonce_test` (feature `_test-vectors`) permettent des sorties reproductibles pour les vectors.

### Conventions

- Un test = un comportement métier, pas une fonction.
- Nommage : `test_[comportement]_[contexte]` (style snake_case Rust) ou `should_X_when_Y` si plus lisible.
- Toute nouvelle fonction publique doit avoir : round-trip, tamper-detection, wrong-key/wrong-param, edge case (empty, max size).

### Zones d'angle mort à surveiller

- **`jni_bridge.rs`** (~470 L) exclu de la coverage : aucun harness Kotlin/Android aujourd'hui. Tout changement sur ce module doit être validé manuellement ou par un test d'intégration device-side.
- **`logging.rs`** exclu de la coverage : rester vigilant à ne rien logger de sensible.

---

## Commandes

```bash
# Build
cargo build --release
cargo check --target aarch64-linux-android      # cross-check sans NDK complet

# Test
cargo test --all
cargo test --all-features
cargo test --features _test-vectors             # golden files déterministes
cargo test --test compat_tests --features _test-vectors

# Lint / format
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Bench
cargo bench

# Mobile
./scripts/build-android.sh
./scripts/build-ios.sh
./scripts/run-ffi-harness.sh
./scripts/check-ffi-header.sh                    # vérifie sync include/secure_core.h ↔ FFI exports
./scripts/generate-compat-pack.sh
```

---

## Invariants non-négociables

1. **Format `.enc` V1 figé** — le header (25 B, magic `SENC`) et les vectors golden sont un contrat public. Toute modification binaire exige : bump de version, documentation de migration, nouveaux vectors. Jamais de patch silencieux.
2. **ABI FFI figée** — les 7 symboles `secure_core_*` et les symboles JNI `Java_com_securecore_SecureCoreLib_*` sont consommés par les apps mobiles. Changer une signature = nouvelle version majeure.
3. **`include/secure_core.h`** DOIT rester synchronisé avec `ffi/functions.rs`. Le script `check-ffi-header.sh` le vérifie en CI.
4. **`Dek`** ne doit jamais être `Clone`, jamais `Debug` non-redacté, jamais sérialisé.
5. **Aucune dépendance réseau ni téléphone-maison** dans le cœur.

---

## Workflow attendu

1. Avant toute modification multi-fichiers : proposer un plan (fichiers touchés, séquence, impact ABI/format).
2. Avant d'implémenter : écrire/adapter le test.
3. Si la modification touche `ffi/` ou `jni_bridge.rs` : vérifier `include/secure_core.h`, prévoir le run du harness.
4. Si la modification touche le format binaire : regenerer les golden files volontairement via `generate_compat_pack` + documenter dans `docs/compat-promises.md`.
5. Commits conventionnels (`feat:`, `fix:`, `test:`, `refactor:`, `chore:`, `docs:`). Un commit = une intention.

---

## Documentation de référence

- `docs/api-overview.md` — API Rust + FFI
- `docs/ffi-abi-v1.md` — promesses de stabilité ABI
- `docs/enc-format-v1.md` — spec binaire `.enc`
- `docs/recovery-format-v1.md` — format recovery V1
- `docs/wraps-schema-v1.md` — schéma wrapped-DEK
- `docs/platform-contract.md` — frontière core / platform mobile
- `docs/threat-model.md` + `docs/security-considerations.md` — modèle de menace
- `docs/decisions/ADR-001-algo-choice.md`, `ADR-002-streaming-strategy.md`

---

## Ce que Claude ne doit pas faire ici

- Introduire une lib réseau, un ORM, ou tout I/O bloquant dans le cœur.
- Ajouter un `unsafe` sans `// SAFETY:` documenté au-dessus.
- Modifier un golden file sans bump de version explicite.
- Casser la signature d'une fonction `extern "C"` ou `Java_*` sans en discuter d'abord.
- Mettre de la logique métier dans `ffi/functions.rs` ou `jni_bridge.rs` (validation + délégation uniquement).
- Logger un secret, une clé, une passphrase, un nonce, du plaintext.
- Ajouter un mock / auto-mock alors que le pattern du repo est "implémentation réelle + `Cursor`/`tempfile`".
