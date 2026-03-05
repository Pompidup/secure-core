# FFI ABI Contract — v1.0.0

**STATUS: FROZEN — NE PAS MODIFIER SANS CHANGEMENT DE VERSION MAJEURE**

Ce document definit l'ABI C stable de secure-core. Toute modification de signature,
de layout de struct ou de semantique de code de retour constitue un breaking change
et necessite un bump de version majeure (v2.0.0).

Le header C de reference est `include/secure_core.h`.

---

## 1. Types

### SecureCoreBuffer

```c
typedef struct {
    uint8_t *ptr;   // Pointeur vers les donnees (ou NULL si vide)
    size_t   len;   // Nombre d'octets
} SecureCoreBuffer;
```

- `#[repr(C)]` en Rust — layout garanti identique au C.
- `ptr` est alloue par Rust via `Vec`. Le caller ne doit **jamais** ecrire dedans ni le `free()` directement.
- `ptr == NULL && len == 0` represente un buffer vide.

### SecureCoreResult

```c
typedef struct {
    int32_t          status;     // Code de retour (voir section 2)
    SecureCoreBuffer data;       // Donnees de sortie (succes) ou vide (erreur)
    char            *error_msg;  // Message d'erreur C string ou NULL (succes)
} SecureCoreResult;
```

- `#[repr(C)]` en Rust.
- Le caller **doit** liberer via `secure_core_free_result()`.
- Ne **jamais** appeler free/delete sur les champs individuellement.

---

## 2. Codes de retour

| Valeur | Constante C | Constante Rust | Signification |
|--------|-------------|----------------|---------------|
| 0 | `SECURE_CORE_OK` | `FFI_OK` | Succes |
| 1 | `SECURE_CORE_ERROR_INVALID_FORMAT` | `FFI_ERROR_INVALID_FORMAT` | Format `.enc` invalide |
| 2 | `SECURE_CORE_ERROR_UNSUPPORTED_VERSION` | `FFI_ERROR_UNSUPPORTED_VERSION` | Version de format non supportee |
| 3 | `SECURE_CORE_ERROR_CRYPTO` | `FFI_ERROR_CRYPTO` | Erreur crypto (cle invalide, donnees alterees) |
| 4 | `SECURE_CORE_ERROR_IO` | `FFI_ERROR_IO` | Erreur d'E/S |
| 5 | `SECURE_CORE_ERROR_INVALID_PARAM` | `FFI_ERROR_INVALID_PARAM` | Parametre invalide |

Les valeurs numeriques sont **gelees**. Aucune valeur existante ne sera reattribuee.
De nouveaux codes peuvent etre ajoutes (>= 6) en minor version.

---

## 3. Fonctions exportees

### secure_core_version

```c
const char *secure_core_version(void);
```

| Aspect | Detail |
|--------|--------|
| Parametres | Aucun |
| Retour | Pointeur statique vers une chaine C null-terminee |
| Ownership retour | **Statique** — ne PAS liberer |
| Thread-safety | Safe |
| Codes possibles | N/A |

### secure_core_encrypt_bytes

```c
SecureCoreResult secure_core_encrypt_bytes(
    const uint8_t *plaintext_ptr,
    size_t         plaintext_len,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

| Aspect | Detail |
|--------|--------|
| `plaintext_ptr` | Borrowed, read-only. Peut etre NULL si `plaintext_len == 0` |
| `plaintext_len` | Nombre d'octets de plaintext |
| `dek_ptr` | Borrowed, read-only. Ne doit PAS etre NULL |
| `dek_len` | Doit etre exactement 32 |
| Retour | `SecureCoreResult` avec le blob `.enc` V1 dans `data` |
| Ownership retour | Caller owns — liberer via `secure_core_free_result()` |
| Thread-safety | Safe (pas d'etat mutable partage) |
| Codes possibles | `OK`, `INVALID_PARAM`, `CRYPTO` |

### secure_core_decrypt_bytes

```c
SecureCoreResult secure_core_decrypt_bytes(
    const uint8_t *blob_ptr,
    size_t         blob_len,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

| Aspect | Detail |
|--------|--------|
| `blob_ptr` | Borrowed, read-only. Ne doit PAS etre NULL |
| `blob_len` | Doit etre > 0 |
| `dek_ptr` | Borrowed, read-only. Ne doit PAS etre NULL |
| `dek_len` | Doit etre exactement 32 |
| Retour | `SecureCoreResult` avec le plaintext dans `data` |
| Ownership retour | Caller owns — liberer via `secure_core_free_result()` |
| Thread-safety | Safe |
| Codes possibles | `OK`, `INVALID_PARAM`, `INVALID_FORMAT`, `UNSUPPORTED_VERSION`, `CRYPTO` |

### secure_core_encrypt_file

```c
SecureCoreResult secure_core_encrypt_file(
    const char    *input_path_ptr,
    const char    *output_path_ptr,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

| Aspect | Detail |
|--------|--------|
| `input_path_ptr` | Borrowed, C string null-terminee UTF-8 |
| `output_path_ptr` | Borrowed, C string null-terminee UTF-8 |
| `dek_ptr` | Borrowed, read-only. Ne doit PAS etre NULL |
| `dek_len` | Doit etre exactement 32 |
| Retour | `SecureCoreResult` avec JSON metadata dans `data` |
| Ownership retour | Caller owns — liberer via `secure_core_free_result()` |
| Thread-safety | Safe (I/O peut bloquer) |
| Codes possibles | `OK`, `INVALID_PARAM`, `IO`, `CRYPTO` |

### secure_core_decrypt_file

```c
SecureCoreResult secure_core_decrypt_file(
    const char    *input_path_ptr,
    const char    *output_path_ptr,
    const uint8_t *dek_ptr,
    size_t         dek_len
);
```

| Aspect | Detail |
|--------|--------|
| `input_path_ptr` | Borrowed, C string null-terminee UTF-8 |
| `output_path_ptr` | Borrowed, C string null-terminee UTF-8 |
| `dek_ptr` | Borrowed, read-only. Ne doit PAS etre NULL |
| `dek_len` | Doit etre exactement 32 |
| Retour | `SecureCoreResult` avec JSON metadata dans `data` |
| Ownership retour | Caller owns — liberer via `secure_core_free_result()` |
| Thread-safety | Safe (I/O peut bloquer) |
| Codes possibles | `OK`, `INVALID_PARAM`, `IO`, `INVALID_FORMAT`, `UNSUPPORTED_VERSION`, `CRYPTO` |

### secure_core_free_buffer

```c
void secure_core_free_buffer(SecureCoreBuffer buf);
```

| Aspect | Detail |
|--------|--------|
| `buf` | Transfere l'ownership a Rust pour deallocation |
| Retour | Aucun |
| Contrainte | Ne PAS appeler deux fois sur le meme buffer |
| Thread-safety | Safe si le buffer n'est pas accede concurremment |

### secure_core_free_result

```c
void secure_core_free_result(SecureCoreResult result);
```

| Aspect | Detail |
|--------|--------|
| `result` | Transfere l'ownership a Rust (data + error_msg) |
| Retour | Aucun |
| Contrainte | Ne PAS appeler deux fois sur le meme result |
| Thread-safety | Safe si le result n'est pas accede concurremment |

---

## 4. Thread-safety

Toutes les fonctions sont **thread-safe** :

- Aucun etat global mutable n'est utilise.
- Chaque appel est independant (pas de session, pas de contexte).
- Les generateurs de nonces utilisent le CSPRNG du systeme (thread-safe par l'OS).
- Les operations sur fichiers peuvent bloquer mais n'interagissent pas entre elles.

Il est safe d'appeler `secure_core_encrypt_bytes` depuis N threads simultanement.

---

## 5. Garanties de layout

- Tous les types exposes sont `#[repr(C)]` — le layout memoire correspond exactement au C.
- `int32_t` = `i32`, `size_t` = `usize`, `uint8_t *` = `*mut u8` / `*const u8`.
- Les pointeurs retournes sont valides jusqu'a l'appel `free_*` correspondant.
- Aucun type Rust non-FFI-safe (`String`, `Vec`, `Box`, `Option`) ne traverse la frontiere FFI.

---

## 6. Politique de compatibilite

- **Les signatures de ce header sont stables pour toute la serie v1.x.**
- Un changement de signature, de layout de struct ou de semantique de code de retour = **nouveau major** (v2.0.0).
- De nouveaux codes de retour (>= 6) peuvent etre ajoutes en minor.
- De nouvelles fonctions peuvent etre ajoutees en minor (jamais de suppression).
- Le fichier `include/secure_core.h` est le contrat de reference. Un test CI verifie sa synchronisation.
