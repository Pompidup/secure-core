# Format de fichier chiffré `.enc` — Version 1

> **Depuis secure-core 1.0.0**, les streams sont écrits au format **V2** ([`enc-format-v2.md`](enc-format-v2.md)), qui authentifie le header dans chaque chunk. Ce document reste la référence du format in-memory (toujours V1) et du streaming V1.1, que la 1.x continue de **lire**.

## Vue d'ensemble

Le format `.enc` V1 est un format binaire simple et non-streamable conçu pour le chiffrement de fichiers individuels. Il encapsule un payload chiffré avec AES-256-GCM, précédé d'un header fixe.

## Structure binaire

```
Offset  Taille   Champ            Description
──────  ──────   ─────            ───────────
0x00    4        magic            Magic bytes : ASCII "SENC" (0x53 0x45 0x4E 0x43)
0x04    2        version          Version du format, u16 little-endian (0x0001 pour V1)
0x06    1        algorithm_id     Identifiant algorithme : 0x01 = AES-256-GCM
0x07    12       nonce            Nonce/IV (96 bits, unique par chiffrement)
0x13    2        flags            Flags, u16 little-endian (0x0000 en in-memory, 0x0001 en stream V1.1)
0x15    4        header_length    Longueur totale du header en bytes, u32 little-endian
0x19    N        payload          Ciphertext (N bytes)
0x19+N  16       auth_tag         Tag d'authentification GCM (128 bits)
```

**Longueur totale du header V1** : 25 bytes (0x19).

Le champ `header_length` permet aux futures versions d'étendre le header sans casser la compatibilité : un lecteur V1 peut sauter `header_length` bytes depuis le début du fichier pour atteindre le payload, même si des champs ont été ajoutés.

## Diagramme

```
┌──────────┬─────────┬──────┬──────────────┬───────┬───────────────┬─────────────────┬──────────┐
│  SENC    │ version │ algo │    nonce     │ flags │ header_length │    payload      │ auth_tag │
│ 4 bytes  │ 2 bytes │ 1 b  │  12 bytes    │ 2 b   │   4 bytes     │   N bytes       │ 16 bytes │
└──────────┴─────────┴──────┴──────────────┴───────┴───────────────┴─────────────────┴──────────┘
```

## Identifiants d'algorithme

| ID     | Algorithme       | Statut   |
| ------ | ---------------- | -------- |
| `0x01` | AES-256-GCM      | Actif    |
| `0x02` — `0xFF` | Réservé | — |

## Règles

### Nonce (IV)

- Le nonce **DOIT** être unique pour chaque opération de chiffrement avec la même DEK.
- Le nonce **DOIT** être généré via un CSPRNG (ex: `getrandom`).
- Taille fixe : 12 bytes (96 bits), imposée par AES-256-GCM.

### Taille maximale du fichier

Les deux chemins d'API ont des bornes différentes — by design, pas un oubli :

| Chemin | Constante Rust | Limite | Raison |
| --- | --- | --- | --- |
| `encrypt_bytes` (in-memory) | `crypto::MAX_PLAINTEXT_SIZE` | **4 GiB** (2³²) sur 64-bit, 2 GiB sur 32-bit | Le plaintext entier tient en RAM ; plafond conservateur bien en-dessous de la borne NIST GCM (~64 Go par invocation). |
| `encrypt_stream` (streaming) | `streaming::MAX_STREAM_PLAINTEXT_SIZE` | **~128 TiB** (`MAX_STREAM_CHUNKS × CHUNK_SIZE` = `0x7FFF_FFFF × 64 KiB`) | Chaque chunk (64 KiB) est une invocation GCM indépendante ; la limite vient du cap `u32` sur l'index de chunk (bit haut réservé depuis V1.1). |

**Règle opérationnelle** : au-dessus de `MAX_PLAINTEXT_SIZE`, bascule obligatoire sur le streaming. Le crate exporte les deux constantes pour que le consumer puisse décider à la compilation.

### Flags

Champ `u16` little-endian. Le traitement d'un bit inconnu dépend du mode, car seul l'in-memory authentifie le header :

- **In-memory** : le header est l'AAD GCM, un bit inconnu vient donc forcément d'un écrivain légitime. Le lecteur **DOIT** l'ignorer (forward compatibility).
- **Streaming V1.1** : le header n'est pas authentifié, un bit inconnu peut venir d'une corruption ou d'une falsification. Depuis 0.6.0, le lecteur **DOIT** rejeter le stream (`InvalidFormat`) avant d'écrire du clair. Tout nouveau flag de streaming exige donc une nouvelle version du lecteur (même règle en V2).

| Bit    | Nom                         | Sémantique                                                                 |
| ------ | --------------------------- | -------------------------------------------------------------------------- |
| `0x0001` | `FLAG_STREAM_FINAL_CHUNK` | V1.1 streaming : le dernier chunk est authentifié avec un marqueur (voir ci-dessous). Absent = layout V1.0 legacy, sans détection de troncature. |
| `0x0002` — `0x8000` | réservés                  | Doivent être `0`. Un futur bit sera ignoré par les lecteurs in-memory existants et rejeté par les lecteurs streaming existants (voir ci-dessus). |

#### Streaming V1.1 — détection de troncature

Les streams V1.1 (produits par `encrypt_stream` de 0.3.0 à 0.6.x) portent `flags & FLAG_STREAM_FINAL_CHUNK` à `1`. Dans ce mode :

- L'AAD d'un chunk non-final est `chunk_index.to_be_bytes()` (4 octets, bit haut = 0).
- L'AAD du **dernier** chunk est `(chunk_index | 0x80000000).to_be_bytes()` (bit haut = 1).
- Au décryptage, le dernier chunk doit valider avec le marqueur ; l'absence est rejetée → `InvalidFormat("stream is missing its final chunk")` ou `CryptoError(...)` selon l'endroit de la troncature.
- Conséquence : `chunk_index` est borné à `0x7FFF_FFFF` (2 147 483 647 chunks × 64 KiB ≈ 128 TiB par stream).

**Depuis 0.5.0, un stream sans `FLAG_STREAM_FINAL_CHUNK` est rejeté par défaut** (`decrypt_stream` / `decrypt_file` → `InvalidFormat`, avant toute écriture de clair). En streaming, le header n'entre pas dans l'AAD des chunks, et un chunk non-final V1.1 a exactement l'AAD d'un chunk V1.0. Honorer un flag absent permettrait donc d'effacer le flag d'un stream V1.1 tronqué et de le faire accepter comme un stream legacy.

Les streams produits avant V1.1 (`flags == 0`, secure-core < 0.3.0, AAD = `chunk_index.to_be_bytes()` pour tous les chunks) **ne sont plus lisibles depuis 1.0.0**. En 0.5.x et 0.6.x, une API de migration explicite (`*_allow_legacy`, sans détection de troncature) permettait de les rechiffrer une fois en V1.1 ; elle est retirée en 1.0.0. Pour un tel fichier : le rechiffrer avec une version 0.5.x ou 0.6.x avant de passer en 1.0.

### Auth tag

- Le tag GCM de 16 bytes est toujours placé **après** le payload.
- **In-memory** (`encrypt_bytes`) : le header complet (magic + version + algorithm_id + nonce + flags + header_length) est l'**Additional Authenticated Data (AAD)** du calcul GCM. Toute modification du header est détectée.
- **Streaming** : le header **n'est pas** dans l'AAD. Chaque chunk authentifie seulement son index (+ le marqueur de fin). Le nonce reste protégé de fait, car il dérive les nonces des chunks, mais `version` et `flags` ne sont pas authentifiés. D'où le rejet par défaut des streams sans `FLAG_STREAM_FINAL_CHUNK` ci-dessus. La V2 (1.0.0) inclut le header dans l'AAD de chaque chunk.

## Gestion des versions

- Un lecteur 1.x accepte `version = 1` et `version = 2` (streams V2 uniquement) ; toute autre valeur, y compris `0` (jamais produit), **DOIT** être rejetée avec `UnsupportedVersion { max_supported: 2 }`. `decrypt_bytes` (in-memory) rejette `version = 2` avec `InvalidFormat`.
- Si `magic ≠ "SENC"`, le lecteur **DOIT** rejeter le fichier avec l'erreur `InvalidFormat`.
- Si `algorithm_id` est inconnu, le lecteur **DOIT** rejeter le fichier avec l'erreur `InvalidFormat`.

## Exemples

### Fichier minimal (plaintext vide)

```
53 45 4E 43    — magic "SENC"
01 00          — version 1
01             — AES-256-GCM
XX XX ... XX   — 12 bytes de nonce
00 00          — flags
19 00 00 00    — header_length = 25
               — (pas de ciphertext)
YY YY ... YY   — 16 bytes auth tag
```

Taille totale : 25 (header) + 0 (ciphertext) + 16 (tag) = **41 bytes**.
