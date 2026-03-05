# Format de fichier chiffré `.enc` — Version 1

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
0x13    2        flags            Flags réservés, u16 little-endian (0x0000 en V1)
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

- La taille maximale du plaintext est de **4 Go** (2³² bytes).
- Cette limite est imposée par la spécification GCM (NIST SP 800-38D) qui recommande un maximum de 2³⁹ - 256 bits (~64 Go) par invocation, mais nous imposons une limite plus conservatrice de 4 Go pour des raisons pratiques (fichiers mobiles).

### Flags

- En V1, le champ flags **DOIT** être `0x0000`.
- Un lecteur V1 **DOIT** ignorer les bits de flags qu'il ne connaît pas (forward compatibility).

### Auth tag

- Le tag GCM de 16 bytes est toujours placé **après** le payload.
- Le header complet (magic + version + algorithm_id + nonce + flags + header_length) est inclus comme **Additional Authenticated Data (AAD)** dans le calcul GCM. Cela garantit que toute modification du header est détectée.

## Gestion des versions

- Si `version > 1`, le lecteur **DOIT** rejeter le fichier avec l'erreur `UnsupportedVersion`.
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
