# Format de fichier chiffré `.enc` — Version 2 (streaming)

Statut : **actif depuis secure-core 1.0.0**. Écrit par `encrypt_stream`, `encrypt_file`, `secure_core_encrypt_file` et `nativeEncryptFile`.

La V2 ne concerne que le **streaming**. Le format in-memory (`encrypt_bytes`) reste le V1 de [`enc-format-v1.md`](enc-format-v1.md) : son header est déjà authentifié comme AAD.

## Pourquoi une V2

En V1.1, chaque chunk n'authentifie que son index (et le marqueur de fin) : le header du stream n'entre dans aucune AAD. Le nonce de base est protégé indirectement (il dérive les nonces des chunks), mais `version`, `flags`, `algorithm_id` et `header_length` ne le sont pas. Toute la sécurité du streaming V1.1 repose donc sur un lecteur strict (flag de fin exigé, flags inconnus rejetés, version exacte), et chaque futur champ du header serait falsifiable.

La V2 lie **le header complet à chaque chunk**. Plus aucun octet du header n'est modifiable sans faire échouer le tag GCM, y compris pour une extension future.

## Structure binaire

```
Offset  Taille  Champ          Valeur V2
──────  ──────  ─────          ─────────
0x00    4       magic          "SENC" (0x53 0x45 0x4E 0x43)
0x04    2       version        0x0002, u16 little-endian
0x06    1       algorithm_id   0x01 = AES-256-GCM
0x07    12      base_nonce     Nonce de base (96 bits, CSPRNG, unique par stream)
0x13    2       flags          0x0001 (FLAG_STREAM_FINAL_CHUNK), u16 little-endian. Obligatoire
0x15    4       header_length  25, u32 little-endian
0x19    …       chunks         [chunk_len u32 LE][ciphertext || tag 16 B] répétés
```

Le layout du header est identique à V1 : seuls `version` et la règle d'AAD changent.

### Chunks

- Plaintext découpé en chunks de 64 KiB (`CHUNK_SIZE`), le dernier pouvant être plus court. Un plaintext vide produit **un** chunk final vide.
- `chunk_len` = longueur du ciphertext + tag, entre 16 et 65 552 octets.
- Nonce du chunk `i` : `base_nonce` dont les 4 derniers octets sont XORés avec `i` en big-endian (inchangé depuis V1).
- `i` est borné à `0x7FFF_FFFF` (bit haut réservé au marqueur de fin), soit ~128 TiB par stream.

### AAD d'un chunk (le changement de la V2)

```
AAD(i) = header[0 .. header_length]  ||  BE32(i | (est_le_dernier ? 0x8000_0000 : 0))
```

29 octets en V2 : les 25 octets du header **tels qu'ils figurent dans le fichier**, suivis de l'index du chunk avec le marqueur de fin sur le dernier chunk.

Pour comparaison, V1.1 : `AAD(i) = BE32(i | marqueur)`, sans le header.

## Règles de lecture (`decrypt_stream`, secure-core 1.x)

1. Lire 25 octets et les parser. `version` : `1` (V1.1) ou `2` (V2), sinon `UnsupportedVersion { max_supported: 2 }`.
2. `flags` doit valoir exactement `FLAG_STREAM_FINAL_CHUNK` : flag absent ou bit inconnu → `InvalidFormat`, avant toute écriture de clair. (En V2 le header est authentifié, mais un bit inconnu signifie une sémantique que ce lecteur ne sait pas appliquer.)
3. Calculer l'AAD selon la version (V1.1 : index seul ; V2 : header + index).
4. Un chunk n'est écrit en sortie qu'une fois authentifié ; le dernier chunk doit valider avec le marqueur de fin.
5. Aucun chunk du tout → `InvalidFormat`.

`decrypt_bytes` (in-memory) n'accepte que la version 1 : un stream V2 lui est refusé avec `InvalidFormat`.

## Propriétés de sécurité

| Attaque | V1.1 (lecteur strict 1.x) | V2 |
| --- | --- | --- |
| Modification de n'importe quel octet du header | Rejet par les contrôles du lecteur (ou échec GCM pour le nonce) | Échec GCM sur le premier chunk, quel que soit l'octet |
| Troncature (dernier chunk ou plus retiré) | Détectée (marqueur de fin) | Détectée |
| Réordonnancement, duplication, chunk venant d'un autre stream | Détecté (index + nonce) | Détecté (index + nonce + header) |
| Downgrade V2 → V1.1 (`version` passée à 1) | — | Échec GCM : les chunks ont été scellés avec le header dans l'AAD |
| « Upgrade » V1.1 → V2 | Échec GCM | — |
| Nouveau champ ou flag futur dans le header | Non authentifié | Authentifié automatiquement |

Non couvert, comme en V1 : la confidentialité de la taille (nombre et taille des chunks visibles), et l'engagement de clé (« key commitment ») de GCM, sans objet avec une DEK aléatoire par document.

## Compatibilité

| Lecteur \ Fichier | V1 in-memory | V1.1 stream | V2 stream |
| --- | --- | --- | --- |
| secure-core 0.3 – 0.6 | OK | OK | `UnsupportedVersion { found: 2, max_supported: 1 }` |
| secure-core 1.x | OK | OK | OK |

- **Aucune migration requise** : les streams V1.1 existants restent lisibles par toute version 1.x. Les rechiffrer en V2 est possible mais facultatif.
- **Attention aux échanges entre versions** : un fichier (ou une sauvegarde) produit par une app en 1.x n'est pas lisible par une app restée en 0.x.
- Golden files : `testdata/compat/v2/stream/` (V2), `testdata/compat/v1_1/stream/` (V1.1, inchangés), `testdata/compat/v1/` (in-memory, inchangés).

Décision : [ADR-003](decisions/ADR-003-stream-header-in-aad.md).
