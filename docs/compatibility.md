# Compatibility — secure-core

## Forward Compatibility Promise

**Tout fichier `.enc` V1 (in-memory), V1.1 (stream) ou V2 (stream) restera lisible par toutes les versions futures 1.x de secure-core.**

Ce contrat est garanti par :

1. Le champ `version` dans le header (octets 4-5) identifie la version du format : `1` (in-memory, et streams V1.1 en lecture seule) ou `2` (streams V2, écrits depuis 1.0.0).
2. Le champ `flags` (octets 19-20) signale les extensions mineures (ex. `FLAG_STREAM_FINAL_CHUNK`). En in-memory (header authentifié), un lecteur ignore les bits qu'il ne connaît pas. En streaming, il les rejette (V1.1 et V2) et exige `FLAG_STREAM_FINAL_CHUNK`.
3. Les futures versions 1.x du core devront toujours supporter le parsing et le déchiffrement des headers V1, V1.1 et V2.
4. Le blob de référence `testdata/v1_reference.enc` est vérifié dans les tests d'intégration pour détecter toute régression.
5. Les packs compat `testdata/compat/v1/` (in-memory), `testdata/compat/v1_1/stream/` et `testdata/compat/v2/stream/` figent les layouts : leurs tests échouent au moindre diff binaire, et la CI vérifie que leur régénération est identique octet pour octet.

## Format V2 (secure-core 1.0.0)

Spécification : [`enc-format-v2.md`](enc-format-v2.md), décision : [ADR-003](decisions/ADR-003-stream-header-in-aad.md).

- Ne concerne que le **streaming**. Le in-memory reste V1 (son header est déjà authentifié).
- Header identique à V1 (25 octets, magic `SENC`), avec `version = 2`.
- **Le header complet entre dans l'AAD de chaque chunk** : aucun octet du header n'est modifiable, un downgrade vers V1.1 échoue à l'authentification.
- Découpage, framing, dérivation des nonces et marqueur de fin inchangés.

La stratégie envisagée auparavant (extensions TLV après le header de base) n'a pas été retenue : elle ne réglait pas l'authentification du header. Avec la V2, une extension future comptée dans `header_length` serait authentifiée par construction.

### Backward compatibility

| Lecteur \ Fichier | V1 in-memory | V1.1 stream | V2 stream |
|---|---|---|---|
| Core 0.3 – 0.6 | OK | OK | Erreur `UnsupportedVersion { found: 2, max_supported: 1 }` (propre, pas de crash) |
| Core 1.x | OK | OK | OK |

Aucune migration n'est requise : les streams V1.1 existants restent lisibles. En revanche, un fichier ou une sauvegarde écrits par une app en 1.x ne sont pas lisibles par une app restée en 0.x.

## Hooks réservés pour l'évolution des métadonnées

Les champs suivants sont réservés dans les structures de métadonnées mais non utilisés. Leur évolution est indépendante du format `.enc` V2.

| Champ | Emplacement | Usage prevu |
|---|---|---|
| `recovery_wrap` | `WrappedDek` | DEK chiffree avec une cle de recovery (account-level) pour permettre le transfert entre devices |
| `content_hash` | `DocumentMetadata` | SHA-256 du plaintext pour verification d'integrite cote plateforme |
| `flags` | `.enc` header | Bits reserves pour signaler des extensions (compression, key rotation, etc.) |

### recovery_wrap

En V1, `recovery_wrap` est `null` (serialise comme absent en JSON). En V2, il contiendra la DEK chiffree par une cle de recovery derivee du compte utilisateur (ex : HKDF depuis un secret serveur). Cela permettra :

- La recuperation des fichiers apres changement de device
- La migration de compte
- Le partage de documents entre utilisateurs (si la cle de recovery est partagee)

### content_hash

En V1, `content_hash` est optionnel et non calcule par le core. En V2, le core pourra le calculer automatiquement (SHA-256 du plaintext) pour permettre a la plateforme de verifier l'integrite du fichier avant ou apres le dechiffrement.

### flags

Champ `u16` little-endian. Authentifié (AAD) en in-memory et en stream V2 ; non authentifié en stream V1.1 (voir `enc-format-v1.md`, section Auth tag, et `enc-format-v2.md`).

| Bit | Nom / usage | Statut |
|---|---|---|
| 0 | `FLAG_STREAM_FINAL_CHUNK` — streaming : AAD du dernier chunk marquée pour détection de troncature | **Actif** (depuis v0.3.0) ; **obligatoire** en lecture streaming (V1.1 depuis v0.5.0, V2) |
| 1 | Key rotation marker | Réservé |
| 2 | Compression (zstd avant chiffrement) | Réservé |
| 3-15 | Divers | Réservés, doivent être `0` |

En in-memory, tout nouveau bit restera additif et n'invalidera pas les lecteurs V1.x (via `header_length` pour les extensions longues, ou via une sémantique "safe to ignore" pour les flags purement informatifs). En streaming, les lecteurs existants refusent tout bit inconnu : un nouveau flag de streaming nécessitera une nouvelle version du lecteur. Son authentification est en revanche acquise en V2.
