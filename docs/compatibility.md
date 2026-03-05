# Compatibility — secure-core

## Forward Compatibility Promise

**Tout fichier `.enc` V1 restera lisible par toutes les versions futures de secure-core.**

Ce contrat est garanti par :

1. Le champ `version` dans le header (octets 4-5) identifie la version du format.
2. Les futures versions du core devront toujours supporter le parsing et le dechiffrement des headers V1.
3. Le blob de reference `testdata/v1_reference.enc` est verifie dans les tests d'integration pour detecter toute regression.

## Strategie de migration V2

### Principe : extension sans rupture

Le format V2 sera retro-compatible avec V1 :

- Le magic `SENC` reste identique.
- Le champ `version` passera a `2`.
- Le header V2 utilisera des **champs TLV** (Type-Length-Value) apres les 25 octets du header V1 de base :

```
[V1 header 25B][TLV extension 1][TLV extension 2]...
```

- Le champ `header_length` (octets 21-24) indiquera la taille totale du header, permettant aux parsers V1 de sauter les extensions inconnues.
- Le payload (ciphertext) reste au meme format.

### Backward compatibility

| Lecteur \ Fichier | V1 | V2 |
|---|---|---|
| Core V1 | OK | Erreur `UnsupportedVersion` (propre, pas de crash) |
| Core V2+ | OK | OK |

Un core V1 rejettera proprement un fichier V2 via `SecureCoreError::UnsupportedVersion { found: 2, max_supported: 1 }`.

## Hooks reserves pour V2

Les champs suivants sont reserves dans les structures V1 mais non utilises :

| Champ | Emplacement | Usage prevu en V2 |
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

Les 16 bits du champ `flags` sont tous a zero en V1. Les bits suivants sont reserves :

| Bit | Usage prevu |
|---|---|
| 0 | Compression active (zstd avant chiffrement) |
| 1 | Key rotation marker |
| 2-15 | Reserves |
