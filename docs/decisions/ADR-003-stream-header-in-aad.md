# ADR-003 : Authentifier le header du stream dans chaque chunk (format V2)

- **Statut** : Accepté
- **Date** : 2026-11-22
- **Complète** : ADR-002 (chiffrement streaming par chunks)

## Contexte

Dans le streaming V1/V1.1 (ADR-002), chaque chunk n'authentifie que son index et, depuis V1.1, un marqueur de fin. Le header du stream n'entre dans aucune AAD. Conséquences observées :

- **GHSA-43rf-fggr-vcgg** (0.5.0) : effacer un seul bit de `flags` faisait lire un stream tronqué comme un stream legacy valide.
- Chaque champ du header (`version`, `flags`, `algorithm_id`, `header_length`) ne tient que par les contrôles du lecteur. Les correctifs de 0.5.0 et 0.6.0 ont dû durcir ces contrôles un par un (flag exigé, flags inconnus rejetés, version exacte).
- Tout champ ou flag ajouté plus tard au header serait falsifiable de la même façon.

## Décision

Format `.enc` **V2**, pour le streaming uniquement :

- Header identique à V1 (25 octets), avec `version = 2` et `FLAG_STREAM_FINAL_CHUNK` obligatoire.
- **AAD de chaque chunk = header complet (`header_length` octets, tels que lus) || BE32(index | marqueur de fin)**.
- Découpage, framing, dérivation des nonces et marqueur de fin inchangés.
- Le in-memory reste en V1 : son header est déjà l'AAD.
- secure-core 1.x écrit la V2 et lit V1.1 + V2. Pas de migration obligatoire des fichiers V1.1.

## Alternatives écartées

- **Extensions TLV après le header** (stratégie V2 envisagée dans `compatibility.md`) : ne répond pas au problème d'authentification, et aucune extension n'est nécessaire aujourd'hui. La V2 retenue les rend sûres plus tard : toute extension comptée dans `header_length` sera authentifiée.
- **MAC du header avec une sous-clé dédiée (HKDF)** : un tag de plus à stocker et une dérivation de clé en plus, pour la même propriété que l'inclusion dans l'AAD GCM.
- **Authentifier le header seulement dans le premier chunk** : un attaquant pourrait retirer ou remplacer le premier chunk ; l'inclure dans chaque chunk ne coûte que 25 octets d'AAD par chunk de 64 KiB.
- **Passer aussi le in-memory en V2** : aucun gain de sécurité, et un changement de golden files sans raison.

## Conséquences

- **Positives** : plus aucun octet du header n'est modifiable ; downgrade V2 → V1.1 impossible (échec GCM) ; les futurs champs sont authentifiés par construction.
- **Négatives** : un fichier V2 n'est pas lisible par secure-core 0.x (rejet propre, `UnsupportedVersion`). Les apps qui échangent des fichiers ou des sauvegardes doivent toutes passer en 1.x.
- **Coût** : 25 octets d'AAD par chunk, négligeable (GHASH d'un bloc et demi supplémentaire).
- Spécification : [`docs/enc-format-v2.md`](../enc-format-v2.md).
