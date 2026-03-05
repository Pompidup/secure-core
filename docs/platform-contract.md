# Platform Contract

Ce document définit le contrat entre le core Rust (`secure-core`) et la plateforme hôte (Android, iOS, ou tout autre intégrateur).

## Ce que le core attend

Le core est une fonction pure de transformation cryptographique. Il attend de la plateforme :

| Entrée | Type | Description |
| ------ | ---- | ----------- |
| `plaintext` | `&[u8]` | Les octets en clair à chiffrer. |
| `ciphertext` | `&[u8]` | Les octets chiffrés à déchiffrer (incluant nonce + tag). |
| `dek` | `&[u8; 32]` | La Data Encryption Key (256 bits), déjà unwrappée par la plateforme. |

Le core retourne des octets. Il ne décide pas où les écrire, ni comment les nommer.

## Ce que la plateforme doit implémenter

### 1. Wrap / Unwrap de la DEK (`deviceWrap`)

La plateforme est responsable de :

- **Générer** la DEK lors du premier usage (via le Keystore/Keychain de l'OS).
- **Wrapper** (chiffrer) la DEK avec une clé matérielle (KEK) gérée par le secure element ou le TEE.
- **Stocker** la DEK wrappée dans le stockage applicatif.
- **Unwrapper** la DEK à la demande, la transmettre au core, puis **zéroïser** la copie en mémoire après usage.

Le core ne connaît pas l'existence de la KEK ni du mécanisme de wrapping.

### 2. Stockage des métadonnées

Pour chaque fichier chiffré, la plateforme stocke :

- Le chemin du fichier chiffré sur le système de fichiers.
- Le nom original du fichier (si nécessaire pour la restitution).
- Toute métadonnée applicative (date, taille originale, type MIME, etc.).

Le core ne gère aucune métadonnée. Il produit des octets chiffrés, point.

### 3. Gestion des fichiers

- Lecture des octets en clair depuis le fichier source.
- Écriture des octets chiffrés sur le système de fichiers.
- Suppression sécurisée du fichier en clair après chiffrement (si applicable).
- Gestion des chemins, permissions, et accès concurrent.

## Ce que le core ne fera JAMAIS

Ces garanties sont des invariants de conception. Toute violation est un bug de sécurité.

| Interdit | Raison |
| -------- | ------ |
| Écrire du clair sur disque | Le core n'a pas accès au système de fichiers. Il retourne des `Vec<u8>`. |
| Logger une DEK ou du plaintext | Aucune dépendance de logging. Aucun `println!`, `log::*`, ou `tracing::*` sur des données sensibles. |
| Dépendre d'Android ou iOS | Zéro dépendance plateforme. Le core compile pour toute target Rust supportée. |
| Faire des appels réseau | Aucune dépendance réseau. Le core est offline par définition. |
| Gérer le cycle de vie des clés | Pas de génération, stockage, rotation ou destruction de DEK. C'est le rôle de la plateforme. |
| Prendre des décisions d'UI | Pas de prompt, pas de dialogue, pas de notification. Le core est silencieux. |
