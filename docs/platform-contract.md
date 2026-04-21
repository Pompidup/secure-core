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

### 4. Cycle de vie de la passphrase (recovery)

Quand la plateforme appelle `wrap_dek_with_passphrase` ou `unwrap_dek_with_passphrase` (export/import d'un bundle de recovery), elle est responsable du buffer qu'elle détient côté UI :

- **Collecte** : saisie via un champ sécurisé (masqué, sans backup clavier/IME malveillant qui mémoriserait). Android `EditText` avec `inputType="textPassword"`, iOS `SecureField`.
- **Passage au core** :
  - **Côté C FFI** : la plateforme passe un `const char*` à `secure_core_wrap_dek_with_passphrase` / `..._unwrap_...`. Le core emprunte les octets via `CStr::from_ptr` **sans jamais copier** dans une allocation Rust — rien à zeroizer côté Rust.
  - **Côté JNI** : la plateforme passe un `String` JVM. Le core le matérialise via `env.get_string()` dans une copie Rust-owned qui est **automatiquement zeroizée** au drop (`zeroize::Zeroizing<String>`). La plateforme n'a pas à s'en soucier — mais elle doit gérer **son propre** buffer JVM (voir ci-dessous).
- **Zéroïsation côté plateforme** (obligatoire, car le core ne peut pas atteindre le buffer d'origine) :
  - **Android** : `CharArray.fill('\u0000')` sur le tableau extrait de l'`EditText`. Éviter de construire un `String` Kotlin intermédiaire, qui est immutable et non zeroizable.
  - **iOS** : pour un `String` Swift, remplacer immédiatement par `""` après usage, ou mieux : manipuler la passphrase sous forme de `Data` et appeler `resetBytes(in:)`. `SecureField` de SwiftUI expose déjà un `@State String` qui doit être vidé post-appel.
  - **C direct** : `memset_s(buf, len, 0, len)` (ou `explicit_bzero` sur glibc). Ne jamais utiliser `memset` simple, qu'un compilateur agressif peut éliminer.

- **Durée de vie** : la passphrase doit exister dans la mémoire plateforme **le temps minimal** (quelques millisecondes pour l'appel FFI). Elle ne doit jamais être persistée, loggée, ou envoyée sur le réseau.

Voir `docs/security-considerations.md#passphrase-handling` pour les détails côté Rust.

### 5. Gestion des erreurs de version recovery

Depuis v0.2.0, le format `RecoveryWrap` porte un champ `schema_version`. Un core qui ne reconnaît pas la version déclarée **rejette explicitement** le bundle :

```
SecureCoreError::InvalidParameter(
  "unsupported recovery schema_version: \"2.0\" (this build only accepts \"1.0\")"
)
```

Ce code d'erreur remonte comme `FFI_ERROR_INVALID_PARAM` côté FFI C et dans le status du `NativeResult` JNI. La plateforme **DOIT** :

- **Détecter** le texte `"unsupported recovery schema_version"` dans le message, OU comparer `schema_version` localement avant de passer au core.
- **Surfacer** à l'utilisateur un message actionnable — exemple :
  > « Ce bundle de recovery a été créé par une version plus récente de l'app. Mettez à jour l'app et réessayez. »
- **Ne pas** tenter de "réparer" le bundle en modifiant son `schema_version` dans le JSON. Même si le JSON n'est pas signé directement, toute modification entraîne un rejet crypto côté GCM (les paramètres KDF/cipher déclarés par la version ne correspondraient plus à ceux utilisés à l'encryption), et masquer ça à l'utilisateur créerait une confusion (« mauvaise passphrase ? ») là où la vraie cause est « app obsolète ».

Les autres versions connues (rétro-compat deserialization) :

| Cas | Comportement core |
| --- | --- |
| `schema_version` absent (bundle antérieur au versioning) | Traité comme `"1.0"` via `#[serde(default)]` → unwrap normal |
| `schema_version == "1.0"` | Accepté, comportement historique |
| `schema_version` inconnu (`"1.1"`, `"2.0"`, …) | `InvalidParameter` explicite |

Voir `docs/recovery-format-v1.md#recoverywrap-schema` pour la politique d'évolution.

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
| Décrypter silencieusement un stream tronqué (V1.1) | `decrypt_stream` authentifie le dernier chunk via un marqueur AAD dédié ; une troncature en fin de stream retourne `InvalidFormat` ou `CryptoError`, jamais un plaintext incomplet. |
| Paniquer à travers la frontière FFI/JNI | Tout appel fallible (JNI `find_class`, `new_byte_array`, `new_string`, …) retourne un `JObject::null()` laissant l'exception JVM pending ; le C FFI retourne un `FfiResult` avec status et message non-null — jamais `abort()`. |
| Accepter un `RecoveryWrap` de version inconnue | `unwrap_dek_with_passphrase` valide `schema_version` avant toute opération crypto. Voir section 5 ci-dessus. |
