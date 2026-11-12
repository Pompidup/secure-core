# Threat Model

## Périmètre

Le core Rust `secure-core` est une bibliothèque de chiffrement pure : **bytes in, bytes out**. Il ne connaît ni le réseau, ni le système d'exploitation hôte. Il n'accède au système de fichiers que via les wrappers `encrypt_file` / `decrypt_file`, sur les chemins que la plateforme lui donne explicitement. Son unique responsabilité est de transformer des octets en clair en octets chiffrés (et inversement), étant donné une DEK (Data Encryption Key) fournie par l'appelant.

## Menaces couvertes

| Menace | Description | Mitigation |
| ------ | ----------- | ---------- |
| Extraction de fichiers chiffrés | Un attaquant accède au stockage et copie les fichiers chiffrés. | AES-256-GCM : confidentialité et intégrité. Sans la DEK, les données sont inexploitables. |
| Modification du ciphertext | Un attaquant altère un fichier chiffré (bit-flip, troncature, injection). | Le tag GCM détecte toute modification. Le déchiffrement échoue explicitement. |
| Corruption partielle | Perte ou altération de blocs suite à une défaillance stockage. | L'authentification GCM couvre l'intégralité du ciphertext. Toute corruption est détectée. |
| Réutilisation de nonce | Deux chiffrements avec le même nonce compromettent la confidentialité. | Génération de nonce aléatoire (96 bits) via CSPRNG pour chaque opération. |
| Downgrade algorithmique | Un attaquant tente de forcer l'utilisation d'un algorithme faible. | Un seul algorithme supporté, identifié dans le header. Rejet de tout algorithme inconnu. |
| Downgrade de format (streaming) | Un attaquant efface `FLAG_STREAM_FINAL_CHUNK` (header non authentifié en streaming) pour faire lire un stream V1.1 tronqué comme un stream legacy V1.0. | Depuis 0.5.0, les lecteurs par défaut rejettent tout stream sans le flag. Le chemin legacy n'existe que via l'API de migration explicite `*_allow_legacy`. Prévu en V2 : header dans l'AAD de chaque chunk. |

## Bundle de recovery (export / import par passphrase)

Le core fournit la primitive `wrap_dek_with_passphrase` / `unwrap_dek_with_passphrase` (Argon2id puis AES-256-GCM). La plateforme assemble le bundle (`.zip` décrit dans `docs/recovery-format-v1.md`) et le transporte (AirDrop, cloud, USB…). Un bundle doit être considéré comme **exposé** : il quitte l'appareil et son keystore.

| Menace | Mitigation | Limite |
| ------ | ---------- | ------ |
| Brute force hors-ligne de la passphrase sur un bundle exfiltré | Argon2id m=64 MiB, t=3, p=4, sel aléatoire de 32 octets par wrap : chaque essai coûte une dérivation complète. Les paramètres sont ceux du `schema_version`, jamais ceux lus dans le bundle, donc un bundle ne peut pas les affaiblir. | Ne compense pas une passphrase faible. La politique (longueur, force, nombre d'essais) relève de la plateforme (`platform-contract.md` §4). |
| Passphrase trouvée | Aucune côté core. | **Donne les DEK de tous les documents du bundle**, donc leur contenu. Pas de forward secrecy, pas de révocation. |
| Altération d'un wrap ou d'un `.enc` | Tag GCM du wrap, et du document à l'ouverture. | Détectée, mais seulement au déchiffrement. |
| Métadonnées lisibles | Aucune. | `manifest.json` et `metadata/{docId}.meta.json` sont **en clair** : nom de fichier, type MIME, tailles, dates. Quiconque obtient le bundle les lit sans la passphrase. |
| Ajout, retrait ou modification de documents ou de métadonnées dans le bundle | Aucune côté core. | Le `checksum` du manifest est un SHA-256 de la liste des `docId`, sans clé : un attaquant peut retirer un document, ou modifier une métadonnée (par exemple le type MIME), puis recalculer le checksum. Ce n'est pas une authentification. |
| Bundle d'une version future (`schema_version` inconnu) | Rejet explicite avant toute opération crypto (status `6`). | — |

Hors périmètre du core, à la charge de la plateforme : la saisie et la zéroïsation de la passphrase, le choix du canal de transport, et la suppression du bundle après import. Une version future du format pourrait chiffrer les métadonnées et authentifier le manifest avec une clé dérivée de la passphrase.

## Menaces NON couvertes

Ces menaces sont **hors périmètre** du core. Elles relèvent de la plateforme hôte (Android/iOS) ou de l'environnement utilisateur.

| Menace | Raison de l'exclusion |
| ------ | --------------------- |
| Appareil rooté / jailbreaké | Le core n'a aucune visibilité sur l'intégrité de l'OS. C'est à la plateforme de détecter et réagir. |
| Keylogging | La saisie utilisateur (passphrase, PIN) est gérée par la plateforme, jamais par le core. |
| Capture d'écran | Le core ne produit aucune sortie visuelle. La protection d'écran relève de la couche UI. |
| Compromission de l'OS | Si l'OS est compromis, l'attaquant peut lire la mémoire du processus. Le core ne peut pas se défendre contre un kernel malveillant. |
| Side-channel physique | Attaques par timing, consommation électrique ou émission EM. Le core s'appuie sur des implémentations cryptographiques à temps constant mais ne garantit pas la résistance matérielle. |

## Hypothèses du modèle

1. **Gestion des clés par l'OS.** La DEK est protégée par le Keystore Android ou le Keychain iOS. Le core ne génère, ne stocke et ne persiste jamais de DEK. Seule exception : il **dérive** une clé de recovery à partir d'une passphrase (Argon2id, `recovery.rs`) pour wrapper ou unwrapper une DEK. Cette clé n'existe que le temps de l'appel.

2. **DEK jamais en clair côté application.** La DEK est unwrappée par la plateforme et transmise au core uniquement pour la durée de l'opération cryptographique. La plateforme est responsable du zéroïsation après usage.

3. **CSPRNG disponible.** Le core suppose que l'environnement fournit un générateur d'aléa cryptographiquement sûr (via `getrandom` / OS entropy).

4. **Intégrité du binaire.** Le code du core n'a pas été altéré. La vérification de l'intégrité du binaire (code signing) relève de la plateforme.

5. **Transport hors périmètre.** Le core ne gère pas le transport réseau. Si les fichiers chiffrés transitent par le réseau, c'est à la couche transport (TLS) d'assurer la confidentialité en transit.
