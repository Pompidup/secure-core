# Threat Model

## Périmètre

Le core Rust `secure-core` est une bibliothèque de chiffrement pure : **bytes in, bytes out**. Il ne connaît ni le système de fichiers, ni le réseau, ni le système d'exploitation hôte. Son unique responsabilité est de transformer des octets en clair en octets chiffrés (et inversement), étant donné une DEK (Data Encryption Key) fournie par l'appelant.

## Menaces couvertes

| Menace | Description | Mitigation |
| ------ | ----------- | ---------- |
| Extraction de fichiers chiffrés | Un attaquant accède au stockage et copie les fichiers chiffrés. | AES-256-GCM : confidentialité et intégrité. Sans la DEK, les données sont inexploitables. |
| Modification du ciphertext | Un attaquant altère un fichier chiffré (bit-flip, troncature, injection). | Le tag GCM détecte toute modification. Le déchiffrement échoue explicitement. |
| Corruption partielle | Perte ou altération de blocs suite à une défaillance stockage. | L'authentification GCM couvre l'intégralité du ciphertext. Toute corruption est détectée. |
| Réutilisation de nonce | Deux chiffrements avec le même nonce compromettent la confidentialité. | Génération de nonce aléatoire (96 bits) via CSPRNG pour chaque opération. |
| Downgrade algorithmique | Un attaquant tente de forcer l'utilisation d'un algorithme faible. | Un seul algorithme supporté, identifié dans le header. Rejet de tout header inconnu. |

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

1. **Gestion des clés par l'OS.** La DEK est protégée par le Keystore Android ou le Keychain iOS. Le core ne stocke, ne persiste et ne dérive jamais de clé lui-même.

2. **DEK jamais en clair côté application.** La DEK est unwrappée par la plateforme et transmise au core uniquement pour la durée de l'opération cryptographique. La plateforme est responsable du zéroïsation après usage.

3. **CSPRNG disponible.** Le core suppose que l'environnement fournit un générateur d'aléa cryptographiquement sûr (via `getrandom` / OS entropy).

4. **Intégrité du binaire.** Le code du core n'a pas été altéré. La vérification de l'intégrité du binaire (code signing) relève de la plateforme.

5. **Transport hors périmètre.** Le core ne gère pas le transport réseau. Si les fichiers chiffrés transitent par le réseau, c'est à la couche transport (TLS) d'assurer la confidentialité en transit.
