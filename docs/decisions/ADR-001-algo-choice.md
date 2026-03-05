# ADR-001 : Choix de AES-256-GCM comme algorithme de chiffrement

- **Statut** : Accepté
- **Date** : 2025-03-05
- **Auteurs** : Équipe secure-core

## Contexte

Le projet secure-core doit chiffrer des fichiers utilisateur sur des appareils mobiles (Android et iOS). L'algorithme choisi doit satisfaire les contraintes suivantes :

1. **Confidentialité et intégrité** en une seule opération (AEAD).
2. **Performance** sur les processeurs ARM des appareils mobiles modernes, qui disposent d'instructions AES-NI (ARMv8 Cryptographic Extensions).
3. **Conformité** avec les standards reconnus (NIST, ANSSI).
4. **Taille du ciphertext** raisonnable (overhead minimal).
5. **Écosystème Rust** : implémentations matures et auditées disponibles.

## Décision

Nous choisissons **AES-256-GCM** comme unique algorithme de chiffrement.

- Taille de clé : 256 bits.
- Taille de nonce : 96 bits (12 octets), généré aléatoirement via CSPRNG.
- Taille de tag : 128 bits (16 octets).

## Justification

### Performance matérielle

Les SoC ARM modernes (Apple A-series, Qualcomm Snapdragon) incluent des extensions cryptographiques matérielles pour AES. AES-256-GCM bénéficie directement de cette accélération, atteignant des débits de plusieurs Go/s sur les appareils récents.

### Standard et conformité

- AES-256-GCM est recommandé par le NIST (SP 800-38D).
- L'ANSSI le recommande dans son référentiel cryptographique.
- C'est l'algorithme AEAD de référence dans TLS 1.3.

### Simplicité

Un seul algorithme simplifie l'implémentation, les tests, la revue de code et la surface d'attaque. Pas de négociation algorithmique, pas de risque de downgrade.

### Écosystème

La crate `aes-gcm` (RustCrypto) est mature, auditée, et utilise les instructions matérielles quand disponibles.

## Alternatives rejetées

### ChaCha20-Poly1305

| Critère | AES-256-GCM | ChaCha20-Poly1305 |
| ------- | ----------- | ----------------- |
| Accélération matérielle ARM | Oui (ARMv8-CE) | Non |
| Performance avec accélération | Supérieure | Inférieure sur ARM avec AES-NI |
| Performance sans accélération | Inférieure | Supérieure (pur logiciel) |
| Standard NIST | SP 800-38D | Non standardisé NIST (IETF RFC 8439) |
| Taille nonce | 96 bits | 96 bits (IETF variant) |

ChaCha20-Poly1305 est un algorithme solide et une alternative valide. Il serait préférable dans un contexte où l'accélération matérielle AES n'est pas disponible (anciens appareils, IoT). Nous le conservons comme **option de fallback future** si le besoin se présente, mais il n'est pas implémenté dans la version initiale.

### AES-256-CBC + HMAC-SHA256

Rejeté car :
- Nécessite deux passes (chiffrement + MAC) au lieu d'une.
- Vulnérable aux attaques padding oracle si mal implémenté.
- Plus complexe à implémenter correctement (encrypt-then-MAC obligatoire).

### XChaCha20-Poly1305

Rejeté car :
- Nonce étendu (192 bits) utile surtout pour les cas où le nonce est dérivé (pas notre cas).
- Pas d'avantage significatif sur notre cas d'usage (nonce aléatoire 96 bits avec AES-256-GCM est suffisant pour notre volume d'opérations).

## Conséquences

- Le core n'implémente qu'un seul chemin cryptographique, ce qui réduit la surface de test et d'audit.
- Le format de sortie est fixe : `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
- Si un appareil sans accélération AES matérielle doit être supporté, il faudra réévaluer cette décision (voir ChaCha20-Poly1305).
- L'ajout d'un second algorithme nécessitera un nouvel ADR et un mécanisme de versioning du format.
