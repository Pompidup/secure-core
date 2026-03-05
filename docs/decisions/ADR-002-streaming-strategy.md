# ADR-002 : Stratégie de chiffrement streaming par chunks

- **Statut** : Accepté
- **Date** : 2025-03-05
- **Auteurs** : Équipe secure-core

## Contexte

Le chiffrement in-memory (`encrypt_bytes` / `decrypt_bytes`) charge l'intégralité du fichier en RAM. Cela fonctionne pour les petits fichiers mais pose problème pour les fichiers volumineux sur mobile (photos haute résolution, vidéos), où la mémoire disponible est limitée.

Il faut une stratégie de chiffrement qui :

1. Ne charge pas l'intégralité du fichier en mémoire.
2. Détecte la corruption ou la modification de n'importe quelle portion du fichier.
3. Reste simple à implémenter et à auditer.

## Décision

Nous adoptons un **chiffrement par chunks avec AEAD indépendant par chunk**.

### Paramètres

- **Taille de chunk** : 64 KB (65 536 bytes) de plaintext par chunk.
- **Algorithme** : AES-256-GCM (identique au mode in-memory, cf. ADR-001).
- **Nonce par chunk** : dérivé du `nonce_base` (12 bytes aléatoires) stocké dans le header global, avec le chunk index encodé dans les 4 derniers bytes (big-endian, incrémentation).

### Format du stream

```
┌─────────────────────────────────┐
│  Header global (25 bytes)       │  ← même format EncHeader V1
├─────────────────────────────────┤
│  Chunk 0: ciphertext + tag      │  ← 64KB + 16 bytes (ou moins pour le dernier)
├─────────────────────────────────┤
│  Chunk 1: ciphertext + tag      │
├─────────────────────────────────┤
│  ...                            │
├─────────────────────────────────┤
│  Chunk N: ciphertext + tag      │  ← dernier chunk, potentiellement < 64KB
└─────────────────────────────────┘
```

### Dérivation des nonces

```
nonce_for_chunk(base, i) :
  result = copy(base)
  result[8..12] = result[8..12] XOR i.to_be_bytes()
  return result
```

Les 4 derniers bytes du nonce_base sont XORés avec le chunk index (u32 big-endian). Cela garantit un nonce unique par chunk tout en restant déterministe pour le déchiffrement.

Avec un nonce_base aléatoire de 96 bits et un compteur sur 32 bits, le risque de collision de nonces entre deux fichiers est négligeable (birthday bound sur 64 bits restants).

## Justification

### Pourquoi pas un seul GCM sur tout le fichier ?

- GCM nécessite de bufferiser l'intégralité du plaintext pour produire le tag. Sur un fichier de 500 MB, cela consomme 500 MB de RAM.
- Le dernier chunk doit être traité avant de pouvoir vérifier l'intégrité. Aucune détection anticipée de corruption.

### Pourquoi pas AES-GCM-SIV ou AES-CTR + HMAC global ?

- AES-GCM-SIV résiste aux nonce reuse mais ne résout pas le problème mémoire.
- AES-CTR + HMAC global nécessite deux passes (chiffrement puis MAC) et complexifie l'implémentation.

### Pourquoi 64 KB ?

- Assez petit pour ne pas impacter la mémoire mobile (~64 KB de buffer).
- Assez grand pour amortir l'overhead du tag GCM (16 bytes / 64 KB = 0.024%).
- Aligné sur les tailles de page courantes et les buffers I/O.

## Conséquences

- Chaque chunk porte son propre tag GCM : une corruption au milieu du fichier est détectée dès le chunk concerné, sans lire la suite.
- L'overhead total est de `nombre_de_chunks × 16 bytes` pour les tags, plus le header de 25 bytes.
- Le nombre maximum de chunks est 2³² (compteur sur 4 bytes), soit un fichier max de 64 KB × 2³² = 256 TB. Largement suffisant.
- Un attaquant ne peut pas réordonner les chunks car le nonce encode l'index.
- Un attaquant ne peut pas tronquer le stream sans que le lecteur détecte un nombre de chunks inférieur à l'attendu (vérifié par EOF prématuré).
