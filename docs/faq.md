# FAQ — secure-core

### Puis-je recuperer mes fichiers si je change de telephone ?

En V1, la cle de chiffrement (DEK) est protegee par le keystore du device (`device_wrap`). Si le device est perdu ou change, la DEK n'est pas recuperable.

Le champ `recovery_wrap` dans les metadonnees est reserve pour la V2 : il permettra de chiffrer la DEK avec une cle de recovery (ex : derivee du compte utilisateur), rendant les fichiers portables entre devices.

**En V1 : non. Prevoyez un mecanisme de sauvegarde cote plateforme si necessaire.**

---

### Le core ecrit-il du clair sur disque ?

**Seulement la ou l'appelant le demande explicitement.** C'est une garantie de design :

- Les fonctions `encrypt_bytes` / `decrypt_bytes` travaillent uniquement en memoire.
- Les fonctions de streaming (`encrypt_stream` / `decrypt_stream`) utilisent des `Read` / `Write` abstraits — c'est la plateforme qui decide la destination.
- **Exception assumee :** `decrypt_file` (C `secure_core_decrypt_file`, JNI `nativeDecryptFile`) ecrit le document dechiffre a l'`output_path` fourni par la plateforme, par exemple pour un apercu ou un partage. Le chemin, ses permissions et la suppression du fichier ensuite (`SecureDelete`) restent a la charge de la plateforme.
- En dehors de `decrypt_file`, le core ne cree aucun fichier contenant du clair.
- Le core ne log jamais de cle, nonce ou plaintext (voir `logging.rs`).

Cette garantie est documentee dans le [contrat plateforme](platform-contract.md).

---

### Quelle est la taille maximale d'un fichier ?

| Mode | Limite |
|---|---|
| In-memory (`encrypt_bytes`) | 4 GB (64-bit) / 2 GB (32-bit) |
| Streaming (`encrypt_stream`) | ~256 TB (2^32 chunks x 64 KB) |

Le format `.enc` V1 n'impose pas de limite theorique sur la taille du fichier — la contrainte vient du nombre maximal de chunks (u32) et de la memoire disponible pour le mode in-memory.

En pratique, pour des fichiers mobiles (photos, documents), ces limites sont largement suffisantes.

---

### Que se passe-t-il si le fichier est corrompu ?

Le dechiffrement echoue avec une erreur `SecureCoreError::CryptoError` ou `InvalidFormat`. AES-256-GCM est un schema AEAD : toute modification du ciphertext ou du tag d'authentification est detectee. Le header est authentifie en mode in-memory ; en streaming, ses champs critiques sont proteges indirectement (le nonce derive les nonces des chunks) et un stream sans `FLAG_STREAM_FINAL_CHUNK` est rejete.

Cas couverts :
- **Bit flip** dans le ciphertext ou le header → erreur d'authentification GCM (in-memory), ou rejet du header (streaming)
- **Troncature** du fichier → erreur de format ou chunk incomplet, y compris si le flag de fin de stream a ete efface
- **Reordonnancement de chunks** (streaming) → erreur d'authentification (le chunk index fait partie de l'AAD)
- **Mauvaise cle** → erreur d'authentification

Le core ne retourne jamais de plaintext partiellement dechiffre. C'est tout ou rien.

---

### Quels algorithmes sont supportes ?

V1 supporte uniquement **AES-256-GCM** (identifiant `0x01` dans le header). Le choix est documente dans [ADR-001](decisions/ADR-001-algo-choice.md).

Le champ `algorithm` dans le header permet d'ajouter d'autres algorithmes dans les versions futures sans casser la compatibilite.

---

### Le core gere-t-il le wrapping de cles ?

**Non.** Le wrapping/unwrapping de la DEK est entierement la responsabilite de la plateforme (Android Keystore, iOS Keychain). Le core recoit la DEK deja en clair et la zeroize des qu'il n'en a plus besoin (`Dek` derive `ZeroizeOnDrop`).

Voir le [contrat plateforme](platform-contract.md) pour la repartition des responsabilites.
