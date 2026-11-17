# Ressources

## Pour commencer

- **Wikipédia, Kerberos (protocole)** : point de départ conseillé par la prof.
  <https://fr.wikipedia.org/wiki/Kerberos_(protocole)>
- **Cahier des charges du groupe** (Google Doc) : plan, répartition, lexique, description de l'algorithme.
  <https://docs.google.com/document/d/1lX21QS8WqnF92lALHuot7x585lKqyM144On_t291JEA/edit?usp=sharing>

## Kerberos

- **RFC 4120, The Kerberos Network Authentication Service (V5)** : la référence, pour vérifier les détails et lister les écarts de notre version.
  <https://www.rfc-editor.org/rfc/rfc4120>
- **Documentation MIT Kerberos** : implémentation de référence, utile pour voir les vrais outils (`kinit`, `klist`, `kdc.conf`).
  <https://web.mit.edu/kerberos/krb5-latest/doc/>

## Chiffrement

- **Documentation `cryptography`, AEAD / AESGCM** : l'API utilisée dans `common/crypto.py`.
  <https://cryptography.io/en/latest/hazmat/primitives/aead/>
- **Réutilisation de nonce en AES-GCM** (conseillé par la prof) : pourquoi un nonce ne doit jamais servir deux fois avec la même clé.
  <https://frereit.de/aes_gcm/>
- **`hashlib.pbkdf2_hmac`** : dérivation de la clé du client à partir du mot de passe.
  <https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac>

## Python

- `socket` : <https://docs.python.org/3/library/socket.html>
- `threading` : <https://docs.python.org/3/library/threading.html>
- `json` : <https://docs.python.org/3/library/json.html>
- `pytest` : <https://docs.pytest.org/>

## À ajouter

Ajoutez ici toute source utilisée pour le rapport (article, cours, vidéo), avec une ligne qui dit à quoi elle a servi.
