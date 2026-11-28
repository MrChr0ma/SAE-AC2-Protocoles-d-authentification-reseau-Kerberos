# `common/` : le code commun

État : fait et testé. Auteur : Hector (17/11), avec `scripts/init_keys.py` et les tests.

Ce dossier contient ce que les quatre programmes partagent : le chiffrement, l'envoi des messages sur le réseau et les paramètres. Toute modification de `common/` ou du format des messages doit être annoncée au groupe avant d'être poussée, car elle touche le code de tout le monde.

## Les fichiers

| Fichier | Contenu |
| --- | --- |
| `config.py` | Ports, durées, itérations PBKDF2, mode de clé, noms des principaux, lecture de `keys.json` |
| `crypto.py` | `derive_key`, `new_session_key`, `weak_key`, `encrypt`, `decrypt`, `DecryptError` |
| `net.py` | `send_msg`, `recv_msg`, `send_request`, `serve`, `serve_socket`, `error`, `log` et les exceptions réseau |

## `config.py`

| Nom | Valeur | Rôle |
| --- | --- | --- |
| `HOST` | `"127.0.0.1"` | Adresse des serveurs |
| `AS_PORT`, `TGS_PORT`, `SERVICE_PORT` | `8800`, `8801`, `8802` | Ports de l'AS, du TGS et du service |
| `TICKET_LIFETIME` | `600` | Durée de vie d'un ticket (secondes) |
| `CLOCK_SKEW` | `300` | Écart toléré entre le timestamp d'un authenticator et l'heure du serveur (5 min) |
| `PBKDF2_ITERATIONS` | `100_000` | Itérations de la dérivation de clé |
| `KEY_MODE` | `"aes128"` ou `"weak8"` | Lu dans la variable d'environnement `KRB_KEY_MODE` (défaut `aes128`). Une autre valeur lève `ValueError` au démarrage |
| `TGS_PRINCIPAL` | `"krbtgt"` | Nom de l'entrée de `keys.json` qui contient K_tgs |
| `SERVICES` | `("mail",)` | Services que le TGS accepte de servir |
| `DEFAULT_CLIENT`, `DEFAULT_SERVICE` | `"alice"`, `"mail"` | Valeurs par défaut du client |
| `KEYS_FILE` | `<racine>/keys.json` | Modifiable avec la variable `KRB_KEYS_FILE` |

`load_keys(path=KEYS_FILE) -> dict[str, bytes]` lit `keys.json` et renvoie les clés en `bytes`. Si le fichier n'existe pas, elle lève `FileNotFoundError` avec la commande à lancer.

```python
from common import config
keys = config.load_keys()
k_tgs = keys[config.TGS_PRINCIPAL]   # 16 octets
```

## `crypto.py`

- `derive_key(password, salt) -> bytes` : clé AES-128 dérivée du mot de passe par PBKDF2-HMAC-SHA256 (`PBKDF2_ITERATIONS` itérations). Le sel est le nom du principal, comme dans Kerberos : deux utilisateurs avec le même mot de passe n'ont pas la même clé. Même mot de passe et même sel donnent la même clé, c'est ce qui permet au client et au KDC d'avoir K_client sans l'échanger.
- `new_session_key(mode=None) -> bytes` : clé aléatoire de 16 octets. En `aes128`, `AESGCM.generate_key(bit_length=128)` ; en `weak8`, `weak_key(secrets.randbelow(256))`. Sans argument, utilise `config.KEY_MODE`.
- `weak_key(n) -> bytes` : `sha256(bytes([n])).digest()[:16]` pour `n` entre 0 et 255.
- `encrypt(key, data, aad) -> str` : sérialise `data` en JSON, tire un nonce de 12 octets, chiffre avec AES-GCM et renvoie `(nonce + chiffré + tag).hex()`. Lève `ValueError` si `aad` n'est pas une valeur autorisée.
- `decrypt(key, blob, aad) -> dict` : l'inverse. Lève `DecryptError` si la clé est mauvaise, si le blob a été modifié, si l'`aad` ne correspond pas, ou si le blob est mal formé.

```python
from common.crypto import decrypt, encrypt, DecryptError
tgt = encrypt(k_tgs, {"client": "alice", "k_c_tgs": k_c_tgs.hex(), "exp": exp}, "TGT")
try:
    contenu = decrypt(k_tgs, tgt, "TGT")
except DecryptError:
    ...
```

### Valeurs d'`aad`

| `aad` | Chiffré avec | Contenu |
| --- | --- | --- |
| `"AS_REP"` | K_client | `{"k_c_tgs", "exp"}` |
| `"TGT"` | K_tgs | `{"client", "k_c_tgs", "exp"}` |
| `"TGS_AUTH"` | K_c_tgs | `{"client", "ts"}` |
| `"TGS_REP"` | K_c_tgs | `{"k_c_service", "exp"}` |
| `"TICKET"` | K_service | `{"client", "k_c_service", "exp"}` |
| `"AP_AUTH"` | K_c_service | `{"client", "ts"}` |
| `"AP_REP"` | K_c_service | `{"ts"}` (ts de l'authenticator + 1) |

## `net.py`

| Fonction | Rôle |
| --- | --- |
| `send_msg(sock, msg)` | Envoie `msg` en JSON UTF-8 précédé de sa longueur sur 4 octets big-endian. Lève `MessageTooLarge` au-delà de 1 Mo. |
| `recv_msg(sock) -> dict` | Lit la longueur puis exactement ce nombre d'octets. Lève `MessageTooLarge`, `ConnectionClosed` ou `ProtocolError` (pas du JSON, pas un objet). |
| `send_request(host, port, msg, timeout=5.0) -> dict` | Côté client : connexion, envoi, réponse, fermeture. Lève `ConnectionRefusedError` si le serveur n'est pas lancé. |
| `serve(host, port, handler, name)` | Côté serveur : écoute sur le port, un thread par connexion. Reçoit un message, appelle `handler(msg) -> dict`, renvoie la réponse. Si `handler` lève une exception, renvoie `ERROR "erreur interne du serveur"` sans arrêter le serveur. |
| `serve_socket(sock, handler, name)` | Pareil sur une socket déjà ouverte (utilisé par les tests). |
| `error(reason) -> dict` | `{"type": "ERROR", "reason": reason}` |
| `log(name, text)` | Affiche `[HH:MM:SS] [name] text`. |

Grâce à `serve`, chaque serveur n'a qu'une fonction à écrire, `handle_request(msg, ...) -> dict`, qu'on teste sans réseau en l'appelant avec un dictionnaire.

## Pourquoi AES-GCM

AES seul (ECB, CBC) ne fait que chiffrer : un attaquant peut modifier le chiffré sans que le destinataire le voie. Dans Kerberos, l'intégrité compte autant que la confidentialité : si Alice pouvait changer le nom dans son TGT, elle deviendrait quelqu'un d'autre. AES-GCM est un chiffrement authentifié (AEAD) : il ajoute un tag de 16 octets. Si un bit du chiffré, du nonce ou de l'`aad` change, ou si la clé est mauvaise, `decrypt` lève `DecryptError`. Le choix de `cryptography` et d'`AESGCM` a été validé par la référente.

## Le nonce

GCM fait un XOR entre le message et un flux qui ne dépend que de la clé et du nonce. Si deux messages sont chiffrés avec la même clé et le même nonce :

- le XOR des deux chiffrés donne le XOR des deux clairs : connaître l'un révèle l'autre ;
- les deux tags permettent de retrouver la clé d'authentification interne de GCM, donc de fabriquer de faux chiffrés acceptés.

Référence conseillée par la référente : <https://frereit.de/aes_gcm/>.

`encrypt` tire donc un nouveau nonce avec `os.urandom(12)` à chaque appel et le colle devant le chiffré. Pas de nonce fixe ni de compteur (un compteur repartirait de zéro à chaque redémarrage, avec les mêmes clés long terme). Avec 96 bits aléatoires, une collision est négligeable tant qu'on chiffre beaucoup moins de 2^32 messages par clé. Personne n'appelle `AESGCM` en dehors de ce module.

## L'`aad`

L'`aad` (*additional authenticated data*) n'est pas chiffré mais entre dans le calcul du tag : il faut le même au déchiffrement. On y met le rôle du chiffré. Exemple : l'authenticator `TGS_AUTH` et la partie `TGS_REP` sont tous deux chiffrés avec K_c_tgs ; avec l'`aad`, `decrypt(k_c_tgs, blob, "TGS_REP")` échoue sur un blob chiffré avec `"TGS_AUTH"`. Le vrai Kerberos fait la même chose avec des « key usage numbers » (RFC 4120, section 7.5.1).

## Le mode `weak8`

L'idée de départ était une clé de 8 bits. AES-GCM refuse une clé de 8 bits (il veut 128, 192 ou 256 bits). On garde donc des clés AES-128, mais en mode `weak8` elles sont fabriquées par `weak_key(n)` avec `n` entre 0 et 255 : 256 clés possibles, soit 8 bits d'entropie. On les essaie toutes en moins d'une seconde (voir `test_weak8_force_brute_en_256_essais_max`).

`KEY_MODE` ne sert qu'à créer des clés, dans `new_session_key` :

- `init_keys.py` : K_tgs et K_service ;
- l'AS et le TGS : les clés de session.

Le client et le service ne créent pas de clé. Une clé weak8 reste une clé AES de 16 octets valide : des programmes lancés avec des modes différents fonctionnent ensemble, sans `DecryptError`. Seules les clés créées en weak8 sont faibles. K_client reste dérivée du mot de passe dans les deux modes.

```bash
KRB_KEY_MODE=weak8 python scripts/init_keys.py --password motdepasse
KRB_KEY_MODE=weak8 python -m as_server.as_server
KRB_KEY_MODE=weak8 python -m tgs_server.tgs_server
```

Sous PowerShell : `$env:KRB_KEY_MODE="weak8"` avant les commandes.

## `scripts/init_keys.py`

```bash
python scripts/init_keys.py --password motdepasse
```

Crée `keys.json` à la racine (droits 600) :

```json
{
  "alice":  "3f0c...a91e",
  "krbtgt": "b27d...04c3",
  "mail":   "e815...7f2a"
}
```

- `alice` = `derive_key(mot_de_passe, "alice")` : K_client ;
- `krbtgt` = `new_session_key()` : K_tgs ;
- `mail` = `new_session_key()` : K_service.

Options : `--client` (défaut `alice`) et `--output`. Relancer le script change K_tgs et K_service : il faut alors redémarrer l'AS, le TGS et le service. `keys.json` est dans `.gitignore`. Simplification : dans un vrai Kerberos, seul le KDC a toutes les clés, et chaque service n'a que la sienne (*keytab*). Ici, les trois serveurs lisent le même fichier.

## Tests

```bash
pytest                          # tous les tests
pytest -v tests/test_crypto.py
```

| Fichier | Tests | Ce qui est testé |
| --- | --- | --- |
| `tests/test_crypto.py` | 17 | aller-retour ; mauvaise clé, mauvais `aad`, chiffré modifié, blob mal formé ; `aad` inconnu ; deux chiffrements différents ; `derive_key` déterministe et dépendante du sel ; `new_session_key` ; `weak_key` ; force brute `weak8` en 256 essais max |
| `tests/test_net.py` | 12 | aller-retour avec `socketpair` ; messages successifs ; gros message ; limite de 1 Mo à l'envoi et à la réception ; connexion fermée ; contenu invalide ; `serve_socket` avec 20 connexions concurrentes et un handler qui plante |
| `tests/test_as_server.py` | 2 | AS_REP valide, client inconnu |
| `tests/test_tgs_server.py` | 22 | voir [tgs_server/README.md](../tgs_server/README.md) |

Pas encore testés : `load_keys`, `init_keys.py` et `serve` (le vrai lancement sur un port).

## Pièges à éviter

- Ne jamais commiter `keys.json` (vérifier `git status` avant chaque commit).
- Un `DecryptError` inattendu vient presque toujours d'un mauvais `aad`, d'un `keys.json` recréé sans redémarrer les serveurs, ou d'une clé passée en hex au lieu de `bytes` (`bytes.fromhex(...)`).
- Ne pas changer une valeur de `config.py` ou une signature sans prévenir.

## État

- [x] `config.py`, `crypto.py`, `net.py` écrits et testés ;
- [x] `scripts/init_keys.py` crée `keys.json` ;
- [x] `pytest` passe sur `main` (53 tests au 28/11) ;
- [ ] le scénario complet fonctionne sur `main` (client → AS → TGS → service) : il manque le service.
