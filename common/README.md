# Partie 5 : `common/`, le code commun

Ce dossier contient le code utilisé par les quatre autres parties : le chiffrement, l'envoi des messages sur le réseau et les paramètres partagés. **Il est déjà écrit et testé.** Ton travail n'est pas de le réécrire mais de le comprendre parfaitement, de le maintenir et de coordonner l'intégration du groupe.

## Ton rôle (personne 5)

1. **Relire et comprendre** chaque ligne de `config.py`, `crypto.py` et `net.py`. Tu es la personne que les autres viennent voir quand un `DecryptError` apparaît ou qu'un message n'arrive pas. Tu dois aussi pouvoir l'expliquer à la soutenance (AES-GCM, nonce, `aad`, PBKDF2).
2. **Maintenir les tests** (`tests/`) : les faire passer à chaque modification, en ajouter si un bug est trouvé dans `common/`.
3. **Gérer `scripts/init_keys.py`** et le fichier `keys.json` qu'il produit : expliquer au groupe comment le générer, quand le régénérer, et vérifier qu'il n'est jamais committé.
4. **Coordonner l'intégration** : relire les PR des autres parties, vérifier qu'elles respectent le contrat des messages ([docs/PROTOCOLE.md](../docs/PROTOCOLE.md)), organiser l'intégration dans l'ordre client + AS, puis TGS, puis service.
5. **Garder le journal** ([docs/JOURNAL.md](../docs/JOURNAL.md)) à jour avec le groupe : il sert de base au rapport et aux slides.

Toute modification de `common/` ou du format des messages doit être annoncée au groupe **avant** d'être poussée : elle touche le code de tout le monde.

## Les fichiers

| Fichier | Contenu |
| --- | --- |
| `config.py` | Ports, durées, nombre d'itérations PBKDF2, mode de clé, noms des principaux, chargement de `keys.json` |
| `crypto.py` | `derive_key`, `new_session_key`, `weak_key`, `encrypt`, `decrypt`, `DecryptError` |
| `net.py` | `send_msg`, `recv_msg`, `send_request`, `serve`, `error`, `log` et les exceptions réseau |

## API de `config.py`

| Nom | Valeur | Rôle |
| --- | --- | --- |
| `HOST` | `"127.0.0.1"` | Adresse des serveurs |
| `AS_PORT`, `TGS_PORT`, `SERVICE_PORT` | `8800`, `8801`, `8802` | Ports de l'AS, du TGS et du service |
| `TICKET_LIFETIME` | `600` | Durée de vie d'un ticket (secondes) |
| `CLOCK_SKEW` | `300` | Écart toléré entre le timestamp d'un authenticator et l'heure du serveur (5 min) |
| `PBKDF2_ITERATIONS` | `100_000` | Itérations de la dérivation de clé |
| `KEY_MODE` | `"aes128"` ou `"weak8"` | Lu dans la variable d'environnement `KRB_KEY_MODE` (défaut `aes128`) |
| `TGS_PRINCIPAL` | `"krbtgt"` | Nom de l'entrée de `keys.json` qui contient K_tgs |
| `SERVICES` | `("mail",)` | Services que le TGS accepte de servir |
| `DEFAULT_CLIENT`, `DEFAULT_SERVICE` | `"alice"`, `"mail"` | Valeurs par défaut du client |
| `KEYS_FILE` | `<racine>/keys.json` | Modifiable avec la variable `KRB_KEYS_FILE` |

```python
load_keys(path=KEYS_FILE) -> dict[str, bytes]
```
Lit `keys.json` et renvoie les clés en `bytes`. Lève `FileNotFoundError` (avec la commande à lancer) si le fichier n'existe pas.

```python
from common import config
keys = config.load_keys()
k_tgs = keys[config.TGS_PRINCIPAL]   # 16 octets
```

## API de `crypto.py`

### `derive_key(password: str, salt: str) -> bytes`
Dérive une clé AES-128 (16 octets) d'un mot de passe avec PBKDF2-HMAC-SHA256 et `PBKDF2_ITERATIONS` itérations. **Le sel est le nom du principal**, comme dans Kerberos : deux utilisateurs ayant le même mot de passe n'ont pas la même clé. Déterministe : même mot de passe + même sel = même clé. C'est ce qui permet au client et au KDC d'avoir K_client sans jamais l'échanger.

```python
k_client = derive_key("motdepasse", "alice")
```

### `new_session_key(mode=None) -> bytes`
Génère une clé aléatoire de 16 octets. En mode `aes128` : `AESGCM.generate_key(bit_length=128)`. En mode `weak8` : `weak_key(secrets.randbelow(256))`. Sans argument, utilise `config.KEY_MODE`.

```python
k_c_tgs = new_session_key()
```

### `weak_key(n: int) -> bytes`
Renvoie `sha256(bytes([n])).digest()[:16]` pour `n` entre 0 et 255. Voir la section « Mode weak8 ».

### `encrypt(key: bytes, data: dict, aad: str) -> str`
Sérialise `data` en JSON, tire un nonce aléatoire de 12 octets, chiffre avec AES-GCM et renvoie `(nonce + chiffré + tag).hex()`. Lève `ValueError` si `aad` n'est pas une des valeurs autorisées.

```python
tgt = encrypt(k_tgs, {"client": "alice", "k_c_tgs": k_c_tgs.hex(), "exp": exp}, "TGT")
```

### `decrypt(key: bytes, blob: str, aad: str) -> dict`
L'inverse. Lève **`DecryptError`** si la clé est mauvaise, si le blob a été modifié (même d'un seul bit), si l'`aad` ne correspond pas, ou si le blob est mal formé.

```python
from common.crypto import decrypt, DecryptError
try:
    tgt = decrypt(k_tgs, msg["tgt"], "TGT")
except DecryptError:
    return error("TGT invalide")
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
| `"AP_REP"` | K_c_service | `{"ts"}` (= ts de l'authenticator + 1) |

## API de `net.py`

| Fonction | Rôle |
| --- | --- |
| `send_msg(sock, msg: dict) -> None` | Envoie `msg` en JSON UTF-8 précédé de sa longueur sur 4 octets big-endian. Lève `MessageTooLarge` au-delà de 1 Mo. |
| `recv_msg(sock) -> dict` | Lit les 4 octets de longueur puis exactement ce nombre d'octets (`recv_exact`). Lève `MessageTooLarge` (> 1 Mo), `ConnectionClosed` (connexion fermée en cours de route) ou `ProtocolError` (pas du JSON, pas un objet). |
| `send_request(host, port, msg, timeout=5.0) -> dict` | Côté client : connexion, envoi, réception de la réponse, fermeture. Lève `ConnectionRefusedError` si le serveur n'est pas lancé. |
| `serve(host, port, handler, name)` | Côté serveur : écoute sur le port, un thread par connexion. Pour chaque connexion : reçoit un message, appelle `handler(msg) -> dict`, renvoie la réponse. Si `handler` lève une exception, renvoie `ERROR "erreur interne du serveur"` et affiche la trace, sans arrêter le serveur. |
| `serve_socket(sock, handler, name)` | Même chose sur une socket déjà ouverte (utilisé par les tests). |
| `error(reason) -> dict` | Renvoie `{"type": "ERROR", "reason": reason}`. |
| `log(name, text)` | Affiche `[HH:MM:SS] [name] text`. |

Grâce à `serve`, chaque serveur n'a qu'une fonction à écrire : `handle_request(msg) -> dict`, qu'on peut tester sans réseau en l'appelant directement avec un dictionnaire.

```python
from common.net import send_request
rep = send_request("127.0.0.1", 8800, {"type": "AS_REQ", "client": "alice"})
```

## Pourquoi AES-GCM

AES seul (mode ECB ou CBC) ne fait que **chiffrer** : un attaquant peut modifier le chiffré sans que le destinataire s'en aperçoive. Or dans Kerberos, l'intégrité est aussi importante que la confidentialité : si Alice pouvait changer le nom écrit dans son TGT, elle deviendrait quelqu'un d'autre. AES-GCM est un chiffrement **authentifié** (AEAD) : il chiffre et ajoute un tag de 16 octets. Au déchiffrement, si un seul bit du chiffré, du nonce ou de l'`aad` a changé, ou si la clé est mauvaise, le tag ne correspond plus et `decrypt` lève `DecryptError`. C'est ce qui permet au service de savoir qu'un ticket vient bien du KDC. Le choix de la bibliothèque `cryptography` et de `AESGCM` a été validé par la prof.

## Le nonce : jamais deux fois le même avec la même clé

GCM chiffre en faisant un XOR entre le message et un flux pseudo-aléatoire qui ne dépend que de la clé et du nonce. Si deux messages sont chiffrés avec la même clé **et** le même nonce :

- le XOR des deux chiffrés est égal au XOR des deux messages clairs : connaître l'un révèle l'autre ;
- les deux tags permettent de retrouver la clé d'authentification interne de GCM, et donc de **fabriquer de faux chiffrés acceptés comme valides**.

Référence conseillée par la prof : <https://frereit.de/aes_gcm/>.

C'est pourquoi `encrypt` tire un nouveau nonce de 12 octets avec `os.urandom(12)` **à chaque appel**, et le colle devant le chiffré pour que `decrypt` le retrouve. Il n'y a ni nonce fixe ni compteur (un compteur repartirait de zéro à chaque redémarrage d'un programme, avec les mêmes clés long terme). Avec 96 bits aléatoires, une collision est négligeable tant qu'on chiffre beaucoup moins de 2^32 messages par clé. **Personne ne doit appeler `AESGCM` directement en dehors de ce module.**

## L'`aad` : lier chaque chiffré à son rôle

L'`aad` (*additional authenticated data*) n'est pas chiffré, mais il entre dans le calcul du tag : il faut donner exactement le même au déchiffrement. On y met le rôle du chiffré. Exemple d'attaque bloquée : l'authenticator `TGS_AUTH` et la partie `TGS_REP` sont tous deux chiffrés avec K_c_tgs ; sans `aad`, un attaquant pourrait essayer de faire passer l'un pour l'autre. Avec l'`aad`, `decrypt(k_c_tgs, blob, "TGS_REP")` échoue sur un blob chiffré avec `"TGS_AUTH"`. Les vrais Kerberos font la même chose avec des « key usage numbers » (RFC 4120, section 7.5.1).

## Le mode `weak8`

L'énoncé initial proposait une clé de 8 bits « par simplicité ». AES-GCM refuse une clé de 8 bits : il veut 128, 192 ou 256 bits. On garde donc de vraies clés AES-128, mais en mode `weak8` elles sont fabriquées par `weak_key(n)` avec `n` entre 0 et 255 : seulement **256 clés possibles**, soit 8 bits d'entropie. Un attaquant qui intercepte un ticket les essaie toutes en moins d'une seconde (voir `test_weak8_force_brute_en_256_essais_max`). En mode `aes128`, il y en a 2^128.

```bash
KRB_KEY_MODE=weak8 python scripts/init_keys.py --password motdepasse
KRB_KEY_MODE=weak8 python -m as_server.as_server
```

Sous Windows (PowerShell) : `$env:KRB_KEY_MODE="weak8"` avant les commandes. Le mode doit être le même pour `init_keys.py` et pour tous les serveurs. K_client reste dérivée du mot de passe dans les deux modes : sa force dépend du mot de passe.

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

Relancer le script change K_tgs et K_service : il faut alors redémarrer l'AS, le TGS et le service. `keys.json` est dans `.gitignore`. Simplification à connaître : dans un vrai Kerberos, seul le KDC a la base des clés, et chaque service n'a que la sienne (fichier *keytab*).

## Lancer les tests

```bash
pytest           # tous les tests
pytest -v tests/test_crypto.py
```

| Fichier | Ce qui est testé |
| --- | --- |
| `tests/test_crypto.py` | aller-retour ; mauvaise clé, mauvais `aad`, chiffré modifié, blob mal formé → `DecryptError` ; deux chiffrements des mêmes données diffèrent ; `derive_key` déterministe et dépendante du sel ; force brute `weak8` en 256 essais max |
| `tests/test_net.py` | aller-retour avec `socket.socketpair()` ; plusieurs messages à la suite ; message proche de 1 Mo ; message trop gros refusé à l'envoi et à la réception ; connexion fermée ; contenu invalide ; `serve` avec connexions concurrentes et handler qui plante |

## Coordonner l'intégration

Ordre conseillé (chaque étape = une PR fusionnée dans `main`) :

1. **Client (échange 1) + AS** : le client obtient un TGT et l'affiche.
2. **TGS** : le client obtient un ticket de service.
3. **Service** : authentification mutuelle complète.

À chaque étape : `pytest` passe, les programmes se lancent avec `python -m ...`, le scénario complet tourne avec un `keys.json` neuf.

## Pièges à éviter

- Ne jamais committer `keys.json` (vérifier `git status` avant chaque commit).
- Un `DecryptError` inattendu vient presque toujours : d'un mauvais `aad`, d'un `keys.json` régénéré sans redémarrer les serveurs, d'un mode `KRB_KEY_MODE` différent entre deux programmes, ou d'une clé passée en hex au lieu de `bytes` (`bytes.fromhex(...)`).
- Ne pas changer une valeur de `config.py` ou une signature sans prévenir.

## C'est terminé quand

- [ ] tu sais expliquer chaque fonction de `common/` et pourquoi le nonce est aléatoire ;
- [ ] `pytest` passe sur `main` après chaque intégration ;
- [ ] tout le groupe sait générer `keys.json` et lancer les quatre programmes ;
- [ ] le scénario complet fonctionne sur `main` (client → AS → TGS → service).

## Ta branche git

`feat/common`. Workflow : `git switch feat/common`, `git pull`, commits, `pytest`, `git push`, puis PR vers `main`. Voir [CONTRIBUTING.md](../CONTRIBUTING.md).
