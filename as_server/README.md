# `as_server/` : l'AS (Authentication Server)

État : fait, fusionné le 25/11 (PR n°5). Auteur : Sasha. Fichier : [`as_server.py`](as_server.py). Port : 8800.

## Rôle

L'AS est la porte d'entrée de Kerberos. Le client lui donne seulement son nom, sans mot de passe. L'AS répond avec :

- une partie chiffrée avec K_client (dérivée du mot de passe d'Alice) : seul quelqu'un qui connaît le mot de passe peut l'ouvrir ;
- le TGT, chiffré avec K_tgs : Alice ne peut pas le lire, elle le transporte jusqu'au TGS.

Les deux contiennent la même clé de session K_c_tgs, tirée par l'AS.

```
Client -> AS : "alice"
AS tire K_c_tgs
AS -> Client : E(K_client, K_c_tgs + expiration)               lisible seulement avec le bon mot de passe
               TGT = E(K_tgs, "alice" + K_c_tgs + expiration)   opaque pour Alice
```

Dans un vrai Kerberos, l'AS et le TGS sont un seul programme, le KDC. Ici ce sont deux programmes qui lisent tous les deux K_tgs dans `keys.json`.

## Messages

Reçu : `{"type": "AS_REQ", "client": "alice"}`

Renvoyé : `{"type": "AS_REP", "enc_part": "...", "tgt": "..."}` avec

```
enc_part = E(K_client, "AS_REP", {"k_c_tgs": "<hex>", "exp": <float>})
tgt      = E(K_tgs,    "TGT",    {"client": "alice", "k_c_tgs": "<hex>", "exp": <float>})
```

`exp` (timestamp Unix) et `k_c_tgs` (hex) sont les mêmes dans les deux. Ou bien un `ERROR`.

| Clé | Où | `aad` |
| --- | --- | --- |
| K_client | `keys[client]` (`keys.json`, chargé par `main()`) | `"AS_REP"` |
| K_tgs | `keys[config.TGS_PRINCIPAL]` = `keys["krbtgt"]` | `"TGT"` |
| K_c_tgs | `new_session_key()` | — |

L'AS ne déchiffre rien, il ne fait que chiffrer.

## Ce que fait `handle_request(msg, keys)`

- [x] 1. Vérifie que `msg` est un dictionnaire, que `type` vaut `"AS_REQ"` et que `client` est une chaîne non vide.
- [x] 2. Vérifie que le client existe : présent dans `keys`, différent de `krbtgt` et absent de `config.SERVICES`.
- [x] 3. Tire `k_c_tgs = new_session_key()`.
- [x] 4. Calcule `exp = time.time() + config.TICKET_LIFETIME`.
- [x] 5. Construit `enc_part` (K_client, `"AS_REP"`).
- [x] 6. Construit le `tgt` (K_tgs, `"TGT"`).
- [x] 7. Renvoie l'AS_REP et affiche une ligne de log.

La partie réseau est faite par `serve()` dans `main()`.

| Contrôle | Réponse |
| --- | --- |
| pas un dictionnaire, `type` différent de `"AS_REQ"`, `client` absent ou pas une chaîne non vide | `error("requête invalide")` |
| client absent de `keys.json`, ou nom réservé (`krbtgt`, `mail`) | `error("client inconnu")` |

Limite connue : l'AS répond à quiconque donne un nom valide, sans pré-authentification. Voir [docs/ANALYSE.md](../docs/ANALYSE.md#3-failles-de-notre-implémentation).

## Lancer et tester

```bash
python scripts/init_keys.py --password motdepasse   # une fois
python -m as_server.as_server
pytest tests/test_as_server.py
```

Tests (`tests/test_as_server.py`) : un AS_REP valide (TGT et `enc_part` cohérents) et un client inconnu. Pas encore de test pour une requête invalide, les noms réservés ou le mode weak8.

Test réseau, serveur lancé, avec le même mot de passe que pour `init_keys.py` :

```bash
python -c "
from common import config
from common.crypto import decrypt, derive_key
from common.net import send_request
rep = send_request(config.HOST, config.AS_PORT, {'type': 'AS_REQ', 'client': 'alice'})
print(decrypt(derive_key('motdepasse', 'alice'), rep['enc_part'], 'AS_REP'))
print(decrypt(config.load_keys()['krbtgt'], rep['tgt'], 'TGT'))
"
```

## Points d'attention

- La même `k_c_tgs` et le même `exp` dans `enc_part` et dans le TGT.
- Clés en hexadécimal dans le JSON (`k_c_tgs.hex()`).
- `exp` calculé avec l'heure du serveur, jamais une valeur du client.
- `enc_part` avec K_client, TGT avec K_tgs : inverser les deux donnerait au client de quoi lire et modifier son TGT.
- Le log passe par `print` (préfixe `[AS]`) et non par `common.net.log` : pas d'heure, et la ligne s'affiche juste avant l'envoi réel.

## État

- [x] `python -m as_server.as_server` démarre et répond à un AS_REQ par un AS_REP ;
- [x] `enc_part` s'ouvre avec `derive_key(mot_de_passe, "alice")` ;
- [x] le TGT s'ouvre avec `keys["krbtgt"]` et contient `client`, `k_c_tgs`, `exp` identiques à `enc_part` ;
- [x] un client inconnu reçoit `ERROR "client inconnu"` ;
- [x] le client obtient un TGT et l'affiche ;
- [x] `pytest` passe.
