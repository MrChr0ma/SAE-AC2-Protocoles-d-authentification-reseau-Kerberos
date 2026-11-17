# Partie 2 : `as_server/`, l'AS (Authentication Server)

Fichier à compléter : [`as_server.py`](as_server.py). Port : **8800**.

## 1. Ton rôle dans le protocole

L'AS est la porte d'entrée de Kerberos. Le client lui donne seulement son nom, sans mot de passe. L'AS répond avec deux choses :

- une partie chiffrée avec K_client (la clé dérivée du mot de passe d'Alice) : seul quelqu'un qui connaît le mot de passe peut l'ouvrir, **c'est ce qui prouve l'identité du client** sans que le mot de passe circule ;
- le TGT, chiffré avec K_tgs : Alice ne peut pas le lire, elle le transporte jusqu'au TGS comme un badge.

Les deux contiennent la même clé de session K_c_tgs, que tu génères.

```
1. AS : obtenir le TGT
   Client -> AS : "alice"
   AS génère K_c_tgs
   AS -> Client : E(K_client, K_c_tgs + expiration)               lisible seulement avec le bon mot de passe
                  TGT = E(K_tgs, "alice" + K_c_tgs + expiration)   opaque pour Alice
```

Dans un vrai Kerberos, l'AS et le TGS sont un seul programme, le KDC. Ici ce sont deux programmes séparés qui lisent tous les deux K_tgs dans `keys.json`.

## 2. Ce que tu reçois et ce que tu envoies

Tu reçois un **AS_REQ** :

```json
{"type": "AS_REQ", "client": "alice"}
```

Tu renvoies un **AS_REP** :

```json
{
  "type": "AS_REP",
  "enc_part": "5be1c0...e93a",
  "tgt": "0d77a4...51fc"
}
```

avec :

```
enc_part = E(K_client, "AS_REP", {"k_c_tgs": "<hex>", "exp": <float>})
tgt      = E(K_tgs,    "TGT",    {"client": "alice", "k_c_tgs": "<hex>", "exp": <float>})
```

`exp` est un timestamp Unix (ex. `1795000123.42`), le même dans les deux. `k_c_tgs` est en hexadécimal (`k_c_tgs.hex()`).

Ou un **ERROR** : `{"type": "ERROR", "reason": "client inconnu"}`.

## 3. Les clés que tu utilises

| Clé | Où la trouver | `aad` |
| --- | --- | --- |
| K_client | `keys["alice"]` (dans `keys.json`, chargé par `main()`) | `"AS_REP"` pour chiffrer `enc_part` |
| K_tgs | `keys[config.TGS_PRINCIPAL]` = `keys["krbtgt"]` | `"TGT"` pour chiffrer le TGT |
| K_c_tgs | tu la génères avec `new_session_key()` | — |

Tu ne déchiffres rien : l'AS ne fait que chiffrer.

## 4. Étapes à coder

Elles correspondent aux `# TODO` de `as_server.py`, dans la fonction `handle_request(msg, keys)`.

- [ ] **1.** Vérifier que `msg["type"] == "AS_REQ"` et que `"client"` est présent.
- [ ] **2.** Vérifier que le client existe : présent dans `keys`, différent de `config.TGS_PRINCIPAL` et absent de `config.SERVICES`. Récupérer `k_client` et `k_tgs`.
- [ ] **3.** Générer `k_c_tgs = new_session_key()`.
- [ ] **4.** Calculer `exp = time.time() + config.TICKET_LIFETIME`.
- [ ] **5.** Construire `enc_part` (chiffré avec K_client, `aad` `"AS_REP"`).
- [ ] **6.** Construire le `tgt` (chiffré avec K_tgs, `aad` `"TGT"`).
- [ ] **7.** Renvoyer `{"type": "AS_REP", "enc_part": ..., "tgt": ...}` et afficher une ligne de log pour la démo.

La partie réseau (socket, threads, réception, envoi) est déjà faite par `serve()` dans `main()` : tu n'écris que `handle_request`, qui reçoit un `dict` et renvoie un `dict`.

## 5. Les vérifications et les erreurs

| Contrôle | Message à renvoyer |
| --- | --- |
| `type` différent de `"AS_REQ"` ou champ `client` absent | `error("requête invalide")` |
| client absent de `keys.json`, ou nom réservé (`krbtgt`, `mail`) | `error("client inconnu")` |

## 6. Les fonctions de `common/` à utiliser

```python
from common import config
from common.crypto import encrypt, new_session_key
from common.net import error

k_c_tgs = new_session_key()                                   # -> bytes (16 octets)
blob = encrypt(k_client, {"k_c_tgs": k_c_tgs.hex(), "exp": exp}, "AS_REP")   # -> str (hex)
return error("client inconnu")                                # -> {"type": "ERROR", "reason": ...}
```

- `encrypt(key: bytes, data: dict, aad: str) -> str`
- `new_session_key() -> bytes`
- `error(reason: str) -> dict`
- `config.TICKET_LIFETIME`, `config.TGS_PRINCIPAL`, `config.SERVICES`

Détails : [common/README.md](../common/README.md).

## 7. Comment lancer et tester ta partie seul

```bash
python scripts/init_keys.py --password motdepasse   # une fois
python -m as_server.as_server
```

**Test sans réseau** (le plus rapide) : appelle directement `handle_request`. Tu peux le mettre dans `tests/test_as_server.py` et lancer `pytest` :

```python
import time
from common.crypto import decrypt, derive_key, new_session_key
from as_server.as_server import handle_request

KEYS = {"alice": derive_key("motdepasse", "alice"),
        "krbtgt": new_session_key(), "mail": new_session_key()}

def test_as_rep():
    rep = handle_request({"type": "AS_REQ", "client": "alice"}, KEYS)
    assert rep["type"] == "AS_REP"
    part = decrypt(KEYS["alice"], rep["enc_part"], "AS_REP")
    tgt = decrypt(KEYS["krbtgt"], rep["tgt"], "TGT")
    assert tgt["client"] == "alice"
    assert tgt["k_c_tgs"] == part["k_c_tgs"]
    assert tgt["exp"] == part["exp"] > time.time()

def test_client_inconnu():
    assert handle_request({"type": "AS_REQ", "client": "bob"}, KEYS)["type"] == "ERROR"
```

**Test réseau** : serveur lancé dans un terminal, puis dans un autre (avec le même mot de passe que pour `init_keys.py`) :

```bash
python -c "
from common import config
from common.crypto import decrypt, derive_key
from common.net import send_request
rep = send_request(config.HOST, config.AS_PORT, {'type': 'AS_REQ', 'client': 'alice'})
print(rep)
print(decrypt(derive_key('motdepasse', 'alice'), rep['enc_part'], 'AS_REP'))
print(decrypt(config.load_keys()['krbtgt'], rep['tgt'], 'TGT'))
"
```

## 8. De qui tu dépends et qui dépend de toi

- Tu dépends de **`common/`** (déjà prêt) et de `keys.json` (`scripts/init_keys.py`).
- **Le client** (partie 1) a besoin de ton AS_REP pour son premier échange : vous intégrez ensemble en premier.
- **Le TGS** (partie 3) ouvre le TGT que tu fabriques : le contenu `{"client", "k_c_tgs", "exp"}` et l'`aad` `"TGT"` doivent être exactement ceux du contrat.

## 9. Pièges à éviter

- Mettre **la même** `k_c_tgs` et **le même** `exp` dans `enc_part` et dans le TGT.
- Mettre les clés en hexadécimal dans le JSON (`k_c_tgs.hex()`), pas des `bytes` (JSON ne sait pas les sérialiser).
- Utiliser l'heure du serveur (`time.time()`) pour `exp`, jamais une valeur envoyée par le client.
- Ne pas te tromper de clé : `enc_part` avec K_client, TGT avec K_tgs. Inverser les deux donnerait au client la possibilité de lire et modifier son TGT.
- Ne jamais réutiliser un nonce : ne pas appeler `AESGCM` toi-même, passer toujours par `encrypt`.
- Ne pas afficher les clés en entier dans les logs.
- Ne pas modifier `common/` sans prévenir la personne 5 et le groupe.

## 10. C'est terminé quand

- [ ] `python -m as_server.as_server` démarre et répond à un AS_REQ par un AS_REP ;
- [ ] `enc_part` s'ouvre avec `derive_key(mot_de_passe, "alice")` et pas avec un autre mot de passe ;
- [ ] le TGT s'ouvre avec `keys["krbtgt"]` et contient `client`, `k_c_tgs`, `exp` identiques à `enc_part` ;
- [ ] un client inconnu reçoit `ERROR "client inconnu"` ;
- [ ] le client (partie 1) obtient un TGT et l'affiche ;
- [ ] `pytest` passe.

## 11. Ta branche git

`feat/as-server`. Workflow : `git switch feat/as-server`, `git pull origin main` pour récupérer les nouveautés, commits réguliers, `pytest`, `git push`, puis PR vers `main`. Voir [CONTRIBUTING.md](../CONTRIBUTING.md).
