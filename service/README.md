# `service/` : le service « mail »

État : en cours, pas encore fusionné. Auteur : Enzo. Fichier : [`service.py`](service.py). Port : 8802.

Sur `main`, `service.py` est encore le squelette du 17/11 : `handle_request` répond toujours `ERROR "non implémenté"`. Les étapes ci-dessous correspondent aux `# TODO` de ce squelette.

## Rôle

Le service est la ressource à laquelle Alice veut accéder. Il ne connaît que sa propre clé K_service et ne contacte jamais le KDC. Le client lui présente le ticket fabriqué par le TGS et un authenticator. Le service ouvre le ticket avec K_service : il y trouve le nom du client et K_c_service. Avec elle, il ouvre et vérifie l'authenticator. Il prouve ensuite son identité au client en renvoyant `ts + 1` chiffré avec K_c_service : seul le vrai service a pu ouvrir le ticket. C'est l'authentification mutuelle.

```
Client -> Service : ticket + E(K_c_service, "alice" + timestamp)
Service ouvre le ticket avec K_service, vérifie l'authenticator, sans contacter le KDC
Service -> Client : E(K_c_service, timestamp + 1)
Client vérifie timestamp + 1
```

## Messages

Reçu : `{"type": "AP_REQ", "ticket": "...", "auth": "..."}` avec

```
ticket = E(K_service,   "TICKET",  {"client": "alice", "k_c_service": "<hex>", "exp": <float>})   (fabriqué par le TGS)
auth   = E(K_c_service, "AP_AUTH", {"client": "alice", "ts": <float>})                            (fabriqué par le client)
```

Renvoyé : `{"type": "AP_REP", "enc_part": "..."}` avec

```
enc_part = E(K_c_service, "AP_REP", {"ts": <ts de l'authenticator + 1>})
```

Ou un `ERROR`, par exemple `{"type": "ERROR", "reason": "ticket expiré"}`.

| Clé | Où | `aad` |
| --- | --- | --- |
| K_service | `config.load_keys()["mail"]`, lue par `main()` et passée à `handle_request` | `"TICKET"` (déchiffrer) |
| K_c_service | dans le ticket : `bytes.fromhex(ticket["k_c_service"])` | `"AP_AUTH"` (déchiffrer), `"AP_REP"` (chiffrer) |

Garde la signature `handle_request(msg, k_service)` : `main()` du squelette et les tests d'exemple l'utilisent. `config` n'a pas de constante pour K_service, la clé vient uniquement de `keys.json`.

## Étapes à coder

Dans `handle_request(msg, k_service)` :

- [ ] 1. Vérifier `msg["type"] == "AP_REQ"` et la présence de `ticket` et `auth`.
- [ ] 2. Ouvrir le ticket avec K_service (`"TICKET"`) et récupérer `k_c_service`.
- [ ] 3. Vérifier que le ticket n'a pas expiré (`time.time() < ticket["exp"]`).
- [ ] 4. Ouvrir l'authenticator avec K_c_service (`"AP_AUTH"`).
- [ ] 5. Vérifier que `auth["client"] == ticket["client"]`.
- [ ] 6. Vérifier que `abs(time.time() - auth["ts"]) <= config.CLOCK_SKEW`.
- [ ] 7. Replay cache : purger, refuser si `(client, ts)` déjà vu, sinon ajouter.
- [ ] 8. Construire `enc_part = encrypt(k_c_service, {"ts": auth["ts"] + 1}, "AP_REP")`.
- [ ] 9. Écrire « accès accordé à alice » avec `log(NAME, ...)` et renvoyer `{"type": "AP_REP", "enc_part": ...}`.

## Contrôles et erreurs

Dans cet ordre, arrêt au premier échec :

| Contrôle | Réponse |
| --- | --- |
| `type` incorrect ou champ manquant | `error("requête invalide")` |
| ticket indéchiffrable, ou `k_c_service`, `exp` mal formés | `error("ticket invalide")` |
| `time.time() >= ticket["exp"]` | `error("ticket expiré")` |
| authenticator indéchiffrable, ou `ts` qui n'est pas un nombre fini | `error("authenticator invalide")` |
| `auth["client"] != ticket["client"]` | `error("client de l'authenticator différent de celui du ticket")` |
| `abs(time.time() - auth["ts"]) > config.CLOCK_SKEW` | `error("timestamp hors de la fenêtre autorisée")` |
| `(client, ts)` déjà dans le replay cache | `error("authenticator déjà utilisé (rejeu)")` |

Le TGS fait déjà ces contrôles de format avec `est_nombre` et `lire_cle` ([tgs_server.py](../tgs_server/tgs_server.py)) : on peut reprendre la même idée.

## Le replay cache

Sans lui, un attaquant qui capture un AP_REQ le renvoie tel quel et se fait passer pour Alice pendant 5 minutes. Le squelette fournit `replay_cache` et `cache_lock`. Même principe que `deja_vu` dans le TGS :

```python
maintenant = time.time()
cle = (auth["client"], auth["ts"])
with cache_lock:
    for k, oubli in list(replay_cache.items()):
        if oubli < maintenant:
            del replay_cache[k]
    if cle in replay_cache:
        return error("authenticator déjà utilisé (rejeu)")
    replay_cache[cle] = auth["ts"] + 2 * config.CLOCK_SKEW
```

Garder l'entrée jusqu'à `ts + 2 * CLOCK_SKEW`, comme le TGS, et pas `ts + CLOCK_SKEW` comme l'indique encore le commentaire du TODO 7 : `maintenant` est lu avant le verrou, et deux requêtes qui se croisent pourraient sinon voir l'entrée purgée trop tôt. N'ajouter l'entrée qu'après tous les autres contrôles.

## Lancer et tester

```bash
python scripts/init_keys.py --password motdepasse   # une fois
python -m service.service
```

`tests/test_service.py` n'existe pas encore. Exemple pour le commencer, en jouant le rôle du TGS :

```python
import time
from common.crypto import decrypt, encrypt, new_session_key
from service.service import handle_request

K_SERVICE = new_session_key()

def make_request(exp_offset=600, ts_offset=0, client_auth="alice"):
    k_c_service = new_session_key()
    ticket = encrypt(K_SERVICE, {"client": "alice", "k_c_service": k_c_service.hex(),
                                 "exp": time.time() + exp_offset}, "TICKET")
    ts = time.time() + ts_offset
    auth = encrypt(k_c_service, {"client": client_auth, "ts": ts}, "AP_AUTH")
    return {"type": "AP_REQ", "ticket": ticket, "auth": auth}, k_c_service, ts

def test_acces_ok_et_ts_plus_un():
    req, k, ts = make_request()
    rep = handle_request(req, K_SERVICE)
    assert rep["type"] == "AP_REP"
    assert decrypt(k, rep["enc_part"], "AP_REP")["ts"] == ts + 1

def test_rejeu_refuse():
    req, _, _ = make_request()
    assert handle_request(req, K_SERVICE)["type"] == "AP_REP"
    assert handle_request(req, K_SERVICE)["type"] == "ERROR"

def test_ticket_expire():
    req, _, _ = make_request(exp_offset=-1)
    assert handle_request(req, K_SERVICE)["type"] == "ERROR"

def test_ticket_d_un_autre_service():
    req, _, _ = make_request()
    assert handle_request(req, new_session_key())["type"] == "ERROR"
```

Comme pour le TGS, ajouter une fixture qui vide `replay_cache` avant chaque test (voir `tests/test_tgs_server.py`).

## Points d'attention

- Vérifier que le programme s'importe et se lance : `python -c "import service.service"` puis `python -m service.service`. La fonction réseau de `common.net` s'appelle `serve`.
- Si une fonction ou une constante est renommée (`handle_request`, `NAME`, `SERVICE_NAME`), mettre `main()` à jour en même temps.
- Renvoyer `ts + 1` avec le `ts` lu dans l'authenticator, pas `time.time() + 1`.
- Comparer le client de l'authenticator avec celui du ticket.
- Utiliser l'heure du serveur pour toutes les vérifications ; ne jamais contacter le KDC.
- Manipuler le replay cache uniquement sous `cache_lock`.
- Passer toujours par `encrypt`, jamais par `AESGCM`.
- Une docstring par fonction, pas de commentaires `#` une fois le code écrit ([CONTRIBUTING.md](../CONTRIBUTING.md#style)).

## C'est terminé quand

- [ ] un AP_REQ valide reçoit un AP_REP qui contient `ts + 1` ;
- [ ] un ticket expiré, modifié ou chiffré pour un autre service est refusé ;
- [ ] un authenticator d'un autre client ou trop ancien est refusé ;
- [ ] un authenticator rejoué est refusé ;
- [ ] le log affiche « accès accordé à alice » ;
- [ ] le client affiche « authentification mutuelle réussie » ;
- [ ] `pytest` passe, avec `tests/test_service.py`.
