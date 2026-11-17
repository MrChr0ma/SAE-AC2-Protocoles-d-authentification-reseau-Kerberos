# Partie 4 : `service/`, le service « mail »

Fichier à compléter : [`service.py`](service.py). Port : **8802**.

## 1. Ton rôle dans le protocole

Le service est la ressource à laquelle Alice veut accéder (ici un serveur de mail). Il ne connaît que sa propre clé K_service et **ne contacte jamais le KDC**. Le client lui présente le ticket fabriqué par le TGS et un authenticator. Tu ouvres le ticket avec K_service : tu y trouves le nom du client et la clé de session K_c_service. Avec elle, tu ouvres et vérifies l'authenticator. Ensuite tu prouves ton identité au client en lui renvoyant `ts + 1` chiffré avec K_c_service : seul le vrai service a pu ouvrir le ticket et connaître cette clé. C'est l'**authentification mutuelle**.

```
3. Service
   Client -> Service : ticket + E(K_c_service, "alice" + timestamp)
   Service ouvre le ticket avec K_service, vérifie l'authenticator (mêmes règles), sans contacter le KDC
   Service -> Client : E(K_c_service, timestamp + 1)
   Client vérifie timestamp + 1 (authentification mutuelle)
```

## 2. Ce que tu reçois et ce que tu envoies

Tu reçois un **AP_REQ** :

```json
{
  "type": "AP_REQ",
  "ticket": "71bd05...c2a9",
  "auth": "e6f412...0d3b"
}
```

```
ticket = E(K_service,   "TICKET",  {"client": "alice", "k_c_service": "<hex>", "exp": <float>})   (fabriqué par le TGS)
auth   = E(K_c_service, "AP_AUTH", {"client": "alice", "ts": <float>})                            (fabriqué par le client)
```

Tu renvoies un **AP_REP** :

```json
{"type": "AP_REP", "enc_part": "28c7aa...91f0"}
```

```
enc_part = E(K_c_service, "AP_REP", {"ts": <ts de l'authenticator + 1>})
```

Ou un **ERROR** : `{"type": "ERROR", "reason": "ticket expiré"}`.

## 3. Les clés que tu utilises

| Clé | Où la trouver | `aad` |
| --- | --- | --- |
| K_service | `keys["mail"]` dans `keys.json`, passée à `handle_request` par `main()` | `"TICKET"` pour déchiffrer le ticket |
| K_c_service | dans le ticket déchiffré : `bytes.fromhex(ticket["k_c_service"])` | `"AP_AUTH"` pour déchiffrer l'authenticator, `"AP_REP"` pour chiffrer la réponse |

## 4. Étapes à coder

Elles correspondent aux `# TODO` de `service.py`, dans `handle_request(msg, k_service)`.

- [ ] **1.** Vérifier `msg["type"] == "AP_REQ"` et la présence de `ticket` et `auth`.
- [ ] **2.** Ouvrir le ticket avec K_service (`aad` `"TICKET"`) et récupérer `k_c_service`.
- [ ] **3.** Vérifier que le ticket n'a pas expiré (`time.time() < ticket["exp"]`).
- [ ] **4.** Ouvrir l'authenticator avec K_c_service (`aad` `"AP_AUTH"`).
- [ ] **5.** Vérifier que `auth["client"] == ticket["client"]`.
- [ ] **6.** Vérifier que `abs(time.time() - auth["ts"]) <= config.CLOCK_SKEW`.
- [ ] **7.** Replay cache : purger, refuser si `(client, ts)` déjà vu, sinon ajouter.
- [ ] **8.** Construire `enc_part = encrypt(k_c_service, {"ts": auth["ts"] + 1}, "AP_REP")`.
- [ ] **9.** Afficher « accès accordé à alice » dans le log et renvoyer `{"type": "AP_REP", "enc_part": ...}`.

## 5. Les vérifications et les erreurs

Dans cet ordre, en t'arrêtant au premier échec :

| Contrôle | Message à renvoyer |
| --- | --- |
| `type` incorrect ou champ manquant | `error("requête invalide")` |
| `decrypt` du ticket lève `DecryptError` | `error("ticket invalide")` |
| `time.time() >= ticket["exp"]` | `error("ticket expiré")` |
| `decrypt` de l'authenticator lève `DecryptError` | `error("authenticator invalide")` |
| `auth["client"] != ticket["client"]` | `error("client de l'authenticator différent de celui du ticket")` |
| `abs(time.time() - auth["ts"]) > config.CLOCK_SKEW` | `error("timestamp hors de la fenêtre autorisée")` |
| `(client, ts)` déjà dans le replay cache | `error("authenticator déjà utilisé (rejeu)")` |

**Le replay cache** : sans lui, un attaquant qui capture un AP_REQ le renvoie tel quel et se fait passer pour Alice pendant 5 minutes. Le squelette fournit `replay_cache` et `cache_lock` (chaque connexion est dans un thread). Principe :

```python
now = time.time()
key = (auth["client"], auth["ts"])
with cache_lock:
    for k, forget_at in list(replay_cache.items()):   # purge
        if forget_at < now:
            del replay_cache[k]
    if key in replay_cache:
        return error("authenticator déjà utilisé (rejeu)")
    replay_cache[key] = auth["ts"] + config.CLOCK_SKEW
```

## 6. Les fonctions de `common/` à utiliser

```python
from common import config
from common.crypto import DecryptError, decrypt, encrypt
from common.net import error

try:
    ticket = decrypt(k_service, msg["ticket"], "TICKET")       # -> dict
except DecryptError:
    return error("ticket invalide")
k_c_service = bytes.fromhex(ticket["k_c_service"])
enc_part = encrypt(k_c_service, {"ts": auth["ts"] + 1}, "AP_REP")   # -> str
```

- `decrypt(key: bytes, blob: str, aad: str) -> dict`, lève `DecryptError`
- `encrypt(key: bytes, data: dict, aad: str) -> str`
- `error(reason: str) -> dict`
- `config.CLOCK_SKEW`

Détails : [common/README.md](../common/README.md).

## 7. Comment lancer et tester ta partie seul

```bash
python scripts/init_keys.py --password motdepasse   # une fois
python -m service.service
```

Pas besoin d'attendre le TGS : **joue le rôle du TGS** en fabriquant toi-même un ticket avec K_service. Exemple à mettre dans `tests/test_service.py` :

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

Pour un test réseau, même principe avec `config.load_keys()["mail"]` et `send_request(config.HOST, config.SERVICE_PORT, req)` pendant que le serveur tourne.

## 8. De qui tu dépends et qui dépend de toi

- Tu dépends de **`common/`** (prêt), de `keys.json`, et du **format du ticket produit par le TGS** (partie 3) : `{"client", "k_c_service", "exp"}`, `aad` `"TICKET"`.
- Tu dépends du **client** (partie 1) pour l'authenticator : `{"client", "ts"}`, `aad` `"AP_AUTH"`.
- **Le client** vérifie ta réponse : `{"ts": ts + 1}`, `aad` `"AP_REP"`. Tu es le dernier maillon de l'intégration.

## 9. Pièges à éviter

- Renvoyer `ts + 1` avec **le `ts` lu dans l'authenticator**, pas `time.time() + 1`.
- Comparer le client de l'authenticator avec **celui du ticket**.
- Utiliser l'heure du serveur pour toutes les vérifications.
- Ne jamais contacter le KDC : tout ce dont tu as besoin est dans le ticket.
- Toujours manipuler le replay cache sous `cache_lock`, et n'y ajouter que des authenticators valides.
- Ne jamais réutiliser un nonce : passer par `encrypt`.
- Ne pas modifier `common/` sans prévenir.

## 10. C'est terminé quand

- [ ] un AP_REQ valide reçoit un AP_REP qui contient `ts + 1` ;
- [ ] un ticket expiré, modifié ou chiffré pour un autre service est refusé ;
- [ ] un authenticator d'un autre client ou trop ancien est refusé ;
- [ ] **un authenticator rejoué est refusé** ;
- [ ] le log affiche « accès accordé à alice » ;
- [ ] le client affiche « authentification mutuelle réussie » ;
- [ ] `pytest` passe.

## 11. Ta branche git

`feat/service`. Workflow : `git switch feat/service`, `git pull origin main`, commits réguliers, `pytest`, `git push`, puis PR vers `main`. Voir [CONTRIBUTING.md](../CONTRIBUTING.md).
