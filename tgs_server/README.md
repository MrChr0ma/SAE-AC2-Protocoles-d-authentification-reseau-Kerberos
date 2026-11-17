# Partie 3 : `tgs_server/`, le TGS (Ticket Granting Server)

Fichier à compléter : [`tgs_server.py`](tgs_server.py). Port : **8801**.

## 1. Ton rôle dans le protocole

Le TGS délivre les tickets de service. Le client lui présente son TGT (obtenu auprès de l'AS), un **authenticator** et le nom du service voulu. Tu ouvres le TGT avec K_tgs, ce qui te donne le nom du client et la clé de session K_c_tgs. Avec K_c_tgs, tu ouvres l'authenticator : seul le vrai client a pu le fabriquer, puisque K_c_tgs ne lui a été envoyée que chiffrée avec son mot de passe. Un TGT volé ne sert donc à rien sans K_c_tgs. Si tout est correct, tu génères K_c_service et tu renvoies un ticket pour le service.

```
2. TGS : obtenir un ticket de service
   Client déchiffre avec K_client et récupère K_c_tgs
   Client -> TGS : TGT + E(K_c_tgs, "alice" + timestamp) + "mail"
   TGS ouvre le TGT avec K_tgs, vérifie l'authenticator :
       même client, timestamp dans la fenêtre de 5 min, TGT non expiré, authenticator jamais vu (replay cache)
   TGS génère K_c_service
   TGS -> Client : E(K_c_tgs, K_c_service + expiration)
                   ticket = E(K_service, "alice" + K_c_service + expiration)
```

## 2. Ce que tu reçois et ce que tu envoies

Tu reçois un **TGS_REQ** :

```json
{
  "type": "TGS_REQ",
  "tgt": "0d77a4...51fc",
  "service": "mail",
  "auth": "c4e290...7b18"
}
```

```
tgt  = E(K_tgs,   "TGT",      {"client": "alice", "k_c_tgs": "<hex>", "exp": <float>})   (fabriqué par l'AS)
auth = E(K_c_tgs, "TGS_AUTH", {"client": "alice", "ts": <float>})                         (fabriqué par le client)
```

Tu renvoies un **TGS_REP** :

```json
{
  "type": "TGS_REP",
  "enc_part": "9a03ff...e611",
  "ticket": "71bd05...c2a9"
}
```

```
enc_part = E(K_c_tgs,   "TGS_REP", {"k_c_service": "<hex>", "exp": <float>})
ticket   = E(K_service, "TICKET",  {"client": "alice", "k_c_service": "<hex>", "exp": <float>})
```

Ou un **ERROR** : `{"type": "ERROR", "reason": "authenticator déjà utilisé (rejeu)"}`.

## 3. Les clés que tu utilises

| Clé | Où la trouver | `aad` |
| --- | --- | --- |
| K_tgs | `keys[config.TGS_PRINCIPAL]` = `keys["krbtgt"]` (`keys.json`) | `"TGT"` pour déchiffrer le TGT |
| K_c_tgs | dans le TGT déchiffré : `bytes.fromhex(tgt["k_c_tgs"])` | `"TGS_AUTH"` pour déchiffrer l'authenticator, `"TGS_REP"` pour chiffrer `enc_part` |
| K_service | `keys[service]` = `keys["mail"]` | `"TICKET"` pour chiffrer le ticket |
| K_c_service | tu la génères avec `new_session_key()` | — |

## 4. Étapes à coder

Elles correspondent aux `# TODO` de `tgs_server.py`, dans `handle_request(msg, keys)`.

- [ ] **1.** Vérifier `msg["type"] == "TGS_REQ"` et la présence de `tgt`, `auth`, `service`.
- [ ] **2.** Vérifier que le service demandé est dans `config.SERVICES` et dans `keys`.
- [ ] **3.** Ouvrir le TGT avec K_tgs (`aad` `"TGT"`) et récupérer `k_c_tgs`.
- [ ] **4.** Vérifier que le TGT n'a pas expiré (`time.time() < tgt["exp"]`).
- [ ] **5.** Ouvrir l'authenticator avec K_c_tgs (`aad` `"TGS_AUTH"`).
- [ ] **6.** Vérifier que `auth["client"] == tgt["client"]`.
- [ ] **7.** Vérifier que `abs(time.time() - auth["ts"]) <= config.CLOCK_SKEW`.
- [ ] **8.** Replay cache : purger les vieilles entrées, refuser si `(client, ts)` est déjà vu, sinon l'ajouter.
- [ ] **9.** Générer `k_c_service` et `exp = min(time.time() + config.TICKET_LIFETIME, tgt["exp"])`.
- [ ] **10.** Construire `enc_part` (K_c_tgs, `"TGS_REP"`) et `ticket` (K_service, `"TICKET"`).
- [ ] **11.** Renvoyer `{"type": "TGS_REP", "enc_part": ..., "ticket": ...}` et afficher une ligne de log.

## 5. Les vérifications et les erreurs

Fais les contrôles **dans cet ordre** et arrête-toi au premier qui échoue.

| Contrôle | Message à renvoyer |
| --- | --- |
| `type` incorrect ou champ manquant | `error("requête invalide")` |
| service absent de `config.SERVICES` ou de `keys` | `error("service inconnu")` |
| `decrypt` du TGT lève `DecryptError` | `error("TGT invalide")` |
| `time.time() >= tgt["exp"]` | `error("TGT expiré")` |
| `decrypt` de l'authenticator lève `DecryptError` | `error("authenticator invalide")` |
| `auth["client"] != tgt["client"]` | `error("client de l'authenticator différent de celui du TGT")` |
| `abs(time.time() - auth["ts"]) > config.CLOCK_SKEW` | `error("timestamp hors de la fenêtre autorisée")` |
| `(client, ts)` déjà dans le replay cache | `error("authenticator déjà utilisé (rejeu)")` |

**Le replay cache.** Sans lui, un attaquant qui capture un TGS_REQ peut le renvoyer tel quel pendant 5 minutes : le timestamp est encore valide. Le squelette fournit `replay_cache` (un `dict`) et `cache_lock` (un verrou, car chaque connexion tourne dans son propre thread). Principe :

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

On peut oublier un authenticator après `ts + CLOCK_SKEW` : passé ce délai, le contrôle du timestamp le refuse de toute façon.

## 6. Les fonctions de `common/` à utiliser

```python
from common import config
from common.crypto import DecryptError, decrypt, encrypt, new_session_key
from common.net import error

try:
    tgt = decrypt(keys[config.TGS_PRINCIPAL], msg["tgt"], "TGT")      # -> dict
except DecryptError:
    return error("TGT invalide")
k_c_tgs = bytes.fromhex(tgt["k_c_tgs"])
k_c_service = new_session_key()                                         # -> bytes
ticket = encrypt(keys["mail"], {"client": tgt["client"], "k_c_service": k_c_service.hex(), "exp": exp}, "TICKET")
```

- `decrypt(key: bytes, blob: str, aad: str) -> dict`, lève `DecryptError`
- `encrypt(key: bytes, data: dict, aad: str) -> str`
- `new_session_key() -> bytes`
- `error(reason: str) -> dict`
- `config.CLOCK_SKEW`, `config.TICKET_LIFETIME`, `config.TGS_PRINCIPAL`, `config.SERVICES`

Détails : [common/README.md](../common/README.md).

## 7. Comment lancer et tester ta partie seul

```bash
python scripts/init_keys.py --password motdepasse   # une fois
python -m tgs_server.tgs_server
```

Tu n'as pas besoin d'attendre l'AS : pour tester, **joue le rôle de l'AS** en fabriquant toi-même un TGT avec K_tgs. Exemple à mettre dans `tests/test_tgs_server.py` :

```python
import time
from common.crypto import decrypt, encrypt, new_session_key
from tgs_server.tgs_server import handle_request

KEYS = {"krbtgt": new_session_key(), "mail": new_session_key()}

def make_request(exp_offset=600, ts_offset=0, client_auth="alice"):
    k_c_tgs = new_session_key()
    tgt = encrypt(KEYS["krbtgt"], {"client": "alice", "k_c_tgs": k_c_tgs.hex(),
                                   "exp": time.time() + exp_offset}, "TGT")
    auth = encrypt(k_c_tgs, {"client": client_auth, "ts": time.time() + ts_offset}, "TGS_AUTH")
    return {"type": "TGS_REQ", "tgt": tgt, "service": "mail", "auth": auth}, k_c_tgs

def test_ticket_ok():
    req, k_c_tgs = make_request()
    rep = handle_request(req, KEYS)
    assert rep["type"] == "TGS_REP"
    part = decrypt(k_c_tgs, rep["enc_part"], "TGS_REP")
    ticket = decrypt(KEYS["mail"], rep["ticket"], "TICKET")
    assert ticket["client"] == "alice" and ticket["k_c_service"] == part["k_c_service"]

def test_rejeu_refuse():
    req, _ = make_request()
    assert handle_request(req, KEYS)["type"] == "TGS_REP"
    assert handle_request(req, KEYS)["type"] == "ERROR"

def test_tgt_expire():
    req, _ = make_request(exp_offset=-1)
    assert handle_request(req, KEYS)["type"] == "ERROR"

def test_timestamp_trop_vieux():
    req, _ = make_request(ts_offset=-301)
    assert handle_request(req, KEYS)["type"] == "ERROR"

def test_mauvais_client():
    req, _ = make_request(client_auth="mallory")
    assert handle_request(req, KEYS)["type"] == "ERROR"
```

Pour un test réseau, fais la même chose avec `config.load_keys()` et `send_request(config.HOST, config.TGS_PORT, req)` pendant que le serveur tourne. Quand l'AS est prêt, le test de bout en bout est : AS, puis TGS, puis le client.

## 8. De qui tu dépends et qui dépend de toi

- Tu dépends de **`common/`** (prêt), de `keys.json`, et du **format du TGT produit par l'AS** (partie 2) : `{"client", "k_c_tgs", "exp"}`, `aad` `"TGT"`.
- Tu dépends du **client** (partie 1) pour le format de l'authenticator : `{"client", "ts"}`, `aad` `"TGS_AUTH"`.
- **Le service** (partie 4) ouvre le ticket que tu fabriques : `{"client", "k_c_service", "exp"}`, `aad` `"TICKET"`.
- **Le client** ouvre ton `enc_part` pour récupérer K_c_service.

## 9. Pièges à éviter

- Comparer le nom du client de l'authenticator avec **celui du TGT**, pas avec un champ envoyé en clair.
- Utiliser **l'heure du serveur** (`time.time()`) pour toutes les vérifications, jamais une heure fournie par le client hors de l'authenticator.
- Bien convertir les clés : `bytes.fromhex(...)` après déchiffrement, `.hex()` avant chiffrement.
- Ne pas mettre une expiration du ticket plus tardive que celle du TGT (`min(...)`).
- Toujours manipuler le replay cache sous `cache_lock`.
- N'ajouter l'authenticator au cache qu'**après** avoir vérifié qu'il est valide (sinon un attaquant remplit ton cache avec des déchets).
- Ne jamais réutiliser un nonce : passer toujours par `encrypt`.
- Ne pas modifier `common/` sans prévenir.

## 10. C'est terminé quand

- [ ] un TGS_REQ valide reçoit un TGS_REP dont le ticket s'ouvre avec `keys["mail"]` ;
- [ ] un TGT expiré est refusé ;
- [ ] un TGT modifié ou chiffré avec une autre clé est refusé ;
- [ ] un authenticator d'un autre client, ou avec un timestamp à plus de 5 min, est refusé ;
- [ ] **un authenticator rejoué est refusé** ;
- [ ] le client obtient un ticket de service et l'affiche ;
- [ ] `pytest` passe.

## 11. Ta branche git

`feat/tgs-server`. Workflow : `git switch feat/tgs-server`, `git pull origin main`, commits réguliers, `pytest`, `git push`, puis PR vers `main`. Voir [CONTRIBUTING.md](../CONTRIBUTING.md).
