# `tgs_server/` : le TGS (Ticket Granting Server)

État : fait. Vérifications fusionnées le 25/11 (PR n°4), terminé le 28/11 (PR n°6). Auteur : Hector. Fichier : [`tgs_server.py`](tgs_server.py). Port : 8801.

## Rôle

Le TGS délivre les tickets de service. Le client lui présente son TGT, un authenticator et le nom du service voulu. Le TGS ouvre le TGT avec K_tgs, ce qui lui donne le nom du client et K_c_tgs. Avec K_c_tgs, il ouvre l'authenticator : seul le vrai client a pu le fabriquer, puisque K_c_tgs ne lui a été envoyée que chiffrée avec K_client. Un TGT volé ne sert donc à rien sans K_c_tgs. Si tout est correct, le TGS tire K_c_service et renvoie un ticket pour le service.

```
Client -> TGS : TGT + E(K_c_tgs, "alice" + timestamp) + "mail"
TGS ouvre le TGT avec K_tgs, vérifie l'authenticator :
    même client, timestamp dans la fenêtre de 5 min, TGT non expiré, authenticator jamais vu
TGS tire K_c_service
TGS -> Client : E(K_c_tgs, K_c_service + expiration)
                ticket = E(K_service, "alice" + K_c_service + expiration)
```

## Messages

Reçu : `{"type": "TGS_REQ", "tgt": "...", "service": "mail", "auth": "..."}` avec

```
tgt  = E(K_tgs,   "TGT",      {"client": "alice", "k_c_tgs": "<hex>", "exp": <float>})   (fabriqué par l'AS)
auth = E(K_c_tgs, "TGS_AUTH", {"client": "alice", "ts": <float>})                         (fabriqué par le client)
```

Renvoyé : `{"type": "TGS_REP", "enc_part": "...", "ticket": "..."}` avec

```
enc_part = E(K_c_tgs,   "TGS_REP", {"k_c_service": "<hex>", "exp": <float>})
ticket   = E(K_service, "TICKET",  {"client": "alice", "k_c_service": "<hex>", "exp": <float>})
```

`exp = min(maintenant + TICKET_LIFETIME, exp du TGT)` : un ticket n'expire jamais après le TGT.

| Clé | Où | `aad` |
| --- | --- | --- |
| K_tgs | `keys["krbtgt"]` (`keys.json`) | `"TGT"` (déchiffrer) |
| K_c_tgs | dans le TGT, lue par `lire_cle` (16 octets) | `"TGS_AUTH"` (déchiffrer), `"TGS_REP"` (chiffrer) |
| K_service | `keys[service]` = `keys["mail"]` | `"TICKET"` (chiffrer) |
| K_c_service | `new_session_key()` | — |

## Ce que fait `handle_request(msg, keys)`

- [x] 1. Vérifie `type == "TGS_REQ"` et que `tgt`, `auth`, `service` sont des chaînes.
- [x] 2. Vérifie que le service est dans `config.SERVICES` et dans `keys`.
- [x] 3. Ouvre le TGT avec K_tgs (`"TGT"`), contrôle `client`, `k_c_tgs` et `exp`.
- [x] 4. Vérifie que le TGT n'a pas expiré.
- [x] 5. Ouvre l'authenticator avec K_c_tgs (`"TGS_AUTH"`).
- [x] 6. Vérifie que `auth["client"] == tgt["client"]`.
- [x] 7. Vérifie que `abs(maintenant - auth["ts"]) <= config.CLOCK_SKEW`.
- [x] 8. Replay cache : purge, refus si `(client, ts)` est déjà vu, sinon ajout (`deja_vu`).
- [x] 9. Tire `k_c_service` et calcule `exp`.
- [x] 10. Construit `enc_part` et `ticket`.
- [x] 11. Renvoie le TGS_REP et écrit une ligne de log (`log("TGS", ...)`).

## Contrôles et erreurs

Dans cet ordre, arrêt au premier qui échoue :

| Contrôle | Réponse |
| --- | --- |
| `type` incorrect, ou `tgt`, `auth`, `service` absent ou pas une chaîne | `error("requête invalide")` |
| service absent de `config.SERVICES` ou de `keys` | `error("service inconnu")` |
| TGT indéchiffrable, ou `client`, `k_c_tgs`, `exp` mal formés | `error("TGT invalide")` |
| `maintenant >= tgt["exp"]` | `error("TGT expiré")` |
| authenticator indéchiffrable, ou `ts` qui n'est pas un nombre fini | `error("authenticator invalide")` |
| `auth["client"] != tgt["client"]` | `error("client de l'authenticator différent de celui du TGT")` |
| `abs(maintenant - auth["ts"]) > config.CLOCK_SKEW` | `error("timestamp hors de la fenêtre autorisée")` |
| `(client, ts)` déjà dans le replay cache | `error("authenticator déjà utilisé (rejeu)")` |

`est_nombre` refuse les booléens, `NaN`, l'infini et les entiers trop grands pour un `float`. L'heure du serveur (`maintenant`) est lue une seule fois, juste après l'ouverture du TGT, et sert à tous les contrôles suivants.

## Le replay cache

Sans lui, un attaquant qui capture un TGS_REQ peut le renvoyer tel quel pendant 5 minutes. `replay_cache` est un `dict` `(client, ts) -> heure d'oubli`, protégé par `cache_lock` car chaque connexion tourne dans son propre thread.

```python
def deja_vu(client, ts, maintenant):
    with cache_lock:
        for cle, oubli in list(replay_cache.items()):
            if oubli < maintenant:
                del replay_cache[cle]
        if (client, ts) in replay_cache:
            return True
        replay_cache[(client, ts)] = ts + 2 * config.CLOCK_SKEW
        return False
```

Une entrée est gardée jusqu'à `ts + 2 * CLOCK_SKEW` et pas seulement `ts + CLOCK_SKEW` : `maintenant` est lu avant de prendre le verrou, et deux requêtes qui se croisent pourraient sinon voir l'entrée purgée trop tôt. L'entrée n'est ajoutée qu'après tous les autres contrôles.

Limites : le cache est en mémoire (perdu au redémarrage) et la purge parcourt tout le cache à chaque requête, en O(n) sous verrou. Voir [docs/ANALYSE.md](../docs/ANALYSE.md).

## Lancer et tester

```bash
python scripts/init_keys.py --password motdepasse   # une fois
python -m tgs_server.tgs_server
pytest tests/test_tgs_server.py
```

Les tests jouent le rôle de l'AS en fabriquant eux-mêmes un TGT avec K_tgs, et une fixture vide le replay cache avant chaque test. 22 tests : ticket délivré, `exp` du ticket ≤ `exp` du TGT, rejeu refusé, deux requêtes distinctes acceptées, requêtes invalides, services inconnus, TGT d'une autre clé, TGT modifié, TGT expiré, authenticator d'une autre clé ou d'un autre client, timestamp hors fenêtre, `ts` non fini (NaN, inf, 10^400, True), durée de rétention du cache.

## Points d'attention

- Le client de l'authenticator est comparé à celui du TGT, jamais à un champ en clair.
- Toutes les vérifications utilisent l'heure du serveur.
- Le TGS ne vérifie pas que le client du TGT existe dans `keys.json` : il fait confiance à tout TGT chiffré avec K_tgs. Avec K_tgs, on peut donc forger un TGT pour n'importe quel nom (voir l'analyse, mode weak8).

## État

- [x] un TGS_REQ valide reçoit un TGS_REP dont le ticket s'ouvre avec `keys["mail"]` ;
- [x] un TGT expiré est refusé ;
- [x] un TGT modifié ou chiffré avec une autre clé est refusé ;
- [x] un authenticator d'un autre client, ou avec un timestamp à plus de 5 min, est refusé ;
- [x] un authenticator rejoué est refusé ;
- [x] le client obtient un ticket de service et l'affiche ;
- [x] `pytest` passe.
