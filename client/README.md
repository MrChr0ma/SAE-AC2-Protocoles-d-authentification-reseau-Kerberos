# Partie 1 : `client/`, le client (Alice)

Fichier à compléter : [`client.py`](client.py).

## 1. Ton rôle dans le protocole

Le client est le seul programme qui connaît le mot de passe d'Alice. Il en dérive K_client, puis enchaîne les trois échanges : AS (obtenir le TGT), TGS (obtenir un ticket pour le service « mail »), service (s'authentifier et vérifier que le service est le bon). **Le mot de passe ne part jamais sur le réseau.** Le client ne peut pas lire le TGT ni le ticket : il les transporte tels quels. C'est aussi le programme qu'on montre à la soutenance : il doit afficher clairement chaque étape.

```
1. AS : obtenir le TGT
   Client -> AS : "alice"
   AS -> Client : E(K_client, K_c_tgs + expiration)  +  TGT (opaque)

2. TGS : obtenir un ticket de service
   Client déchiffre avec K_client et récupère K_c_tgs
   Client -> TGS : TGT + E(K_c_tgs, "alice" + timestamp) + "mail"
   TGS -> Client : E(K_c_tgs, K_c_service + expiration)  +  ticket (opaque)

3. Service
   Client -> Service : ticket + E(K_c_service, "alice" + timestamp)
   Service -> Client : E(K_c_service, timestamp + 1)
   Client vérifie timestamp + 1 (authentification mutuelle)
```

## 2. Ce que tu reçois et ce que tu envoies

| Tu envoies | À | Tu reçois |
| --- | --- | --- |
| `{"type": "AS_REQ", "client": "alice"}` | AS, port 8800 | `{"type": "AS_REP", "enc_part": "5be1...e93a", "tgt": "0d77...51fc"}` |
| `{"type": "TGS_REQ", "tgt": "0d77...51fc", "service": "mail", "auth": "c4e2...7b18"}` | TGS, port 8801 | `{"type": "TGS_REP", "enc_part": "9a03...e611", "ticket": "71bd...c2a9"}` |
| `{"type": "AP_REQ", "ticket": "71bd...c2a9", "auth": "e6f4...0d3b"}` | Service, port 8802 | `{"type": "AP_REP", "enc_part": "28c7...91f0"}` |

Contenu des parties chiffrées :

```
AS_REP.enc_part  = E(K_client,    "AS_REP",   {"k_c_tgs": "<hex>", "exp": <float>})     -> tu l'ouvres
TGS_REQ.auth     = E(K_c_tgs,     "TGS_AUTH", {"client": "alice", "ts": <float>})       -> tu le fabriques
TGS_REP.enc_part = E(K_c_tgs,     "TGS_REP",  {"k_c_service": "<hex>", "exp": <float>}) -> tu l'ouvres
AP_REQ.auth      = E(K_c_service, "AP_AUTH",  {"client": "alice", "ts": <float>})       -> tu le fabriques
AP_REP.enc_part  = E(K_c_service, "AP_REP",   {"ts": <ts + 1>})                          -> tu l'ouvres
```

À chaque échange, le serveur peut aussi répondre `{"type": "ERROR", "reason": "..."}` : affiche la raison et arrête-toi.

## 3. Les clés que tu utilises

| Clé | Où la trouver | `aad` |
| --- | --- | --- |
| K_client | `derive_key(password, user)` : **tu ne lis pas `keys.json`**, tu dérives la clé du mot de passe tapé | `"AS_REP"` pour ouvrir `enc_part` de l'AS |
| K_c_tgs | dans `enc_part` de l'AS : `bytes.fromhex(part["k_c_tgs"])` | `"TGS_AUTH"` pour chiffrer l'authenticator, `"TGS_REP"` pour ouvrir `enc_part` du TGS |
| K_c_service | dans `enc_part` du TGS : `bytes.fromhex(part["k_c_service"])` | `"AP_AUTH"` pour chiffrer l'authenticator, `"AP_REP"` pour ouvrir la réponse du service |

## 4. Étapes à coder

Elles correspondent aux `# TODO` de la fonction `run(user, password, service)` de `client.py`.

**Échange 1 : AS**
- [ ] **1.** Dériver `k_client = derive_key(password, user)`.
- [ ] **2.** Envoyer l'AS_REQ à `(config.HOST, config.AS_PORT)` ; gérer une réponse `ERROR`.
- [ ] **3.** Ouvrir `enc_part` avec K_client (`"AS_REP"`) ; récupérer `k_c_tgs` ; garder le TGT ; afficher.

**Échange 2 : TGS**
- [ ] **4.** Fabriquer l'authenticator `{"client": user, "ts": time.time()}` chiffré avec K_c_tgs (`"TGS_AUTH"`).
- [ ] **5.** Envoyer le TGS_REQ à `(config.HOST, config.TGS_PORT)` ; gérer `ERROR`.
- [ ] **6.** Ouvrir `enc_part` avec K_c_tgs (`"TGS_REP"`) ; récupérer `k_c_service` ; garder le ticket ; afficher.

**Échange 3 : service**
- [ ] **7.** Fabriquer l'authenticator avec K_c_service (`"AP_AUTH"`) en **gardant `ts`** dans une variable.
- [ ] **8.** Envoyer l'AP_REQ à `(config.HOST, config.SERVICE_PORT)` ; gérer `ERROR`.
- [ ] **9.** Ouvrir la réponse avec K_c_service (`"AP_REP"`) et vérifier qu'elle contient `ts + 1`.
- [ ] **10.** Afficher « authentification mutuelle réussie » et renvoyer `True`.

Pour la démo, affiche à chaque étape ce qui est envoyé et reçu, avec les fonctions fournies `show(étape, texte)` et `short(hex)` (qui raccourcit les longues valeurs) : par exemple « TGT reçu : 0d77a4...51fc, expire à 14:32:10 ». N'affiche jamais le mot de passe.

## 5. Les vérifications et les erreurs

Le client ne renvoie pas de message `ERROR` : il affiche le problème et s'arrête (`return False`, code de sortie 1).

| Situation | Ce que tu affiches |
| --- | --- |
| serveur non lancé (`ConnectionRefusedError`) | « impossible de joindre l'AS / le TGS / le service » |
| réponse de type `"ERROR"` | la raison donnée par le serveur |
| `decrypt` de l'`enc_part` de l'AS lève `DecryptError` | « mot de passe incorrect » |
| `decrypt` de l'`enc_part` du TGS lève `DecryptError` | « réponse du TGS invalide » |
| `decrypt` de l'AP_REP lève `DecryptError`, ou `ts` reçu ≠ `ts + 1` | « service non authentifié : authentification mutuelle échouée » |

## 6. Les fonctions de `common/` à utiliser

```python
from common import config
from common.crypto import DecryptError, decrypt, derive_key, encrypt
from common.net import send_request

k_client = derive_key("motdepasse", "alice")                                          # -> bytes
rep = send_request(config.HOST, config.AS_PORT, {"type": "AS_REQ", "client": "alice"})  # -> dict
part = decrypt(k_client, rep["enc_part"], "AS_REP")                                   # -> dict, ou DecryptError
k_c_tgs = bytes.fromhex(part["k_c_tgs"])
auth = encrypt(k_c_tgs, {"client": "alice", "ts": time.time()}, "TGS_AUTH")             # -> str
```

- `derive_key(password: str, salt: str) -> bytes`
- `encrypt(key: bytes, data: dict, aad: str) -> str`
- `decrypt(key: bytes, blob: str, aad: str) -> dict`, lève `DecryptError`
- `send_request(host: str, port: int, msg: dict) -> dict`, lève `ConnectionRefusedError` si le serveur ne tourne pas
- `config.HOST`, `config.AS_PORT`, `config.TGS_PORT`, `config.SERVICE_PORT`

Détails : [common/README.md](../common/README.md).

## 7. Comment lancer et tester ta partie seul

```bash
python scripts/init_keys.py --password motdepasse   # une fois, le même mot de passe ensuite
python -m client.client --password motdepasse
python -m client.client                             # le mot de passe est alors demandé au clavier
```

Tant que les serveurs ne sont pas codés, ils répondent `ERROR "non implémenté"` : lance-les (`python -m as_server.as_server`, etc.) et vérifie déjà que ton client affiche proprement cette erreur et le cas « serveur non lancé ».

**Voir ce que ton client envoie** : remplace un serveur par un « espion » qui affiche le message reçu. Exemple pour l'AS (arrête d'abord le vrai AS) :

```bash
python -c "
from common import config
from common.net import serve, error
def espion(msg):
    print('REÇU :', msg)
    return error('espion')
serve(config.HOST, config.AS_PORT, espion, 'ESPION')
"
```

Même chose avec `config.TGS_PORT` ou `config.SERVICE_PORT`. Tu peux aussi vérifier tes authenticators hors réseau : `decrypt(k_c_tgs, auth, "TGS_AUTH")` doit redonner `{"client": "alice", "ts": ...}`.

Dès que l'AS est prêt, intégrez ensemble l'échange 1 (c'est la première étape d'intégration du groupe), puis le TGS, puis le service.

## 8. De qui tu dépends et qui dépend de toi

- Tu dépends des **trois serveurs** : AS (partie 2) pour l'échange 1, TGS (partie 3) pour l'échange 2, service (partie 4) pour l'échange 3. Tu peux coder les trois échanges tout de suite, mais tu ne les testes de bout en bout qu'au fur et à mesure de l'intégration.
- Le **TGS** et le **service** dépendent de tes authenticators : `{"client", "ts"}` avec les bons `aad`.
- Ton programme est celui de la **démo de soutenance** : soigne l'affichage.

## 9. Pièges à éviter

- Le sel de `derive_key` est le **nom du client** (`"alice"`) : `derive_key(password, user)`, pas l'inverse.
- Garder le TGT et le ticket **tels quels** (chaînes hex) : tu ne peux pas les ouvrir, ne les modifie pas.
- Un authenticator **neuf** pour chaque requête (TGS puis service), avec un nouveau `time.time()` : le serveur refuse un authenticator déjà vu.
- Garder dans une variable le `ts` envoyé au service pour comparer avec la réponse (`== ts + 1`). Les nombres à virgule passent sans perte dans le JSON de Python, la comparaison exacte fonctionne.
- Convertir les clés : `bytes.fromhex(...)` après déchiffrement.
- Ne pas confondre les `aad` : `"TGS_AUTH"` pour l'authenticator du TGS, `"AP_AUTH"` pour celui du service.
- Ne jamais afficher ni envoyer le mot de passe ; ne jamais appeler `AESGCM` directement (risque de réutiliser un nonce).
- Ne pas modifier `common/` sans prévenir.

## 10. C'est terminé quand

- [ ] le client obtient un TGT auprès de l'AS et l'affiche ;
- [ ] avec un mauvais mot de passe, il affiche « mot de passe incorrect » ;
- [ ] il obtient un ticket de service auprès du TGS et l'affiche ;
- [ ] il obtient l'AP_REP du service, vérifie `ts + 1` et affiche « authentification mutuelle réussie » ;
- [ ] chaque erreur d'un serveur est affichée clairement, sans trace Python ;
- [ ] l'affichage est lisible pour une démo de soutenance ;
- [ ] `pytest` passe.

## 11. Ta branche git

`feat/client`. Workflow : `git switch feat/client`, `git pull origin main`, commits réguliers, `pytest`, `git push`, puis PR vers `main`. Voir [CONTRIBUTING.md](../CONTRIBUTING.md).
