# `client/` : le client (Alice)

État : fait, fusionné le 20/11 (PR n°3). Auteur : Denis. Fichier : [`client.py`](client.py).

## Rôle

Le client est le seul programme qui connaît le mot de passe d'Alice. Il en dérive K_client, puis enchaîne les trois échanges : AS (obtenir le TGT), TGS (obtenir un ticket pour « mail »), service (s'authentifier et vérifier que le service est le bon). Le mot de passe ne part jamais sur le réseau. Le client ne peut pas lire le TGT ni le ticket : il les transporte tels quels. C'est le programme qu'on montre à la soutenance, il affiche chaque étape.

```
1. AS
   Client -> AS : "alice"
   AS -> Client : E(K_client, K_c_tgs + expiration)  +  TGT (opaque)

2. TGS
   Client déchiffre avec K_client et récupère K_c_tgs
   Client -> TGS : TGT + E(K_c_tgs, "alice" + timestamp) + "mail"
   TGS -> Client : E(K_c_tgs, K_c_service + expiration)  +  ticket (opaque)

3. Service
   Client -> Service : ticket + E(K_c_service, "alice" + timestamp)
   Service -> Client : E(K_c_service, timestamp + 1)
   Client vérifie timestamp + 1 (authentification mutuelle)
```

## Messages

| Le client envoie | À | Il reçoit |
| --- | --- | --- |
| `{"type": "AS_REQ", "client": "alice"}` | AS, port 8800 | `{"type": "AS_REP", "enc_part": "...", "tgt": "..."}` |
| `{"type": "TGS_REQ", "tgt": "...", "service": "mail", "auth": "..."}` | TGS, port 8801 | `{"type": "TGS_REP", "enc_part": "...", "ticket": "..."}` |
| `{"type": "AP_REQ", "ticket": "...", "auth": "..."}` | Service, port 8802 | `{"type": "AP_REP", "enc_part": "..."}` |

```
AS_REP.enc_part  = E(K_client,    "AS_REP",   {"k_c_tgs": "<hex>", "exp": <float>})     ouvert par le client
TGS_REQ.auth     = E(K_c_tgs,     "TGS_AUTH", {"client": "alice", "ts": <float>})       fabriqué par le client
TGS_REP.enc_part = E(K_c_tgs,     "TGS_REP",  {"k_c_service": "<hex>", "exp": <float>}) ouvert par le client
AP_REQ.auth      = E(K_c_service, "AP_AUTH",  {"client": "alice", "ts": <float>})       fabriqué par le client
AP_REP.enc_part  = E(K_c_service, "AP_REP",   {"ts": <ts + 1>})                          ouvert par le client
```

| Clé | D'où elle vient |
| --- | --- |
| K_client | `derive_key(password, user)` : le client ne lit pas `keys.json` |
| K_c_tgs | `enc_part` de l'AS, contrôlée par `extraire_cle` (16 octets) |
| K_c_service | `enc_part` du TGS, contrôlée de la même façon |

## Ce que fait `run(user, password, service)`

Échange 1 : AS
- [x] 1. Dérive `k_client = derive_key(password, user)`.
- [x] 2. Envoie l'AS_REQ à `(config.HOST, config.AS_PORT)` ; gère une réponse `ERROR`.
- [x] 3. Ouvre `enc_part` avec K_client (`"AS_REP"`), récupère `k_c_tgs`, garde le TGT, l'affiche.

Échange 2 : TGS
- [x] 4. Fabrique l'authenticator `{"client": user, "ts": time.time()}` avec K_c_tgs (`"TGS_AUTH"`).
- [x] 5. Envoie le TGS_REQ à `(config.HOST, config.TGS_PORT)` ; gère `ERROR`.
- [x] 6. Ouvre `enc_part` avec K_c_tgs (`"TGS_REP"`), récupère `k_c_service`, garde le ticket, l'affiche.

Échange 3 : service
- [x] 7. Fabrique l'authenticator avec K_c_service (`"AP_AUTH"`) en gardant `ts`.
- [x] 8. Envoie l'AP_REQ à `(config.HOST, config.SERVICE_PORT)` ; gère `ERROR`.
- [x] 9. Ouvre la réponse avec K_c_service (`"AP_REP"`) et vérifie `ts + 1`.
- [x] 10. Affiche « authentification mutuelle réussie » et renvoie `True`.

## Erreurs affichées

Le client n'envoie pas de message `ERROR` : il affiche le problème et s'arrête (`return False`, code de sortie 1).

| Situation | Affichage |
| --- | --- |
| serveur non joignable (`OSError`) | « impossible de joindre l'AS / le TGS / le service » |
| réponse illisible (`ProtocolError`) | « réponse de l'AS / du TGS / du service invalide ou incomplète » |
| réponse de type `"ERROR"` | « erreur du serveur : » suivi de la raison |
| `enc_part` de l'AS indéchiffrable | « mot de passe incorrect » |
| réponse du TGS mal formée ou indéchiffrable | « réponse du TGS invalide » |
| AP_REP indéchiffrable, ou `ts` reçu différent de `ts + 1` | « service non authentifié : authentification mutuelle échouée » |

## Lancer

```bash
python scripts/init_keys.py --password motdepasse   # une fois, même mot de passe ensuite
python -m client.client --password motdepasse
python -m client.client                             # le mot de passe est demandé au clavier
```

Options : `--user` (défaut `alice`), `--service` (défaut `mail`). Sur `main`, l'AS et le TGS répondent ; le service répond encore `ERROR "non implémenté"`, que le client affiche.

Pour voir ce que le client envoie, on peut remplacer un serveur par un « espion » (arrêter d'abord le vrai serveur) :

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

## Points d'attention

- Le sel de `derive_key` est le nom du client : `derive_key(password, user)`.
- Le TGT et le ticket restent des chaînes hex qu'on ne modifie pas.
- Un authenticator neuf pour chaque requête, avec un nouveau `time.time()`.
- Le `ts` envoyé au service est gardé pour comparer avec la réponse. Les `float` passent sans perte dans le JSON de Python, la comparaison exacte marche.
- Le mot de passe n'est jamais affiché ni envoyé.

## État

- [x] le client obtient un TGT auprès de l'AS et l'affiche ;
- [x] avec un mauvais mot de passe, il affiche « mot de passe incorrect » ;
- [x] il obtient un ticket de service auprès du TGS et l'affiche ;
- [ ] il obtient l'AP_REP du service, vérifie `ts + 1` et affiche « authentification mutuelle réussie » : le code est prêt, il attend le service ;
- [x] chaque erreur d'un serveur est affichée clairement, sans trace Python ;
- [x] l'affichage est lisible pour la démo ;
- [x] `pytest` passe.

Il n'y a pas encore de `tests/test_client.py` : le client n'a aucun test automatique.
